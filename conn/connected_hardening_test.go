//go:build unix && !aix && !solaris && !illumos

package conn

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A datagram queued before a socket's connect is reported with its real source, not the peer.
func TestConnectedReportsTrueSource(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	other, otherAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})

	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.WriteToUDPAddrPort([]byte("from other"), c.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // let it queue before the connect
	rc, _ := c.SyscallConn()
	var cerr error
	rc.Control(func(fd uintptr) {
		cerr = unix.Connect(int(fd), &unix.SockaddrInet4{Port: int(peerAP.Port()), Addr: peerAP.Addr().As4()})
	})
	if cerr != nil {
		t.Fatal(cerr)
	}
	s.mu.Lock()
	s.adopt(pairKey{remote: peerAP}, c)
	s.mu.Unlock()
	if _, err := peer.WriteToUDPAddrPort([]byte("from peer"), c.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		t.Fatal(err)
	}

	slab := make([]byte, 1<<16)
	pkts := make([]ConnectedPacket, 8)
	got := map[string]netip.AddrPort{}
	for deadline := time.Now().Add(3 * time.Second); len(got) < 2 && time.Now().Before(deadline); {
		n := readWithin(t, s, slab, pkts)
		for _, p := range pkts[:n] {
			got[string(slab[p.Offset:p.Offset+p.Size])] = p.Source
		}
	}
	if got["from other"] != otherAP || got["from peer"] != peerAP {
		t.Fatalf("sources: %v; want %q from %v and %q from %v", got, "from other", otherAP, "from peer", peerAP)
	}
}

// The caller can rebind its port while connected sockets hold it, and replies still reach them.
func TestConnectedCallerRebindsSamePort(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			peer, peerAP := listenPeer(t, network)
			shared, port := listenShared(t, network)
			s := newSet(t, ConnectedConfig{Port: port})
			if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); !handled || err != nil {
				t.Fatalf("Send = %v, %v", handled, err)
			}
			_, from := peerRead(t, peer)

			shared.Close()
			lc := net.ListenConfig{Control: ReusePortControl}
			pc, err := lc.ListenPacket(context.Background(), network, net.JoinHostPort("", strconv.Itoa(port)))
			if err != nil {
				t.Fatalf("rebinding the caller's socket to its own port beside the connected sockets: %v", err)
			}
			defer pc.Close()
			s.Rebind(port)

			if handled, err := s.Send(peerAP, [][]byte{[]byte("y")}, 0); !handled || err != nil {
				t.Fatalf("Send after Rebind = %v, %v", handled, err)
			}
			peerRead(t, peer)
			peer.WriteToUDPAddrPort([]byte("pong"), from)
			slab := make([]byte, 1<<16)
			pkts := make([]ConnectedPacket, 8)
			if n := readWithin(t, s, slab, pkts); n != 1 || pkts[0].Source != peerAP {
				t.Fatalf("after the rebind, read %d packets, first from %v", n, pkts[0].Source)
			}
		})
	}
}

// After Close nothing is dialled: Send leaves the batch to the caller and starts no reader.
func TestConnectedSendAfterClose(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := NewConnectedSockets(ConnectedConfig{Port: port, OpenAfter: 1})
	s.Close()
	before := runtime.NumGoroutine()
	if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); handled || err != nil {
		t.Fatalf("Send after Close = %v, %v; want false, nil", handled, err)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("Send after Close started %d goroutines", after-before)
	}
	peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := peer.ReadFrom(make([]byte, 16)); err == nil {
		t.Fatal("a socket dialled after Close sent the datagram")
	}
}

// A dial that races Rebind or Close is discarded, not kept with the old port or left running after Close.
func TestConnectedDialRacingResetIsDiscarded(t *testing.T) {
	for _, tc := range []struct {
		name string
		race func(*ConnectedSockets)
	}{
		{"Rebind", func(s *ConnectedSockets) { s.Rebind(s.cfg.Port) }},
		{"Close", func(s *ConnectedSockets) { s.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, peerAP := listenPeer(t, "udp4")
			_, port := listenShared(t, "udp4")
			var s *ConnectedSockets
			var once atomic.Bool
			s = newSet(t, ConnectedConfig{Port: port, Control: func(network, address string, c syscall.RawConn) error {
				if once.CompareAndSwap(false, true) {
					tc.race(s) // while the dial is in progress
				}
				return nil
			}})
			if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); handled || err != nil {
				t.Fatalf("Send whose dial raced %s = %v, %v; want false, nil", tc.name, handled, err)
			}
			s.mu.Lock()
			n := len(s.socks)
			s.mu.Unlock()
			if n != 0 {
				t.Fatalf("a dial that raced %s was kept", tc.name)
			}
		})
	}
}

// A slab too small for one slot is an error, not an endless empty read.
func TestConnectedReadSlabTooSmall(t *testing.T) {
	_, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	got := make(chan started, 1)
	s := newSet(t, ConnectedConfig{Port: port, Reader: capture(got)})
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	st := <-got
	if n, err := st.read(make([]byte, 500), make([]ConnectedPacket, st.batchSize)); err == nil || errors.Is(err, net.ErrClosed) {
		t.Fatalf("read into a 500-byte slab = %d, %v; want an error that is not net.ErrClosed", n, err)
	}
}

// A ConnectedReadFunc reports net.ErrClosed after Close even when its socket had datagrams waiting.
func TestConnectedReadAfterCloseIsClosed(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	got := make(chan started, 1)
	s := newSet(t, ConnectedConfig{Port: port, Reader: capture(got)})
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	_, from := peerRead(t, peer)
	st := <-got
	peer.WriteToUDPAddrPort([]byte("a"), from)
	peer.WriteToUDPAddrPort([]byte("b"), from)
	time.Sleep(50 * time.Millisecond)
	slab := make([]byte, st.slabSize)
	if n, err := st.read(slab, make([]ConnectedPacket, st.batchSize)); err != nil || n < 1 {
		t.Fatalf("read before Close = %d, %v", n, err)
	}
	s.Close()
	if n, err := st.read(slab, make([]ConnectedPacket, st.batchSize)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after Close = %d, %v; want net.ErrClosed", n, err)
	}
}

// An address whose dial failed is not dialled again on every send, and Rebind clears that.
func TestConnectedFailedDialBacksOff(t *testing.T) {
	_, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	var dials atomic.Int32
	s := newSet(t, ConnectedConfig{Port: port, Control: func(network, address string, c syscall.RawConn) error {
		dials.Add(1)
		return errors.New("refused by the test")
	}})
	for range 5 {
		if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); handled || err != nil {
			t.Fatalf("Send = %v, %v; want false, nil", handled, err)
		}
	}
	first := dials.Load()
	if first == 0 {
		t.Fatal("Control was never called")
	}
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	if dials.Load() != first {
		t.Fatalf("a failed address was dialled again on the next send (%d Control calls, then %d)", first, dials.Load())
	}
	s.Rebind(port)
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	if dials.Load() == first {
		t.Fatal("Rebind did not clear the failed dial")
	}
}

// A socket closed underneath is redialled rather than failing the send.
func TestConnectedSendRedialsClosedSocket(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	peerRead(t, peer)
	socketTo(s, peerAP).c.Close() // closed underneath, but still in the map
	if handled, err := s.Send(peerAP, [][]byte{[]byte("again")}, 0); !handled || err != nil {
		t.Fatalf("Send on a socket closed underneath = %v, %v; want true, nil", handled, err)
	}
	if got, _ := peerRead(t, peer); string(got) != "again" {
		t.Fatalf("peer got %q", got)
	}
}

// A send error meaning the source address is gone closes the socket so the next send redials. EINVAL counts only on Linux, where it can mean that.
func TestConnectedLostSourceRecycles(t *testing.T) {
	_, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	for _, errno := range []error{unix.EINVAL, unix.EADDRNOTAVAIL, unix.ENETUNREACH} {
		s.Send(peerAP, [][]byte{[]byte("x")}, 0)
		cs := socketTo(s, peerAP)
		s.classify(cs, &net.OpError{Op: "write", Err: errno})
		kept := socketTo(s, peerAP) != nil
		if want := errno == unix.EINVAL && runtime.GOOS != "linux"; kept != want {
			t.Fatalf("after %v: socket kept %v, want %v", errno, kept, want)
		}
	}
}

// Dial opens a socket for an address the caller never sent to, which then takes that address's datagrams.
func TestConnectedDialTakesInbound(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	shared, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	to := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))

	peer.WriteToUDPAddrPort([]byte("before"), to)
	shared.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	if n, _, err := shared.ReadFromUDP(buf); err != nil || string(buf[:n]) != "before" {
		t.Fatalf("before Dial the caller's socket read %q, %v; want the datagram", buf[:max(n, 0)], err)
	}

	if !s.Dial(peerAP, netip.Addr{}, 1) {
		t.Fatal("Dial reported no socket")
	}
	peer.WriteToUDPAddrPort([]byte("after"), to)
	slab := make([]byte, 1<<16)
	pkts := make([]ConnectedPacket, 8)
	if n := readWithin(t, s, slab, pkts); n != 1 || string(slab[pkts[0].Offset:pkts[0].Offset+pkts[0].Size]) != "after" || pkts[0].Source != peerAP {
		t.Fatalf("after Dial, ReadBatch returned %d packets from %v; want %q from %v", n, pkts[0].Source, "after", peerAP)
	}
	shared.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := shared.ReadFromUDP(buf); err == nil {
		t.Fatal("after Dial the datagram still reached the caller's socket")
	}
}

// Receiving counts as use: the idle check keeps a receive-only socket until its traffic stops.
func TestConnectedReceiveOnlyStaysOpen(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	to := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
	s.Dial(peerAP, netip.Addr{}, 1)
	slab := make([]byte, 1<<16)
	pkts := make([]ConnectedPacket, 8)
	has := func() bool { return socketTo(s, peerAP) != nil }
	for range 3 {
		peer.WriteToUDPAddrPort([]byte("x"), to)
		readWithin(t, s, slab, pkts)
		s.closeIdle()
	}
	if !has() {
		t.Fatal("a socket receiving traffic was closed as idle")
	}
	s.closeIdle()
	s.closeIdle()
	if has() {
		t.Fatal("a socket with no traffic either way was kept")
	}
}

// Concurrent first callers for a pair dial it once. Dial with a local address skips the route lookup, which spaces callers out too much to race.
func TestConnectedConcurrentFirstSendsDialOnce(t *testing.T) {
	for range 20 {
		_, peerAP := listenPeer(t, "udp4")
		_, port := listenShared(t, "udp4")
		var dials atomic.Int32
		s := newSet(t, ConnectedConfig{Port: port, Control: func(string, string, syscall.RawConn) error {
			dials.Add(1)
			time.Sleep(time.Millisecond) // hold the dial open so the others arrive
			return nil
		}})
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				s.Dial(peerAP, netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1)
			}()
		}
		close(start)
		wg.Wait()
		s.mu.Lock()
		socks, failed := len(s.socks), len(s.failed)
		s.mu.Unlock()
		if n := dials.Load(); socks != 1 || failed != 0 || n != 1 {
			t.Fatalf("after 8 concurrent first callers: %d dials, %d sockets and %d failed dials; want 1, 1 and 0", n, socks, failed)
		}
	}
}

// otherIPv4 returns one of this host's non-loopback IPv4 addresses.
func otherIPv4(t *testing.T) netip.Addr {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return ip.Unmap()
			}
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return netip.Addr{}
}

// Dial opens one socket for a peer sending to a host address other than the route's pick, and repeat Dials open nothing more.
func TestConnectedDialForLocalAddress(t *testing.T) {
	other := otherIPv4(t)
	peer, peerAP := listenPeer(t, "udp4")
	shared, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); !handled || err != nil {
		t.Fatalf("Send = %v, %v", handled, err)
	}
	peerRead(t, peer)
	to := netip.AddrPortFrom(other, uint16(port))
	buf := make([]byte, 64)

	peer.WriteToUDPAddrPort([]byte("before"), to)
	shared.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := shared.ReadFromUDP(buf); err != nil || string(buf[:n]) != "before" {
		t.Fatalf("to %v before Dial, the caller's socket read %q, %v; the socket Send opened should not have matched", other, buf[:max(n, 0)], err)
	}

	if !s.Dial(peerAP, other, 1) {
		t.Fatal("Dial reported no socket")
	}
	peer.WriteToUDPAddrPort([]byte("after"), to)
	slab := make([]byte, 1<<16)
	pkts := make([]ConnectedPacket, 8)
	if n := readWithin(t, s, slab, pkts); n != 1 || string(slab[pkts[0].Offset:pkts[0].Offset+pkts[0].Size]) != "after" || pkts[0].Source != peerAP {
		t.Fatalf("after Dial, ReadBatch returned %d packets from %v; want %q from %v", n, pkts[0].Source, "after", peerAP)
	}
	shared.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := shared.ReadFromUDP(buf); err == nil {
		t.Fatal("after Dial the datagram still reached the caller's socket")
	}

	s.Dial(peerAP, other, 1)
	s.Dial(peerAP, netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1)
	s.mu.Lock()
	socks := len(s.socks)
	s.mu.Unlock()
	if socks != 2 {
		t.Fatalf("after repeat Dials: %d sockets; want 2, one for each pair that carried traffic", socks)
	}
}

// Send reuses a pair Dial opened rather than dialling it again, which darwin and the BSDs refuse.
func TestConnectedSendUsesPairOpenedByDial(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	if !s.Dial(peerAP, netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1) {
		t.Fatal("Dial reported no socket")
	}
	if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); !handled || err != nil {
		t.Fatalf("Send on a pair Dial opened = %v, %v; want true, nil", handled, err)
	}
	if got, _ := peerRead(t, peer); string(got) != "x" {
		t.Fatalf("peer got %q", got)
	}
	s.mu.Lock()
	socks, failed := len(s.socks), len(s.failed)
	s.mu.Unlock()
	if socks != 1 || failed != 0 {
		t.Fatalf("%d sockets and %d failed dials; want 1 and 0", socks, failed)
	}
}

// Dials past the socket limit are never started, rather than completed and closed, since a new socket may already hold other peers' datagrams.
func TestConnectedLimitDiscardsNoDial(t *testing.T) {
	_, port := listenShared(t, "udp4")
	var dials atomic.Int32
	s := newSet(t, ConnectedConfig{Port: port, MaxSockets: 2, Control: func(string, string, syscall.RawConn) error {
		dials.Add(1)
		time.Sleep(time.Millisecond) // keep a dial in progress while the others arrive
		return nil
	}})
	var peers []netip.AddrPort
	for range 6 {
		_, ap := listenPeer(t, "udp4")
		peers = append(peers, ap)
	}
	burst(peers, func(ap netip.AddrPort) { s.Dial(ap, netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1) })
	for _, ap := range peers { // and each asks again, so the limit is reached
		s.Dial(ap, netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1)
	}
	s.mu.Lock()
	socks := len(s.socks)
	s.mu.Unlock()
	if n := dials.Load(); socks != 2 || n != 2 {
		t.Fatalf("%d dials for %d sockets under a limit of 2; want 2 and 2, none thrown away", n, socks)
	}
}

// Many peers on one local address opened at once all get sockets, with no failed dials.
// On darwin and the BSDs two unconnected sockets cannot bind the same address and port, so dials run one at a time.
func TestConnectedConcurrentPairsOnOneAddress(t *testing.T) {
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port, Control: func(string, string, syscall.RawConn) error {
		time.Sleep(time.Millisecond)
		return nil
	}})
	var peers []netip.AddrPort
	for range 8 {
		_, ap := listenPeer(t, "udp4")
		peers = append(peers, ap)
	}
	local := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	burst(peers, func(ap netip.AddrPort) { s.Dial(ap, local, 1) })
	for _, ap := range peers {
		if !s.Dial(ap, local, 1) {
			t.Fatalf("no socket for %v on its second try", ap)
		}
	}
	s.mu.Lock()
	socks, failed := len(s.socks), len(s.failed)
	s.mu.Unlock()
	if socks != len(peers) || failed != 0 {
		t.Fatalf("%d sockets and %d failed dials for %d peers; want %d and 0", socks, failed, len(peers), len(peers))
	}
}

// burst runs f for every peer at once.
func burst(peers []netip.AddrPort, f func(netip.AddrPort)) {
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, ap := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			f(ap)
		}()
	}
	close(start)
	wg.Wait()
}

// Opening a pair mid-stream loses nothing and credits each datagram to its real sender.
func TestConnectedOpeningMidStreamLosesNothing(t *testing.T) {
	a, aAP := listenPeer(t, "udp4")
	b, bAP := listenPeer(t, "udp4")
	shared, port := listenShared(t, "udp4")
	shared.SetReadBuffer(4 << 20)
	s := newSet(t, ConnectedConfig{Port: port})
	to := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port))
	tags := map[netip.AddrPort]byte{aAP: 'a', bAP: 'b'}
	const n = 2000

	var mu sync.Mutex
	seen := map[byte]map[uint32]bool{'a': {}, 'b': {}}
	var misattributed atomic.Int32
	note := func(src netip.AddrPort, p []byte) {
		if len(p) != 5 {
			return
		}
		if tags[src] != p[0] {
			misattributed.Add(1)
		}
		mu.Lock()
		seen[p[0]][binary.BigEndian.Uint32(p[1:])] = true
		mu.Unlock()
	}
	count := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return len(seen['a']), len(seen['b'])
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		buf := make([]byte, 64)
		for {
			select {
			case <-stop:
				return
			default:
			}
			shared.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if n, src, err := shared.ReadFromUDPAddrPort(buf); err == nil {
				note(src, buf[:n])
			}
		}
	}()
	c, _ := collectors.Load(s)
	go func() {
		for {
			select {
			case <-stop:
				return
			case r := <-c.(*collector).ch:
				note(r.p.Source, r.data)
			}
		}
	}()

	msg := func(tag byte, i int) []byte {
		p := []byte{tag, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(p[1:], uint32(i))
		return p
	}
	for i := range n {
		a.WriteToUDPAddrPort(msg('a', i), to)
		b.WriteToUDPAddrPort(msg('b', i), to)
		if i == n/2 {
			if !s.Dial(aAP, to.Addr(), 1) {
				t.Fatal("Dial reported no socket")
			}
		}
		if i%50 == 49 {
			time.Sleep(time.Millisecond) // pace it so loopback drops nothing
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if na, nb := count(); na == n && nb == n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	na, nb := count()
	if na != n || nb != n || misattributed.Load() != 0 {
		t.Fatalf("received %d of %d from a and %d of %d from b, %d credited to the wrong peer; want all and none", na, n, nb, n, misattributed.Load())
	}
	if socketTo(s, aAP) == nil {
		t.Fatal("a's pair was not opened")
	}
}

// A pair opens only after OpenAfter bytes, sent and received combined.
func TestConnectedOpensAfterThreshold(t *testing.T) {
	_, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port, OpenAfter: 10000})
	dgram := [][]byte{make([]byte, 1000)}
	for i := range 5 {
		if handled, _ := s.Send(peerAP, dgram, 0); handled {
			t.Fatalf("send %d, at %d bytes, was taken; the threshold is 10000", i+1, (i+1)*1000)
		}
	}
	local := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	for i := range 4 {
		if s.Dial(peerAP, local, 1000) {
			t.Fatalf("receive %d, at %d bytes in all, opened the pair", i+1, 6000+i*1000)
		}
	}
	if handled, _ := s.Send(peerAP, dgram, 0); !handled {
		t.Fatal("the send that brought the pair to 10000 bytes was not taken")
	}
}

// The byte count resets at every idle check, so occasional traffic never opens a pair.
func TestConnectedThresholdCountsRecentTraffic(t *testing.T) {
	_, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port, OpenAfter: 10000})
	for range 9 {
		s.Send(peerAP, [][]byte{make([]byte, 1000)}, 0)
	}
	s.closeIdle()
	if handled, _ := s.Send(peerAP, [][]byte{make([]byte, 1000)}, 0); handled {
		t.Fatal("9000 bytes before an idle check and 1000 after opened the pair")
	}
}

// An open pair survives a trickle and closes only after a whole idle interval, so it does not flap.
func TestConnectedTrickleKeepsPairOpen(t *testing.T) {
	_, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port, OpenAfter: 10000})
	for range 10 {
		s.Send(peerAP, [][]byte{make([]byte, 1000)}, 0)
	}
	if socketTo(s, peerAP) == nil {
		t.Fatal("pair not opened")
	}
	for range 5 {
		s.closeIdle()
		s.Send(peerAP, [][]byte{make([]byte, 60)}, 0) // a keepalive's worth
	}
	if socketTo(s, peerAP) == nil {
		t.Fatal("a pair with a trickle of traffic was closed")
	}
	s.closeIdle()
	s.closeIdle()
	if socketTo(s, peerAP) != nil {
		t.Fatal("a pair with no traffic for a whole interval stayed open")
	}
}

// When the route's pick changes, sends move to the new pair at the next recheck and the old socket stays until idle.
func TestConnectedRecheckFollowsRoute(t *testing.T) {
	other := otherIPv4(t)
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	var picks atomic.Value
	picks.Store(loopback)
	s.route = func(netip.AddrPort) (netip.Addr, error) { return picks.Load().(netip.Addr), nil }

	send := func() netip.Addr {
		t.Helper()
		if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); !handled || err != nil {
			t.Fatalf("Send = %v, %v", handled, err)
		}
		_, from := peerRead(t, peer)
		return from.Addr()
	}
	if from := send(); from != loopback {
		t.Fatalf("first send from %v, want %v", from, loopback)
	}

	picks.Store(other)
	if from := send(); from != loopback {
		t.Fatalf("before the check, send from %v; want the pair already in use, %v", from, loopback)
	}
	s.recheckRoutes()
	if from := send(); from != other {
		t.Fatalf("after the check, send from %v; want the route's new pick, %v", from, other)
	}
	s.mu.Lock()
	_, kept := s.socks[pairKey{loopback, peerAP}]
	s.mu.Unlock()
	if !kept {
		t.Fatal("the check closed the old pair's socket; it should be left for the idle check")
	}
	s.closeIdle()
	s.closeIdle()
	s.mu.Lock()
	_, kept = s.socks[pairKey{loopback, peerAP}]
	s.mu.Unlock()
	if kept {
		t.Fatal("the old pair's socket outlived two idle checks without traffic")
	}
}
