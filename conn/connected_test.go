//go:build unix && !aix && !solaris && !illumos

package conn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// socketTo returns the socket connected to dst, or nil.
func socketTo(s *ConnectedSockets, dst netip.AddrPort) *connectedSocket {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, cs := range s.socks {
		if k.remote == dst {
			return cs
		}
	}
	return nil
}

// openPairThroughBind sends enough through b to open a pair and returns the source address the peer saw.
func openPairThroughBind(t *testing.T, b Bind, ep Endpoint, peer *net.UDPConn) netip.AddrPort {
	t.Helper()
	bufs := make([][]byte, 64)
	for i := range bufs {
		bufs[i] = make([]byte, 1024)
	}
	for sent := 0; sent <= DefaultOpenAfter; sent += len(bufs) * 1024 {
		if err := b.Send(bufs, ep, 0); err != nil {
			t.Fatal(err)
		}
	}
	var from netip.AddrPort
	buf := make([]byte, 2048)
	for {
		peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, src, err := peer.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		from = src
	}
	if !from.IsValid() {
		t.Fatal("the peer received nothing")
	}
	return from
}

// listenPeer returns a UDP socket standing in for a remote peer.
func listenPeer(t *testing.T, network string) (*net.UDPConn, netip.AddrPort) {
	t.Helper()
	ip := net.IPv4(127, 0, 0, 1)
	if network == "udp6" {
		ip = net.IPv6loopback
	}
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Skipf("listen %s: %v", network, err)
	}
	t.Cleanup(func() { c.Close() })
	return c, c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// listenShared returns a socket that shares its port the way a Bind's does.
func listenShared(t *testing.T, network string) (*net.UDPConn, int) {
	t.Helper()
	lc := net.ListenConfig{Control: ReusePortControl}
	pc, err := lc.ListenPacket(context.Background(), network, ":0")
	if err != nil {
		t.Fatalf("listen shared: %v", err)
	}
	c := pc.(*net.UDPConn)
	t.Cleanup(func() { c.Close() })
	return c, c.LocalAddr().(*net.UDPAddr).Port
}

func newSet(t *testing.T, cfg ConnectedConfig) *ConnectedSockets {
	t.Helper()
	if cfg.OpenAfter == 0 {
		cfg.OpenAfter = 1 // open on first use
	}
	s := NewConnectedSockets(cfg)
	if s == nil {
		t.Skip("connected sockets unavailable on this platform")
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// readWithin runs ReadBatch with a deadline, since it blocks by design.
func readWithin(t *testing.T, s *ConnectedSockets, slab []byte, pkts []ConnectedPacket) int {
	t.Helper()
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		n, err := s.ReadBatch(slab, pkts)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("ReadBatch: %v", r.err)
		}
		return r.n
	case <-time.After(3 * time.Second):
		t.Fatal("ReadBatch timed out")
		return 0
	}
}

func peerRead(t *testing.T, peer *net.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()
	buf := make([]byte, 65535)
	peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := peer.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	return buf[:n], from
}

// The peer sees the shared port as the source, and its reply reaches only the connected socket.
func TestConnectedSharesPortAndStealsReplies(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			peer, peerAP := listenPeer(t, network)
			shared, port := listenShared(t, network)
			s := newSet(t, ConnectedConfig{Port: port})

			if handled, err := s.Send(peerAP, [][]byte{[]byte("ping")}, 0); !handled || err != nil {
				t.Fatalf("Send = %v, %v; want true, nil", handled, err)
			}
			got, from := peerRead(t, peer)
			if string(got) != "ping" {
				t.Fatalf("peer got %q", got)
			}
			if int(from.Port()) != port {
				t.Fatalf("peer saw source port %d, want the shared port %d; NAT mappings would differ", from.Port(), port)
			}

			if _, err := peer.WriteToUDPAddrPort([]byte("pong"), from); err != nil {
				t.Fatal(err)
			}
			slab := make([]byte, 1<<16)
			pkts := make([]ConnectedPacket, IdealBatchSize)
			n := readWithin(t, s, slab, pkts)
			if n != 1 || string(slab[pkts[0].Offset:pkts[0].Offset+pkts[0].Size]) != "pong" {
				t.Fatalf("ReadBatch got %d packets, first %q", n, slab[pkts[0].Offset:pkts[0].Offset+pkts[0].Size])
			}
			if pkts[0].Source != peerAP {
				t.Fatalf("Source = %v, want %v", pkts[0].Source, peerAP)
			}
			shared.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, _, err := shared.ReadFromUDP(make([]byte, 64)); err == nil {
				t.Fatal("the reply also reached the caller's own socket; it should go only to the connected one")
			}
		})
	}
}

// A batch arrives intact and in order in both directions.
func TestConnectedBatchInOrder(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})

	const offset = 16
	var bufs [][]byte
	for i := range 64 {
		b := make([]byte, offset+1000)
		b[offset] = byte(i)
		bufs = append(bufs, b)
	}
	if _, err := s.Send(peerAP, bufs, offset); err != nil {
		t.Fatal(err)
	}
	var from netip.AddrPort
	for i := range 64 {
		got, f := peerRead(t, peer)
		from = f
		if len(got) != 1000 || got[0] != byte(i) {
			t.Fatalf("datagram %d: len %d first byte %d", i, len(got), got[0])
		}
	}

	for i := range 64 {
		peer.WriteToUDPAddrPort([]byte{byte(i), 1, 2, 3}, from)
	}
	slab := make([]byte, 1<<16)
	pkts := make([]ConnectedPacket, IdealBatchSize)
	seen := 0
	for seen < 64 {
		n := readWithin(t, s, slab, pkts)
		for _, p := range pkts[:n] {
			if p.Size != 4 || slab[p.Offset] != byte(seen) {
				t.Fatalf("reply %d out of order or damaged: size %d first %d", seen, p.Size, slab[p.Offset])
			}
			seen++
		}
	}
}

// Concurrent sends to one address all arrive intact.
func TestConnectedConcurrentSends(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	shared, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	// Small enough to fit an unprivileged Linux receive buffer (about 200 KiB).
	const senders, each = 8, 10
	done := make(chan struct{})
	for g := range senders {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := range each {
				bufs := [][]byte{{byte(g), byte(i), 0xaa}, {byte(g), byte(i), 0xbb}}
				handled, err := s.Send(peerAP, bufs, 0)
				if err != nil {
					t.Error(err)
					return
				}
				if !handled { // fall back, as a Bind does
					for _, b := range bufs {
						shared.WriteToUDPAddrPort(b, peerAP)
					}
				}
			}
		}()
	}
	got := 0
	buf := make([]byte, 64)
	for got < senders*each*2 {
		peer.SetReadDeadline(time.Now().Add(time.Second)) // stop a second after the last datagram
		n, _, err := peer.ReadFromUDPAddrPort(buf)
		if err != nil {
			break
		}
		if n != 3 || buf[0] >= senders || (buf[2] != 0xaa && buf[2] != 0xbb) {
			t.Fatalf("damaged datagram %x", buf[:n])
		}
		got++
	}
	for range senders {
		<-done
	}
	if got < senders*each*2*9/10 { // loopback may drop a few; damage is what matters
		t.Fatalf("received %d of %d datagrams", got, senders*each*2)
	}
}

// A read that does not fit the caller's descriptors or slab is kept for the next call, not dropped.
func TestConnectedReadBatchCarries(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	_, from := peerRead(t, peer)
	for i := range 10 {
		peer.WriteToUDPAddrPort([]byte{byte(i)}, from)
	}
	time.Sleep(100 * time.Millisecond) // let them queue so one read collects several

	pkts := make([]ConnectedPacket, 3)
	slab := make([]byte, 1<<16)
	seen := 0
	for seen < 10 {
		n := readWithin(t, s, slab, pkts)
		if n > 3 {
			t.Fatalf("ReadBatch returned %d, more than the %d descriptors it was given", n, len(pkts))
		}
		for _, p := range pkts[:n] {
			if slab[p.Offset] != byte(seen) {
				t.Fatalf("got %d, want %d", slab[p.Offset], seen)
			}
			seen++
		}
	}
}

// A datagram too large for a socket's slots costs that one datagram and moves the socket to larger slots. The socket stays connected, so a jumbo path keeps its connected socket and its full batch.
func TestConnectedGrowsForLargerDatagrams(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	shared, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	_, from := peerRead(t, peer)
	slab := make([]byte, 1<<17)
	pkts := make([]ConnectedPacket, IdealBatchSize)
	expect := func(size int) {
		t.Helper()
		if n := readWithin(t, s, slab, pkts); n != 1 || pkts[0].Size != size {
			t.Fatalf("got %d packets, first size %d; want one of %d", n, pkts[0].Size, size)
		}
	}

	if socketTo(s, peerAP).gro {
		// A GRO socket already has the largest slots.
		for range 3 {
			peer.WriteToUDPAddrPort(make([]byte, 9000), from)
			expect(9000)
		}
		if got := s.oversize.Load(); got != 0 {
			t.Fatalf("a GRO socket lost %d datagrams; it should lose none", got)
		}
		return
	}

	peer.WriteToUDPAddrPort(make([]byte, connectedSmallSlot-1), from)
	expect(connectedSmallSlot - 1) // the largest that fits a small slot

	// Too big: dropped, and the socket grows.
	peer.WriteToUDPAddrPort(make([]byte, 9000), from)
	deadline := time.Now().Add(3 * time.Second)
	for s.oversize.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for range 3 {
		peer.WriteToUDPAddrPort(make([]byte, 9000), from)
		expect(9000)
	}
	if got := s.oversize.Load(); got != 1 {
		t.Fatalf("lost %d datagrams growing the slots, want exactly 1", got)
	}
	if handled, _ := s.Send(peerAP, [][]byte{[]byte("x")}, 0); !handled {
		t.Fatal("the address lost its connected socket; it should have kept it with larger slots")
	}
	shared.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := shared.ReadFromUDP(make([]byte, 65535)); err == nil {
		t.Fatal("traffic moved to the caller's socket; it should stay on the connected one")
	}
	if n := len(s.pools[1].Get().(*rxBatch).bufs); n != IdealBatchSize {
		t.Fatalf("a jumbo socket reads %d datagrams per call, want a full batch of %d", n, IdealBatchSize)
	}
}

// A caller that expects jumbo datagrams starts there and loses none.
func TestConnectedMaxDatagramHint(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port, MaxDatagram: 9000 + 32})
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	_, from := peerRead(t, peer)
	peer.WriteToUDPAddrPort(make([]byte, 9000+32), from)
	pkts := make([]ConnectedPacket, IdealBatchSize)
	if n := readWithin(t, s, make([]byte, 1<<17), pkts); n != 1 || pkts[0].Size != 9032 || s.oversize.Load() != 0 {
		t.Fatalf("got %d packets of %d with %d lost; want one of 9032 and none lost", n, pkts[0].Size, s.oversize.Load())
	}
}

// Past the limit Send declines, so the caller uses its own socket.
func TestConnectedLimit(t *testing.T) {
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port, MaxSockets: 2})
	for i := range 3 {
		_, ap := listenPeer(t, "udp4")
		handled, err := s.Send(ap, [][]byte{[]byte("x")}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if want := i < 2; handled != want {
			t.Fatalf("send %d: handled = %v, want %v", i, handled, want)
		}
	}
}

// The idle check closes a socket unused for a whole interval.
func TestConnectedCloseIdle(t *testing.T) {
	_, a := listenPeer(t, "udp4")
	_, b := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	s.Send(a, [][]byte{[]byte("x")}, 0)
	s.Send(b, [][]byte{[]byte("x")}, 0)
	s.closeIdle() // both were used at creation: second chance
	s.Send(a, [][]byte{[]byte("x")}, 0)
	s.closeIdle()
	hasA := socketTo(s, a) != nil
	hasB := socketTo(s, b) != nil
	if !hasA || hasB {
		t.Fatalf("after two checks: a open %v (want true), b open %v (want false)", hasA, hasB)
	}
}

// Sending to a closed port is not an error.
func TestConnectedRefusedIsNotAnError(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	peer.Close()
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	for range 3 {
		if _, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); err != nil {
			t.Fatalf("Send to a closed port: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The reader survives the ECONNREFUSED some platforms report after an ICMP port unreachable.
func TestConnectedReaderSurvivesRefused(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	_, from := peerRead(t, peer)
	peer.Close()
	for range 3 { // provoke port unreachables while nothing listens
		s.Send(peerAP, [][]byte{[]byte("x")}, 0)
		time.Sleep(20 * time.Millisecond)
	}
	back, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(peerAP))
	if err != nil {
		t.Skipf("could not reopen the peer's port: %v", err)
	}
	defer back.Close()
	back.WriteToUDPAddrPort([]byte("again"), from)
	pkts := make([]ConnectedPacket, IdealBatchSize)
	slab := make([]byte, 1<<16)
	if n := readWithin(t, s, slab, pkts); n != 1 || string(slab[pkts[0].Offset:pkts[0].Offset+pkts[0].Size]) != "again" {
		t.Fatalf("after the peer came back: %d packets", n)
	}
}

// The caller's Control runs on every dialled socket; if it fails, the send is left to the caller.
func TestConnectedControl(t *testing.T) {
	_, port := listenShared(t, "udp4")
	var calls atomic.Int32
	s := newSet(t, ConnectedConfig{Port: port, Control: func(string, string, syscall.RawConn) error {
		calls.Add(1)
		return nil
	}})
	for range 2 {
		_, ap := listenPeer(t, "udp4")
		s.Send(ap, [][]byte{[]byte("x")}, 0)
	}
	// Some platforms also run it for the route lookup.
	if calls.Load() < 2 {
		t.Fatalf("Control ran %d times, want at least once for each of 2 sockets", calls.Load())
	}
	f := newSet(t, ConnectedConfig{Port: port, Control: func(string, string, syscall.RawConn) error { return errors.New("no") }})
	_, ap := listenPeer(t, "udp4")
	if handled, _ := f.Send(ap, [][]byte{[]byte("x")}, 0); handled {
		t.Fatal("Send took a batch on a socket whose Control failed")
	}
}

// Close unblocks a waiting ReadBatch and waits for the readers, and a nil set is safe to use.
func TestConnectedClose(t *testing.T) {
	_, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := NewConnectedSockets(ConnectedConfig{Port: port, OpenAfter: 1})
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	errc := make(chan error, 1)
	go func() {
		_, err := s.ReadBatch(make([]byte, 1<<16), make([]ConnectedPacket, 8))
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	s.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadBatch after Close: %v, want net.ErrClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock ReadBatch")
	}

	var nilSet *ConnectedSockets
	if handled, err := nilSet.Send(peerAP, nil, 0); handled || err != nil {
		t.Fatal("nil set took a send")
	}
	nilSet.reset()
	nilSet.Close()
}

// Rebind moves new sockets to the caller's new port.
func TestConnectedRebind(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	_, port2 := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	if _, from := peerRead(t, peer); int(from.Port()) != port {
		t.Fatalf("source port %d, want %d", from.Port(), port)
	}
	s.Rebind(port2)
	s.Send(peerAP, [][]byte{[]byte("x")}, 0)
	if _, from := peerRead(t, peer); int(from.Port()) != port2 {
		t.Fatalf("after Rebind, source port %d, want %d", from.Port(), port2)
	}
}

// A set with no port takes no sends, as an ephemeral source port would look like another peer.
func TestConnectedPortZeroTakesNothing(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{})
	if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); handled || err != nil {
		t.Fatalf("Send with no port = %v, %v; want false, nil", handled, err)
	}
	if s.Dial(peerAP, netip.AddrFrom4([4]byte{127, 0, 0, 1}), 1) {
		t.Fatal("Dial with no port opened a socket")
	}
	s.Rebind(port)
	if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); !handled || err != nil {
		t.Fatalf("Send after Rebind(%d) = %v, %v; want true, nil", port, handled, err)
	}
	if _, from := peerRead(t, peer); int(from.Port()) != port {
		t.Fatalf("source port %d, want %d", from.Port(), port)
	}
	s.Rebind(0)
	if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); handled || err != nil {
		t.Fatalf("Send after Rebind(0) = %v, %v; want false, nil", handled, err)
	}
}

// WithConnectedSockets is honoured per Bind, and a send and its reply use the connected socket.
func TestStdNetBindConnected(t *testing.T) {
	on := NewStdNetBind(WithConnectedSockets(true)).(*StdNetBind)
	off := NewStdNetBind(WithConnectedSockets(false)).(*StdNetBind)
	def := NewStdNetBind().(*StdNetBind)
	if !on.connected || off.connected || def.connected != connectedByDefault {
		t.Fatalf("connected: on %v off %v default %v (platform default %v)", on.connected, off.connected, def.connected, connectedByDefault)
	}
	if on.BatchSize() != IdealBatchSize {
		t.Fatalf("BatchSize with connected sockets = %d, want %d", on.BatchSize(), IdealBatchSize)
	}

	peer, peerAP := listenPeer(t, "udp4")
	fns, port, err := on.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer on.Close()
	if on.cs == nil {
		t.Fatal("no connected sockets after Open")
	}
	ep := &StdNetEndpoint{AddrPort: peerAP}
	from := openPairThroughBind(t, on, ep, peer)
	if socketTo(on.cs, peerAP) == nil {
		t.Fatal("no connected socket after sending the threshold's worth")
	}
	if from.Port() != port {
		t.Fatalf("source port %d, want the bind's %d", from.Port(), port)
	}
	peer.WriteToUDPAddrPort([]byte("pong"), from)
	recv := fns[len(fns)-1] // the connected ReceiveFunc is last
	slab := make([]byte, 1<<16)
	packets := make([]ReceivedPacket, IdealBatchSize)
	done := make(chan int, 1)
	go func() { n, _ := recv(slab, packets); done <- n }()
	select {
	case n := <-done:
		p := packets[0]
		if n != 1 || string(slab[p.Offset:p.Offset+p.Size]) != "pong" || p.Endpoint.DstToString() != peerAP.String() {
			t.Fatalf("got %d packets, %q from %v", n, slab[p.Offset:p.Offset+p.Size], p.Endpoint.DstToString())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reply never reached the connected ReceiveFunc")
	}
}
