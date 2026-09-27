//go:build linux

package conn

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// SetMark applies to connected sockets, so their packets do not route back into the tunnel.
func TestConnectedSocketsCarryTheMark(t *testing.T) {
	b := NewStdNetBind(WithConnectedSockets(true)).(*StdNetBind)
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.SetMark(0x1234); err != nil {
		t.Skipf("SetMark needs CAP_NET_ADMIN: %v", err)
	}
	peer, peerAP := listenPeer(t, "udp4")
	openPairThroughBind(t, b, &StdNetEndpoint{AddrPort: peerAP}, peer)
	markOf := func() int {
		cs := socketTo(b.cs, peerAP)
		if cs == nil {
			t.Fatal("no connected socket for the peer")
		}
		rc, _ := cs.c.SyscallConn()
		var mark int
		rc.Control(func(fd uintptr) { mark, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK) })
		return mark
	}
	if got := markOf(); got != 0x1234 {
		t.Fatalf("socket dialled after SetMark has mark %#x, want 0x1234", got)
	}
	// Changing the mark closes the sockets so they redial with it.
	b.SetMark(0x5678)
	openPairThroughBind(t, b, &StdNetEndpoint{AddrPort: peerAP}, peer)
	if got := markOf(); got != 0x5678 {
		t.Fatalf("after changing the mark, socket has %#x, want 0x5678", got)
	}
}

// Connected sockets use UDP GRO where available and split a coalesced read back into datagrams.
// The coalesced counter proves GRO was in effect, since without it the datagrams would arrive intact anyway.
func TestConnectedReceivesWithGRO(t *testing.T) {
	peer, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	if handled, _ := s.Send(peerAP, [][]byte{[]byte("x")}, 0); !handled {
		t.Fatal("no connected socket")
	}
	_, from := peerRead(t, peer)
	if cs := socketTo(s, peerAP); !cs.gro {
		// Skip only if the kernel lacks UDP GRO.
		probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer probe.Close()
		rc, _ := probe.SyscallConn()
		var perr error
		rc.Control(func(fd uintptr) { perr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, socketOptionUDPGRO, 1) })
		if perr != nil {
			t.Skipf("kernel has no UDP GRO: %v", perr)
		}
		t.Fatal("the kernel supports UDP GRO but the connected socket does not have it on")
	}

	const segSize, segs, last = 1200, 8, 500
	payload := make([]byte, segSize*(segs-1)+last)
	for i := range payload {
		payload[i] = byte(i / segSize) // each datagram's bytes name its index
	}
	var oob []byte
	oob = make([]byte, 0, controlSize)
	setGSOSize(&oob, segSize)
	rc, _ := peer.SyscallConn()
	var serr error
	rc.Control(func(fd uintptr) {
		serr = unix.Sendmsg(int(fd), payload, oob, &unix.SockaddrInet4{Port: int(from.Port()), Addr: from.Addr().As4()}, 0)
	})
	if serr != nil {
		t.Skipf("cannot send with UDP_SEGMENT: %v", serr)
	}

	slab := make([]byte, 1<<17)
	pkts := make([]ConnectedPacket, 64)
	var got []int
	for deadline := time.Now().Add(3 * time.Second); len(got) < segs && time.Now().Before(deadline); {
		n := readWithin(t, s, slab, pkts)
		for _, p := range pkts[:n] {
			d := slab[p.Offset : p.Offset+p.Size]
			for _, c := range d {
				if c != d[0] {
					t.Fatalf("datagram %d is not one segment's bytes", d[0])
				}
			}
			if p.Source != peerAP {
				t.Fatalf("source %v, want %v", p.Source, peerAP)
			}
			got = append(got, p.Size)
		}
	}
	want := []int{segSize, segSize, segSize, segSize, segSize, segSize, segSize, last}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("datagram sizes %v, want %v", got, want)
	}
	if s.coalesced.Load() == 0 {
		t.Fatal("no read was coalesced; GRO is not in effect")
	}
}

// A connected socket's receive buffer is as large as allowed, up to connectedRecvBufSize.
func TestConnectedRecvBufLinux(t *testing.T) {
	_, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	if handled, _ := s.Send(peerAP, [][]byte{[]byte("x")}, 0); !handled {
		t.Fatal("no connected socket")
	}
	rc, err := socketTo(s, peerAP).c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	rc.Control(func(fd uintptr) { got, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF) })
	if err != nil {
		t.Fatal(err)
	}
	// The kernel reports double what was set. Without CAP_NET_ADMIN, SO_RCVBUF is capped at net.core.rmem_max.
	want := connectedRecvBufSize
	if !canForceBuffers() {
		if b, err := os.ReadFile("/proc/sys/net/core/rmem_max"); err == nil {
			if max, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && max < want {
				want = max
			}
		}
	}
	if got < 2*want {
		t.Fatalf("receive buffer is %d, want at least %d", got, 2*want)
	}
}

// canForceBuffers reports whether this process may set SO_RCVBUFFORCE.
func canForceBuffers() bool {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return false
	}
	defer c.Close()
	rc, _ := c.SyscallConn()
	var ferr error
	rc.Control(func(fd uintptr) { ferr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 1<<20) })
	return ferr == nil
}

// StdNetBind's connected socket uses the endpoint's sticky source, and received packets carry it back. Once it is cleared, sends return to the route's pick.
func TestStdNetBindConnectedFollowsStickySource(t *testing.T) {
	other := otherIPv4(t)
	loopback := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	b := NewStdNetBind(WithConnectedSockets(true)).(*StdNetBind)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	peer, peerAP := listenPeer(t, "udp4")

	ep := &StdNetEndpoint{AddrPort: peerAP}
	setSrc(ep, other, 0)
	from := openPairThroughBind(t, b, ep, peer)
	if from.Addr() != other {
		t.Fatalf("with sticky source %v, the connected socket sent from %v", other, from.Addr())
	}
	if cs := socketTo(b.cs, peerAP); cs == nil || cs.key.local != other {
		t.Fatalf("no connected socket on the pair from %v", other)
	}

	peer.WriteToUDPAddrPort([]byte("pong"), from)
	recv := fns[len(fns)-1] // the connected ReceiveFunc is last
	slab := make([]byte, 1<<16)
	packets := make([]ReceivedPacket, IdealBatchSize)
	done := make(chan int, 1)
	go func() { n, _ := recv(slab, packets); done <- n }()
	select {
	case n := <-done:
		if n != 1 || packets[0].Endpoint.SrcIP() != other {
			t.Fatalf("got %d packets, sticky source %v; want 1 with %v", n, packets[0].Endpoint.SrcIP(), other)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reply never reached the connected ReceiveFunc")
	}

	ep.ClearSrc()
	if from := openPairThroughBind(t, b, ep, peer); from.Addr() != loopback {
		t.Fatalf("with no sticky source, sent from %v; want the route's pick, %v", from.Addr(), loopback)
	}
}
