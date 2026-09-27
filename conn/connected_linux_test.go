//go:build linux

package conn

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

/*
Connected sockets receive with GRO where the kernel has it, as StdNetBind's own socket does, and ReadBatch still hands out the individual datagrams.

A peer sends one GSO super-datagram. On loopback a socket with UDP_GRO receives it as a single coalesced read, which the set must split back into datagrams of the segment size with a shorter last one. The coalesced counter shows the read really was one, since without GRO the kernel segments it and the datagrams would arrive intact anyway.
*/
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
