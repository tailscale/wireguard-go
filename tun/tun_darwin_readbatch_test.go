//go:build darwin

package tun

import (
	"net"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func newTestUTUN(t *testing.T, local, remote string) *NativeTun {
	t.Helper()
	if unix.Getuid() != 0 {
		t.Skip("needs root to create a utun")
	}
	dev, err := CreateTUN("utun", 1420)
	if err != nil {
		t.Skipf("CreateTUN: %v", err)
	}
	t.Cleanup(func() { dev.Close() })
	name, _ := dev.Name()
	if out, err := exec.Command("ifconfig", name, "inet", local, remote, "up").CombinedOutput(); err != nil {
		t.Skipf("ifconfig: %v: %s", err, out)
	}
	return dev.(*NativeTun)
}

// CreateTUNFromFile raises the pending-packet queue, so a utun handed over as a file, such as a network extension's, gets it too.
func TestMaxPendingRaisedForFileTUN(t *testing.T) {
	if darwinBatch <= 1 {
		t.Skip("no batched reads on this build or kernel")
	}
	tun := newTestUTUN(t, "10.97.1.1", "10.97.1.2")
	rc, _ := tun.tunFile.SyscallConn()
	var got int
	var err error
	rc.Control(func(fd uintptr) { got, err = unix.GetsockoptInt(int(fd), sysprotoControl, utunOptMaxPendingPackets) })
	if err != nil {
		t.Fatalf("getsockopt: %v", err)
	}
	if got != darwinMaxPending {
		t.Fatalf("pending queue is %d, want %d", got, darwinMaxPending)
	}
}

// Packets the kernel routes into the utun come back several to a read, each intact.
func TestReadBatchReturnsSeveralPackets(t *testing.T) {
	if darwinBatch <= 1 {
		t.Skip("no batched reads on this build or kernel")
	}
	tun := newTestUTUN(t, "10.97.2.1", "10.97.2.2")
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(10, 97, 2, 2), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const count, size = 20, 100
	for i := range count {
		p := make([]byte, size)
		p[0] = byte(i)
		if _, err := c.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond) // let them all queue

	slab := make([]byte, 1<<17)
	packets := make([]ReadPacket, 128)
	seen, reads, maxPerRead := 0, 0, 0
	deadline := time.Now().Add(3 * time.Second)
	for seen < count && time.Now().Before(deadline) {
		n, err := tun.Read(slab, packets)
		if err != nil {
			t.Fatal(err)
		}
		reads++
		mine := 0
		for _, p := range packets[:n] {
			pkt := slab[p.Offset : p.Offset+p.Size]
			// Only our IPv4 UDP datagrams to 10.97.2.2; the interface may carry other traffic.
			if len(pkt) < 28 || pkt[0]>>4 != 4 || pkt[9] != unix.IPPROTO_UDP || pkt[19] != 2 {
				continue
			}
			if len(pkt) != 28+size || pkt[28] != byte(seen) {
				t.Fatalf("packet %d: length %d, first payload byte %d", seen, len(pkt), pkt[28])
			}
			seen++
			mine++
		}
		maxPerRead = max(maxPerRead, mine)
	}
	if seen != count {
		t.Fatalf("read %d of %d packets", seen, count)
	}
	if maxPerRead < 2 {
		t.Fatalf("no read returned more than one packet over %d reads; batching is not taking effect", reads)
	}
}

// A read with a stale, smaller MTU drops the packets it cut short and looks the MTU up again for the next read.
func TestReadBatchDropsTruncated(t *testing.T) {
	if darwinBatch <= 1 {
		t.Skip("no batched reads on this build or kernel")
	}
	tun := newTestUTUN(t, "10.97.3.1", "10.97.3.2")
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(10, 97, 3, 2), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	slab := make([]byte, 1<<17)
	packets := make([]ReadPacket, 128)
	// read returns the sizes of our UDP datagrams to 10.97.3.2 that one read delivered.
	read := func() []int {
		t.Helper()
		var sizes []int
		deadline := time.Now().Add(3 * time.Second)
		for len(sizes) == 0 && time.Now().Before(deadline) {
			n, err := tun.Read(slab, packets)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range packets[:n] {
				pkt := slab[p.Offset : p.Offset+p.Size]
				if len(pkt) >= 28 && pkt[0]>>4 == 4 && pkt[9] == unix.IPPROTO_UDP && pkt[19] == 2 {
					sizes = append(sizes, len(pkt))
				}
			}
		}
		return sizes
	}

	tun.mtuCache.Store(500) // as if the MTU had been raised after the cache was filled
	c.Write(make([]byte, 1000))
	c.Write(make([]byte, 100))
	time.Sleep(100 * time.Millisecond)
	if got := read(); len(got) != 1 || got[0] != 128 {
		t.Fatalf("with a stale MTU, read delivered %v, want only the small packet, [128]", got)
	}
	if got := tun.mtuCache.Load(); got == 500 {
		t.Fatalf("the stale MTU is still cached after a truncated read")
	}
	c.Write(make([]byte, 1000))
	if got := read(); len(got) != 1 || got[0] != 1028 {
		t.Fatalf("after the MTU was looked up again, read delivered %v, want [1028]", got)
	}
}
