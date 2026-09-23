//go:build darwin

package tun

import (
	"bytes"
	"crypto/rand"
	"os/exec"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// TestWriteBatchMatchesUnbatched checks that both write paths hand the kernel the same bytes, address family header included. A mistake here shows up only as packet loss.
func TestWriteBatchMatchesUnbatched(t *testing.T) {
	if unix.Getuid() != 0 {
		t.Skip("needs root to create a utun")
	}
	dev, err := CreateTUN("utun", 1420)
	if err != nil {
		t.Skipf("CreateTUN: %v", err)
	}
	defer dev.Close()
	name, _ := dev.Name()
	// A configured, up interface is required or every write is rejected.
	if out, err := exec.Command("ifconfig", name, "inet", "10.97.0.1", "10.97.0.2", "up").CombinedOutput(); err != nil {
		t.Skipf("ifconfig: %v: %s", err, out)
	}

	tun := dev.(*NativeTun)

	// The minimum IPv4 header, odd lengths and the MTU.
	sizes := []int{20, 21, 63, 64, 128, 576, 1000, 1420}
	const off = 4

	mk := func(n int, tag byte) []byte {
		b := make([]byte, off+n)
		p := b[off:]
		rand.Read(p)
		p[0] = 0x45
		p[2] = byte(n >> 8)
		p[3] = byte(n)
		p[8] = 64
		p[9] = 253
		copy(p[12:16], []byte{10, 97, 0, 1})
		copy(p[16:20], []byte{10, 97, 0, 2})
		p[10], p[11] = 0, tag // checksum field, reused as a marker
		return b
	}

	for _, n := range sizes {
		a := mk(n, 1)
		b := mk(n, 1)
		copy(b[off:], a[off:])

		if _, err := tun.writeUnbatched([][]byte{a}, off); err != nil {
			t.Fatalf("unbatched write at n=%d: %v", n, err)
		}
		gotA := bytes.Clone(a[:off+n])

		if k, err := tun.writeBatch([][]byte{b}, off); err != nil || k != 1 {
			t.Fatalf("batched write at n=%d: k=%d err=%v", n, k, err)
		}
		gotB := bytes.Clone(b[:off+n])

		if !bytes.Equal(gotA, gotB) {
			t.Errorf("n=%d: the two paths produced different wire bytes\n unbatched %x\n batched   %x",
				n, gotA[:8], gotB[:8])
		}
		if gotB[3] != unix.AF_INET {
			t.Errorf("n=%d: batched path wrote AF byte %d, want %d", n, gotB[3], unix.AF_INET)
		}
	}
}

// TestWriteBatchMultiPacket writes many packets in one call and checks that all are accepted with the right header.
func TestWriteBatchMultiPacket(t *testing.T) {
	if unix.Getuid() != 0 {
		t.Skip("needs root to create a utun")
	}
	dev, err := CreateTUN("utun", 1420)
	if err != nil {
		t.Skipf("CreateTUN: %v", err)
	}
	defer dev.Close()
	name, _ := dev.Name()
	if out, err := exec.Command("ifconfig", name, "inet", "10.97.1.1", "10.97.1.2", "up").CombinedOutput(); err != nil {
		t.Skipf("ifconfig: %v: %s", err, out)
	}
	tun := dev.(*NativeTun)

	const off = 4
	const count = 32
	// A variable: byte(n) of a constant 1000 would not compile.
	n := 1000
	bufs := make([][]byte, count)
	for i := range bufs {
		b := make([]byte, off+n)
		p := b[off:]
		p[0] = 0x45
		p[2] = byte(n >> 8)
		p[3] = byte(n)
		p[8] = 64
		p[9] = 253
		copy(p[12:16], []byte{10, 97, 1, 1})
		copy(p[16:20], []byte{10, 97, 1, 2})
		p[20] = byte(i) // marker, so a reordering or duplication would be visible
		bufs[i] = b
	}
	k, err := tun.writeBatch(bufs, off)
	if err != nil {
		t.Fatalf("writeBatch: %v", err)
	}
	if k != count {
		t.Errorf("writeBatch accepted %d of %d packets", k, count)
	}
	for i, b := range bufs {
		if b[3] != unix.AF_INET {
			t.Errorf("packet %d: AF byte %d, want %d", i, b[3], unix.AF_INET)
		}
	}
}

// A packet that is neither IPv4 nor IPv6 stops the write with EAFNOSUPPORT, as in the unbatched path.
func TestWriteBatchRejectsBadVersion(t *testing.T) {
	if unix.Getuid() != 0 {
		t.Skip("needs root to create a utun")
	}
	dev, err := CreateTUN("utun", 1420)
	if err != nil {
		t.Skipf("CreateTUN: %v", err)
	}
	defer dev.Close()
	name, _ := dev.Name()
	if out, err := exec.Command("ifconfig", name, "inet", "10.97.2.1", "10.97.2.2", "up").CombinedOutput(); err != nil {
		t.Skipf("ifconfig: %v: %s", err, out)
	}
	tun := dev.(*NativeTun)
	const off = 4
	bad := make([]byte, off+40)
	bad[off] = 0x75 // version 7
	if k, err := tun.writeBatch([][]byte{bad}, off); err != unix.EAFNOSUPPORT || k != 0 {
		t.Errorf("got k=%d err=%v, want 0 and EAFNOSUPPORT", k, err)
	}
}

// TestWriteBatchConcurrent writes from several goroutines at once, as the per-peer RoutineSequentialReceiver does, to catch write state shared between writers.
func TestWriteBatchConcurrent(t *testing.T) {
	if unix.Getuid() != 0 {
		t.Skip("needs root to create a utun")
	}
	dev, err := CreateTUN("utun", 1420)
	if err != nil {
		t.Skipf("CreateTUN: %v", err)
	}
	defer dev.Close()
	name, _ := dev.Name()
	if out, err := exec.Command("ifconfig", name, "inet", "10.97.3.1", "10.97.3.2", "up").CombinedOutput(); err != nil {
		t.Skipf("ifconfig: %v: %s", err, out)
	}
	tun := dev.(*NativeTun)

	const off = 4
	const writers = 4
	const rounds = 200
	n := 1000

	mk := func(count int) [][]byte {
		bufs := make([][]byte, count)
		for i := range bufs {
			b := make([]byte, off+n)
			p := b[off:]
			p[0] = 0x45
			p[2] = byte(n >> 8)
			p[3] = byte(n)
			p[8] = 64
			p[9] = 253
			copy(p[12:16], []byte{10, 97, 3, 1})
			copy(p[16:20], []byte{10, 97, 3, 2})
			bufs[i] = b
		}
		return bufs
	}

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// Varying batch sizes, so a too-small pooled state would be caught.
			bufs := mk(8 + w*8)
			for r := 0; r < rounds; r++ {
				if _, err := tun.writeBatch(bufs, off); err != nil {
					errs <- err
					return
				}
				for i := range bufs {
					bufs[i] = bufs[i][:off+n]
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent writeBatch: %v", err)
	}
}

// TestWriteBatchFallsBackOverOnePage checks that Write keeps its contract on both sides of the page gate: every packet accepted, each with its header.
func TestWriteBatchFallsBackOverOnePage(t *testing.T) {
	if unix.Getuid() != 0 {
		t.Skip("needs root to create a utun")
	}
	dev, err := CreateTUN("utun", 9000)
	if err != nil {
		t.Skipf("CreateTUN: %v", err)
	}
	defer dev.Close()
	name, _ := dev.Name()
	if out, err := exec.Command("ifconfig", name, "inet", "10.97.3.1", "10.97.3.2", "up").CombinedOutput(); err != nil {
		t.Skipf("ifconfig: %v: %s", err, out)
	}
	tun := dev.(*NativeTun)

	const off = 4
	// 4092 plus the header fills a 4096-byte page exactly, 4093 is over it, and 8920 is a jumbo MTU.
	for _, n := range []int{4092, 4093, 8920} {
		bufs := make([][]byte, 8)
		for i := range bufs {
			b := make([]byte, off+n)
			p := b[off:]
			p[0] = 0x45
			p[2] = byte(n >> 8)
			p[3] = byte(n)
			p[8] = 64
			p[9] = 253
			copy(p[12:16], []byte{10, 97, 3, 1})
			copy(p[16:20], []byte{10, 97, 3, 2})
			bufs[i] = b
		}
		k, err := tun.Write(bufs, off)
		if err != nil {
			t.Fatalf("packet size %d: Write: %v", n, err)
		}
		if k != len(bufs) {
			t.Errorf("packet size %d: accepted %d of %d", n, k, len(bufs))
		}
		for i, b := range bufs {
			if b[3] != unix.AF_INET {
				t.Errorf("packet size %d, packet %d: AF byte %d, want %d", n, i, b[3], unix.AF_INET)
			}
		}
	}
}
