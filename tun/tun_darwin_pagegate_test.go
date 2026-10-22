//go:build darwin

package tun

import (
	"os"
	"testing"
)

// TestWriteBatchTooBig covers the page gate without root, pinning both sides of each boundary.
func TestWriteBatchTooBig(t *testing.T) {
	const page = 4096
	for _, c := range []struct {
		name string
		need int
		max  int
		want bool
	}{
		{"well under the page", 1500, page, false},
		{"exactly the page still batches", page, page, false},
		{"one byte over falls back", page + 1, page, true},
		{"the measured 4100 falls back", 4100, page, true},
		{"jumbo on a 4K page falls back", 8924, page, true},
		{"jumbo on a 16K page still batches", 8924, 16384, false},
		{"16K page boundary still batches", 16384, 16384, false},
		{"over a 16K page falls back", 17424, 16384, true},
		{"max 0 disables the gate", 65535, 0, false},
		{"negative max disables the gate", 65535, -1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := writeBatchTooBig(c.need, c.max); got != c.want {
				t.Errorf("writeBatchTooBig(%d, %d) = %v, want %v", c.need, c.max, got, c.want)
			}
		})
	}
}

// The gate must be the page size, not 4096, or Apple Silicon loses batching for 4-16 KB packets.
func TestDarwinWriteBatchMaxDefaultsToPageSize(t *testing.T) {
	if darwinWriteBatchMax != os.Getpagesize() {
		t.Errorf("darwinWriteBatchMax = %d, want os.Getpagesize() = %d",
			darwinWriteBatchMax, os.Getpagesize())
	}
	// An MTU-sized tunnel packet never falls back.
	if writeBatchTooBig(1420+4, darwinWriteBatchMax) {
		t.Errorf("an MTU 1420 packet must not fall back on a %d-byte page", darwinWriteBatchMax)
	}
}
