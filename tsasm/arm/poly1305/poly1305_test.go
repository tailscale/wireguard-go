// SPDX-License-Identifier: BSD-3-Clause

//go:build arm

package poly1305

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	xpoly1305 "golang.org/x/crypto/poly1305"
)

// RFC 8439 §2.5.2 test vector.
func TestRFC8439Vector(t *testing.T) {
	keyHex := "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
	msg := []byte("Cryptographic Forum Research Group")
	wantHex := "a8061dc1305136c6c22b8baf0c0127a9"

	var key [32]byte
	mustHex(t, key[:], keyHex)
	want := mustHexBytes(t, wantHex)

	var got [16]byte
	Sum(&got, msg, &key)
	if string(got[:]) != string(want) {
		t.Errorf("RFC 8439 vector mismatch:\n got %x\nwant %x", got, want)
	}
}

// Cross-check against golang.org/x/crypto/poly1305 across many
// lengths. Picks include the 16-byte block boundary, the NEON
// transition points used by poly1305_arm.go's dispatcher (192 bytes
// is the inner-loop unit), and a few multi-page sizes.
func TestAgainstReference(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	lengths := []int{
		// per-block boundary (16 bytes)
		0, 1, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65,
		127, 128, 129,
		// NEON-block-unit boundary (poly1305 NEON processes 4 blocks
		// = 64 bytes at a time; chacha20 NEON's analogous 256-byte
		// boundary motivates 383..385).
		191, 192, 193,
		255, 256, 257,
		383, 384, 385,
		// larger multi-page
		1024, 1500, 4096,
	}
	for _, n := range lengths {
		m := make([]byte, n)
		rand.Read(m)

		var got, want [16]byte
		Sum(&got, m, &key)
		xpoly1305.Sum(&want, m, &key)

		if got != want {
			t.Errorf("len=%d mismatch:\n got %x\nwant %x", n, got, want)
		}
	}
}

func mustHex(t *testing.T, dst []byte, s string) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	copy(dst, b)
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
