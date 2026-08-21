// SPDX-License-Identifier: BSD-3-Clause

//go:build mips64

package poly1305

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	xpoly1305 "golang.org/x/crypto/poly1305"
)

// RFC 8439 §2.5.2 test vector.
func TestRFC8439Vector(t *testing.T) {
	keyHex := "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
	src := "Cryptographic Forum Research Group"
	msg := make([]byte, len(src))
	copy(msg, src)
	wantHex := "a8061dc1305136c6c22b8baf0c0127a9"

	var key [32]byte
	mustHex(t, key[:], keyHex)
	wantTag := mustHexBytes(t, wantHex)

	var got [16]byte
	Sum(&got, msg, &key)
	if !bytes.Equal(got[:], wantTag) {
		t.Errorf("Sum mismatch:\n got %x\nwant %x", got, wantTag)
	}
}

// Cross-check against golang.org/x/crypto/poly1305 over a sweep of
// lengths.
func TestAgainstReference(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	for _, n := range []int{0, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1023, 1024, 1436, 4096} {
		t.Run(fmt.Sprintf("len=%d", n), func(t *testing.T) {
			msg := make([]byte, n)
			rand.Read(msg)

			var got [16]byte
			Sum(&got, msg, &key)

			var want [16]byte
			xpoly1305.Sum(&want, msg, &key)

			if !bytes.Equal(got[:], want[:]) {
				t.Errorf("mismatch (len=%d):\n got %x\nwant %x", n, got, want)
			}
		})
	}
}

// TestIncrementalWrite stresses the buffer-merge path that intermittently
// failed on the earlier 5x26 attempt: many small Writes, varying chunk
// alignment, then Sum.
func TestIncrementalWrite(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	full := make([]byte, 4096)
	rand.Read(full)

	var want [16]byte
	xpoly1305.Sum(&want, full, &key)

	for _, chunk := range []int{1, 7, 15, 16, 17, 64, 1024} {
		t.Run(fmt.Sprintf("chunk=%d", chunk), func(t *testing.T) {
			var mac MAC
			mac.Init(&key)
			for i := 0; i < len(full); i += chunk {
				j := min(i+chunk, len(full))
				mac.Write(full[i:j])
			}
			var got [16]byte
			mac.Sum(&got)
			if !bytes.Equal(got[:], want[:]) {
				t.Errorf("chunk=%d mismatch:\n got %x\nwant %x", chunk, got, want)
			}
		})
	}
}

func mustHex(t *testing.T, dst []byte, s string) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != len(dst) {
		t.Fatalf("hex length %d, want %d", len(b), len(dst))
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

// BenchmarkSum compares our asm Sum against x/crypto/poly1305 across
// the sizes that show up on the WireGuard data path.
func BenchmarkSum(b *testing.B) {
	for _, size := range []int{64, 1436, 4096, 16384} {
		var key [32]byte
		rand.Read(key[:])
		msg := make([]byte, size)
		rand.Read(msg)
		b.Run(fmt.Sprintf("%d/asm", size), func(b *testing.B) {
			var tag [16]byte
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				Sum(&tag, msg, &key)
			}
		})
		b.Run(fmt.Sprintf("%d/xcrypto", size), func(b *testing.B) {
			var tag [16]byte
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				xpoly1305.Sum(&tag, msg, &key)
			}
		})
	}
}
