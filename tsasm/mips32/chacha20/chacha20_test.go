// SPDX-License-Identifier: BSD-3-Clause

//go:build mips || mipsle

package chacha20

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	xchacha "golang.org/x/crypto/chacha20"
)

// RFC 8439 §2.4.2 test vector.
func TestRFC8439Vector(t *testing.T) {
	keyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	nonceHex := "000000000000004a00000000"
	const counter = 1
	src := "Ladies and Gentlemen of the class of '99: " +
		"If I could offer you only one tip for the future, sunscreen would be it."
	plaintext := make([]byte, len(src))
	copy(plaintext, src)
	wantHex := "" +
		"6e2e359a2568f98041ba0728dd0d6981" +
		"e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab" +
		"8f593dabcd62b3571639d624e65152ab8f530c359f0861d8" +
		"07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806" +
		"818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42" +
		"874d"

	var key [32]byte
	mustHex(t, key[:], keyHex)
	var nonce [12]byte
	mustHex(t, nonce[:], nonceHex)
	want := mustHexBytes(t, wantHex)

	out := make([]byte, len(plaintext))
	XORKeyStream(out, plaintext, &key, &nonce, counter)

	if !bytes.Equal(out, want) {
		t.Fatalf("RFC 8439 vector mismatch:\n got %x\nwant %x", out, want)
	}
}

func TestAgainstReference(t *testing.T) {
	var key [32]byte
	var nonce [12]byte
	rand.Read(key[:])
	rand.Read(nonce[:])

	for _, n := range []int{0, 1, 16, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 1024, 1500, 4096} {
		t.Run(fmt.Sprintf("len=%d", n), func(t *testing.T) {
			in := make([]byte, n)
			rand.Read(in)
			got := make([]byte, n)
			want := make([]byte, n)

			XORKeyStream(got, in, &key, &nonce, 0)

			c, err := xchacha.NewUnauthenticatedCipher(key[:], nonce[:])
			if err != nil {
				t.Fatal(err)
			}
			c.XORKeyStream(want, in)

			if !bytes.Equal(got, want) {
				t.Errorf("mismatch (n=%d):\n got %x\nwant %x", n, got, want)
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

// BenchmarkXORKeyStream measures pure ChaCha20 throughput at a
// typical WireGuard data-packet size (1420 bytes), comparing the
// asm path against pure-Go.
func BenchmarkXORKeyStream(b *testing.B) {
	for _, size := range []int{64, 256, 1420, 8192} {
		var key [32]byte
		var nonce [12]byte
		in := make([]byte, size)
		out := make([]byte, size)
		b.Run(fmt.Sprintf("%d/asm", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				XORKeyStream(out, in, &key, &nonce, 0)
			}
		})
		b.Run(fmt.Sprintf("%d/xcrypto", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				c, _ := xchacha.NewUnauthenticatedCipher(key[:], nonce[:])
				c.XORKeyStream(out, in)
			}
		})
	}
}
