// SPDX-License-Identifier: BSD-3-Clause

//go:build arm

package chacha20

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	xchacha "golang.org/x/crypto/chacha20"
)

// RFC 8439 §2.4.2 test vector.
func TestRFC8439Vector(t *testing.T) {
	keyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	nonceHex := "000000000000004a00000000"
	const counter = 1
	plaintext := []byte("Ladies and Gentlemen of the class of '99: " +
		"If I could offer you only one tip for the future, sunscreen would be it.")
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

// Cross-check against golang.org/x/crypto/chacha20 for randomized
// inputs. Lengths cover the 64-byte block boundary, the 192/256-byte
// NEON cross-function-branch boundary (where XORKeyStream has to
// trim the length before passing it to ChaCha20_neon -- see the
// length-gating comment in chacha20_arm.go), and a few multi-page
// sizes.
func TestAgainstReference(t *testing.T) {
	var key [32]byte
	var nonce [12]byte
	rand.Read(key[:])
	rand.Read(nonce[:])

	lengths := []int{
		// per-block boundary (64 bytes)
		0, 1, 16, 31, 32, 33, 63, 64, 65,
		127, 128, 129,
		191, 192, 193,
		255, 256, 257,
		// NEON cross-function-branch boundary: chacha20_arm.go has
		// to trim lengths where len%256 falls in 1..128 because the
		// upstream NEON path's break-to-scalar branch we replaced
		// with UDF would otherwise fire. 257..384 and 513..640 etc.
		// stress that trimming logic.
		320, 383, 384, 385,
		511, 512, 513,
		639, 640, 641,
		// larger multi-page
		1024, 1500, 4096,
	}
	for _, n := range lengths {
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
			t.Errorf("len=%d mismatch", n)
		}
	}
}

// Counter is incremented correctly across multi-block calls.
func TestCounterAdvance(t *testing.T) {
	var key [32]byte
	var nonce [12]byte
	rand.Read(key[:])
	rand.Read(nonce[:])

	in := make([]byte, 192) // 3 full blocks
	out := make([]byte, len(in))

	got := XORKeyStream(out, in, &key, &nonce, 7)
	if got != 7+3 {
		t.Errorf("counter = %d, want %d", got, 7+3)
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
