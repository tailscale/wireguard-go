// SPDX-License-Identifier: BSD-3-Clause

//go:build amd64 && gc && !purego

/*
This file follows tsasm/arm/chacha20poly1305/aead_compat_test.go, which was in turn derived from device/aead_compat_test.go (originally MIT-licensed by WireGuard LLC). The aeadCtors slice names our asm-backed implementation alongside the reference pure-Go path so every test and benchmark runs against both.
*/

package chacha20poly1305

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	xchacha20poly1305 "golang.org/x/crypto/chacha20poly1305"
)

type aeadCtorEntry struct {
	name string
	new  func(key []byte) (cipher.AEAD, error)
}

var aeadCtors = []aeadCtorEntry{
	{"go-chacha20poly1305", xchacha20poly1305.New},
	{"asm-chacha20poly1305", New},
}

// requireAsm skips a test when the CPU cannot run the kernel at all, so a
// pre-SSSE3 machine reports a skip rather than a confusing failure.
func requireAsm(t testing.TB) {
	if !Available() {
		t.Skip("CPU lacks SSSE3; nothing in this package can run here")
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

/*
TestAEAD_RFC8439Vector verifies each implementation against the vector from RFC 8439 section 2.8.2, for both Seal and Open. A round-trip-only test (one implementation decrypting its own output) would pass even if the whole construction were symmetrically wrong; this will not.
*/
func TestAEAD_RFC8439Vector(t *testing.T) {
	requireAsm(t)
	key := mustHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex("070000004041424344454647")
	aad := mustHex("50515253c0c1c2c3c4c5c6c7")
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	wantCT := mustHex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
	wantTag := mustHex("1ae10b594f09e26a7e902ecbd0600691")
	want := append(append([]byte{}, wantCT...), wantTag...)

	for _, c := range aeadCtors {
		t.Run(c.name, func(t *testing.T) {
			aead, err := c.new(key)
			if err != nil {
				t.Fatal(err)
			}
			if got := aead.Seal(nil, nonce, plaintext, aad); !bytes.Equal(got, want) {
				t.Errorf("Seal mismatch:\n got: %x\nwant: %x", got, want)
			}
			opened, err := aead.Open(nil, nonce, want, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(opened, plaintext) {
				t.Errorf("Open mismatch:\n got: %q\nwant: %q", opened, plaintext)
			}
		})
	}
}

/*
sealSizes covers every length boundary the SSE kernel branches on. The kernel has a dedicated path for buffers up to 128 bytes (openSSE128), a 4x64-byte main loop, dedicated 192- and 320-byte entries, and a tail handler that works in 64-, 16- and 1-byte steps, so each of those boundaries is probed at -1, exact and +1.
*/
var sealSizes = []int{
	0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65,
	127, 128, 129, 191, 192, 193, 255, 256, 257,
	319, 320, 321, 383, 384, 385, 447, 448, 449,
	511, 512, 513, 575, 576, 639, 640, 641,
	1023, 1024, 1025, 1420, 1500, 4096, 16384,
}

// TestAEAD_AgreesWithReference Seals identical inputs with each implementation
// and the reference and asserts byte-for-byte equality, which pins down
// counter, endianness and tag-placement bugs that a self-round-trip cannot.
func TestAEAD_AgreesWithReference(t *testing.T) {
	requireAsm(t)
	aadSizes := []int{0, 1, 13, 16, 17, 64}

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}

	ref, err := xchacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range aeadCtors {
		aead, err := c.new(key[:])
		if err != nil {
			t.Fatalf("%s: New: %v", c.name, err)
		}
		if got := aead.NonceSize(); got != NonceSize {
			t.Errorf("%s: NonceSize = %d, want %d", c.name, got, NonceSize)
		}
		if got := aead.Overhead(); got != Overhead {
			t.Errorf("%s: Overhead = %d, want %d", c.name, got, Overhead)
		}
		for _, plen := range sealSizes {
			plaintext := make([]byte, plen)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatal(err)
			}
			for _, alen := range aadSizes {
				aad := make([]byte, alen)
				if _, err := rand.Read(aad); err != nil {
					t.Fatal(err)
				}
				wantCT := ref.Seal(nil, nonce[:], plaintext, aad)

				t.Run(fmt.Sprintf("%s/pt=%d/aad=%d", c.name, plen, alen), func(t *testing.T) {
					gotCT := aead.Seal(nil, nonce[:], plaintext, aad)
					if !bytes.Equal(gotCT, wantCT) {
						t.Fatalf("Seal mismatch (pt=%d aad=%d)\n got: %x\nwant: %x", plen, alen, gotCT, wantCT)
					}
					pt, err := aead.Open(nil, nonce[:], wantCT, aad)
					if err != nil {
						t.Fatalf("Open: %v", err)
					}
					if !bytes.Equal(pt, plaintext) {
						t.Fatalf("Open mismatch (pt=%d aad=%d)", plen, alen)
					}
				})
			}
		}
	}
}

// TestAEAD_InPlace exercises exact aliasing, which Seal and Open must accept
// (the WireGuard data path relies on it) while still rejecting partial overlap.
func TestAEAD_InPlace(t *testing.T) {
	requireAsm(t)
	var key [32]byte
	rand.Read(key[:])
	var nonce [12]byte

	ref, err := xchacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := New(key[:])
	if err != nil {
		t.Fatal(err)
	}

	for _, plen := range sealSizes {
		plaintext := make([]byte, plen)
		rand.Read(plaintext)
		want := ref.Seal(nil, nonce[:], plaintext, nil)

		buf := make([]byte, 0, plen+Overhead)
		buf = append(buf, plaintext...)
		got := aead.Seal(buf[:0], nonce[:], buf[:plen], nil)
		if !bytes.Equal(got, want) {
			t.Fatalf("in-place Seal mismatch at pt=%d", plen)
		}

		opened, err := aead.Open(got[:0], nonce[:], got, nil)
		if err != nil {
			t.Fatalf("in-place Open at pt=%d: %v", plen, err)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Fatalf("in-place Open mismatch at pt=%d", plen)
		}
	}
}

// TestAEAD_OpenRejectsTamper checks that Open fails when the ciphertext, tag,
// AAD or nonce is altered, and that a rejected Open leaves no plaintext behind.
func TestAEAD_OpenRejectsTamper(t *testing.T) {
	requireAsm(t)
	var key [32]byte
	rand.Read(key[:])
	var nonce [12]byte
	rand.Read(nonce[:])
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	aad := []byte("metadata")

	for _, c := range aeadCtors {
		t.Run(c.name, func(t *testing.T) {
			aead, err := c.new(key[:])
			if err != nil {
				t.Fatal(err)
			}
			ct := aead.Seal(nil, nonce[:], plaintext, aad)

			tamper := append([]byte{}, ct...)
			tamper[0] ^= 1
			if _, err := aead.Open(nil, nonce[:], tamper, aad); err == nil {
				t.Error("Open accepted tampered ciphertext")
			}

			tamper = append([]byte{}, ct...)
			tamper[len(tamper)-1] ^= 1
			if _, err := aead.Open(nil, nonce[:], tamper, aad); err == nil {
				t.Error("Open accepted tampered tag")
			}

			badAAD := append([]byte{}, aad...)
			badAAD[0] ^= 1
			if _, err := aead.Open(nil, nonce[:], ct, badAAD); err == nil {
				t.Error("Open accepted wrong AAD")
			}

			var badNonce [12]byte
			copy(badNonce[:], nonce[:])
			badNonce[0] ^= 1
			if _, err := aead.Open(nil, badNonce[:], ct, aad); err == nil {
				t.Error("Open accepted wrong nonce")
			}

			/*
				A failed Open must not leave decrypted bytes in the caller's buffer.

				The tag is tampered rather than the ciphertext, and that choice is what makes the assertion able to fail. With the ciphertext intact the kernel decrypts it to exactly plaintext and only the MAC check fails, so a missing zeroing step leaves the real plaintext behind where a comparison can see it. Flipping a ciphertext byte instead leaves a plaintext that differs in that byte, which no comparison against plaintext detects, and the test passes whether or not Open zeroes anything.
			*/
			out := make([]byte, len(plaintext))
			for i := range out {
				out[i] = 0xaa
			}
			tamper = append([]byte{}, ct...)
			tamper[len(tamper)-1] ^= 1
			if _, err := aead.Open(out[:0], nonce[:], tamper, aad); err == nil {
				t.Fatal("Open accepted a tampered tag")
			}
			if !bytes.Equal(out, make([]byte, len(out))) {
				t.Errorf("failed Open left %q in the caller's buffer; it must be zeroed", out)
			}
		})
	}
}

// FuzzAEAD_AgreesWithReference differentially fuzzes the kernel against the
// reference implementation across arbitrary plaintext and AAD lengths, which
// is the check most likely to find a bug in a length-dispatched kernel.
func FuzzAEAD_AgreesWithReference(f *testing.F) {
	if !Available() {
		f.Skip("CPU lacks SSSE3")
	}
	f.Add([]byte("hello"), []byte("aad"))
	f.Add(make([]byte, 128), []byte{})
	f.Add(make([]byte, 320), make([]byte, 17))
	f.Add(make([]byte, 1420), make([]byte, 13))

	var key [32]byte
	rand.Read(key[:])
	var nonce [12]byte
	ref, err := xchacha20poly1305.New(key[:])
	if err != nil {
		f.Fatal(err)
	}
	aead, err := New(key[:])
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, plaintext, aad []byte) {
		want := ref.Seal(nil, nonce[:], plaintext, aad)
		got := aead.Seal(nil, nonce[:], plaintext, aad)
		if !bytes.Equal(got, want) {
			t.Fatalf("Seal mismatch (pt=%d aad=%d)\n got: %x\nwant: %x", len(plaintext), len(aad), got, want)
		}
		back, err := aead.Open(nil, nonce[:], want, aad)
		if err != nil {
			t.Fatalf("Open (pt=%d aad=%d): %v", len(plaintext), len(aad), err)
		}
		if !bytes.Equal(back, plaintext) {
			t.Fatalf("Open mismatch (pt=%d aad=%d)", len(plaintext), len(aad))
		}
	})
}

/*
TestAEAD_Concurrent exercises Seal and Open from many goroutines to catch shared-state bugs. The kernel keeps all state on the stack, so this should be uneventful; it is here because a regression would be catastrophic and silent.
*/
func TestAEAD_Concurrent(t *testing.T) {
	requireAsm(t)
	var key [32]byte
	rand.Read(key[:])
	plaintext := []byte("wireguard concurrent aead test")
	aad := []byte("aad")

	for _, c := range aeadCtors {
		t.Run(c.name, func(t *testing.T) {
			aead, err := c.new(key[:])
			if err != nil {
				t.Fatal(err)
			}
			const goroutines = 16
			const iters = 200
			var wg sync.WaitGroup
			wg.Add(goroutines)
			errs := make(chan error, goroutines)
			for g := range goroutines {
				go func(id int) {
					defer wg.Done()
					var nonce [12]byte
					binary.BigEndian.PutUint64(nonce[4:], uint64(id))
					for i := range iters {
						binary.BigEndian.PutUint32(nonce[:4], uint32(i))
						ct := aead.Seal(nil, nonce[:], plaintext, aad)
						pt, err := aead.Open(nil, nonce[:], ct, aad)
						if err != nil {
							errs <- fmt.Errorf("goroutine %d iter %d: Open: %w", id, i, err)
							return
						}
						if !bytes.Equal(pt, plaintext) {
							errs <- fmt.Errorf("goroutine %d iter %d: plaintext mismatch", id, i)
							return
						}
					}
				}(g)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
		})
	}
}

// BenchmarkAEAD_Seal and BenchmarkAEAD_Open measure per-packet cost at a
// typical WireGuard data-packet plaintext size (1500 MTU minus IP, UDP and
// WireGuard transport headers, rounded down to a 16-byte multiple).
func BenchmarkAEAD_Seal(b *testing.B) { benchmarkAEAD(b, false) }
func BenchmarkAEAD_Open(b *testing.B) { benchmarkAEAD(b, true) }

func benchmarkAEAD(b *testing.B, open bool) {
	requireAsm(b)
	const ptSize = 1420
	var key [32]byte
	rand.Read(key[:])
	var nonce [12]byte
	plaintext := make([]byte, ptSize)
	rand.Read(plaintext)

	for _, c := range aeadCtors {
		b.Run(c.name, func(b *testing.B) {
			aead, err := c.new(key[:])
			if err != nil {
				b.Fatal(err)
			}
			ctBuf := make([]byte, 0, ptSize+aead.Overhead())
			ct := aead.Seal(ctBuf, nonce[:], plaintext, nil)
			ptBuf := make([]byte, 0, ptSize)
			b.SetBytes(int64(ptSize))
			b.ResetTimer()
			if open {
				for range b.N {
					if _, err := aead.Open(ptBuf[:0], nonce[:], ct, nil); err != nil {
						b.Fatal(err)
					}
				}
			} else {
				for range b.N {
					_ = aead.Seal(ctBuf[:0], nonce[:], plaintext, nil)
				}
			}
		})
	}
}
