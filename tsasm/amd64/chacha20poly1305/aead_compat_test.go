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
	"os"
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

/*
New covers whichever kernel this CPU picks. On an AVX-512 machine that is the fused kernel at every length, so the SSSE3 kernel is pinned as a second arm there; without it nothing would test the SSSE3 kernel on such a machine.
*/
func init() {
	if AvailableAVX512() {
		aeadCtors = append(aeadCtors, aeadCtorEntry{"asm-ssse3", newAEADSSSE3})
	}
}

// newAEADAVX512 and newAEADSSSE3 pin a kernel regardless of what New would choose.
func newAEADAVX512(key []byte) (cipher.AEAD, error) { return pinned(key, true) }
func newAEADSSSE3(key []byte) (cipher.AEAD, error)  { return pinned(key, false) }

func pinned(key []byte, avx512 bool) (cipher.AEAD, error) {
	a, err := newAEAD(key, avx512)
	if err != nil {
		return nil, err
	}
	return a, nil
}

/*
avx512Sizes are lengths chosen for the AVX-512 kernel rather than the SSE one.

Up to 704 bytes the kernel takes its short path: the counter-0 group alone up to 192, plus one more group up to 448 and two up to 704, with every block under a byte mask. Those lengths cover empty, sub-block, block and group boundaries on both sides of 192, 448 and 704.

Above that the kernel works in 256-byte groups and batches two of them, so what matters is L mod 512. When sealing, the final batch is then a masked partial group alone when the remainder is in (0, 256), and a whole group paired with a masked partial one when it is in (256, 512). Opening stops its loop a batch early, so its final batch always carries one or two whole groups with the partial one, which covers those same remainders from the other side.

sealSizes was chosen for the SSE kernel's branch points and only reaches these by chance, so the list below targets them on purpose. A mask error writes past the caller's buffer rather than producing wrong bytes inside it, which is why the sweep that uses these lengths checks guard bytes.
*/
var avx512Sizes = []int{
	// short path: the key group alone up to 192, plus one group up to 448 and two up to 704
	0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 191, 192, 193, 255, 256, 257, 320, 383, 384, 447, 448,
	449, 511, 512, 513, 575, 576, 577, 639, 640, 703, 704,
	// the general path from its shortest lengths
	705, 767,
	// exact group and batch multiples: no partial group at all
	768, 1024, 1280, 1536, 2048,
	// L mod 512 in (0, 256): a partial group alone, including remainders under 64 and under 16
	1025, 1028, 1040, 1088, 1279, 1537, 1540, 1552, 1586,
	// L mod 512 in (256, 512): a whole group paired with a partial one, including partials under 64 and under 16
	1281, 1284, 1296, 1330, 1420, 1500, 1535, 2047,
	// larger, to cover several batch iterations before the tail
	4096, 4097, 4111, 8920, 16384, 16385,
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
	for _, c := range aeadCtors {
		aead, err := c.new(key[:])
		if err != nil {
			t.Fatal(err)
		}
		for _, plen := range append(append([]int{}, sealSizes...), avx512Sizes...) {
			plaintext := make([]byte, plen)
			rand.Read(plaintext)
			want := ref.Seal(nil, nonce[:], plaintext, nil)

			buf := make([]byte, 0, plen+Overhead)
			buf = append(buf, plaintext...)
			got := aead.Seal(buf[:0], nonce[:], buf[:plen], nil)
			if !bytes.Equal(got, want) {
				t.Fatalf("%s: in-place Seal mismatch at pt=%d", c.name, plen)
			}

			opened, err := aead.Open(got[:0], nonce[:], got, nil)
			if err != nil {
				t.Fatalf("%s: in-place Open at pt=%d: %v", c.name, plen, err)
			}
			if !bytes.Equal(opened, plaintext) {
				t.Fatalf("%s: in-place Open mismatch at pt=%d", c.name, plen)
			}
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
	var aeads []aeadCtorEntry
	var impls []cipher.AEAD
	for _, c := range aeadCtors {
		a, err := c.new(key[:])
		if err != nil {
			f.Fatal(err)
		}
		aeads, impls = append(aeads, c), append(impls, a)
	}

	f.Fuzz(func(t *testing.T, plaintext, aad []byte) {
		want := ref.Seal(nil, nonce[:], plaintext, aad)
		for i, aead := range impls {
			got := aead.Seal(nil, nonce[:], plaintext, aad)
			if !bytes.Equal(got, want) {
				t.Fatalf("%s: Seal mismatch (pt=%d aad=%d)\n got: %x\nwant: %x", aeads[i].name, len(plaintext), len(aad), got, want)
			}
			back, err := aead.Open(nil, nonce[:], want, aad)
			if err != nil {
				t.Fatalf("%s: Open (pt=%d aad=%d): %v", aeads[i].name, len(plaintext), len(aad), err)
			}
			if !bytes.Equal(back, plaintext) {
				t.Fatalf("%s: Open mismatch (pt=%d aad=%d)", aeads[i].name, len(plaintext), len(aad))
			}
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

/*
TestNewPicksAVX512 checks that New actually selects the fused kernel where the CPU allows it.

The device-level dispatch test cannot see this: both tiers are the same concrete type, so from outside the package an AVX-512 machine running the SSSE3 kernel is indistinguishable from one running the AVX-512 kernel, and the whole tier would be dead code without anything failing.
*/
func TestNewPicksAVX512(t *testing.T) {
	a, err := New(make([]byte, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	impl, ok := a.(*aead)
	if !ok {
		t.Fatalf("New returned %T, want *aead", a)
	}
	if got, want := impl.avx512, AvailableAVX512(); got != want {
		t.Errorf("New returned an AEAD with avx512=%t on a CPU where AvailableAVX512()=%t", got, want)
	}
}

/*
TestAVX512OpenRejectsTamper covers the AVX-512 kernel's authentication-failure path, which nothing else here reaches.

TestAEAD_OpenRejectsTamper only tries one 43-byte plaintext, which reaches the short path and nothing else. A kernel that stored 1 into its return slot unconditionally on some other path would pass it while accepting forgeries there.

Both halves of the ciphertext are tampered with, separately: a byte of the payload, which must fail because the tag covers it, and a byte of the tag itself, which must fail because it no longer matches. The lengths cover all three short-path variants and the general path's batch loop and both forms of its final batch.
*/
func TestAVX512OpenRejectsTamper(t *testing.T) {
	if !AvailableAVX512() {
		t.Skip("CPU cannot run the AVX-512 kernel")
	}
	var key [KeySize]byte
	rand.Read(key[:])
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	aead, err := newAEADAVX512(key[:])
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("metadata")

	for _, n := range []int{1, 64, 192, 193, 448, 449, 704, 705, 768, 1024, 1280, 1420, 1537, 4096} {
		plaintext := make([]byte, n)
		rand.Read(plaintext)
		ct := aead.Seal(nil, nonce, plaintext, aad)

		for _, tc := range []struct {
			what string
			at   int
		}{
			{"payload byte", 0},
			{"last payload byte", n - 1},
			{"tag byte", n},
			{"last tag byte", len(ct) - 1},
		} {
			bad := append([]byte{}, ct...)
			bad[tc.at] ^= 1
			out, err := aead.Open(nil, nonce, bad, aad)
			if err == nil {
				t.Fatalf("len %d: Open accepted a flipped %s", n, tc.what)
			}
			if out != nil {
				t.Fatalf("len %d: Open returned %d bytes alongside an error", n, len(out))
			}
		}

		// A wrong nonce and wrong additional data must fail too, and for the same reason.
		badNonce := append([]byte{}, nonce...)
		badNonce[0] ^= 1
		if _, err := aead.Open(nil, badNonce, ct, aad); err == nil {
			t.Fatalf("len %d: Open accepted a wrong nonce", n)
		}
		if _, err := aead.Open(nil, nonce, ct, append(aad, 0)); err == nil {
			t.Fatalf("len %d: Open accepted wrong additional data", n)
		}

		/*
			On failure the caller must be left with a zeroed buffer rather than the plaintext the kernel had already written: the kernel decrypts before the tag is known. Open into a destination whose backing array is visible afterwards to check that it was.
		*/
		bad := append([]byte{}, ct...)
		bad[len(bad)-1] ^= 1
		dst := make([]byte, 0, n)
		if _, err := aead.Open(dst, nonce, bad, aad); err == nil {
			t.Fatalf("len %d: Open accepted a flipped tag", n)
		}
		for i, b := range dst[:n] {
			if b != 0 {
				t.Fatalf("len %d: byte %d of the output was left as %#x after a failed Open", n, i, b)
			}
		}
	}
}

/*
TestAVX512SizeSweep runs the AVX-512-specific lengths through Seal and Open against x/crypto, with guard bytes past the output so a mask or length error that writes beyond the caller's buffer is caught rather than merely producing wrong bytes inside it.
*/
func TestAVX512SizeSweep(t *testing.T) {
	if !AvailableAVX512() {
		t.Skip("CPU cannot run the AVX-512 kernel")
	}
	var key [KeySize]byte
	rand.Read(key[:])
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	ours, err := newAEADAVX512(key[:])
	if err != nil {
		t.Fatal(err)
	}
	ref, err := xchacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}

	const guard = 0xA5
	for _, n := range avx512Sizes {
		for _, adLen := range []int{0, 1, 16, 17, 63, 64} {
			plaintext := make([]byte, n)
			rand.Read(plaintext)
			ad := make([]byte, adLen)
			rand.Read(ad)
			want := ref.Seal(nil, nonce, plaintext, ad)

			sealDst := make([]byte, n+Overhead+96)
			for i := range sealDst {
				sealDst[i] = guard
			}
			got := ours.Seal(sealDst[:0], nonce, plaintext, ad)
			if !bytes.Equal(got, want) {
				t.Fatalf("len %d adlen %d: Seal differs from x/crypto", n, adLen)
			}
			for i := len(got); i < len(sealDst); i++ {
				if sealDst[i] != guard {
					t.Fatalf("len %d adlen %d: Seal wrote %d bytes past its output", n, adLen, i-len(got)+1)
				}
			}

			openDst := make([]byte, n+96)
			for i := range openDst {
				openDst[i] = guard
			}
			back, err := ours.Open(openDst[:0], nonce, want, ad)
			if err != nil {
				t.Fatalf("len %d adlen %d: Open rejected a valid tag: %v", n, adLen, err)
			}
			if !bytes.Equal(back, plaintext) {
				t.Fatalf("len %d adlen %d: Open produced wrong plaintext", n, adLen)
			}
			for i := len(back); i < len(openDst); i++ {
				if openDst[i] != guard {
					t.Fatalf("len %d adlen %d: Open wrote %d bytes past its output", n, adLen, i-len(back)+1)
				}
			}
		}
	}
}

/*
TestAVX512TierWasExercised makes a CI run that never touched the AVX-512 kernel say so.

Every AVX-512 test here skips on a CPU without the features, which is correct, but it means a green run proves nothing about the tier. GitHub's ubuntu runners are a mix of Intel Ice Lake, which has AVX-512, and AMD EPYC Milan, which does not, so roughly half of them exercise none of this package's newer half and report success.

Failing on every AVX-512-less runner would be wrong: it would break unrelated pull requests on hardware nobody chose. Instead this fails only when asked to, so a maintainer can pin one job to a runner with AVX-512 and set TS_WG_REQUIRE_AVX512=1 there, and it logs the tier's status unconditionally so the reason a run proved nothing is visible in the output rather than absent from it.
*/
func TestAVX512TierWasExercised(t *testing.T) {
	if AvailableAVX512() {
		t.Log("AVX-512 kernel is present and was exercised by this run")
		return
	}
	t.Log("AVX-512 kernel is ABSENT on this CPU: every AVX-512 test in this package skipped")
	if os.Getenv("TS_WG_REQUIRE_AVX512") == "1" {
		t.Fatal("TS_WG_REQUIRE_AVX512=1 but this CPU has no AVX512F+AVX512BW+BMI2, so the tier went untested")
	}
}

/*
TestAVX512NeedsBW guards the one combination that would fault rather than merely be slow. A part with AVX512F but not AVX512BW, such as Knights Landing or Knights Mill, must not be offered this kernel: every payload up to 704 bytes and every partial group after that is loaded and stored under KMOVQ masks with VMOVDQU8, both of which need BW, so it would SIGILL on the first handshake-sized packet.
*/
func TestAVX512NeedsBW(t *testing.T) {
	if avx512Usable(true, true, false, true) {
		t.Error("AVX512F without AVX512BW was accepted; the kernel would SIGILL")
	}
	if avx512Usable(true, true, true, false) {
		t.Error("AVX-512 without BMI2 was accepted; the Poly1305 multiply needs MULXQ")
	}
	if avx512Usable(false, true, true, true) {
		t.Error("AVX-512 without AVX was accepted; the kernel ends with VZEROUPPER")
	}
	if !avx512Usable(true, true, true, true) {
		t.Error("AVX, F, BW and BMI2 together were refused")
	}
}
