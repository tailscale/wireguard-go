// SPDX-License-Identifier: BSD-3-Clause

//go:build amd64 && gc && !purego

package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"testing"

	xchacha20poly1305 "golang.org/x/crypto/chacha20poly1305"
)

/*
Benchmarks for the two kernels in this package against x/crypto, which is what they displace.

Both are run in one process so they see the same clocks and the same cache state, and both directions are measured, because a tunnel does one Seal and one Open per packet and a kernel that wins one and loses the other is not a win. Report bytes per second and compare the arms at a given size; the absolute numbers move with the machine, the ratios do not.

Both kernels are pinned rather than taken from New, which on an AVX-512 machine would make the two arms the same kernel.

Sizes are the ones that decide the dispatch. 1280 is Tailscale's MTU and exactly five of the kernel's 256-byte groups, so it runs no partial group. 1420 is WireGuard's, and leaves 140 bytes over, which both directions pair with a whole group. 8920 is a jumbo frame. 512 takes the short path, which handles everything up to 704 bytes in one pass of rounds.
*/

var benchSizes = []int{512, 1280, 1420, 8920}

func benchArms(tb testing.TB, key []byte) []struct {
	name string
	aead cipher.AEAD
} {
	type arm = struct {
		name string
		aead cipher.AEAD
	}
	/*
		Constructing the SSSE3 arm by hand skips New, and with it New's SSSE3 check. This package exists to serve pre-AVX2 amd64, which includes pre-SSSE3 parts where that kernel faults, so the check has to happen here instead.
	*/
	if !Available() {
		tb.Skip("CPU lacks SSSE3; nothing in this package can run here")
	}
	ssse3, err := newAEADSSSE3(key)
	if err != nil {
		tb.Fatal(err)
	}
	xc, err := xchacha20poly1305.New(key)
	if err != nil {
		tb.Fatal(err)
	}
	arms := []arm{{"xcrypto", xc}, {"ssse3", ssse3}}
	if AvailableAVX512() {
		a, err := newAEADAVX512(key)
		if err != nil {
			tb.Fatal(err)
		}
		arms = append(arms, arm{"avx512", a})
	}
	return arms
}

func BenchmarkSeal(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	for _, arm := range benchArms(b, key) {
		for _, size := range benchSizes {
			plaintext := make([]byte, size)
			rand.Read(plaintext)
			dst := make([]byte, 0, size+Overhead)
			b.Run(fmt.Sprintf("%s/%d", arm.name, size), func(b *testing.B) {
				b.SetBytes(int64(size))
				for range b.N {
					arm.aead.Seal(dst[:0], nonce, plaintext, nil)
				}
			})
		}
	}
}

/*
The parallel variants give whole-chip throughput rather than per-core, which is what a reader sizing a machine against a link actually wants. Each goroutine keeps its own output buffer, so what is measured is the chip's aggregate and not contention on one slice.
*/
func BenchmarkSealParallel(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	for _, arm := range benchArms(b, key) {
		for _, size := range benchSizes {
			plaintext := make([]byte, size)
			rand.Read(plaintext)
			b.Run(fmt.Sprintf("%s/%d", arm.name, size), func(b *testing.B) {
				b.SetBytes(int64(size))
				b.RunParallel(func(pb *testing.PB) {
					dst := make([]byte, 0, size+Overhead)
					for pb.Next() {
						arm.aead.Seal(dst[:0], nonce, plaintext, nil)
					}
				})
			})
		}
	}
}

func BenchmarkOpenParallel(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	for _, arm := range benchArms(b, key) {
		for _, size := range benchSizes {
			plaintext := make([]byte, size)
			rand.Read(plaintext)
			ciphertext := arm.aead.Seal(nil, nonce, plaintext, nil)
			b.Run(fmt.Sprintf("%s/%d", arm.name, size), func(b *testing.B) {
				b.SetBytes(int64(size))
				b.RunParallel(func(pb *testing.PB) {
					dst := make([]byte, 0, size)
					for pb.Next() {
						// RunParallel bodies run on worker goroutines, where Fatal must not be called.
						if _, err := arm.aead.Open(dst[:0], nonce, ciphertext, nil); err != nil {
							b.Error(err)
							return
						}
					}
				})
			})
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	key := make([]byte, KeySize)
	rand.Read(key)
	nonce := make([]byte, NonceSize)
	rand.Read(nonce)
	for _, arm := range benchArms(b, key) {
		for _, size := range benchSizes {
			plaintext := make([]byte, size)
			rand.Read(plaintext)
			ciphertext := arm.aead.Seal(nil, nonce, plaintext, nil)
			dst := make([]byte, 0, size)
			b.Run(fmt.Sprintf("%s/%d", arm.name, size), func(b *testing.B) {
				b.SetBytes(int64(size))
				for range b.N {
					if _, err := arm.aead.Open(dst[:0], nonce, ciphertext, nil); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
