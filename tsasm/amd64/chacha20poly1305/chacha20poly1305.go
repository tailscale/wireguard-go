// SPDX-License-Identifier: BSD-3-Clause

//go:build amd64 && gc && !purego

// Package chacha20poly1305 provides a ChaCha20-Poly1305 AEAD backed by
// the SSE assembly kernel that golang.org/x/crypto carried from 2016
// until it was deleted in x/crypto commit 7ee5970 ("chacha20poly1305:
// drop pre-AVX assembly impl", shipped in v0.52.0).
//
// After that removal the dispatch gate in x/crypto became
// HasSSSE3 && HasAVX2 && HasBMI2, so an amd64 CPU without AVX2 gets no
// assembly at all and the WireGuard data-path AEAD runs generic Go,
// roughly half the throughput. That is most of Intel's Atom line
// (everything before Gracemont, 2021: Silvermont, Airmont, Goldmont,
// Goldmont Plus, Tremont), the AVX-disabled Haswell and Broadwell
// Celeron and Pentium SKUs, AMD before Excavator, and every Intel core
// before Sandy Bridge.
//
// This package restores that path for exactly those CPUs. CPUs with
// AVX2 are not routed here; they keep using x/crypto's maintained AVX2
// kernel. See device/aead_amd64.go for the dispatch and tsasm/amd64/README.md
// for the provenance and measurements.
package chacha20poly1305

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/cpu"
)

const (
	KeySize   = 32
	NonceSize = 12
	Overhead  = 16
)

// Available reports whether this CPU can run the assembly in this
// package. The kernel uses PSHUFB for its rot16 and rot8 macros, so
// SSSE3 is a hard floor; below that there is nothing here to use.
func Available() bool { return cpu.X86.HasSSSE3 }

//go:noescape
func chacha20Poly1305Open(dst []byte, key []uint32, src []byte, ad []byte) bool

//go:noescape
func chacha20Poly1305Seal(dst []byte, key []uint32, src []byte, ad []byte)

// useAVX2 is read directly by the assembly (CMPB ·useAVX2+0(SB), $1) at
// the top of both entry points to pick between its SSE and AVX2 halves.
// It is deliberately always false: callers with AVX2 are routed to
// x/crypto instead of here, so the AVX2 half of the kernel is
// unreachable. Keeping it as a variable rather than deleting the branch
// is what makes this file's generator a byte-for-byte copy of the one
// upstream deleted.
var useAVX2 = false

type aead struct {
	key [KeySize]byte
}

// New returns a ChaCha20-Poly1305 AEAD using the assembly kernel.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	if !Available() {
		return nil, errors.New("chacha20poly1305: CPU lacks SSSE3")
	}
	a := &aead{}
	copy(a.key[:], key)
	return a, nil
}

func (a *aead) NonceSize() int { return NonceSize }
func (a *aead) Overhead() int  { return Overhead }

// setupState writes a ChaCha20 input matrix to state, per RFC 8439 §2.3.
// Copied from x/crypto's chacha20poly1305_amd64.go.
func setupState(state *[16]uint32, key *[KeySize]byte, nonce []byte) {
	state[0] = 0x61707865
	state[1] = 0x3320646e
	state[2] = 0x79622d32
	state[3] = 0x6b206574

	state[4] = binary.LittleEndian.Uint32(key[0:4])
	state[5] = binary.LittleEndian.Uint32(key[4:8])
	state[6] = binary.LittleEndian.Uint32(key[8:12])
	state[7] = binary.LittleEndian.Uint32(key[12:16])
	state[8] = binary.LittleEndian.Uint32(key[16:20])
	state[9] = binary.LittleEndian.Uint32(key[20:24])
	state[10] = binary.LittleEndian.Uint32(key[24:28])
	state[11] = binary.LittleEndian.Uint32(key[28:32])

	state[12] = 0
	state[13] = binary.LittleEndian.Uint32(nonce[0:4])
	state[14] = binary.LittleEndian.Uint32(nonce[4:8])
	state[15] = binary.LittleEndian.Uint32(nonce[8:12])
}

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: bad nonce length passed to Seal")
	}
	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}

	var state [16]uint32
	setupState(&state, &a.key, nonce)

	ret, out := sliceForAppend(dst, len(plaintext)+Overhead)
	if inexactOverlap(out, plaintext) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if anyOverlap(out, additionalData) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
	chacha20Poly1305Seal(out[:], state[:], plaintext, additionalData)
	return ret
}

var errOpen = errors.New("chacha20poly1305: message authentication failed")

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		// x/crypto panics here rather than returning an error, and this is a
		// drop-in for it: a wrong-size nonce is API misuse, not a decrypt
		// failure, and a caller distinguishing the two must not see it as one.
		panic("chacha20poly1305: bad nonce length passed to Open")
	}
	if len(ciphertext) < Overhead {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("chacha20poly1305: ciphertext too large")
	}

	var state [16]uint32
	setupState(&state, &a.key, nonce)

	ciphertext = ciphertext[:len(ciphertext)-Overhead]
	ret, out := sliceForAppend(dst, len(ciphertext))
	if inexactOverlap(out, ciphertext) {
		panic("chacha20poly1305: invalid buffer overlap of output and input")
	}
	if anyOverlap(out, additionalData) {
		panic("chacha20poly1305: invalid buffer overlap of output and additional data")
	}
	if !chacha20Poly1305Open(out, state[:], ciphertext, additionalData) {
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}
	return ret, nil
}

func sliceForAppend(dst []byte, n int) (head, tail []byte) {
	if total := len(dst) + n; cap(dst) >= total {
		head = dst[:total]
	} else {
		head = make([]byte, total)
		copy(head, dst)
	}
	tail = head[len(dst):]
	return
}

// anyOverlap and inexactOverlap reproduce golang.org/x/crypto/internal/alias,
// which cannot be imported from outside x/crypto. Same semantics: Seal and
// Open accept exact aliasing (in-place operation) but reject partial overlap,
// which would silently corrupt output.
func anyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}
