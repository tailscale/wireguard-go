// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64 && gc && !purego

// Package chacha20poly1305 provides the SSSE3 ChaCha20-Poly1305
// implementation removed from golang.org/x/crypto in v0.52.0. It is used on
// amd64 systems which have SSSE3 but cannot use x/crypto's AVX2+BMI2 kernel.
//
// The assembly is mechanically extracted from the generated assembly in the
// pinned golang.org/x/crypto v0.51.0 module; see _asm/main.go.
package chacha20poly1305

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"unsafe"

	xchacha20poly1305 "golang.org/x/crypto/chacha20poly1305"
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

type aead struct {
	key [KeySize]byte
}

// New returns a ChaCha20-Poly1305 AEAD using the assembly kernel.
func New(key []byte) (cipher.AEAD, error) {
	// Besides validating the key, this preserves x/crypto's policy check that
	// rejects ChaCha20-Poly1305 when Go is running in FIPS 140-only mode.
	if _, err := xchacha20poly1305.New(key); err != nil {
		return nil, err
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
