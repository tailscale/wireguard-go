// SPDX-License-Identifier: BSD-3-Clause

//go:build mips64

// Package chacha20 implements the ChaCha20 stream cipher with a
// scalar mips64r2 inner loop. It only builds on big-endian
// GOARCH=mips64; other architectures should use
// golang.org/x/crypto/chacha20. (The byte-swap path here assumes
// big-endian memory order; mips64le would need a separate asm.)
package chacha20

import (
	"encoding/binary"
	"unsafe"
)

const (
	KeySize   = 32
	NonceSize = 12
	BlockSize = 64
)

// ChaCha20 sigma constants ("expand 32-byte k" in little-endian u32
// chunks).
const (
	sigma0 uint32 = 0x61707865
	sigma1 uint32 = 0x3320646e
	sigma2 uint32 = 0x79622d32
	sigma3 uint32 = 0x6b206574
)

// chacha20BlocksASM XORs `blocks` 64-byte blocks of ChaCha20
// keystream into `in`, writing to `out`. state[0..15] is the initial
// 16 u32 ChaCha20 state in machine-endian form (sigma | key |
// counter | nonce). On return, state[12] is incremented by `blocks`.
//
//go:noescape
func chacha20BlocksASM(out, in unsafe.Pointer, state *[16]uint32, blocks uintptr)

// XORKeyStream XORs a ChaCha20 keystream into in, writing to out, using
// the given 32-byte key, 12-byte IETF nonce, and starting 32-bit block
// counter. out and in must have the same length and may overlap exactly
// or not at all. It returns the next block counter
// (counter + ceil(len/64)).
//
// Both `out` and `in` should be 4-byte aligned. Slices from make()
// are; slices derived from string literals (which may live in
// rodata) are not. The asm reads/writes 32-bit words; on Octeon the
// kernel silently fixes up unaligned traps (slow but correct), but
// stricter MIPS environments (qemu-user, certain bare-metal kernels)
// raise SIGBUS. WireGuard's data path uses pooled make()-allocated
// buffers and is therefore safe.
func XORKeyStream(out, in []byte, key *[KeySize]byte, nonce *[NonceSize]byte, counter uint32) uint32 {
	if len(out) < len(in) {
		panic("chacha20: output buffer shorter than input")
	}
	if len(in) == 0 {
		return counter
	}

	var state [16]uint32
	state[0] = sigma0
	state[1] = sigma1
	state[2] = sigma2
	state[3] = sigma3
	for i := range 8 {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	state[12] = counter
	state[13] = binary.LittleEndian.Uint32(nonce[0:])
	state[14] = binary.LittleEndian.Uint32(nonce[4:])
	state[15] = binary.LittleEndian.Uint32(nonce[8:])

	full := len(in) &^ 63 // largest multiple of 64
	if full > 0 {
		chacha20BlocksASM(
			unsafe.Pointer(&out[0]),
			unsafe.Pointer(&in[0]),
			&state,
			uintptr(full>>6),
		)
	}
	if rem := len(in) - full; rem > 0 {
		// Handle the final partial block by routing it through a
		// 64-byte staging buffer so the asm always sees a full block.
		var inBuf, outBuf [64]byte
		copy(inBuf[:], in[full:])
		chacha20BlocksASM(
			unsafe.Pointer(&outBuf[0]),
			unsafe.Pointer(&inBuf[0]),
			&state,
			1,
		)
		copy(out[full:], outBuf[:rem])
	}

	return counter + uint32((len(in)+63)>>6)
}
