// SPDX-License-Identifier: BSD-3-Clause

//go:build amd64 && gc && !purego

/*
Package chacha20poly1305 provides a ChaCha20-Poly1305 AEAD backed by the SSE assembly kernel golang.org/x/crypto deleted in commit 7ee5970 ("chacha20poly1305: drop pre-AVX assembly impl", v0.52.0). It is used on amd64 CPUs with SSSE3 that cannot use x/crypto's AVX2 kernel.

It also carries a fused AVX-512 kernel, which New picks on CPUs that can run it (see AvailableAVX512). Whether a given CPU should use this package at all is decided by the caller, in wireguard-go's device package.
*/
package chacha20poly1305

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/cpu"

	xchacha20poly1305 "golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = 32
	NonceSize = 12
	Overhead  = 16
)

// Available reports whether this CPU can run the SSSE3 kernel.
func Available() bool { return cpu.X86.HasSSSE3 }

/*
AvailableAVX512 reports whether this CPU can run the fused AVX-512 kernel.

The features are read off the generated assembly rather than off the tier's name. AVX for the VZEROUPPER on the way out, which every AVX-512 part has but GODEBUG can mask separately. AVX512BW because partial blocks, every one in the short path and the last group in the long one, are loaded and stored under byte masks with VMOVDQU8 and KMOVQ, and BMI2 because the Poly1305 chain multiplies with MULXQ. AVX512VL is not required, since the kernel issues no 128-bit or 256-bit EVEX operation, and ADX is not required, since the carry chain uses ADCQ rather than ADCXQ and ADOXQ. Gating on AVX512F alone would fault on a part with F but not BW.
*/
func AvailableAVX512() bool {
	return avx512Usable(cpu.X86.HasAVX, cpu.X86.HasAVX512F, cpu.X86.HasAVX512BW, cpu.X86.HasBMI2)
}

// avx512Usable is AvailableAVX512's rule as a pure function, so a test can cover combinations no real CPU in the lab has.
func avx512Usable(avx, f, bw, bmi2 bool) bool { return avx && f && bw && bmi2 }

//go:noescape
func chacha20Poly1305Open(dst []byte, key []uint32, src []byte, ad []byte) bool

//go:noescape
func chacha20Poly1305Seal(dst []byte, key []uint32, src []byte, ad []byte)

//go:noescape
func chacha20Poly1305OpenAVX512(dst []byte, key []uint32, src []byte, ad []byte) bool

//go:noescape
func chacha20Poly1305SealAVX512(dst []byte, key []uint32, src []byte, ad []byte)

type aead struct {
	key    [KeySize]byte
	avx512 bool // use the fused AVX-512 kernel, at every length
}

// New returns a ChaCha20-Poly1305 AEAD using the best assembly kernel this CPU can run: the fused AVX-512 one where it is available, otherwise the SSSE3 one.
func New(key []byte) (cipher.AEAD, error) {
	avx512 := AvailableAVX512()
	if !avx512 && !Available() {
		return nil, errors.New("chacha20poly1305: CPU lacks SSSE3")
	}
	return newAEAD(key, avx512)
}

/*
newAEAD builds an AEAD on the named kernel. The key check is delegated to x/crypto rather than done here: its New also refuses ChaCha20-Poly1305 under fips140=only, and this package is reached instead of x/crypto on the CPUs it covers. The instance itself is not needed.
*/
func newAEAD(key []byte, avx512 bool) (*aead, error) {
	if _, err := xchacha20poly1305.New(key); err != nil {
		return nil, err
	}
	a := &aead{avx512: avx512}
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
	if a.avx512 {
		chacha20Poly1305SealAVX512(out[:], state[:], plaintext, additionalData)
	} else {
		chacha20Poly1305Seal(out[:], state[:], plaintext, additionalData)
	}
	return ret
}

var errOpen = errors.New("chacha20poly1305: message authentication failed")

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		// Matches x/crypto: a wrong-size nonce is API misuse, not a decrypt failure.
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
	var ok bool
	if a.avx512 {
		ok = chacha20Poly1305OpenAVX512(out, state[:], ciphertext, additionalData)
	} else {
		ok = chacha20Poly1305Open(out, state[:], ciphertext, additionalData)
	}
	if !ok {
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

// anyOverlap and inexactOverlap reproduce x/crypto/internal/alias, which cannot be
// imported from outside x/crypto: exact aliasing is fine, partial overlap is not.
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
