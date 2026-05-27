// SPDX-License-Identifier: BSD-3-Clause

//go:build mips || mipsle

// Package chacha20poly1305 provides a ChaCha20-Poly1305 AEAD that
// pairs the hand-ported scalar mips32r2 ChaCha20 in
// tsasm/mips32/chacha20 with the matching scalar Poly1305 in
// tsasm/mips32/poly1305 (a port of openssl/Linux poly1305-mips.pl's
// 32-bit non-MADDU code path). Both halves are asm here.
//
// Only builds on GOARCH=mips / mipsle; other architectures should
// use golang.org/x/crypto/chacha20poly1305 directly.
package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	chacha "github.com/tailscale/wireguard-go/tsasm/mips32/chacha20"
	"github.com/tailscale/wireguard-go/tsasm/mips32/poly1305"
)

const (
	KeySize   = 32
	NonceSize = 12
	Overhead  = 16
)

type aead struct {
	key [KeySize]byte
}

func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}
	a := &aead{}
	copy(a.key[:], key)
	return a, nil
}

func (a *aead) NonceSize() int { return NonceSize }
func (a *aead) Overhead() int  { return Overhead }

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: bad nonce length")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+Overhead)

	var nonceArr [chacha.NonceSize]byte
	copy(nonceArr[:], nonce)

	var (
		zeros   [64]byte
		polyBuf [64]byte
		polyKey [32]byte
	)
	chacha.XORKeyStream(polyBuf[:], zeros[:], &a.key, &nonceArr, 0)
	copy(polyKey[:], polyBuf[:32])
	chacha.XORKeyStream(out[:len(plaintext)], plaintext, &a.key, &nonceArr, 1)

	tag := computeTag(additionalData, out[:len(plaintext)], &polyKey)
	copy(out[len(plaintext):], tag[:])
	return ret
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("chacha20poly1305: bad nonce length")
	}
	if len(ciphertext) < Overhead {
		return nil, errors.New("chacha20poly1305: ciphertext too short")
	}
	ctLen := len(ciphertext) - Overhead
	ct := ciphertext[:ctLen]
	receivedTag := ciphertext[ctLen:]

	var nonceArr [chacha.NonceSize]byte
	copy(nonceArr[:], nonce)

	var (
		zeros   [64]byte
		polyBuf [64]byte
		polyKey [32]byte
	)
	chacha.XORKeyStream(polyBuf[:], zeros[:], &a.key, &nonceArr, 0)
	copy(polyKey[:], polyBuf[:32])

	expectedTag := computeTag(additionalData, ct, &polyKey)
	if subtle.ConstantTimeCompare(receivedTag, expectedTag[:]) != 1 {
		return nil, errors.New("chacha20poly1305: message authentication failed")
	}

	ret, out := sliceForAppend(dst, ctLen)
	chacha.XORKeyStream(out, ct, &a.key, &nonceArr, 1)
	return ret, nil
}

var zeros16 [16]byte

func computeTag(aad, ct []byte, polyKey *[32]byte) [16]byte {
	var mac poly1305.MAC
	mac.Init(polyKey)
	mac.Write(aad)
	if rem := len(aad) % 16; rem != 0 {
		mac.Write(zeros16[:16-rem])
	}
	mac.Write(ct)
	if rem := len(ct) % 16; rem != 0 {
		mac.Write(zeros16[:16-rem])
	}
	var lenBuf [16]byte
	binary.LittleEndian.PutUint64(lenBuf[0:8], uint64(len(aad)))
	binary.LittleEndian.PutUint64(lenBuf[8:16], uint64(len(ct)))
	mac.Write(lenBuf[:])

	var tag [16]byte
	mac.Sum(&tag)
	return tag
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
