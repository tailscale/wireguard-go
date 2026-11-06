/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	// PublicKeySize is the public-key size in bytes.
	PublicKeySize = 32
	// PrivateKeySize is the private-key size in bytes.
	PrivateKeySize = 32
	// PresharedKeySize is the preshared-key size in bytes.
	PresharedKeySize = 32
)

type (
	// PublicKey is a Curve25519 public key.
	PublicKey [PublicKeySize]byte
	// PrivateKey is a Curve25519 private key.
	PrivateKey [PrivateKeySize]byte
	// PresharedKey is an optional symmetric pre-shared key mixed into a session.
	PresharedKey [PresharedKeySize]byte
)

var errInvalidPublicKey = errors.New("invalid public key")

// IsZero reports whether the key is all zero.
func (k PublicKey) IsZero() bool {
	var zero PublicKey
	return subtle.ConstantTimeCompare(k[:], zero[:]) == 1
}

// Equals reports whether two public keys are equal in constant time.
func (k PublicKey) Equals(o PublicKey) bool {
	return subtle.ConstantTimeCompare(k[:], o[:]) == 1
}

func (sk *PrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

// NewPrivateKey returns a fresh, clamped Curve25519 private key.
func NewPrivateKey() (sk PrivateKey, err error) {
	_, err = rand.Read(sk[:])
	sk.clamp()
	return
}

// Public returns the public key for sk.
func (sk PrivateKey) Public() (pk PublicKey) {
	apk := (*[PublicKeySize]byte)(&pk)
	ask := (*[PrivateKeySize]byte)(&sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

// sharedSecret computes X25519(sk, pk). It returns errInvalidPublicKey if the
// result is the all-zero point.
func (sk PrivateKey) sharedSecret(pk PublicKey) (ss [PublicKeySize]byte, err error) {
	apk := (*[PublicKeySize]byte)(&pk)
	ask := (*[PrivateKeySize]byte)(&sk)
	curve25519.ScalarMult(&ss, ask, apk)
	if isZero(ss[:]) {
		return ss, errInvalidPublicKey
	}
	return ss, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// KDF helpers use HKDF with BLAKE2s (RFC 5869).

func hmac1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func hmac2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func kdf1(t0 *[blake2s.Size]byte, key, input []byte) {
	hmac1(t0, key, input)
	hmac1(t0, t0[:], []byte{0x1})
}

func kdf2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	hmac1(&prk, key, input)
	hmac1(t0, prk[:], []byte{0x1})
	hmac2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func kdf3(t0, t1, t2 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	hmac1(&prk, key, input)
	hmac1(t0, prk[:], []byte{0x1})
	hmac2(t1, prk[:], t0[:], []byte{0x2})
	hmac2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
}

func mixKey(dst, c *[blake2s.Size]byte, data []byte) { kdf1(dst, c[:], data) }

func mixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hsh, _ := blake2s.New256(nil)
	hsh.Write(h[:])
	hsh.Write(data)
	hsh.Sum(dst[:0])
	hsh.Reset()
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

// setZero clears a slice. Go does not guarantee erasure of key material.
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}
