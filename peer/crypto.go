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

	"github.com/tailscale/wireguard-go/internal/aead"
)

// PublicKeySize, PrivateKeySize, and PresharedKeySize are key lengths in bytes.
const (
	PublicKeySize = 32

	PrivateKeySize = 32

	PresharedKeySize = 32
)

type (
	// PublicKey is a Curve25519 public key.
	PublicKey [PublicKeySize]byte

	// PrivateKey is a Curve25519 private key.
	PrivateKey [PrivateKeySize]byte

	// PresharedKey is the optional symmetric key mixed into the handshake.
	// The zero value disables the additional preshared secret.
	PresharedKey [PresharedKeySize]byte
)

// noiseNonce holds four zero bytes followed by a little-endian 64-bit counter.
type noiseNonce [chacha20poly1305.NonceSize]byte

var errInvalidPublicKey = errors.New("invalid public key")

// IsZero reports whether k is all zero, using a constant-time comparison.
func (k PublicKey) IsZero() bool {
	var zero PublicKey
	return subtle.ConstantTimeCompare(k[:], zero[:]) == 1
}

// Equals reports whether k and o are equal, using a constant-time comparison.
func (k PublicKey) Equals(o PublicKey) bool {
	return subtle.ConstantTimeCompare(k[:], o[:]) == 1
}

func (sk *PrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

// NewPrivateKey returns a randomly generated, clamped Curve25519 private key.
func NewPrivateKey() (sk PrivateKey, err error) {
	_, err = rand.Read(sk[:])
	sk.clamp()
	return
}

// Public returns the Curve25519 public key corresponding to sk.
func (sk PrivateKey) Public() (pk PublicKey) {
	apk := (*[PublicKeySize]byte)(&pk)
	ask := (*[PrivateKeySize]byte)(&sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

func (sk PrivateKey) sharedSecret(pk PublicKey) (ss [PublicKeySize]byte, err error) {
	secret, err := curve25519.X25519(sk[:], pk[:])
	if err != nil {
		return ss, errInvalidPublicKey
	}
	copy(ss[:], secret)
	clear(secret)
	return ss, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	return aead.New(key)
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

func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}
