/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import (
	"golang.org/x/crypto/chacha20poly1305"
)

// Static provides the public key and Curve25519 shared-secret operation for a
// local private key. The key must remain unchanged. Implementations shared by
// concurrent peers or preparation workers must support concurrent calls.
type Static interface {
	// Public returns the local public key.
	Public() PublicKey

	// SharedSecret returns the Curve25519 shared secret with remote, or an error
	// if the key agreement fails. The peer rejects an all-zero result.
	SharedSecret(remote PublicKey) ([32]byte, error)
}

// Identity is an in-memory [Static] implementation holding a private key.
// Its methods may be called concurrently.
type Identity struct {
	private PrivateKey
	public  PublicKey
}

// NewIdentity returns an identity holding a copy of private.
func NewIdentity(private PrivateKey) *Identity { return &Identity{private, private.Public()} }

// Public returns the identity's public key.
func (s *Identity) Public() PublicKey { return s.public }

// SharedSecret returns the Curve25519 shared secret with remote.
// It returns an error if the result is all zero.
func (s *Identity) SharedSecret(remote PublicKey) ([32]byte, error) {
	return s.private.sharedSecret(remote)
}

func sharedSecret(s Static, remote PublicKey) ([32]byte, error) {
	ss, err := s.SharedSecret(remote)
	if err == nil && isZero(ss[:]) {
		err = errInvalidPublicKey
	}
	return ss, err
}

// LocalIdentity identifies one local key generation. Copy the same value to
// peers and [Admission] instances that should accept each other's handshake work.
// Separate calls to [NewLocalIdentity] create distinct generations even with the
// same epoch and provider. The zero value is invalid.
type LocalIdentity struct{ record *identityRecord }

type identityRecord struct {
	provider Static
	public   PublicKey
	epoch    uint64
	marker   *generation
}

type generation struct{ epoch uint64 }

// NewLocalIdentity returns a generation using provider and a nonzero epoch.
// It returns [ErrConfig] if epoch is zero, provider is nil, or its public key is
// zero. Epochs must increase when replacing a [Peer]'s identity.
func NewLocalIdentity(epoch uint64, provider Static) (LocalIdentity, error) {
	if epoch == 0 || provider == nil || provider.Public().IsZero() {
		return LocalIdentity{}, ErrConfig
	}
	return LocalIdentity{&identityRecord{provider, provider.Public(), epoch, &generation{epoch}}}, nil
}

// PreparedInitiation holds an admitted initiation with its remote static key
// decrypted. It owns its message bytes and is bound to the admitting local
// generation. It may be copied or passed to another goroutine. Treat it as secret
// key material. [Peer.HandleInitiation] must authenticate it before the remote
// is trusted.
type PreparedInitiation struct {
	message        messageInitiation
	remote         PublicKey
	chainKey, hash [32]byte
	generation     *generation
}

// RemoteStatic returns the claimed remote public key for selecting a [Peer].
// It is a routing hint, not proof that the sender holds the private key.
func (v PreparedInitiation) RemoteStatic() PublicKey { return v.remote }

// PrepareInitiation decrypts the remote static key in admitted for routing.
// It may run independently of the selected [Peer] using the bound [Static] provider.
// It returns [ErrHandshake] for a zero token, a response, or failed static-key
// authentication, and propagates key-agreement errors from the provider.
func PrepareInitiation(admitted AdmittedHandshake) (PreparedInitiation, error) {
	var v PreparedInitiation
	if admitted.identity == nil || admitted.size != MessageInitiationSize {
		return v, ErrHandshake
	}
	if err := v.message.unmarshal(admitted.wire[:admitted.size]); err != nil {
		return PreparedInitiation{}, err
	}
	msg := &v.message
	if msg.Type != MessageInitiationType {
		return PreparedInitiation{}, ErrHandshake
	}
	var key [chacha20poly1305.KeySize]byte
	pub := admitted.identity.public
	mixHash(&v.hash, &initialHash, pub[:])
	mixHash(&v.hash, &v.hash, msg.Ephemeral[:])
	mixKey(&v.chainKey, &initialChainKey, msg.Ephemeral[:])
	ss, err := sharedSecret(admitted.identity.provider, msg.Ephemeral)
	if err != nil {
		return PreparedInitiation{}, err
	}
	defer clear(ss[:])
	defer clear(key[:])
	kdf2(&v.chainKey, &key, v.chainKey[:], ss[:])
	aead, _ := newAEAD(key[:])
	if _, err := aead.Open(v.remote[:0], zeroNonce[:], msg.Static[:], v.hash[:]); err != nil {
		return PreparedInitiation{}, ErrHandshake
	}
	mixHash(&v.hash, &v.hash, msg.Static[:])
	v.generation = admitted.identity.marker
	return v, nil
}
