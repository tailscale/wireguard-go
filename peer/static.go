/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import (
	"golang.org/x/crypto/chacha20poly1305"
)

// Static is an immutable local identity. Public and SharedSecret must use the
// same private key throughout its lifetime. Shared implementations must support
// concurrent calls. HSM and agent implementations must pin a key generation.
// Replace identities through Peer.ReplaceIdentity and replace ingress Admission.
// Do not mutate an existing identity.
type Static interface {
	// Public returns the identity's public key.
	Public() PublicKey
	// SharedSecret returns the X25519 shared secret with remote.
	SharedSecret(remote PublicKey) ([32]byte, error)
}

// Identity holds an immutable private-key snapshot in process memory.
type Identity struct {
	private PrivateKey
	public  PublicKey
}

// NewIdentity returns an identity holding a copy of private.
func NewIdentity(private PrivateKey) *Identity { return &Identity{private, private.Public()} }

// Public returns the identity's public key.
func (s *Identity) Public() PublicKey { return s.public }

// SharedSecret returns the X25519 shared secret with remote.
// It rejects an all-zero result.
func (s *Identity) SharedSecret(remote PublicKey) ([32]byte, error) {
	return s.private.sharedSecret(remote)
}

// sharedSecret rejects all-zero results, including those accepted by a provider.
func sharedSecret(s Static, remote PublicKey) ([32]byte, error) {
	ss, err := s.SharedSecret(remote)
	if err == nil && isZero(ss[:]) {
		err = errInvalidPublicKey
	}
	return ss, err
}

// LocalIdentity binds an immutable provider to a control-plane generation.
// Share one handle among all peers and admission shards for that generation.
// Epochs are caller-assigned, nonzero, and strictly increasing on replacement.
// Separate NewLocalIdentity calls create distinct generations even with the
// same epoch and provider.
type LocalIdentity struct{ record *identityRecord }
type identityRecord struct {
	provider Static
	public   PublicKey
	epoch    uint64
	marker   *generation
}
type generation struct{ epoch uint64 }

// NewLocalIdentity returns a handle for provider at epoch.
// It returns ErrConfig for a zero epoch, nil provider, or zero public key.
func NewLocalIdentity(epoch uint64, provider Static) (LocalIdentity, error) {
	if epoch == 0 || provider == nil || provider.Public().IsZero() {
		return LocalIdentity{}, ErrConfig
	}
	return LocalIdentity{&identityRecord{provider, provider.Public(), epoch, &generation{epoch}}}, nil
}

// PreparedInitiation holds sensitive handshake work for one admitted message
// and identity generation. It retains no packet buffers. RemoteStatic is a
// routing hint, not proof of private-key possession. HandleInitiation must
// authenticate the timestamp and check replay state. Bound queues holding these
// values and discard them after use. Do not log or serialize them. Go cannot
// guarantee erasure of all copies.
type PreparedInitiation struct {
	message        messageInitiation
	remote         PublicKey
	chainKey, hash [32]byte
	generation     *generation
}

// RemoteStatic returns the unauthenticated remote public-key routing hint.
func (v PreparedInitiation) RemoteStatic() PublicKey { return v.remote }

// PrepareInitiation decrypts the remote static key in an admitted initiation.
// It performs one provider DH and one static-key decryption. It neither allocates
// receiver indices nor mutates a Peer. The result still requires HandleInitiation
// authentication.
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
