/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 WireGuard LLC. All Rights Reserved.
 */

// Hybrid ML-KEM-768 + Noise_IKpsk2 handshake extension.
//
// This file implements message types 5 (initiation) and 6 (response) that
// extend the standard WireGuard Noise_IKpsk2 handshake with a post-quantum
// ML-KEM-768 (FIPS 203, formerly Kyber-768) key encapsulation mechanism,
// provided by the Go standard library crypto/mlkem package.
//
// # Protocol overview
//
// The initiator generates an ephemeral ML-KEM-768 keypair alongside the
// standard X25519 ephemeral key and appends the ML-KEM public key to the
// initiation message (before MAC1/MAC2).  The responder encapsulates a
// random shared secret to that public key, appends the ciphertext to the
// response message (before MAC1/MAC2), and mixes the ML-KEM shared secret
// into the Noise chain key after the X25519 DH operations and before the
// PSK step.  The initiator decapsulates the ciphertext and mirrors the same
// chain-key mixing, arriving at identical session keys.
//
// The result is a hybrid scheme whose security requires breaking *both*
// X25519 and ML-KEM-768.  A quantum adversary capable of breaking X25519
// still cannot recover the session keys without also breaking ML-KEM-768.
//
// # Interoperability
//
// Nodes that have MLKEMEnabled send type-5 initiations and reject type-1
// initiations (and vice versa).  The flag must be set identically on every
// peer in the network; no mixed-mode operation is supported.

package device

import (
	"crypto/mlkem"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tai64n"
)

// ML-KEM hybrid message type identifiers.
const (
	MessageInitiationMLKEMType = 5
	MessageResponseMLKEMType   = 6
)

// ML-KEM-768 (FIPS 203) wire sizes.
const (
	MLKEMPublicKeySize  = mlkem.EncapsulationKeySize768 // 1184 bytes
	MLKEMCiphertextSize = mlkem.CiphertextSize768       // 1088 bytes
)

// Total wire sizes for the hybrid handshake messages.
// The ML-KEM material is appended after the existing Noise fields and before
// MAC1/MAC2, so sizes are exactly MessageInitiationSize + MLKEMPublicKeySize
// and MessageResponseSize + MLKEMCiphertextSize.
const (
	MessageInitiationMLKEMSize = MessageInitiationSize + MLKEMPublicKeySize // 1332 bytes
	MessageResponseMLKEMSize   = MessageResponseSize + MLKEMCiphertextSize  // 1180 bytes
)

// MessageInitiationMLKEM is the hybrid Noise_IKpsk2 + ML-KEM-768 initiation.
//
// Wire layout (sizes in bytes):
//
//	Type            4   little-endian uint32 = MessageInitiationMLKEMType
//	Sender          4
//	Ephemeral      32   X25519 ephemeral public key
//	Static         48   AEAD-encrypted X25519 static public key
//	Timestamp      28   AEAD-encrypted TAI64N timestamp
//	MLKEMPublicKey 1184 ML-KEM-768 ephemeral public key (plaintext)
//	MAC1           16
//	MAC2           16
type MessageInitiationMLKEM struct {
	Type           uint32
	Sender         uint32
	Ephemeral      NoisePublicKey
	Static         [NoisePublicKeySize + poly1305.TagSize]byte
	Timestamp      [tai64n.TimestampSize + poly1305.TagSize]byte
	MLKEMPublicKey [MLKEMPublicKeySize]byte
	MAC1           [blake2s.Size128]byte
	MAC2           [blake2s.Size128]byte
}

// MessageResponseMLKEM is the hybrid Noise_IKpsk2 + ML-KEM-768 response.
//
// Wire layout:
//
//	Type             4
//	Sender           4
//	Receiver         4
//	Ephemeral       32
//	Empty           16   AEAD-encrypted empty string
//	MLKEMCiphertext 1088 ML-KEM-768 encapsulation ciphertext
//	MAC1            16
//	MAC2            16
type MessageResponseMLKEM struct {
	Type            uint32
	Sender          uint32
	Receiver        uint32
	Ephemeral       NoisePublicKey
	Empty           [poly1305.TagSize]byte
	MLKEMCiphertext [MLKEMCiphertextSize]byte
	MAC1            [blake2s.Size128]byte
	MAC2            [blake2s.Size128]byte
}

func (msg *MessageInitiationMLKEM) unmarshal(b []byte) error {
	if len(b) != MessageInitiationMLKEMSize {
		return errMessageLengthMismatch
	}
	off := 0
	msg.Type = binary.LittleEndian.Uint32(b[off:])
	off += 4
	msg.Sender = binary.LittleEndian.Uint32(b[off:])
	off += 4
	copy(msg.Ephemeral[:], b[off:])
	off += NoisePublicKeySize
	copy(msg.Static[:], b[off:])
	off += len(msg.Static)
	copy(msg.Timestamp[:], b[off:])
	off += len(msg.Timestamp)
	copy(msg.MLKEMPublicKey[:], b[off:])
	off += MLKEMPublicKeySize
	copy(msg.MAC1[:], b[off:])
	off += blake2s.Size128
	copy(msg.MAC2[:], b[off:])
	return nil
}

func (msg *MessageInitiationMLKEM) marshal(b []byte) error {
	if len(b) != MessageInitiationMLKEMSize {
		return errMessageLengthMismatch
	}
	off := 0
	binary.LittleEndian.PutUint32(b[off:], msg.Type)
	off += 4
	binary.LittleEndian.PutUint32(b[off:], msg.Sender)
	off += 4
	copy(b[off:], msg.Ephemeral[:])
	off += NoisePublicKeySize
	copy(b[off:], msg.Static[:])
	off += len(msg.Static)
	copy(b[off:], msg.Timestamp[:])
	off += len(msg.Timestamp)
	copy(b[off:], msg.MLKEMPublicKey[:])
	off += MLKEMPublicKeySize
	copy(b[off:], msg.MAC1[:])
	off += blake2s.Size128
	copy(b[off:], msg.MAC2[:])
	return nil
}

func (msg *MessageResponseMLKEM) unmarshal(b []byte) error {
	if len(b) != MessageResponseMLKEMSize {
		return errMessageLengthMismatch
	}
	off := 0
	msg.Type = binary.LittleEndian.Uint32(b[off:])
	off += 4
	msg.Sender = binary.LittleEndian.Uint32(b[off:])
	off += 4
	msg.Receiver = binary.LittleEndian.Uint32(b[off:])
	off += 4
	copy(msg.Ephemeral[:], b[off:])
	off += NoisePublicKeySize
	copy(msg.Empty[:], b[off:])
	off += len(msg.Empty)
	copy(msg.MLKEMCiphertext[:], b[off:])
	off += MLKEMCiphertextSize
	copy(msg.MAC1[:], b[off:])
	off += blake2s.Size128
	copy(msg.MAC2[:], b[off:])
	return nil
}

func (msg *MessageResponseMLKEM) marshal(b []byte) error {
	if len(b) != MessageResponseMLKEMSize {
		return errMessageLengthMismatch
	}
	off := 0
	binary.LittleEndian.PutUint32(b[off:], msg.Type)
	off += 4
	binary.LittleEndian.PutUint32(b[off:], msg.Sender)
	off += 4
	binary.LittleEndian.PutUint32(b[off:], msg.Receiver)
	off += 4
	copy(b[off:], msg.Ephemeral[:])
	off += NoisePublicKeySize
	copy(b[off:], msg.Empty[:])
	off += len(msg.Empty)
	copy(b[off:], msg.MLKEMCiphertext[:])
	off += MLKEMCiphertextSize
	copy(b[off:], msg.MAC1[:])
	off += blake2s.Size128
	copy(b[off:], msg.MAC2[:])
	return nil
}

// CreateMessageInitiationMLKEM creates a hybrid ML-KEM-768 + Noise_IKpsk2
// initiation message (type 5).
//
// It follows the same Noise transcript as CreateMessageInitiation and
// additionally:
//  1. Generates an ephemeral ML-KEM-768 keypair.
//  2. Appends its public key to the message and binds it into the transcript
//     via mixHash so both sides authenticate it.
//  3. Stores the ML-KEM-768 private key in the handshake state for use by
//     ConsumeMessageResponseMLKEM.
func (device *Device) CreateMessageInitiationMLKEM(peer *Peer) (*MessageInitiationMLKEM, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// Initialise Noise transcript state.
	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}

	handshake.mixHash(handshake.remoteStatic[:])

	msg := MessageInitiationMLKEM{
		Type:      MessageInitiationMLKEMType,
		Ephemeral: handshake.localEphemeral.publicKey(),
	}

	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	// Encrypt static X25519 key (same as standard initiation).
	ss, err := handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	var key [chacha20poly1305.KeySize]byte
	KDF2(&handshake.chainKey, &key, handshake.chainKey[:], ss[:])
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Static[:0], ZeroNonce[:], device.staticIdentity.publicKey[:], handshake.hash[:])
	handshake.mixHash(msg.Static[:])

	// Encrypt timestamp (same as standard initiation).
	if isZero(handshake.precomputedStaticStatic[:]) {
		return nil, errInvalidPublicKey
	}
	KDF2(&handshake.chainKey, &key, handshake.chainKey[:], handshake.precomputedStaticStatic[:])
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])
	handshake.mixHash(msg.Timestamp[:])

	// Generate ML-KEM-768 ephemeral keypair.  The public key is sent in the
	// clear and bound into the transcript via mixHash so both sides commit
	// to the same ML-KEM public key before deriving session keys.
	mlkemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	copy(handshake.localMLKEMPrivKey[:], mlkemDK.Bytes())
	handshake.localMLKEMPrivKeySet = true
	copy(msg.MLKEMPublicKey[:], mlkemDK.EncapsulationKey().Bytes())
	handshake.mixHash(msg.MLKEMPublicKey[:])

	// Assign sender index.
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

// ConsumeMessageInitiationMLKEM is the responder-side handler for a type-5
// initiation message.
//
// It authenticates the Noise transcript, decodes and validates the ML-KEM-768
// public key, mirrors the transcript binding (mixHash), and stores the public
// key in the handshake state for use by CreateMessageResponseMLKEM.
func (device *Device) ConsumeMessageInitiationMLKEM(msg *MessageInitiationMLKEM, endpoint conn.Endpoint) *Peer {
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	if msg.Type != MessageInitiationMLKEMType {
		return nil
	}

	// Snapshot staticIdentity outside handshake.mutex (lock-ordering: see
	// lock-ordering.md; staticIdentity < handshake.mutex).
	device.staticIdentity.RLock()
	publicKey := device.staticIdentity.publicKey
	privateKey := device.staticIdentity.privateKey
	device.staticIdentity.RUnlock()

	mixHash(&hash, &InitialHash, publicKey[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])

	// Decrypt static key.
	var peerPK NoisePublicKey
	var key [chacha20poly1305.KeySize]byte
	ss, err := privateKey.sharedSecret(msg.Ephemeral)
	if err != nil {
		return nil
	}
	KDF2(&chainKey, &key, chainKey[:], ss[:])
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(peerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Static[:])

	// Look up peer.
	initEP, ok := endpoint.(conn.InitiationAwareEndpoint)
	if ok {
		initEP.InitiationMessagePublicKey(peerPK)
	}
	peer := device.LookupPeer(peerPK)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}

	handshake := &peer.handshake
	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()
	if isZero(handshake.precomputedStaticStatic[:]) {
		handshake.mutex.RUnlock()
		return nil
	}
	KDF2(&chainKey, &key, chainKey[:], handshake.precomputedStaticStatic[:])
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()

	if replay {
		device.log.Verbosef("%v - ConsumeMessageInitiationMLKEM: handshake replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Verbosef("%v - ConsumeMessageInitiationMLKEM: handshake flood", peer)
		return nil
	}

	// Decode and validate the ML-KEM-768 public key, then bind it into the
	// transcript.  Done outside the write-lock so key parsing cost is not
	// charged while holding the mutex.
	mlkemEK, err := mlkem.NewEncapsulationKey768(msg.MLKEMPublicKey[:])
	if err != nil {
		device.log.Verbosef("%v - ConsumeMessageInitiationMLKEM: invalid ML-KEM public key: %v", peer, err)
		return nil
	}
	mixHash(&hash, &hash, msg.MLKEMPublicKey[:])

	// Commit handshake state.
	handshake.mutex.Lock()
	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = msg.Ephemeral
	handshake.remoteMLKEMPubKey = mlkemEK
	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed
	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])
	return peer
}

// CreateMessageResponseMLKEM creates a hybrid ML-KEM-768 + Noise_IKpsk2
// response message (type 6).
//
// After the standard X25519 DH operations it encapsulates a random shared
// secret to the initiator's ML-KEM-768 public key, mixes the encapsulation
// shared secret into the chain key (before the PSK step), and includes the
// ciphertext in the response.
func (device *Device) CreateMessageResponseMLKEM(peer *Peer) (*MessageResponseMLKEM, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}
	if handshake.remoteMLKEMPubKey == nil {
		return nil, errors.New("ML-KEM response requires a remote ML-KEM public key")
	}

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	var msg MessageResponseMLKEM
	msg.Type = MessageResponseMLKEMType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	// Create X25519 ephemeral (same as standard response).
	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = handshake.localEphemeral.publicKey()
	handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(msg.Ephemeral[:])

	// X25519 DH operations (same as standard response).
	ss, err := handshake.localEphemeral.sharedSecret(handshake.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	handshake.mixKey(ss[:])
	setZero(ss[:])

	ss, err = handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	handshake.mixKey(ss[:])
	setZero(ss[:])

	// ML-KEM-768 encapsulation.  The shared secret is mixed into the chain
	// key immediately after the X25519 operations and before the PSK step,
	// so both the classical and post-quantum secrets must be known to derive
	// the final session keys.
	mlkemSS, mlkemCT := handshake.remoteMLKEMPubKey.Encapsulate()
	handshake.mixKey(mlkemSS)
	setZero(mlkemSS)
	handshake.remoteMLKEMPubKey = nil // no longer needed; drop reference
	copy(msg.MLKEMCiphertext[:], mlkemCT)
	handshake.mixHash(msg.MLKEMCiphertext[:])

	// PSK step (same as standard response).
	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	KDF3(&handshake.chainKey, &tau, &key, handshake.chainKey[:], handshake.presharedKey[:])
	handshake.mixHash(tau[:])
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
	handshake.mixHash(msg.Empty[:])

	handshake.state = handshakeResponseCreated
	return &msg, nil
}

// ConsumeMessageResponseMLKEM is the initiator-side handler for a type-6
// response message.
//
// It mirrors the chain-key operations performed by CreateMessageResponseMLKEM:
// X25519 DH, ML-KEM-768 decapsulation (using the private key stored by
// CreateMessageInitiationMLKEM), and PSK step.
func (device *Device) ConsumeMessageResponseMLKEM(msg *MessageResponseMLKEM) *Peer {
	if msg.Type != MessageResponseMLKEMType {
		return nil
	}

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	// Snapshot static private key outside handshake.mutex (lock-ordering).
	device.staticIdentity.RLock()
	privateKey := device.staticIdentity.privateKey
	device.staticIdentity.RUnlock()

	ok := func() bool {
		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}
		if !handshake.localMLKEMPrivKeySet {
			return false
		}

		// X25519 DH (same as standard ConsumeMessageResponse).
		mixHash(&hash, &handshake.hash, msg.Ephemeral[:])
		mixKey(&chainKey, &handshake.chainKey, msg.Ephemeral[:])

		ss, err := handshake.localEphemeral.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, ss[:])
		setZero(ss[:])

		ss, err = privateKey.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, ss[:])
		setZero(ss[:])

		// ML-KEM-768 decapsulation.  Must produce the same shared secret
		// as the encapsulation in CreateMessageResponseMLKEM; any mismatch
		// causes the PSK AEAD verification below to fail, which is a
		// constant-time rejection per the ML-KEM-768 spec (implicit
		// rejection).
		//
		// Reconstruct the decapsulation key from the stored seed and
		// decapsulate the ciphertext.
		privKey, err := mlkem.NewDecapsulationKey768(handshake.localMLKEMPrivKey[:])
		if err != nil {
			return false
		}
		mlkemSS, err := privKey.Decapsulate(msg.MLKEMCiphertext[:])
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, mlkemSS)
		setZero(mlkemSS)
		mixHash(&hash, &hash, msg.MLKEMCiphertext[:])

		// PSK step.
		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(&chainKey, &tau, &key, chainKey[:], handshake.presharedKey[:])
		mixHash(&hash, &hash, tau[:])

		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	handshake.mutex.Lock()
	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	setZero(handshake.localMLKEMPrivKey[:])
	handshake.localMLKEMPrivKeySet = false
	handshake.state = handshakeResponseConsumed
	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])
	return lookup.peer
}
