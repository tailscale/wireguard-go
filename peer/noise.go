/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import (
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/tailscale/wireguard-go/tai64n"
)

type handshakeState int

const (
	handshakeZeroed handshakeState = iota
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

// handshake is owned by Peer. Replay history survives ephemeral clearing.
type handshake struct {
	state           handshakeState
	hash            [blake2s.Size]byte
	chainKey        [blake2s.Size]byte
	localEphemeral  PrivateKey
	localIndex      uint32
	remoteIndex     uint32
	remoteEphemeral PublicKey

	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

func (h *handshake) mixHash(data []byte) { mixHash(&h.hash, &h.hash, data) }
func (h *handshake) mixKey(data []byte)  { mixKey(&h.chainKey, &h.chainKey, data) }

func (h *handshake) clear() {
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	h.localIndex = 0
	h.remoteIndex = 0
	h.state = handshakeZeroed
}

// createInitiation builds a handshake initiation on the control owner.
func (p *Peer) createInitiation(now time.Time) (*messageInitiation, error) {
	h := &p.handshake
	if !p.precomputedValid {
		return nil, errInvalidPublicKey
	}

	var err error
	h.hash = initialHash
	h.chainKey = initialChainKey
	h.localEphemeral, err = NewPrivateKey()
	if err != nil {
		return nil, err
	}

	h.mixHash(p.remoteStatic[:])

	msg := &messageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: h.localEphemeral.Public(),
	}
	h.mixKey(msg.Ephemeral[:])
	h.mixHash(msg.Ephemeral[:])

	// encrypt our static public key
	ss, err := h.localEphemeral.sharedSecret(p.remoteStatic)
	if err != nil {
		return nil, err
	}
	var key [chacha20poly1305.KeySize]byte
	kdf2(&h.chainKey, &key, h.chainKey[:], ss[:])
	aead, _ := newAEAD(key[:])
	pub := p.localPublic
	aead.Seal(msg.Static[:0], zeroNonce[:], pub[:], h.hash[:])
	h.mixHash(msg.Static[:])

	// encrypt timestamp using the precomputed static-static secret
	kdf2(&h.chainKey, &key, h.chainKey[:], p.precomputedStaticStatic[:])
	var timestamp tai64n.Timestamp
	binary.BigEndian.PutUint64(timestamp[:8], uint64(now.Unix())+0x400000000000000a)
	binary.BigEndian.PutUint32(timestamp[8:], uint32(now.Nanosecond())&^0xffffff)
	aead, _ = newAEAD(key[:])
	aead.Seal(msg.Timestamp[:0], zeroNonce[:], timestamp[:], h.hash[:])

	// assign a fresh local index
	msg.Sender, err = p.allocateIndex()
	if err != nil {
		return nil, err
	}
	p.releaseHandshakeIndex()
	h.localIndex = msg.Sender

	h.mixHash(msg.Timestamp[:])
	h.state = handshakeInitiationCreated
	return msg, nil
}

// consumeInitiation authenticates prepared work and updates handshake state.
func (p *Peer) consumeInitiation(v PreparedInitiation, now time.Time) bool {
	if v.generation == nil || p.identity.record == nil || v.generation != p.identity.record.marker || !p.precomputedValid || !v.remote.Equals(p.remoteStatic) {
		return false
	}
	msg := &v.message
	hash, chainKey := v.hash, v.chainKey
	var key [chacha20poly1305.KeySize]byte

	var timestamp tai64n.Timestamp
	kdf2(&chainKey, &key, chainKey[:], p.precomputedStaticStatic[:])
	aead, _ := newAEAD(key[:])
	if _, err := aead.Open(timestamp[:0], zeroNonce[:], msg.Timestamp[:], hash[:]); err != nil {
		return false
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// replay & flood protection
	h := &p.handshake
	if !timestamp.After(h.lastTimestamp) {
		return false
	}
	if !h.lastInitiationConsumption.IsZero() && now.Sub(h.lastInitiationConsumption) <= HandshakeInitRate {
		return false
	}

	h.hash = hash
	h.chainKey = chainKey
	h.remoteIndex = msg.Sender
	h.remoteEphemeral = msg.Ephemeral
	if timestamp.After(h.lastTimestamp) {
		h.lastTimestamp = timestamp
	}
	if now.After(h.lastInitiationConsumption) {
		h.lastInitiationConsumption = now
	}
	h.state = handshakeInitiationConsumed
	return true
}

// createResponse builds a response to a consumed initiation on the control owner.
func (p *Peer) createResponse() (*messageResponse, error) {
	h := &p.handshake
	if h.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	var err error

	msg := &messageResponse{
		Type:     MessageResponseType,
		Sender:   h.localIndex,
		Receiver: h.remoteIndex,
	}

	h.localEphemeral, err = NewPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = h.localEphemeral.Public()
	h.mixHash(msg.Ephemeral[:])
	h.mixKey(msg.Ephemeral[:])

	ss, err := h.localEphemeral.sharedSecret(h.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	h.mixKey(ss[:])
	ss, err = h.localEphemeral.sharedSecret(p.remoteStatic)
	if err != nil {
		return nil, err
	}
	h.mixKey(ss[:])

	var tau, key [blake2s.Size]byte
	kdf3(&h.chainKey, &tau, &key, h.chainKey[:], p.presharedKey[:])
	h.mixHash(tau[:])

	aead, _ := newAEAD(key[:])
	aead.Seal(msg.Empty[:0], zeroNonce[:], nil, h.hash[:])
	h.mixHash(msg.Empty[:])

	index, err := p.allocateIndex()
	if err != nil {
		return nil, err
	}
	p.releaseHandshakeIndex()
	h.localIndex = index
	msg.Sender = index
	h.state = handshakeResponseCreated
	return msg, nil
}

// consumeResponse authenticates a response for the pending initiation.
func (p *Peer) consumeResponse(msg *messageResponse) bool {
	h := &p.handshake
	if msg.Type != MessageResponseType || h.state != handshakeInitiationCreated || msg.Receiver != h.localIndex {
		return false
	}

	var hash, chainKey [blake2s.Size]byte
	mixHash(&hash, &h.hash, msg.Ephemeral[:])
	mixKey(&chainKey, &h.chainKey, msg.Ephemeral[:])

	ss, err := h.localEphemeral.sharedSecret(msg.Ephemeral)
	if err != nil {
		return false
	}
	mixKey(&chainKey, &chainKey, ss[:])
	setZero(ss[:])

	ss, err = sharedSecret(p.static, msg.Ephemeral)
	if err != nil {
		return false
	}
	mixKey(&chainKey, &chainKey, ss[:])
	setZero(ss[:])

	var tau, key [blake2s.Size]byte
	kdf3(&chainKey, &tau, &key, chainKey[:], p.presharedKey[:])
	mixHash(&hash, &hash, tau[:])

	aead, _ := newAEAD(key[:])
	if _, err := aead.Open(nil, zeroNonce[:], msg.Empty[:], hash[:]); err != nil {
		return false
	}
	mixHash(&hash, &hash, msg.Empty[:])

	h.hash = hash
	h.chainKey = chainKey
	h.remoteIndex = msg.Sender
	h.state = handshakeResponseConsumed
	return true
}

// beginSession derives and installs a keypair from the completed handshake.
func (p *Peer) beginSession(now time.Time) error {
	h := &p.handshake

	var isInitiator bool
	var sendKey, recvKey [chacha20poly1305.KeySize]byte

	switch h.state {
	case handshakeResponseConsumed:
		kdf2(&sendKey, &recvKey, h.chainKey[:], nil)
		isInitiator = true
	case handshakeResponseCreated:
		kdf2(&recvKey, &sendKey, h.chainKey[:], nil)
		isInitiator = false
	default:
		return errors.New("invalid state for keypair derivation")
	}

	kp := &keypair{isInitiator: isInitiator, created: now}
	kp.send, _ = newAEAD(sendKey[:])
	kp.receive, _ = newAEAD(recvKey[:])
	setZero(sendKey[:])
	setZero(recvKey[:])
	kp.replayFilter.Reset()
	kp.localIndex = h.localIndex
	kp.remoteIndex = h.remoteIndex

	// Transfer index ownership to the keypair without changing its route.
	h.localIndex = 0
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	h.state = handshakeZeroed

	kps := &p.keypairs
	previous := kps.previous
	next := kps.next
	current := kps.current
	if isInitiator {
		if next != nil {
			kps.next = nil
			kps.previous = next
			p.deleteKeypair(current)
		} else {
			kps.previous = current
		}
		p.deleteKeypair(previous)
		kps.current = kp
	} else {
		kps.next = kp
		p.deleteKeypair(next)
		kps.previous = nil
		p.deleteKeypair(previous)
	}
	return nil
}

// receivedWithKeypair promotes next on authenticated transport confirmation.
// It reports whether promotion occurred. Old-identity receive-only keys cannot
// complete the current identity's recovery.
func (p *Peer) receivedWithKeypair(received *keypair) bool {
	kps := &p.keypairs
	if kps.next != received || !usable(received, p.now) {
		return false
	}
	old := kps.previous
	kps.previous = kps.current
	p.deleteKeypair(old)
	kps.current = kps.next
	kps.next = nil
	return true
}

// deleteKeypair retires a keypair and releases its route without clearing key
// material. In-flight calls retain the immutable AEAD state. Clearing it here
// would race those calls.
func (p *Peer) deleteKeypair(kp *keypair) {
	if kp != nil && !kp.retired.Swap(true) {
		kp.sendDisabled.Store(true)
		p.alloc.Release(kp.localIndex, p)
	}
}
