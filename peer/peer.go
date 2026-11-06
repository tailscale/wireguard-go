/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import (
	"errors"
	"time"
)

var (
	// ErrClosed indicates that the peer is closed.
	ErrClosed = errors.New("peer: closed")
	// ErrNoSession indicates that no send session is usable.
	ErrNoSession = errors.New("peer: no usable send session")
	// ErrExhausted indicates that a send counter or transport sequence is exhausted.
	ErrExhausted = errors.New("peer: send counter exhausted")
	// ErrShortBuffer indicates insufficient caller storage.
	ErrShortBuffer = errors.New("peer: insufficient caller storage")
	// ErrInvalidBuffer indicates an invalid packet range.
	ErrInvalidBuffer = errors.New("peer: invalid packet range")
	// ErrOverlap indicates overlapping cookie-challenge input and output.
	ErrOverlap = errors.New("peer: overlapping packet ranges")
	// ErrHandshake indicates a rejected handshake.
	ErrHandshake = errors.New("peer: rejected handshake")
	// ErrTransport indicates a rejected transport packet.
	ErrTransport = errors.New("peer: rejected transport")
	// ErrReplay indicates a replayed transport packet.
	ErrReplay = errors.New("peer: replayed transport")
	// ErrRateLimited indicates that an initiation is too soon.
	ErrRateLimited = errors.New("peer: initiation rate limited")
	// ErrTime indicates a zero or decreasing clock, or a receipt later than now.
	ErrTime = errors.New("peer: zero or decreasing clock")
	// ErrConfig indicates invalid configuration.
	ErrConfig = errors.New("peer: invalid configuration")
	// ErrIndex indicates that an allocator returned a zero index without an error.
	ErrIndex = errors.New("peer: allocator returned reserved zero index")
	// ErrActivity indicates a foreign, duplicate, or out-of-order transport receipt.
	ErrActivity = errors.New("peer: foreign, duplicate, or out-of-order transport activity")
)

// IndexAllocator allocates cryptographically random, nonzero receiver indices,
// unique among live allocations across all identities sharing ingress.
// Peer transfers handshake indices to sessions and releases each allocation
// exactly once. Implementations shared by concurrent control owners must be
// safe for concurrent use. A peerindex.Table[*Peer] implements IndexAllocator.
type IndexAllocator interface {
	// Allocate registers owner, returning zero and retaining no allocation on error.
	Allocate(owner *Peer) (uint32, error)
	// Release removes index only if it belongs to owner.
	Release(index uint32, owner *Peer)
}

// HandshakePolicy controls autonomous initiation. Rekey permits key refresh.
// Retry permits repeated attempts. Silence permits recovery after unanswered data.
// EstablishForKeepalive permits starting a session for a due keepalive.
// The zero value leaves initiation to the caller. Other triggers cannot restart
// an unanswered attempt when retries are disabled or exhausted. Key rejection
// and cleanup are unconditional.
type HandshakePolicy struct {
	Rekey, Retry, Silence, EstablishForKeepalive bool
}

// KeepaliveStart selects when the first persistent keepalive becomes due.
type KeepaliveStart uint8

const (
	// KeepaliveAfterInterval waits one configured interval.
	KeepaliveAfterInterval KeepaliveStart = iota
	// KeepaliveImmediate makes the first keepalive due at the current control time.
	KeepaliveImmediate
)

// Config configures a new Peer. PersistentKeepalive and PaddingMTU must be
// nonnegative. A zero PersistentKeepalive disables persistent keepalives.
// A zero PaddingMTU pads to a multiple of 16 bytes without an MTU cap.
// PaddingMTU does not limit packet size. The caller must limit the complete
// outer datagram to the path MTU. The zero HandshakePolicy leaves initiation
// to the caller.
type Config struct {
	PresharedKey        PresharedKey
	PersistentKeepalive time.Duration
	KeepaliveStart      KeepaliveStart
	HandshakePolicy     HandshakePolicy
	PaddingMTU          int
}

// Peer holds one remote peer's protocol state. The caller must serialize all
// its methods, including Send, Receive, status accessors, and Close. Ownership
// may be transferred with caller synchronization. Transport provides concurrent
// send and receive lanes. Peer.Send and Peer.Receive must also be serialized
// with the corresponding lane. Peer owns no I/O, workers, queues, or packet
// storage. The zero value is not usable. Use New. Peer must not be copied.
type Peer struct {
	alloc                      IndexAllocator
	remoteStatic               PublicKey
	static                     Static
	localPublic                PublicKey
	presharedKey               PresharedKey
	precomputedStaticStatic    [32]byte
	precomputedValid           bool
	handshake                  handshake
	cookieGen                  cookieGenerator
	keypairs                   keypairs
	timers                     timerState
	cachedWake                 Wake
	wakeValid                  bool // Handshake advice is recomputed independently at the accepted time.
	policy                     HandshakePolicy
	identity                   LocalIdentity
	identityEpoch              uint64
	persistent                 time.Duration
	mtu                        int
	now, lastHandshake         time.Time
	closed                     bool
	sendNonceBuf, recvNonceBuf [12]byte
	transport                  Transport
	appliedTX, appliedRX       uint64
}

// New returns a peer and its initial Update without emitting packets.
// now must be nonzero. Share id with ingress. The allocator must use the
// receiver-index namespace common to all identities sharing ingress.
// The caller must reject duplicate local-generation and remote-key pairs.
// On failure, New returns nil and an empty Update.
func New(now time.Time, id LocalIdentity, alloc IndexAllocator, remote PublicKey, config Config) (*Peer, Update, error) {
	if now.IsZero() {
		return nil, Update{}, ErrTime
	}
	if id.record == nil || alloc == nil || remote.IsZero() || config.PersistentKeepalive < 0 || config.PaddingMTU < 0 || config.KeepaliveStart > KeepaliveImmediate {
		return nil, Update{}, ErrConfig
	}
	ss, err := sharedSecret(id.record.provider, remote)
	if err != nil {
		return nil, Update{}, err
	}
	p := &Peer{static: id.record.provider, localPublic: id.record.public, identity: id, identityEpoch: id.record.epoch, alloc: alloc, remoteStatic: remote, presharedKey: config.PresharedKey, precomputedStaticStatic: ss, precomputedValid: true, policy: config.HandshakePolicy, persistent: config.PersistentKeepalive, mtu: config.PaddingMTU, now: now}
	p.transport.tx.now, p.transport.rx.now = now, now
	p.cookieGen.init(remote)
	p.armPersistent(config.KeepaliveStart)
	return p, p.update(), nil
}

// advance accepts a nonzero, nondecreasing clock and cleans expired secrets.
// It emits no packets, even when cleanup is overdue.
func (p *Peer) advance(now time.Time) error {
	if p.closed {
		return ErrClosed
	}
	if now.IsZero() || (!p.now.IsZero() && now.Before(p.now)) {
		return ErrTime
	}
	p.now = now
	p.cleanup(now)
	return nil
}

// RemoteStatic returns the configured remote public key.
func (p *Peer) RemoteStatic() PublicKey { return p.remoteStatic }

// LastHandshake returns the control time of the last completed handshake,
// or zero if none has completed.
func (p *Peer) LastHandshake() time.Time { return p.lastHandshake }

// HasSession reports whether the current send session is usable at now.
// It returns false before the control clock and does not advance time or clean up.
func (p *Peer) HasSession(now time.Time) bool {
	return !p.closed && !now.Before(p.now) && usable(p.keypairs.current, now)
}

// SetPresharedKey affects subsequent handshake steps, not established sessions.
// To revoke existing sessions, stop dispatch, drain transport and writers, and
// close the peer.
func (p *Peer) SetPresharedKey(now time.Time, psk PresharedKey) (u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	p.presharedKey = psk
	return
}

// ReplaceIdentity replaces the local identity. After accepting now, it invalidates
// pending handshakes and disables old-identity sending, even if replacement fails.
// Old receive keys retain their age limits but cannot become send-usable.
// In-flight transport calls may still finish with pinned keys.
//
// id must have a strictly newer epoch. A newer epoch is consumed even if the
// provider fails. Recovery then requires another newer handle. Invalid or old
// handles leave sending disabled. The caller must replace ingress Admission and
// static-key routing in the same ownership handoff. Generation checks reject
// old tokens, not old wire messages. Retained timestamp history still applies.
func (p *Peer) ReplaceIdentity(now time.Time, id LocalIdentity) (u Update, err error) {
	defer func() { u = p.update() }()
	if err := p.advance(now); err != nil {
		return u, err
	}
	p.releaseHandshakeIndex()
	p.handshake.clear()
	p.handshake.lastSentHandshake = time.Time{}
	for _, k := range [...]*keypair{p.keypairs.previous, p.keypairs.current, p.keypairs.next} {
		if k != nil {
			k.sendDisabled.Store(true)
			k.sendNonce.Store(RejectAfterMessages)
		}
	}
	p.setWakeTimer(&p.timers.retransmit, time.Time{})
	p.setWakeTimer(&p.timers.newHandshake, time.Time{})
	p.setWakeTimer(&p.timers.refresh, time.Time{})
	p.timers.refreshNeeded = true
	p.timers.attempted = false
	p.timers.attempts = 0
	p.timers.silenceAt = time.Time{}
	p.identity = LocalIdentity{}
	p.precomputedValid = false
	clear(p.precomputedStaticStatic[:])
	p.static = nil
	p.localPublic = PublicKey{}
	p.cookieGen.init(p.remoteStatic)
	if id.record == nil || id.record.epoch <= p.identityEpoch {
		return u, ErrConfig
	}
	p.identityEpoch = id.record.epoch
	p.static = id.record.provider
	p.localPublic = id.record.public
	ss, err := sharedSecret(p.static, p.remoteStatic)
	if err != nil {
		return u, err
	}
	p.precomputedStaticStatic = ss
	p.precomputedValid = true
	p.identity = id
	p.scheduleRecovery()
	return u, nil
}

// SetHandshakePolicy changes autonomous initiation permissions without resetting
// attempt history or the retry budget.
func (p *Peer) SetHandshakePolicy(now time.Time, policy HandshakePolicy) (u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	p.policy = policy
	p.scheduleRecovery()
	return
}

// SetPersistentKeepalive rearms the first keepalive on every valid call.
// A zero interval disables it. Authenticated traffic restarts the interval.
// Without a session, a due intent can initiate only if EstablishForKeepalive
// permits it. Invalid configuration still permits clock advancement and cleanup.
func (p *Peer) SetPersistentKeepalive(now time.Time, interval time.Duration, start KeepaliveStart) (u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	if interval < 0 || start > KeepaliveImmediate {
		return u, ErrConfig
	}
	p.persistent = interval
	p.armPersistent(start)
	return
}
func (p *Peer) armPersistent(start KeepaliveStart) {
	p.setWakeTimer(&p.timers.persistent, time.Time{})
	if p.persistent > 0 {
		p.setWakeTimer(&p.timers.persistent, p.now.Add(p.persistent))
		if start == KeepaliveImmediate {
			p.setWakeTimer(&p.timers.persistent, p.now)
		}
	}
}

func (p *Peer) allocateIndex() (uint32, error) {
	index, err := p.alloc.Allocate(p)
	if err == nil && index == 0 {
		err = ErrIndex
	}
	return index, err
}
func (p *Peer) releaseHandshakeIndex() {
	index := p.handshake.localIndex
	p.handshake.localIndex = 0
	if index != 0 {
		p.alloc.Release(index, p)
	}
}

// Close releases indices and permanently disables new protocol work.
// It is idempotent and returns an empty Update. The caller must remove static-key
// registrations and stop dispatch. Routers do not close peers. Drain transport
// lanes and writers before treating shutdown or revocation as complete.
// Keep routed work attached to this peer. A replacement has separate replay state.
// Subsequent protocol calls return ErrClosed. Status accessors remain available.
func (p *Peer) Close() Update {
	if p.closed {
		return Update{}
	}
	p.releaseHandshakeIndex()
	p.handshake.clear()
	p.deleteKeypair(p.keypairs.previous)
	p.deleteKeypair(p.keypairs.current)
	p.deleteKeypair(p.keypairs.next)
	p.keypairs = keypairs{}
	p.timers = timerState{}
	p.cookieGen = cookieGenerator{}
	clear(p.precomputedStaticStatic[:])
	clear(p.presharedKey[:])
	p.static = nil
	p.precomputedValid = false
	p.closed = true
	p.identity = LocalIdentity{}
	p.publishTransport()
	return Update{}
}
