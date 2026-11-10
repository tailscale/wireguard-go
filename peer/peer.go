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
	// ErrClosed reports an operation on a closed [Peer].
	ErrClosed = errors.New("peer: closed")

	// ErrNoSession reports that no send session is usable.
	ErrNoSession = errors.New("peer: no usable send session")

	// ErrExhausted reports that a counter cannot cover the requested work.
	ErrExhausted = errors.New("peer: send counter exhausted")

	// ErrShortBuffer reports insufficient caller-provided storage.
	ErrShortBuffer = errors.New("peer: insufficient caller storage")

	// ErrInvalidBuffer reports an invalid packet range or missing send headroom.
	ErrInvalidBuffer = errors.New("peer: invalid packet range")

	// ErrOverlap reports overlapping input and output where prohibited.
	ErrOverlap = errors.New("peer: overlapping packet ranges")

	// ErrHandshake reports a rejected handshake.
	ErrHandshake = errors.New("peer: rejected handshake")

	// ErrTransport reports rejected transport framing, keys, or authentication.
	ErrTransport = errors.New("peer: rejected transport")

	// ErrReplay reports an authenticated counter already received or outside the
	// replay window.
	ErrReplay = errors.New("peer: replayed transport")

	// ErrRateLimited reports an initiation before the handshake send interval has elapsed.
	ErrRateLimited = errors.New("peer: initiation rate limited")

	// ErrTime reports a zero or decreasing clock.
	ErrTime = errors.New("peer: zero or decreasing clock")

	// ErrConfig reports invalid configuration.
	ErrConfig = errors.New("peer: invalid configuration")

	// ErrIndex reports that an allocator returned the reserved zero index.
	ErrIndex = errors.New("peer: allocator returned reserved zero index")

	// ErrActivity reports foreign, duplicate, or out-of-order transport activity.
	ErrActivity = errors.New("peer: foreign, duplicate, or out-of-order transport activity")
)

// IndexAllocator reserves cryptographically random, nonzero receiver indexes
// for routing incoming packets to peers. Indexes must be unique across all peers
// sharing an incoming routing namespace.
// An index remains reserved until [IndexAllocator.Release], including while its
// key is retained only for receiving.
// Implementations shared by peers must support concurrent use.
type IndexAllocator interface {
	// Allocate reserves a nonzero index routed to owner until [IndexAllocator.Release].
	// An error must leave no reservation for the failed allocation.
	Allocate(owner *Peer) (uint32, error)

	// Release removes index only if it is still assigned to owner.
	Release(index uint32, owner *Peer)
}

// HandshakePolicy enables independent automatic handshake triggers in
// [Peer.HandleWake].
// The zero value leaves initiation to the caller. Keepalives and key expiry
// continue to operate regardless of these flags.
type HandshakePolicy struct {
	// Rekey enables key-freshness renewal. Retry enables retransmission after
	// an initiation attempt. Silence enables renewal when sent data goes
	// unanswered. EstablishForKeepalive enables initiation for a due keepalive
	// when no send session exists.
	Rekey, Retry, Silence, EstablishForKeepalive bool
}

// KeepaliveStart selects when a newly configured persistent keepalive is first due.
type KeepaliveStart uint8

const (
	// KeepaliveAfterInterval waits one configured interval.
	KeepaliveAfterInterval KeepaliveStart = iota

	// KeepaliveImmediate makes the first keepalive due at the configuration time.
	KeepaliveImmediate
)

// Config sets the handshake and transport policy for a new [Peer].
// The zero value uses manual handshakes, no persistent keepalives, and
// transport padding to a multiple of [PaddingMultiple].
type Config struct {
	// PresharedKey is the optional symmetric handshake secret.
	PresharedKey PresharedKey
	// Hybrid selects the Tailscale ML-KEM-768 hybrid handshake.
	// Both endpoints must use the same mode. There is no automatic fallback.
	Hybrid bool
	// PersistentKeepalive is the interval between idle keepalives.
	// Zero disables persistent keepalives. Negative values are invalid.
	PersistentKeepalive time.Duration
	// KeepaliveStart selects the first persistent keepalive time.
	KeepaliveStart KeepaliveStart
	// HandshakePolicy selects the automatic handshake triggers.
	HandshakePolicy HandshakePolicy
	// PaddingMTU caps transport padding at the MTU boundary. Zero pads to
	// a multiple of [PaddingMultiple] without an MTU cap. Negative values are invalid.
	// The caller must enforce the path MTU for complete outer datagrams.
	PaddingMTU int
}

// Peer maintains the WireGuard handshake and transport state for one remote key.
// Construct it with [New] and serialize its method calls. [Transport] provides
// separate send and receive lanes that can run alongside the control methods.
// A Peer must not be copied after construction.
//
// State-changing methods taking now require a nonzero, nondecreasing time and
// return [ErrTime] otherwise. They return [ErrClosed] after [Peer.Close].
// An accepted time advances cleanup even if later validation fails.
// Its wall time supplies handshake timestamps.
// Every returned [Update] describes the resulting state, including on errors.
// Output packets share caller storage. Single-packet output methods ignore
// out.Size and return [ErrShortBuffer] for insufficient storage. On error they return
// a zero [Packet] and preserve pending handshake state apart from time-based cleanup.
type Peer struct {
	alloc                      IndexAllocator
	remoteStatic               PublicKey
	static                     Static
	localPublic                PublicKey
	presharedKey               PresharedKey
	hybrid                     bool
	precomputedStaticStatic    [32]byte
	precomputedValid           bool
	handshake                  handshake
	cookieGen                  cookieGenerator
	keypairs                   keypairs
	timers                     timerState
	cachedWake                 Wake
	wakeValid                  bool
	policy                     HandshakePolicy
	identity                   LocalIdentity
	identityEpoch              uint64
	persistent                 time.Duration
	mtu                        int
	now, lastHandshake         time.Time
	closed                     bool
	sendNonceBuf, recvNonceBuf noiseNonce
	transport                  Transport
	appliedTX, appliedRX       uint64
}

// New returns a [Peer] for remote and its initial [Update].
// The caller must maintain one [Peer] per local generation and remote key.
// It returns nil and an empty [Update] on failure. It returns [ErrTime] for zero
// now, or [ErrConfig] for an invalid identity, nil allocator, zero remote key,
// or invalid config. Key-agreement errors from id's [Static] provider propagate.
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
	p := &Peer{static: id.record.provider, localPublic: id.record.public, identity: id, identityEpoch: id.record.epoch, alloc: alloc, remoteStatic: remote, presharedKey: config.PresharedKey, hybrid: config.Hybrid, precomputedStaticStatic: ss, precomputedValid: true, policy: config.HandshakePolicy, persistent: config.PersistentKeepalive, mtu: config.PaddingMTU, now: now}
	p.transport.tx.now, p.transport.rx.now = now, now
	p.cookieGen.init(remote)
	p.armPersistent(config.KeepaliveStart)
	return p, p.update(), nil
}

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

// LastHandshake returns the last handshake completion time, or zero if none
// has completed. A responder completes when it receives authenticated transport.
func (p *Peer) LastHandshake() time.Time { return p.lastHandshake }

// HasSession reports whether p has a usable send session at now.
// It returns false for a closed peer or a time before the peer's current time.
func (p *Peer) HasSession(now time.Time) bool {
	return !p.closed && !now.Before(p.now) && usable(p.keypairs.current, now)
}

// HasHybridSession reports whether p has a usable send session derived from a
// hybrid handshake at now. Changing handshake mode does not change existing keys.
func (p *Peer) HasHybridSession(now time.Time) bool {
	return p.HasSession(now) && p.keypairs.current.isHybrid
}

// SetHybridHandshake changes the mode used by subsequent handshakes.
// A mode change discards the pending handshake and schedules recovery according
// to [HandshakePolicy]. Established sessions remain usable. Repeating the current
// mode preserves pending work. The handshake send-rate guard remains in effect.
func (p *Peer) SetHybridHandshake(now time.Time, hybrid bool) (u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	if p.hybrid == hybrid {
		return
	}
	p.hybrid = hybrid
	p.releaseHandshakeIndex()
	p.handshake.clear()
	p.setWakeTimer(&p.timers.handshakeExpiry, time.Time{})
	p.timers.attempted = false
	p.timers.attempts = 0
	p.timers.refreshNeeded = true
	p.scheduleRecovery()
	return
}

// SetPresharedKey changes the secret used by subsequent handshake processing.
// Established transport sessions remain usable.
func (p *Peer) SetPresharedKey(now time.Time, psk PresharedKey) (u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	p.presharedKey = psk
	return
}

// ReplaceIdentity replaces the local generation and disables sending with
// existing keys. It discards the pending handshake and preserves retained keys
// for receiving until their normal expiry.
//
// After time validation, replacement disables the old identity even on failure.
// It returns [ErrConfig] if id is invalid or its epoch does not exceed the last
// epoch recorded by the peer. A provider failure still records the new epoch.
// Recovery requires another replacement with a higher epoch.
// Handshake work admitted for an earlier generation is rejected.
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

// SetHandshakePolicy changes automatic initiation triggers and reschedules
// recovery from the current handshake state.
func (p *Peer) SetHandshakePolicy(now time.Time, policy HandshakePolicy) (u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	p.policy = policy
	p.scheduleRecovery()
	return
}

// SetPersistentKeepalive resets the persistent keepalive schedule using interval
// and start. Zero interval disables it. It returns [ErrConfig] for a negative
// interval or an unknown start value.
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

// Close releases reserved indexes, discards handshake and session state, and
// returns an empty [Update]. Repeated calls are harmless. In-flight [Transport]
// operations may finish using their retained keys. Stop dispatch and wait for
// those operations before reusing their packet storage.
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
