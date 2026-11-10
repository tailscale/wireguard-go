/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import "time"

// Initiate writes a handshake initiation at out.Offset and returns its packet.
// It requires [MessageInitiationSize] bytes after the offset, or
// [MessageHybridInitiationSize] when hybrid mode is enabled. It returns
// [ErrRateLimited] if the last sent handshake was less than [RekeyTimeout] ago.
func (p *Peer) Initiate(now time.Time, out Packet) (Packet, Update, error) {
	return p.initiateOutput(now, out, false)
}

// RetryInitiation writes a fresh initiation for a caller-driven retry.
// Buffer and rate-limit rules match [Peer.Initiate]. Hybrid packets carry the
// retry hint. A successful call preserves and increments the automatic retry
// count instead of starting a new attempt budget. Manual retries are allowed
// after the automatic budget is exhausted.
func (p *Peer) RetryInitiation(now time.Time, out Packet) (Packet, Update, error) {
	return p.initiateOutput(now, out, true)
}

func (p *Peer) initiationSize() int {
	if p.hybrid {
		return MessageHybridInitiationSize
	}
	return MessageInitiationSize
}

func (p *Peer) responseSize() int {
	if p.hybrid {
		return MessageHybridResponseSize
	}
	return MessageResponseSize
}

func (p *Peer) initiateOutput(now time.Time, out Packet, retry bool) (packet Packet, u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	out, err = output(out, p.initiationSize())
	if err != nil {
		return
	}
	packet, err = p.initiate(now, out, retry)
	if err == nil && retry && p.timers.attempts <= MaxTimerHandshakes {
		p.timers.attempts++
	}
	return
}

func (p *Peer) initiate(now time.Time, out Packet, retry bool) (Packet, error) {
	if !p.handshake.lastSentHandshake.IsZero() && now.Sub(p.handshake.lastSentHandshake) < RekeyTimeout {
		return Packet{}, ErrRateLimited
	}
	saved := p.handshake
	msg, err := p.createInitiation(now)
	if err != nil {
		p.handshake = saved
		return Packet{}, err
	}
	msg.IsRetry = p.hybrid && retry
	out.Size = p.initiationSize()
	_ = msg.marshal(out.Bytes())
	p.cookieGen.addMACs(now, out.Bytes())
	p.handshake.lastSentHandshake = now
	p.setWakeTimer(&p.timers.handshakeExpiry, now.Add(3*RejectAfterTime))
	if !retry {
		p.timers.attempts = 0
	}
	p.timers.attempted = true
	p.timers.lastAttempt = now
	p.setWakeTimer(&p.timers.newHandshake, time.Time{})
	p.setWakeTimer(&p.timers.retransmit, time.Time{})
	if p.policy.Retry {
		p.setWakeTimer(&p.timers.retransmit, now.Add(RekeyTimeout))
	}
	p.setWakeTimer(&p.timers.refresh, time.Time{})
	p.onAuthSent(now)
	return out, nil
}

// HandleInitiation authenticates v and writes a handshake response at out.Offset.
// It requires [MessageResponseSize] bytes after the offset, or
// [MessageHybridResponseSize] when hybrid mode is enabled. It returns [ErrHandshake]
// if v belongs to another local generation or remote, uses another handshake
// mode, fails authentication, or violates timestamp replay or initiation rate limits. On success, the derived
// session awaits an authenticated transport packet before it can send.
func (p *Peer) HandleInitiation(now time.Time, v PreparedInitiation, out Packet) (packet Packet, u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	out, err = output(out, p.responseSize())
	if err != nil {
		return
	}
	saved := p.handshake
	if !p.consumeInitiation(v, now) {
		return Packet{}, u, ErrHandshake
	}
	response, err := p.createResponse()
	if err != nil {
		p.handshake = saved
		return Packet{}, u, err
	}
	// Index replacement has committed. Derivation cannot fail with 32-byte keys.
	if err = p.beginSession(now); err != nil {
		panic(err)
	}
	response.IsRetry = p.hybrid && v.message.IsRetry
	_ = response.marshal(out.Bytes())
	p.cookieGen.addMACs(now, out.Bytes())
	p.handshake.lastSentHandshake = now
	p.onSessionDerived()
	p.onAuthReceived(now)
	p.onAuthSent(now)
	return out, u, nil
}

// HandleResponse authenticates v, installs the send session, and writes a
// confirmation keepalive at out.Offset. It requires [MessageKeepaliveSize] bytes
// after the offset. It returns [ErrHandshake] if v is not a response for the
// current local generation and pending initiation, or authentication fails.
func (p *Peer) HandleResponse(now time.Time, v AdmittedHandshake, out Packet) (packet Packet, u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	out, err = output(out, MessageKeepaliveSize)
	if err != nil {
		return
	}
	if v.identity == nil || p.identity.record == nil || v.identity.marker != p.identity.record.marker || v.size != p.responseSize() {
		return Packet{}, u, ErrHandshake
	}
	var msg messageResponse
	if msg.unmarshal(v.wire[:v.size]) != nil || !p.consumeResponse(&msg) {
		return Packet{}, u, ErrHandshake
	}
	if err = p.beginSession(now); err != nil {
		panic(err)
	}
	p.onSessionDerived()
	p.onHandshakeComplete(now)
	p.onAuthReceived(now)
	packet, err = p.keepalive(now, out)
	return packet, u, err
}

func (p *Peer) keepalive(now time.Time, out Packet) (Packet, error) {
	packet := Packet{out.Buffer, out.Offset + TransportHeaderSize, 0}
	k := p.keypairs.current
	counter, n := k.reserve(1)
	if n == 0 {
		return Packet{}, ErrExhausted
	}
	wire := encrypt(k, packet, p.mtu, counter, &p.sendNonceBuf)
	p.sentTransport(now, false, k)
	return wire, nil
}
