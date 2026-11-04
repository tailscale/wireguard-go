/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import "time"

// Initiate starts a fresh attempt sequence under any policy, subject to the
// handshake rate limit. On error it writes no packet and preserves handshake
// state and indices except for accepted-clock cleanup.
func (p *Peer) Initiate(now time.Time, out Packet) (packet Packet, u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	out, err = output(out, MessageInitiationSize)
	if err != nil {
		return
	}
	packet, err = p.initiate(now, out, false)
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
	out.Size = MessageInitiationSize
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

// HandleInitiation authenticates v for this peer and identity generation and
// writes a response. On error it writes no packet and preserves handshake state
// and indices except for accepted-clock cleanup. v may be retried after storage
// or allocation failure. Successful use makes copies fail timestamp replay.
// out may reuse the original input buffer.
func (p *Peer) HandleInitiation(now time.Time, v PreparedInitiation, out Packet) (packet Packet, u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	out, err = output(out, MessageResponseSize)
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
	_ = response.marshal(out.Bytes())
	p.cookieGen.addMACs(now, out.Bytes())
	p.handshake.lastSentHandshake = now
	p.onSessionDerived()
	p.onAuthReceived(now)
	p.onAuthSent(now)
	return out, u, nil
}

// HandleResponse authenticates an admitted response and writes an empty
// transport confirmation. On error it writes no packet and preserves handshake
// state and indices except for accepted-clock cleanup. out may reuse the
// original input buffer.
func (p *Peer) HandleResponse(now time.Time, v AdmittedHandshake, out Packet) (packet Packet, u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.advance(now); err != nil {
		return
	}
	out, err = output(out, MessageKeepaliveSize)
	if err != nil {
		return
	}
	if v.identity == nil || p.identity.record == nil || v.identity.marker != p.identity.record.marker || v.size != MessageResponseSize {
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

// keepalive requires an already checked usable key and 32 bytes at out.Offset.
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
