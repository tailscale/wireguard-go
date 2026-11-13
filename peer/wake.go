/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import "time"

// Wake is an inclusive maintenance window for calling [Peer.HandleWake].
// Earliest is the first due maintenance time.
// Deadline is the earliest deadline among pending tasks.
// The zero value means no maintenance is scheduled.
// A caller may coalesce work within the window, but must call by Deadline to
// perform hard cleanup on time.
type Wake struct{ Earliest, Deadline time.Time }

func (w Wake) merge(v Wake) Wake {
	if v.Earliest.IsZero() {
		return w
	}
	if w.Earliest.IsZero() {
		return v
	}
	if v.Earliest.Before(w.Earliest) {
		w.Earliest = v.Earliest
	}
	if v.Deadline.Before(w.Deadline) {
		w.Deadline = v.Deadline
	}
	return w
}

func window(at time.Time, slack time.Duration) Wake {
	if at.IsZero() {
		return Wake{}
	}
	return Wake{at, at.Add(slack)}
}

func due(at, now time.Time) bool { return !at.IsZero() && !now.Before(at) }

type timerState struct {
	retransmit, sendKeepalive, newHandshake, persistent, refresh, handshakeExpiry time.Time
	attempts                                                                      int
	needAnotherKeepalive, receiveRefreshSent, refreshNeeded                       bool
	attempted                                                                     bool
	silenceAt, lastAttempt                                                        time.Time
}

func (p *Peer) setWakeTimer(slot *time.Time, at time.Time) {
	if *slot != at {
		*slot = at
		p.wakeValid = false
	}
}

func (p *Peer) nextWake() Wake {
	if !p.wakeValid {
		p.cachedWake = p.computeWake()
		p.wakeValid = true
	}
	return p.cachedWake
}

func (p *Peer) computeWake() Wake {
	if p.closed {
		return Wake{}
	}
	t := &p.timers
	var w Wake
	w = w.merge(window(t.retransmit, RekeyTimeoutJitter))
	w = w.merge(window(t.newHandshake, RekeyTimeoutJitter))
	w = w.merge(window(t.refresh, RekeyTimeoutJitter))
	w = w.merge(window(t.sendKeepalive, time.Second))
	w = w.merge(window(t.persistent, time.Second))
	w = w.merge(window(t.handshakeExpiry, 0))
	for _, k := range [...]*keypair{p.keypairs.current, p.keypairs.previous, p.keypairs.next} {
		if k != nil {
			w = w.merge(window(k.created.Add(3*RejectAfterTime), 0))
		}
	}
	return w
}

func (p *Peer) cleanup(now time.Time) {
	if due(p.timers.handshakeExpiry, now) {
		p.releaseHandshakeIndex()
		p.handshake.clear()
		p.setWakeTimer(&p.timers.handshakeExpiry, time.Time{})
		p.setWakeTimer(&p.timers.retransmit, time.Time{})
	}
	for _, slot := range [...]**keypair{&p.keypairs.previous, &p.keypairs.current, &p.keypairs.next} {
		if k := *slot; k != nil && now.Sub(k.created) >= 3*RejectAfterTime {
			p.deleteKeypair(k)
			*slot = nil
		}
	}
	// Persistence is configuration, not key material. Cleanup never disables it.
}

func (p *Peer) onAuthSent(now time.Time) {
	p.setWakeTimer(&p.timers.sendKeepalive, time.Time{})
	if p.persistent > 0 {
		p.setWakeTimer(&p.timers.persistent, now.Add(p.persistent))
	}
}

func (p *Peer) onAuthReceived(now time.Time) {
	p.timers.silenceAt = time.Time{}
	p.setWakeTimer(&p.timers.newHandshake, time.Time{})
	if p.persistent > 0 {
		p.setWakeTimer(&p.timers.persistent, now.Add(p.persistent))
	}
}

func (p *Peer) onDataReceived(now time.Time) {
	if p.timers.sendKeepalive.IsZero() {
		p.setWakeTimer(&p.timers.sendKeepalive, now.Add(KeepaliveTimeout))
	} else {
		p.timers.needAnotherKeepalive = true
	}
}

func (p *Peer) onHandshakeComplete(now time.Time) {
	p.setWakeTimer(&p.timers.retransmit, time.Time{})
	p.setWakeTimer(&p.timers.refresh, time.Time{})
	p.timers.attempts = 0
	p.timers.attempted = false
	p.timers.silenceAt = time.Time{}
	p.setWakeTimer(&p.timers.newHandshake, time.Time{})
	p.timers.receiveRefreshSent = false
	p.timers.refreshNeeded = false
	p.lastHandshake = now
}

func (p *Peer) onSessionDerived() { p.setWakeTimer(&p.timers.handshakeExpiry, time.Time{}) }

func (p *Peer) requestRefresh() {
	p.timers.refreshNeeded = true
	if p.policy.Rekey && !p.timers.attempted && p.precomputedValid && p.timers.refresh.IsZero() {
		p.setWakeTimer(&p.timers.refresh, p.initiationAt())
	}
}

func (p *Peer) sentTransport(now time.Time, data bool, k *keypair) {
	p.onAuthSent(now)
	if data && p.timers.silenceAt.IsZero() {
		p.timers.silenceAt = now.Add(KeepaliveTimeout + RekeyTimeout)
		if p.policy.Silence && !p.timers.attempted {
			p.setWakeTimer(&p.timers.newHandshake, p.timers.silenceAt)
		}
	}
	if k == p.keypairs.current && !k.retired.Load() && !k.sendDisabled.Load() && (k.sendNonce.Load() > RekeyAfterMessages || (k.isInitiator && now.Sub(k.created) > RekeyAfterTime)) {
		p.requestRefresh()
	}
}

// HandleWake performs due maintenance and writes control packets into controls.
// Each slot provides writable storage from Offset to len(Buffer). Size is ignored.
// The slots' writable suffixes must not overlap. N counts emitted packets in the
// completed prefix, which must be handled even when an error is returned.
//
// It returns [ErrShortBuffer] if another output slot is needed or a slot is too
// small. Due output remains pending for retry. [ErrInvalidBuffer] rejects an invalid
// offset before emitting packets. [ErrNoSession] means a due keepalive could not
// be sent and policy did not establish a session. Handshake output follows
// [HandshakePolicy] and the shared initiation rate guard.
func (p *Peer) HandleWake(now time.Time, controls []Packet) (result BatchResult, err error) {
	defer func() { result.Update = p.update() }()
	if err := p.advance(now); err != nil {
		return result, err
	}
	// Slots own their full writable suffix because their eventual wire type is
	// not known yet. Do not provide overlapping slots in a shared slab.
	for _, c := range controls {
		if c.Offset < 0 || c.Offset > len(c.Buffer) {
			return result, ErrInvalidBuffer
		}
	}
	n := 0
	for {
		t := &p.timers
		retry := due(t.retransmit, now)
		if retry && t.attempts > MaxTimerHandshakes {
			p.setWakeTimer(&t.retransmit, time.Time{})
			p.setWakeTimer(&t.sendKeepalive, time.Time{})
			p.setWakeTimer(&t.newHandshake, time.Time{})
			p.setWakeTimer(&t.refresh, time.Time{})
			t.needAnotherKeepalive = false
			continue
		}
		handshake := retry || due(t.newHandshake, now) || due(t.refresh, now)
		passive, persistent := due(t.sendKeepalive, now), due(t.persistent, now)
		keep := passive || persistent
		if !handshake && !keep {
			return BatchResult{N: n}, nil
		}
		if keep && !usable(p.keypairs.current, now) && !handshake {
			if p.policy.EstablishForKeepalive && !t.attempted && p.precomputedValid {
				handshake = true
			} else {
				p.setWakeTimer(&t.sendKeepalive, time.Time{})
				t.needAnotherKeepalive = false
				if persistent {
					p.setWakeTimer(&t.persistent, now.Add(p.persistent))
				}
				return BatchResult{N: n}, ErrNoSession
			}
		}
		if handshake && !p.handshake.lastSentHandshake.IsZero() {
			limit := p.handshake.lastSentHandshake.Add(RekeyTimeout)
			if now.Before(limit) {
				if retry {
					p.setWakeTimer(&t.retransmit, limit)
				}
				if due(t.newHandshake, now) {
					p.setWakeTimer(&t.newHandshake, limit)
				}
				if due(t.refresh, now) {
					p.setWakeTimer(&t.refresh, limit)
				}
				if passive {
					p.setWakeTimer(&t.sendKeepalive, limit)
				}
				if persistent {
					p.setWakeTimer(&t.persistent, limit)
				}
				return BatchResult{N: n}, nil
			}
		}
		size := MessageKeepaliveSize
		if handshake {
			size = p.initiationSize()
		}
		if n == len(controls) {
			return BatchResult{N: n}, ErrShortBuffer
		}
		out, err := output(controls[n], size)
		if err != nil {
			return BatchResult{N: n}, err
		}
		if handshake {
			out, err = p.initiate(now, out, retry)
			if err != nil {
				return BatchResult{N: n}, err
			}
			if retry {
				t.attempts++
			}
			p.setWakeTimer(&t.newHandshake, time.Time{})
			p.setWakeTimer(&t.refresh, time.Time{})
		} else {
			another := t.needAnotherKeepalive
			out, err = p.keepalive(now, out)
			if err != nil {
				return BatchResult{N: n}, err
			}
			t.needAnotherKeepalive = false
			if passive && another {
				p.setWakeTimer(&t.sendKeepalive, now.Add(KeepaliveTimeout))
			}
		}
		controls[n] = out
		n++
	}
}
