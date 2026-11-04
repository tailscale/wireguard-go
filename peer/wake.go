/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import "time"

// Wake is an inclusive window for calling HandleWake. The zero value means
// no work is scheduled. Earliest is the first time an event can run. Deadline
// is the earliest deadline of all scheduled events. Equal bounds leave no slack.
// To coalesce peers, take the minimum of each bound. HandleWake also accepts
// early, repeated, or late calls.
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

// timerState retains attempt history across secret cleanup and policy changes.
// A zero retransmit timer does not permit a fresh automatic attempt.
type timerState struct {
	retransmit, sendKeepalive, newHandshake, persistent, refresh, handshakeExpiry time.Time
	attempts                                                                      int
	needAnotherKeepalive, receiveRefreshSent, refreshNeeded                       bool
	attempted                                                                     bool
	silenceAt, lastAttempt                                                        time.Time
}

// setWakeTimer invalidates the wake cache when a scheduled timer changes.
// Compare complete Time values to preserve monotonic and location components.
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

// computeWake computes the window without reading or updating cached state.
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

// HandleWake processes due events using controls as output slots, starting at
// each Offset. It validates all offsets and cleans expired secrets before
// emitting packets. Writable suffixes must be disjoint. Overlap is not checked.
//
// On storage or crypto failure, it returns the successful prefix and leaves the
// blocked event due. Replenish storage before retrying. Do not busy-poll.
// An empty controls slice can process cleanup and no-output events, but a due
// output returns ErrShortBuffer. A keepalive without a send session or permitted
// initiation is consumed or rearmed and returns ErrNoSession without requiring
// storage. Update carries the handshake advice.
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
			size = MessageInitiationSize
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
