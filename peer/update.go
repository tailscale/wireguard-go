// SPDX-License-Identifier: MIT

package peer

import "time"

// HandshakeReason is a bitmask of initiation reasons, independent of policy.
type HandshakeReason uint8

const (
	// HandshakeNoSession indicates no usable current send session.
	HandshakeNoSession HandshakeReason = 1 << iota
	// HandshakeRekey indicates a pending key refresh.
	HandshakeRekey
	// HandshakeRetry indicates an unresolved local attempt.
	HandshakeRetry
	// HandshakeSilence indicates an expired authenticated-receive deadline.
	HandshakeSilence
)

// HandshakeAdvice describes local intent, not delivery or remote acceptance.
// InitiateAt is the earliest rate-permitted explicit initiation, even without
// Reasons, or zero when closed or without a usable identity. Pending reports
// a live local initiation or a responder key that can still accept confirmation.
// Expired and old-generation receive-only keys do not count. HandshakeRetry
// remains set for an unresolved attempt even after its secrets are cleaned up.
type HandshakeAdvice struct {
	InitiateAt time.Time
	Reasons    HandshakeReason
	Pending    bool
}

// Update reports the schedule and handshake advice after committed work.
// Wake includes only scheduled work. Disabled initiation behaviors produce
// advice, not wakes. Schedulers should compare Wake, not InitiateAt.
// Calls that accept now advance time and clean expired keys even on later error.
// ErrTime returns the prior accepted-clock snapshot, not the rejected time.
// ErrClosed and failed construction return an empty Update.
type Update struct {
	Wake      Wake
	Handshake HandshakeAdvice
}

// BatchResult reports committed work, including on error. N is the output
// prefix for Send and HandleWake, the consumed receipt prefix for
// ApplyTransportBatch, or the examined input prefix for Receive, including drops.
// Apply Update and consume the prefix before handling an error. Generating
// output commits state regardless of subsequent delivery failure.
type BatchResult struct {
	N      int
	Update Update
}

func (p *Peer) initiationAt() time.Time {
	if p.closed || !p.precomputedValid {
		return time.Time{}
	}
	at := p.now
	if limit := p.handshake.lastSentHandshake.Add(RekeyTimeout); !p.handshake.lastSentHandshake.IsZero() && at.Before(limit) {
		at = limit
	}
	return at
}
func (p *Peer) update() Update {
	p.publishTransport()
	if p.closed {
		return Update{}
	}
	h := HandshakeAdvice{InitiateAt: p.initiationAt(), Pending: p.handshake.state == handshakeInitiationCreated || usable(p.keypairs.next, p.now)}
	if !usable(p.keypairs.current, p.now) {
		h.Reasons |= HandshakeNoSession
	}
	if p.timers.refreshNeeded {
		h.Reasons |= HandshakeRekey
	}
	if p.timers.attempted {
		h.Reasons |= HandshakeRetry
	}
	if due(p.timers.silenceAt, p.now) {
		h.Reasons |= HandshakeSilence
	}
	return Update{Wake: p.nextWake(), Handshake: h}
}

// scheduleRecovery changes permissions, never the episode or retry budget.
func (p *Peer) scheduleRecovery() {
	t := &p.timers
	p.setWakeTimer(&t.retransmit, time.Time{})
	p.setWakeTimer(&t.refresh, time.Time{})
	p.setWakeTimer(&t.newHandshake, time.Time{})
	if !p.precomputedValid {
		return
	}
	if p.policy.Retry && t.attempted && t.attempts <= MaxTimerHandshakes {
		p.setWakeTimer(&t.retransmit, t.lastAttempt.Add(RekeyTimeout))
		if t.retransmit.Before(p.initiationAt()) {
			p.setWakeTimer(&t.retransmit, p.initiationAt())
		}
	}
	if t.attempted {
		return
	}
	if p.policy.Rekey && t.refreshNeeded {
		p.setWakeTimer(&t.refresh, p.initiationAt())
	}
	if p.policy.Silence && !t.silenceAt.IsZero() {
		p.setWakeTimer(&t.newHandshake, t.silenceAt)
		if t.newHandshake.Before(p.initiationAt()) {
			p.setWakeTimer(&t.newHandshake, p.initiationAt())
		}
	}
}
