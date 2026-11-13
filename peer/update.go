// SPDX-License-Identifier: MIT

package peer

import "time"

// HandshakeReason is a bit mask of reasons to initiate a handshake.
type HandshakeReason uint8

const (
	// HandshakeNoSession means no send session is usable.
	HandshakeNoSession HandshakeReason = 1 << iota

	// HandshakeRekey means key freshness requires renewal.
	HandshakeRekey

	// HandshakeRetry means an initiation attempt has not completed.
	HandshakeRetry

	// HandshakeSilence means sent data has remained unanswered until its timeout.
	HandshakeSilence
)

// HandshakeAdvice describes the current opportunity and reasons to initiate.
// It is returned even for triggers disabled by [HandshakePolicy], so callers
// using manual initiation can act on it.
type HandshakeAdvice struct {
	// InitiateAt is the earliest time allowed by the handshake send guard.
	// Zero means the local identity cannot initiate.
	InitiateAt time.Time
	// Reasons is the set of current initiation reasons.
	Reasons HandshakeReason
	// Pending reports an outstanding local initiation or a responder session
	// that can still be confirmed by authenticated transport.
	Pending bool
}

// Update is the scheduling state after a [Peer] operation.
// Replace the previously saved Update even when the operation returns an error.
// The caller schedules [Peer.HandleWake] using Wake and chooses whether to act on
// Handshake advice.
type Update struct {
	// Wake is the next maintenance window. A zero value needs no scheduled call.
	Wake Wake
	// Handshake is the current initiation advice, independent of automatic policy.
	Handshake HandshakeAdvice
}

// BatchResult reports a completed prefix and the resulting [Peer] scheduling state.
type BatchResult struct {
	// N counts encrypted packets for [Peer.Send], examined packets for [Peer.Receive],
	// emitted packets for [Peer.HandleWake], or consumed activities for
	// [Peer.ApplyTransportBatch].
	// It remains meaningful when an error is returned.
	N int
	// Update describes the [Peer] after the completed work and any cleanup.
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
