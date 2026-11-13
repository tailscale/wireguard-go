// SPDX-License-Identifier: MIT

package peer

import (
	"errors"
	"testing"
	"time"
)

func TestHybridModeChangePendingRecovery(t *testing.T) {
	q := newPair(t, Config{Hybrid: true, HandshakePolicy: automaticPolicy})
	init, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := q.b.HandleInitiation(epoch, prepare(t, admit(t, q.ab, epoch, init)), control())
	if err != nil {
		t.Fatal(err)
	}
	token := admit(t, q.aa, epoch, response)
	before := q.a.handshake
	if _, err := q.a.SetHybridHandshake(time.Time{}, false); !errors.Is(err, ErrTime) || q.a.handshake != before || !q.a.hybrid {
		t.Fatal("invalid clock changed mode or pending work", err)
	}
	now := epoch.Add(time.Second)
	u, err := q.a.SetHybridHandshake(now, false)
	if err != nil || q.a.hybrid || q.a.handshake.localKEM != nil || q.a.handshake.localIndex != 0 {
		t.Fatal("mode change retained pending handshake", err)
	}
	if _, ok := q.indexes.Lookup(before.localIndex); ok {
		t.Fatal("mode change retained pending index")
	}
	at := epoch.Add(RekeyTimeout)
	if u.Wake.Earliest != at || u.Handshake.InitiateAt != at || u.Handshake.Reasons&HandshakeRekey == 0 {
		t.Fatal("mode change did not schedule rate-limited recovery", u)
	}
	if _, _, err := q.a.HandleResponse(now, token, control()); !errors.Is(err, ErrHandshake) {
		t.Fatal("old-mode response accepted after mode change", err)
	}
	if _, _, err := q.a.Initiate(now, control()); !errors.Is(err, ErrRateLimited) {
		t.Fatal("mode change bypassed send guard", err)
	}
	slots := []Packet{control()}
	if r, err := q.a.HandleWake(at, slots); err != nil || r.N != 1 || slots[0].Size != MessageInitiationSize || PacketIsRetry(slots[0].Bytes()) {
		t.Fatal("new-mode recovery", r, err)
	}
	q.a.Close()
	if _, err := q.a.SetHybridHandshake(at, true); !errors.Is(err, ErrClosed) {
		t.Fatal("closed mode change", err)
	}
	if _, _, err := q.a.RetryInitiation(at, control()); !errors.Is(err, ErrClosed) {
		t.Fatal("closed manual retry", err)
	}
}

func TestHybridManualRetryBudget(t *testing.T) {
	q := newPair(t, Config{Hybrid: true, HandshakePolicy: HandshakePolicy{Retry: true}})
	if _, _, err := q.a.Initiate(epoch, control()); err != nil {
		t.Fatal(err)
	}
	before := q.a.handshake
	if _, _, err := q.a.RetryInitiation(epoch, control()); !errors.Is(err, ErrRateLimited) || q.a.handshake != before || q.a.timers.attempts != 0 {
		t.Fatal("rate-limited retry consumed state", err)
	}
	now := epoch
	for i := 0; i < MaxTimerHandshakes+3; i++ {
		now = now.Add(RekeyTimeout)
		packet, _, err := q.a.RetryInitiation(now, control())
		if err != nil || !PacketIsRetry(packet.Bytes()) {
			t.Fatal("manual retry", err)
		}
	}
	if q.a.timers.attempts != MaxTimerHandshakes+1 {
		t.Fatal("manual retry reset or overflowed automatic budget")
	}
	if r, err := q.a.HandleWake(now.Add(RekeyTimeout), []Packet{control()}); err != nil || r.N != 0 {
		t.Fatal("exhausted budget allowed automatic retry", r, err)
	}
}
