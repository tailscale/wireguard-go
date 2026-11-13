// SPDX-License-Identifier: MIT

package peer

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestHandshakePolicyIndependentMatrix(t *testing.T) {
	for mask := 0; mask < 16; mask++ {
		policy := HandshakePolicy{Rekey: mask&1 != 0, Retry: mask&2 != 0, Silence: mask&4 != 0, EstablishForKeepalive: mask&8 != 0}
		t.Run(fmt.Sprintf("%04b", mask), func(t *testing.T) {
			t.Run("Freshness", func(t *testing.T) {
				q := newPair(t, Config{HandshakePolicy: policy})
				establish(t, q, epoch)
				at := epoch.Add(RekeyAfterTime + time.Second)
				r, e := q.a.Send(at, []Packet{plaintext(0, 0)})
				if e != nil || r.Update.Handshake.Reasons&HandshakeRekey == 0 {
					t.Fatal(r, e)
				}
				out, e := q.a.HandleWake(at, []Packet{control()})
				want := 0
				if policy.Rekey {
					want = 1
				}
				if e != nil || out.N != want {
					t.Fatal(out, e)
				}
			})
			t.Run("Retry", func(t *testing.T) {
				q := newPair(t, Config{HandshakePolicy: policy})
				if _, _, e := q.a.Initiate(epoch, control()); e != nil {
					t.Fatal(e)
				}
				r, e := q.a.HandleWake(epoch.Add(RekeyTimeout), []Packet{control()})
				want := 0
				if policy.Retry {
					want = 1
				}
				if e != nil || r.N != want || r.Update.Handshake.Reasons&HandshakeRetry == 0 {
					t.Fatal(r, e)
				}
			})
			t.Run("Silence", func(t *testing.T) {
				q := newPair(t, Config{HandshakePolicy: policy})
				establish(t, q, epoch)
				if _, e := q.a.Send(epoch, []Packet{plaintext(1, 0)}); e != nil {
					t.Fatal(e)
				}
				r, e := q.a.HandleWake(epoch.Add(KeepaliveTimeout+RekeyTimeout), []Packet{control()})
				want := 0
				if policy.Silence {
					want = 1
				}
				if e != nil || r.N != want || r.Update.Handshake.Reasons&HandshakeSilence == 0 {
					t.Fatal(r, e)
				}
				if !policy.Silence && r.Update.Wake.Earliest != epoch.Add(3*RejectAfterTime) {
					t.Fatal("disabled silence scheduled a wake", r)
				}
			})
			t.Run("KeepaliveEstablishment", func(t *testing.T) {
				q := newPair(t, Config{HandshakePolicy: policy, PersistentKeepalive: time.Second, KeepaliveStart: KeepaliveImmediate})
				var slots []Packet
				if policy.EstablishForKeepalive {
					slots = []Packet{control()}
				}
				r, e := q.a.HandleWake(epoch, slots)
				want := 0
				wantErr := ErrNoSession
				if policy.EstablishForKeepalive {
					want = 1
					wantErr = nil
				}
				if !errors.Is(e, wantErr) || r.N != want || !r.Update.Wake.Earliest.After(epoch) {
					t.Fatal(r, e)
				}
			})
			t.Run("SecurityAndKeepalive", func(t *testing.T) {
				q := newPair(t, Config{HandshakePolicy: policy})
				establish(t, q, epoch)
				wire := seal(t, q.a, epoch, plaintext(4, 0))
				replay := clone(wire)
				if r := receive(t, q.b, epoch, wire); r.Err != nil {
					t.Fatal(r.Err)
				}
				if r := receive(t, q.b, epoch, replay); r.Err != ErrReplay {
					t.Fatal(r.Err)
				}
				slots := []Packet{control()}
				r, e := q.b.HandleWake(epoch.Add(KeepaliveTimeout), slots)
				if e != nil || r.N != 1 || slots[0].Size != MessageKeepaliveSize {
					t.Fatal(r, e)
				}
				r, e = q.a.Send(epoch.Add(RejectAfterTime), []Packet{plaintext(1, 0)})
				if !errors.Is(e, ErrNoSession) || r.Update.Handshake.Reasons&HandshakeNoSession == 0 {
					t.Fatal(r, e)
				}
				if _, e = q.a.Send(epoch.Add(3*RejectAfterTime), nil); e != nil {
					t.Fatal(e)
				}
				if q.a.keypairs.current != nil {
					t.Fatal("cleanup disabled")
				}
			})
		})
	}
}

func TestRekeyOnlyCannotLaunderRetries(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: HandshakePolicy{Rekey: true}})
	establish(t, q, epoch)
	start := epoch.Add(RekeyAfterTime + time.Second)
	if _, e := q.a.SetPersistentKeepalive(start, time.Second, KeepaliveImmediate); e != nil {
		t.Fatal(e)
	}
	if _, e := q.a.Send(start, []Packet{plaintext(1, 0)}); e != nil {
		t.Fatal(e)
	}
	first, e := q.a.HandleWake(start, []Packet{control()})
	if e != nil || first.N != 1 || !first.Update.Handshake.Pending {
		t.Fatal(first, e)
	}
	// Lost rekey. All other triggers, old-key authenticated traffic, policy
	// toggles and persistence must not turn a second attempt into a first attempt.
	for i := 1; i < 50; i++ {
		now := start.Add(time.Duration(i) * time.Second)
		if _, e = q.a.SetHandshakePolicy(now, HandshakePolicy{}); e != nil {
			t.Fatal(e)
		}
		if _, e = q.a.SetHandshakePolicy(now, HandshakePolicy{Rekey: true, Silence: true, EstablishForKeepalive: true}); e != nil {
			t.Fatal(e)
		}
		incoming := seal(t, q.b, now, plaintext(1, 0))
		if r := receive(t, q.a, now, incoming); r.Err != nil {
			t.Fatal(r.Err)
		}
		if _, e = q.a.Send(now, []Packet{plaintext(1, 0)}); e != nil {
			t.Fatal(e)
		}
		slots := []Packet{control(), control()}
		r, e := q.a.HandleWake(now, slots)
		if e != nil || r.Update.Handshake.Reasons&HandshakeRetry == 0 {
			t.Fatal(r, e)
		}
		for _, p := range slots[:r.N] {
			typ, _, _ := ParseHeader(p.Bytes())
			if typ == MessageInitiationType {
				t.Fatal("retry laundered", i)
			}
		}
	}
	now := epoch.Add(1000 * time.Second)
	r, e := q.a.HandleWake(now, []Packet{control()})
	if !errors.Is(e, ErrNoSession) || r.N != 0 || r.Update.Handshake.Pending || r.Update.Handshake.Reasons&HandshakeRetry == 0 {
		t.Fatal(r, e)
	}
	// Toggling all non-retry permissions after cleanup must retain the latch.
	if _, e = q.a.SetHandshakePolicy(now, HandshakePolicy{}); e != nil {
		t.Fatal(e)
	}
	if _, e = q.a.SetHandshakePolicy(now, HandshakePolicy{Rekey: true, Silence: true, EstablishForKeepalive: true}); e != nil {
		t.Fatal(e)
	}
	r, e = q.a.HandleWake(now.Add(time.Second), []Packet{control()})
	if !errors.Is(e, ErrNoSession) || r.N != 0 {
		t.Fatal(r, e)
	}
	_, u, e := q.a.Initiate(r.Update.Handshake.InitiateAt, control())
	if e != nil || !u.Handshake.Pending {
		t.Fatal(u, e)
	}
}

func TestExhaustedRetryBudgetSurvivesPolicyAndSecretCleanup(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy, PersistentKeepalive: time.Second})
	if _, _, e := q.a.Initiate(epoch, control()); e != nil {
		t.Fatal(e)
	}
	now := epoch
	for i := 0; i < MaxTimerHandshakes+1; i++ {
		now = now.Add(RekeyTimeout)
		r, e := q.a.HandleWake(now, []Packet{control()})
		if e != nil || r.N != 1 {
			t.Fatal(i, r, e)
		}
	}
	for _, at := range []time.Time{now.Add(RekeyTimeout), epoch.Add(1000 * time.Second)} {
		if _, e := q.a.SetHandshakePolicy(at, HandshakePolicy{}); e != nil {
			t.Fatal(e)
		}
		if _, e := q.a.SetHandshakePolicy(at, automaticPolicy); e != nil {
			t.Fatal(e)
		}
		r, e := q.a.HandleWake(at, []Packet{control()})
		if !errors.Is(e, ErrNoSession) || r.N != 0 || r.Update.Handshake.Reasons&HandshakeRetry == 0 {
			t.Fatal(r, e)
		}
	}
}

func TestFreshnessDeferredAfterResponseGuard(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: HandshakePolicy{Rekey: true}})
	establish(t, q, epoch)
	at := epoch.Add(RekeyAfterTime + time.Second)
	init, _, e := q.b.Initiate(at, control())
	if e != nil {
		t.Fatal(e)
	}
	_, u, e := q.a.HandleInitiation(at, prepare(t, admit(t, q.aa, at, init)), control())
	if e != nil || u.Handshake.InitiateAt != at.Add(RekeyTimeout) {
		t.Fatal(u, e)
	}
	r, e := q.a.Send(at, []Packet{plaintext(0, 0)})
	if e != nil || r.Update.Wake.Earliest != u.Handshake.InitiateAt || r.Update.Handshake.Reasons&HandshakeRekey == 0 {
		t.Fatal(r, e)
	}
	early, e := q.a.HandleWake(at, nil)
	if e != nil || early.N != 0 || early.Update.Wake != r.Update.Wake {
		t.Fatal(early, e)
	}
	slots := []Packet{control()}
	emitted, e := q.a.HandleWake(r.Update.Wake.Earliest, slots)
	if e != nil || emitted.N != 1 || emitted.Update.Handshake.Reasons&HandshakeRetry == 0 {
		t.Fatal(emitted, e)
	}
}
