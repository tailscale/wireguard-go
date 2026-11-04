// SPDX-License-Identifier: MIT

package peer

import (
	"math/rand/v2"
	"testing"
	"time"
)

func checkWakeCache(t testing.TB, p *Peer) {
	t.Helper()
	want := p.computeWake()
	u := p.update()
	got := p.nextWake()
	if u.Wake != want || !p.wakeValid || got != want {
		t.Fatalf("cached/full wake mismatch: got %+v want %+v", got, want)
	}
}

func TestWakeCacheStableTrafficAndDynamicAdvice(t *testing.T) {
	q := newPair(t, Config{})
	establish(t, q, epoch)
	checkWakeCache(t, q.a)
	before := q.a.cachedWake
	tr := q.a.Transport()
	packets := []Packet{plaintext(64, 8)}
	r, err := tr.Send(epoch.Add(time.Second), packets)
	if err != nil {
		t.Fatal(err)
	}
	// Apply the activity without fetching an update to inspect invalidation.
	// disabled silence changes advice, not the core-scheduled window.
	if err := q.a.advance(epoch.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	q.a.applyTransportActivity(q.a.now, r.Activity)
	if !q.a.wakeValid || q.a.cachedWake != before {
		t.Fatal("stable manual TX invalidated schedule")
	}
	checkWakeCache(t, q.a)
	if _, err := q.a.SetPresharedKey(epoch.Add(20*time.Second), PresharedKey{}); err != nil {
		t.Fatal(err)
	}
	u := q.a.update()
	if u.Wake != before || u.Handshake.Reasons&HandshakeSilence == 0 || u.Handshake.InitiateAt != q.a.now {
		t.Fatal("cached window froze time-dependent advice", u)
	}
	// Crossing send rejection changes NoSession advice, not the 540s cleanup.
	if _, err := q.a.SetPresharedKey(epoch.Add(RejectAfterTime), PresharedKey{}); err != nil {
		t.Fatal(err)
	}
	if u := q.a.update(); u.Wake != before || u.Handshake.Reasons&HandshakeNoSession == 0 {
		t.Fatal("age advice/window", u)
	}
}

func TestWakeCacheTimerMutationAndTimeRepresentation(t *testing.T) {
	p := newPair(t, Config{}).a
	checkWakeCache(t, p)
	p.setWakeTimer(&p.timers.persistent, epoch)
	if p.wakeValid {
		t.Fatal("changed timer kept stale cache")
	}
	checkWakeCache(t, p)
	p.setWakeTimer(&p.timers.persistent, epoch)
	if !p.wakeValid {
		t.Fatal("identical timer invalidated cache")
	}
	// Equal instants can have different representations. Preserve exactly the
	// same caller-visible Time that full recomputation would return.
	at := epoch.In(time.FixedZone("other", 3600))
	p.setWakeTimer(&p.timers.persistent, at)
	if p.wakeValid {
		t.Fatal("different Time representation not invalidated")
	}
	checkWakeCache(t, p)
	if p.cachedWake.Earliest != at {
		t.Fatal("lost Time representation")
	}
	p.timers.needAnotherKeepalive = true
	p.timers.attempted = true
	if !p.wakeValid {
		t.Fatal("non-deadline flags changed window")
	}
	checkWakeCache(t, p)
}

func TestWakeCacheHardDeadlineAndBackpressure(t *testing.T) {
	q := newPair(t, Config{})
	establish(t, q, epoch)
	at := epoch.Add(3*RejectAfterTime - time.Second)
	if _, err := q.a.SetPersistentKeepalive(at, time.Second, KeepaliveImmediate); err != nil {
		t.Fatal(err)
	}
	checkWakeCache(t, q.a)
	u := q.a.update()
	if u.Wake.Deadline != epoch.Add(3*RejectAfterTime) {
		t.Fatal("soft intent postponed hard cleanup", u)
	}
	// An expired session consumes the no-session keepalive without storage.
	if r, err := q.a.HandleWake(at, nil); err != ErrNoSession || r.N != 0 {
		t.Fatal(r, err)
	}
	checkWakeCache(t, q.a)
	if _, err := q.a.SetHandshakePolicy(at, automaticPolicy); err != nil {
		t.Fatal(err)
	}
	// Explicit initiation creates retry/handshake-expiry deadlines. A short
	// retry output must leave the cached blocked event due.
	if _, _, err := q.a.Initiate(at, control()); err != nil {
		t.Fatal(err)
	}
	checkWakeCache(t, q.a)
	at = at.Add(RekeyTimeout)
	r, err := q.a.HandleWake(at, nil)
	if err != ErrShortBuffer || r.N != 0 || r.Update.Wake.Earliest.After(at) {
		t.Fatal("retry backpressure lost deadline", r, err)
	}
	checkWakeCache(t, q.a)
	q.a.Close()
	checkWakeCache(t, q.a)
	if q.a.nextWake() != (Wake{}) {
		t.Fatal("closed cache retained schedule")
	}
}

// Random public transitions compare the cache with the unchanged full reduction
// after each entry point, including accepted-clock failures, loss/backpressure,
// rekeys, policy changes, same-key generations and late cleanup. No oracle
// invalidation is performed by the test. All mutations use production methods.
func TestWakeCacheRandomizedPublicTransitions(t *testing.T) {
	for seed := uint64(1); seed <= 6; seed++ {
		rng := rand.New(rand.NewPCG(seed, seed*17))
		q := newPair(t, Config{})
		establish(t, q, epoch)
		now := epoch
		steps := []time.Duration{0, time.Millisecond, 50 * time.Millisecond, time.Second, RekeyTimeout, 20 * time.Second, RejectAfterTime, 3 * RejectAfterTime}
		for range 200 {
			now = now.Add(steps[rng.IntN(len(steps))])
			switch rng.IntN(11) {
			case 0:
				bits := rng.IntN(16)
				policy := HandshakePolicy{Rekey: bits&1 != 0, Retry: bits&2 != 0, Silence: bits&4 != 0, EstablishForKeepalive: bits&8 != 0}
				q.a.SetHandshakePolicy(now, policy)
			case 1:
				interval := []time.Duration{-1, 0, time.Second, 25 * time.Second}[rng.IntN(4)]
				q.a.SetPersistentKeepalive(now, interval, KeepaliveStart(rng.IntN(3)))
			case 2:
				outputs := []Packet{control(), control()}
				q.a.HandleWake(now, outputs[:rng.IntN(3)])
			case 3:
				q.a.Send(now, []Packet{plaintext(rng.IntN(65), 8)})
			case 4:
				q.a.Receive(now, []Packet{{Buffer: make([]byte, 32), Size: 32}}, make([]ReceiveResult, 1))
			case 5:
				q.a.SetPresharedKey(now, PresharedKey{})
			case 6:
				id := localIdentity(t, q.a.identityEpoch+1, q.ia)
				if _, err := q.a.ReplaceIdentity(now, id); err != nil {
					t.Fatal(err)
				}
				q.aa = admission(t, id)
			case 7:
				// Attempt a complete handshake, allowing legitimate timestamp/rate
				// rejection after randomized losses or clock quantization.
				init, _, err := q.a.Initiate(now, control())
				checkWakeCache(t, q.a)
				if err == nil {
					resp, _, e := q.b.HandleInitiation(now, prepare(t, admit(t, q.ab, now, init)), control())
					checkWakeCache(t, q.b)
					if e == nil {
						confirm, _, e := q.a.HandleResponse(now, admit(t, q.aa, now, resp), control())
						checkWakeCache(t, q.a)
						if e == nil {
							q.b.Receive(now, []Packet{confirm}, make([]ReceiveResult, 1))
						}
					}
				}
			case 8:
				if r, _ := q.a.Transport().Send(now, []Packet{plaintext(64, 8)}); r.Activity.Valid() {
					if _, err := q.a.ApplyTransportBatch(now, []TransportActivity{r.Activity}); err != nil {
						t.Fatal(err)
					}
				}
			case 9:
				q.a.ApplyTransportBatch(now, nil)
			case 10:
				// Valid-clock storage failure still has to clean expired keys.
				q.a.Initiate(now, Packet{})
			}
			checkWakeCache(t, q.a)
			checkWakeCache(t, q.b)
		}
	}
}
