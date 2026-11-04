// SPDX-License-Identifier: MIT

package peer

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// All peer entry points must return the unchanged accepted-clock snapshot on
// ErrTime and an empty snapshot on ErrClosed, even with invalid input storage.
func TestOperationUpdatesClockAndClose(t *testing.T) {
	operations := []struct {
		name string
		call func(*Peer, time.Time) (Update, error)
	}{
		{"Send", func(p *Peer, at time.Time) (Update, error) {
			r, e := p.Send(at, []Packet{{Offset: -1}})
			if r.N != 0 {
				t.Fatal(r)
			}
			return r.Update, e
		}},
		{"Receive", func(p *Peer, at time.Time) (Update, error) {
			r, e := p.Receive(at, []Packet{{}}, nil)
			if r.N != 0 {
				t.Fatal(r)
			}
			return r.Update, e
		}},
		{"HandleWake", func(p *Peer, at time.Time) (Update, error) {
			r, e := p.HandleWake(at, []Packet{{Offset: -1}})
			if r.N != 0 {
				t.Fatal(r)
			}
			return r.Update, e
		}},
		{"Initiate", func(p *Peer, at time.Time) (Update, error) {
			o, u, e := p.Initiate(at, Packet{})
			if o.Buffer != nil {
				t.Fatal(o)
			}
			return u, e
		}},
		{"HandleInitiation", func(p *Peer, at time.Time) (Update, error) {
			o, u, e := p.HandleInitiation(at, PreparedInitiation{}, Packet{})
			if o.Buffer != nil {
				t.Fatal(o)
			}
			return u, e
		}},
		{"HandleResponse", func(p *Peer, at time.Time) (Update, error) {
			o, u, e := p.HandleResponse(at, AdmittedHandshake{}, Packet{})
			if o.Buffer != nil {
				t.Fatal(o)
			}
			return u, e
		}},
		{"ConsumeCookie", func(p *Peer, at time.Time) (Update, error) { return p.ConsumeCookie(at, nil) }},
		{"SetHandshakePolicy", func(p *Peer, at time.Time) (Update, error) { return p.SetHandshakePolicy(at, HandshakePolicy{}) }},
		{"SetPersistentKeepalive", func(p *Peer, at time.Time) (Update, error) {
			return p.SetPersistentKeepalive(at, -1, KeepaliveAfterInterval)
		}},
		{"SetPresharedKey", func(p *Peer, at time.Time) (Update, error) { return p.SetPresharedKey(at, PresharedKey{}) }},
		{"ReplaceIdentity", func(p *Peer, at time.Time) (Update, error) { return p.ReplaceIdentity(at, LocalIdentity{}) }},
	}
	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			q := newPair(t, Config{})
			_, initial, e := q.a.Initiate(epoch, control())
			if e != nil {
				t.Fatal(e)
			}
			for _, badTime := range []time.Time{{}, epoch.Add(-time.Nanosecond)} {
				u, e := op.call(q.a, badTime)
				if !errors.Is(e, ErrTime) || u != initial {
					t.Fatalf("rejected clock: %+v %v, want %+v", u, e, initial)
				}
			}
			at := epoch.Add(3 * RejectAfterTime)
			u, _ := op.call(q.a, at)
			if !u.Wake.Earliest.IsZero() || u.Handshake.Pending || u.Handshake.Reasons&HandshakeNoSession == 0 || q.indexes.Len() != 0 || q.a.now != at {
				t.Fatalf("accepted-time cleanup: %+v", u)
			}
			if op.name != "ReplaceIdentity" && u.Handshake.InitiateAt != at {
				t.Fatal("wrong result clock", u)
			}
			if got := q.a.Close(); got != (Update{}) {
				t.Fatal(got)
			}
			if got := q.a.Close(); got != (Update{}) {
				t.Fatal(got)
			}
			u, e = op.call(q.a, at)
			if !errors.Is(e, ErrClosed) || u != (Update{}) {
				t.Fatalf("closed: %+v %v", u, e)
			}
		})
	}
}

func TestOperationUpdatesPartialProgressAndFailures(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: HandshakePolicy{Rekey: true}})
	initial, e := q.a.Send(epoch, []Packet{plaintext(3, 0)})
	if !errors.Is(e, ErrNoSession) || initial.N != 0 || initial.Update.Handshake.Reasons != HandshakeNoSession || initial.Update.Handshake.InitiateAt != epoch {
		t.Fatal(initial, e)
	}
	establish(t, q, epoch)
	q.a.keypairs.current.sendNonce.Store(RejectAfterMessages - 1)
	packets := []Packet{plaintext(3, 0), plaintext(5, 0)}
	untouched := clone(packets[1])
	r, e := q.a.Send(epoch, packets)
	if !errors.Is(e, ErrExhausted) || r.N != 1 || r.Update.Handshake.Reasons&(HandshakeNoSession|HandshakeRekey) != (HandshakeNoSession|HandshakeRekey) || !bytes.Equal(untouched.Buffer, packets[1].Buffer) {
		t.Fatal(r, e)
	}
	// Receive counts examined drops, not just authenticated packets.
	results := make([]ReceiveResult, 2)
	r, e = q.b.Receive(epoch, []Packet{packets[0], {Buffer: []byte{4}, Size: 1}}, results)
	if e != nil || r.N != 2 || results[0].Disposition != Data || results[1].Err != ErrTransport || r.Update.Wake.Earliest != epoch.Add(KeepaliveTimeout) {
		t.Fatal(r, e, results)
	}

	q2 := newPair(t, Config{HandshakePolicy: HandshakePolicy{Rekey: true}})
	establish(t, q2, epoch)
	if _, e = q2.a.SetPersistentKeepalive(epoch, time.Second, KeepaliveImmediate); e != nil {
		t.Fatal(e)
	}
	at := epoch.Add(RekeyAfterTime + time.Second)
	slots := []Packet{control()}
	r, e = q2.a.HandleWake(at, slots)
	typ, _, _ := ParseHeader(slots[0].Bytes())
	if !errors.Is(e, ErrShortBuffer) || r.N != 1 || typ != MessageTransportType || r.Update.Wake.Earliest != at || r.Update.Handshake.Reasons&HandshakeRekey == 0 {
		t.Fatal(r, e)
	}
	slots[0] = control()
	r, e = q2.a.HandleWake(at, slots)
	if e != nil || r.N != 1 || !r.Update.Handshake.Pending || r.Update.Handshake.Reasons&HandshakeRetry == 0 || r.Update.Wake.Earliest == at {
		t.Fatal(r, e)
	}
	// Allocation backpressure must not consume the explicit attempt budget.
	alloc := &failingAllocator{fail: true}
	q3 := newPair(t, Config{})
	q3.a.alloc = alloc
	_, u, e := q3.a.Initiate(epoch, control())
	if e == nil || u.Handshake.Pending || u.Handshake.Reasons != HandshakeNoSession || u.Handshake.InitiateAt != epoch || q3.a.timers.attempted {
		t.Fatal(u, e)
	}
}

func TestManualActionableRetryAndResponseUpdates(t *testing.T) {
	q := newPair(t, Config{})
	init, u, e := q.a.Initiate(epoch, control())
	if e != nil || u.Handshake.InitiateAt != epoch.Add(RekeyTimeout) || !u.Handshake.Pending || u.Handshake.Reasons != (HandshakeNoSession|HandshakeRetry) {
		t.Fatal(u, e)
	}
	_, limited, e := q.a.Initiate(epoch.Add(time.Second), control())
	if !errors.Is(e, ErrRateLimited) || limited.Handshake.InitiateAt != u.Handshake.InitiateAt {
		t.Fatal(limited, e)
	}
	// Cookies don't emit output or advance the guard.
	cookie, e := q.ab.Challenge(epoch, init.Bytes(), nil, control())
	if e != nil {
		t.Fatal(e)
	}
	cu, e := q.a.ConsumeCookie(epoch.Add(time.Second), cookie.Bytes())
	if e != nil || cu != limited {
		t.Fatal(cu, e)
	}
	resp, ru, e := q.b.HandleInitiation(epoch, prepare(t, admit(t, q.ab, epoch, init)), control())
	if e != nil || !ru.Handshake.Pending || ru.Handshake.Reasons != HandshakeNoSession || ru.Handshake.InitiateAt != epoch.Add(RekeyTimeout) {
		t.Fatal(ru, e)
	}
	conf, au, e := q.a.HandleResponse(epoch.Add(time.Second), admit(t, q.aa, epoch.Add(time.Second), resp), control())
	if e != nil || au.Handshake.Pending || au.Handshake.Reasons != 0 {
		t.Fatal(au, e)
	}
	var results [1]ReceiveResult
	br, e := q.b.Receive(epoch.Add(time.Second), []Packet{conf}, results[:])
	if e != nil || br.Update.Handshake.Pending || br.Update.Handshake.Reasons != 0 {
		t.Fatal(br, e)
	}
	_, retry, e := q.a.Initiate(limited.Handshake.InitiateAt, control())
	if e != nil || !retry.Handshake.Pending || retry.Handshake.InitiateAt != epoch.Add(2*RekeyTimeout) {
		t.Fatal(retry, e)
	}
}

func TestConstructionAndPersistentStartUpdates(t *testing.T) {
	q := newPair(t, Config{})
	for _, start := range []KeepaliveStart{KeepaliveAfterInterval, KeepaliveImmediate} {
		p, u, e := New(epoch, q.a.identity, q.indexes, q.ib.Public(), Config{PersistentKeepalive: time.Second, KeepaliveStart: start})
		if e != nil {
			t.Fatal(e)
		}
		at := epoch.Add(time.Second)
		if start == KeepaliveImmediate {
			at = epoch
		}
		if u.Wake.Earliest != at || u.Handshake.InitiateAt != epoch || u.Handshake.Reasons != HandshakeNoSession {
			t.Fatal(u)
		}
		for _, mode := range []KeepaliveStart{KeepaliveImmediate, KeepaliveAfterInterval} {
			u, e = p.SetPersistentKeepalive(epoch, 2*time.Second, mode)
			want := epoch.Add(2 * time.Second)
			if mode == KeepaliveImmediate {
				want = epoch
			}
			if e != nil || u.Wake.Earliest != want {
				t.Fatal(u, e)
			}
		}
		u, e = p.SetPersistentKeepalive(epoch, 0, KeepaliveAfterInterval)
		if e != nil || !u.Wake.Earliest.IsZero() {
			t.Fatal(u, e)
		}
		p.Close()
	}
	for _, cfg := range []Config{{PersistentKeepalive: -1}, {KeepaliveStart: 99}, {PaddingMTU: -1}} {
		p, u, e := New(epoch, q.a.identity, q.indexes, q.ib.Public(), cfg)
		if !errors.Is(e, ErrConfig) || p != nil || u != (Update{}) {
			t.Fatal(p, u, e)
		}
	}
	p, u, e := New(time.Time{}, q.a.identity, q.indexes, q.ib.Public(), Config{})
	if !errors.Is(e, ErrTime) || p != nil || u != (Update{}) {
		t.Fatal(p, u, e)
	}
}

func TestIdentityConstructionFailuresReturnEmptyUpdate(t *testing.T) {
	q := newPair(t, Config{})
	for _, id := range []LocalIdentity{{}, localIdentity(t, 2, errorIdentity{q.ia.Public()}), localIdentity(t, 2, zeroIdentity{q.ia.Public()})} {
		p, u, e := New(epoch, id, q.indexes, q.ib.Public(), Config{})
		if e == nil || p != nil || u != (Update{}) {
			t.Fatal(p, u, e)
		}
	}
	if _, e := NewLocalIdentity(0, q.ia); !errors.Is(e, ErrConfig) {
		t.Fatal(e)
	}
	if _, e := NewLocalIdentity(1, nil); !errors.Is(e, ErrConfig) {
		t.Fatal(e)
	}
	if _, e := NewAdmission(LocalIdentity{}); !errors.Is(e, ErrConfig) {
		t.Fatal(e)
	}
}

func TestBatchUpdatesZeroAllocations(t *testing.T) {
	for _, batch := range []int{1, 16, 64} {
		q := newPair(t, Config{})
		establish(t, q, epoch)
		packets := benchPackets(batch, 1280)
		results := make([]ReceiveResult, batch)
		allocs := testing.AllocsPerRun(100, func() {
			resetPackets(packets, 1280)
			sent, e := q.a.Send(epoch, packets)
			if e != nil || sent.N != batch || sent.Update.Wake.Earliest.IsZero() {
				t.Fatal(sent, e)
			}
			received, e := q.b.Receive(epoch, packets, results)
			if e != nil || received.N != batch || received.Update.Wake.Earliest != epoch.Add(KeepaliveTimeout) {
				t.Fatal(received, e)
			}
		})
		if allocs != 0 {
			t.Fatalf("batch %d: %v allocations", batch, allocs)
		}
	}
}

func TestWakeRetryBackpressureDoesNotConsumeAttempt(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: HandshakePolicy{Retry: true}})
	alloc := new(failingAllocator)
	q.a.alloc = alloc
	_, u, e := q.a.Initiate(epoch, control())
	if e != nil {
		t.Fatal(e)
	}
	at := u.Wake.Earliest
	before := q.a.handshake
	r, e := q.a.HandleWake(at, nil)
	if !errors.Is(e, ErrShortBuffer) || r.N != 0 || r.Update.Wake.Earliest != at || q.a.timers.attempts != 0 || q.a.handshake != before {
		t.Fatal(r, e)
	}
	alloc.fail = true
	r, e = q.a.HandleWake(at, []Packet{control()})
	if e == nil || r.N != 0 || r.Update.Wake.Earliest != at || q.a.timers.attempts != 0 || q.a.handshake != before || len(alloc.live) != 1 {
		t.Fatal(r, e)
	}
	alloc.fail = false
	r, e = q.a.HandleWake(at, []Packet{control()})
	if e != nil || r.N != 1 || q.a.timers.attempts != 1 || !r.Update.Wake.Earliest.After(at) {
		t.Fatal(r, e)
	}
	q.a.Close()
	if len(alloc.live) != 0 {
		t.Fatal("index leak")
	}
}
