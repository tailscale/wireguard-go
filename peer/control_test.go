// SPDX-License-Identifier: MIT

package peer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

type failingAllocator struct {
	next     uint32
	live     map[uint32]*Peer
	releases map[uint32]int
	fail     bool
}

func (a *failingAllocator) Allocate(p *Peer) (uint32, error) {
	if a.fail {
		return 0, errors.New("allocator failure")
	}
	if a.live == nil {
		a.live = make(map[uint32]*Peer)
		a.releases = make(map[uint32]int)
	}
	a.next++
	a.live[a.next] = p
	return a.next, nil
}
func (a *failingAllocator) Release(index uint32, p *Peer) {
	if index == 0 {
		panic("zero release")
	}
	if a.live[index] != p {
		panic("wrong/double index release")
	}
	delete(a.live, index)
	a.releases[index]++
}

func TestIndexFailureTransactionalRollback(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	alloc := new(failingAllocator)
	q.a.alloc = alloc
	first, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	old := q.a.handshake
	alloc.fail = true
	if _, _, err = q.a.Initiate(epoch.Add(6*time.Second), control()); err == nil {
		t.Fatal("allocation succeeded")
	}
	if q.a.handshake != old || len(alloc.live) != 1 || len(alloc.releases) != 0 {
		t.Fatal("allocation failure relinquished old index")
	}
	// The still-valid original response must succeed despite failed replacement.
	response, _, err := q.b.HandleInitiation(epoch.Add(6*time.Second), prepare(t, admit(t, q.ab, epoch.Add(6*time.Second), first)), control())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = q.a.HandleResponse(epoch.Add(6*time.Second), admit(t, q.aa, epoch.Add(6*time.Second), response), control()); err != nil {
		t.Fatal(err)
	}
	alloc.fail = false
	// Fresh pending initiation then replacement frees exactly once.
	if _, _, err = q.a.Initiate(epoch.Add(12*time.Second), control()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = q.a.Initiate(epoch.Add(18*time.Second), control()); err != nil {
		t.Fatal(err)
	}
	q.a.Close()
	q.a.Close()
	if len(alloc.live) != 0 {
		t.Fatal("leak")
	}
	for _, n := range alloc.releases {
		if n != 1 {
			t.Fatal("double release")
		}
	}
}

func TestHandshakeShortOutputAndResponseFailureRollback(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	short := Packet{Buffer: make([]byte, 147)}
	if _, _, err := q.a.Initiate(epoch, short); !errors.Is(err, ErrShortBuffer) || q.indexes.Len() != 0 {
		t.Fatal("initiation short buffer changed state")
	}
	init, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	token := prepare(t, admit(t, q.ab, epoch, init))
	old := q.b.handshake
	if _, _, err = q.b.HandleInitiation(epoch, token, Packet{Buffer: make([]byte, 91)}); !errors.Is(err, ErrShortBuffer) || q.b.handshake != old {
		t.Fatal("short response consumed initiation")
	}
	alloc := &failingAllocator{fail: true}
	q.b.alloc = alloc
	if _, _, err = q.b.HandleInitiation(epoch, token, control()); err == nil || q.b.handshake != old {
		t.Fatal("response allocation failure committed timestamp")
	}
	alloc.fail = false
	resp, _, err := q.b.HandleInitiation(epoch, token, Packet{Buffer: init.Buffer, Offset: init.Offset})
	if err != nil {
		t.Fatal(err)
	}
	old = q.a.handshake
	if _, _, err = q.a.HandleResponse(epoch, admit(t, q.aa, epoch, resp), Packet{Buffer: make([]byte, 31)}); !errors.Is(err, ErrShortBuffer) || q.a.handshake != old {
		t.Fatal("short confirmation consumed response")
	}
	if _, _, err = q.a.HandleResponse(epoch, admit(t, q.aa, epoch, resp), control()); err != nil {
		t.Fatal(err)
	}
	q.b.Close()
	if len(alloc.live) != 0 {
		t.Fatal("response index leak")
	}
}

func TestHandshakeReplayFloodAndMismatchedPSK(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	init, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	token := prepare(t, admit(t, q.ab, epoch, init))
	if _, _, err = q.b.HandleInitiation(epoch, token, control()); err != nil {
		t.Fatal(err)
	}
	before := q.b.handshake
	count := q.indexes.Len()
	for _, now := range []time.Time{epoch, epoch.Add(time.Second)} {
		if _, _, err = q.b.HandleInitiation(now, token, control()); !errors.Is(err, ErrHandshake) {
			t.Fatal("timestamp replay accepted")
		}
		if q.b.handshake != before || q.indexes.Len() != count {
			t.Fatal("replay changed state")
		}
	}
	// A fresh, correctly authenticated timestamp still observes the 20ms gate.
	q.a.handshake.lastSentHandshake = time.Time{}
	fresh, _, err := q.a.Initiate(epoch.Add(2*time.Second), control())
	if err != nil {
		t.Fatal(err)
	}
	q.b.handshake.lastInitiationConsumption = epoch.Add(2*time.Second - 10*time.Millisecond)
	if _, _, err = q.b.HandleInitiation(epoch.Add(2*time.Second), prepare(t, admit(t, q.ab, epoch.Add(2*time.Second), fresh)), control()); !errors.Is(err, ErrHandshake) {
		t.Fatal("flood accepted")
	}
	q2 := newPair(t, Config{HandshakePolicy: automaticPolicy})
	if _, err = q2.b.SetPresharedKey(epoch, PresharedKey{1}); err != nil {
		t.Fatal(err)
	}
	init, _, err = q2.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	resp, _, err := q2.b.HandleInitiation(epoch, prepare(t, admit(t, q2.ab, epoch, init)), control())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = q2.a.HandleResponse(epoch, admit(t, q2.aa, epoch, resp), control()); !errors.Is(err, ErrHandshake) {
		t.Fatal("wrong PSK accepted")
	}
	if !q2.b.LastHandshake().IsZero() || q2.b.HasSession(epoch) {
		t.Fatal("unconfirmed response completed handshake")
	}
}

type errorIdentity struct{ public PublicKey }

func (s errorIdentity) Public() PublicKey { return s.public }
func (s errorIdentity) SharedSecret(PublicKey) ([32]byte, error) {
	return [32]byte{}, errors.New("identity unavailable")
}

type zeroIdentity struct{ public PublicKey }

func (s zeroIdentity) Public() PublicKey                        { return s.public }
func (s zeroIdentity) SharedSecret(PublicKey) ([32]byte, error) { return [32]byte{}, nil }

func TestIdentityRotationExpiresSendingButPreservesReceiving(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	establish(t, q, epoch)
	delayed := seal(t, q.b, epoch, plaintext(12, 0))
	oldInit, _, err := q.a.Initiate(epoch.Add(6*time.Second), control())
	if err != nil {
		t.Fatal(err)
	}
	oldResp, _, err := q.b.HandleInitiation(epoch.Add(6*time.Second), prepare(t, admit(t, q.ab, epoch.Add(6*time.Second), oldInit)), control())
	if err != nil {
		t.Fatal(err)
	}
	private, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	replacement := NewIdentity(private)
	if _, err = q.a.ReplaceIdentity(epoch.Add(6*time.Second), localIdentity(t, 2, errorIdentity{replacement.Public()})); err == nil {
		t.Fatal("failing identity accepted")
	}
	if q.a.HasSession(epoch.Add(6*time.Second)) || q.a.handshake.localIndex != 0 {
		t.Fatal("failed replacement still sends")
	}
	if r := receive(t, q.a, epoch.Add(6*time.Second), delayed); r.Err != nil {
		t.Fatal("receive grace lost", r.Err)
	}
	if _, err = q.a.ReplaceIdentity(epoch.Add(6*time.Second), localIdentity(t, 3, replacement)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = q.a.HandleResponse(epoch.Add(6*time.Second), admit(t, q.aa, epoch.Add(6*time.Second), oldResp), control()); !errors.Is(err, ErrHandshake) {
		t.Fatal("old response accepted")
	}
	// Replace the remote-side registry entry (remote keys themselves are immutable).
	b, _, err := New(epoch, localIdentity(t, 1, q.ib), q.indexes, replacement.Public(), Config{HandshakePolicy: automaticPolicy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	rotated := pair{q.a, b, replacement, q.ib, admission(t, q.a.identity), admission(t, b.identity), q.indexes}
	establish(t, rotated, epoch.Add(6*time.Second))
	if _, _, err = New(epoch, localIdentity(t, 1, zeroIdentity{replacement.Public()}), q.indexes, q.ib.Public(), Config{HandshakePolicy: automaticPolicy}); err == nil {
		t.Fatal("provider's all-zero DH accepted")
	}
}

func TestPSKChangeKeepsEstablishedSession(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	establish(t, q, epoch)
	if _, err := q.a.SetPresharedKey(epoch, PresharedKey{9}); err != nil {
		t.Fatal(err)
	}
	wire := seal(t, q.a, epoch, plaintext(15, 0))
	if r := receive(t, q.b, epoch, wire); r.Err != nil {
		t.Fatal("PSK update revoked session")
	}
}

type allowSource struct {
	calls   int
	allowed bool
}

func (l *allowSource) Allow(time.Time, []byte) bool { l.calls++; return l.allowed }

func TestCookieAdmissionAndReplies(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	source := []byte("source-ip:1234")
	init, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	limiter := &allowSource{allowed: true}
	if _, err = q.ab.Admit(epoch, init.Bytes(), source, true, limiter); !errors.Is(err, ErrCookieRequired) || limiter.calls != 0 {
		t.Fatal("missing cookie not challenged before rate policy")
	}
	challenge, err := q.ab.Challenge(epoch, init.Bytes(), source, control())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){func(b []byte) { b[8] ^= 1 }, func(b []byte) { b[63] ^= 1 }, func(b []byte) { binary.LittleEndian.PutUint32(b[4:8], 0) }} {
		bad := clone(challenge)
		mutate(bad.Bytes())
		if _, err = q.a.ConsumeCookie(epoch, bad.Bytes()); !errors.Is(err, ErrCookie) {
			t.Fatal("bad cookie accepted")
		}
	}
	if _, err = q.a.ConsumeCookie(epoch, challenge.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = q.a.Initiate(epoch, control()); !errors.Is(err, ErrRateLimited) {
		t.Fatal("cookie bypassed rate guard")
	}
	init, _, err = q.a.Initiate(epoch.Add(5*time.Second), control())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.ab.Admit(epoch.Add(5*time.Second), init.Bytes(), []byte("other-ip:1234"), true, limiter); !errors.Is(err, ErrCookieRequired) {
		t.Fatal("cookie not source-bound")
	}
	token, err := q.ab.Admit(epoch.Add(5*time.Second), init.Bytes(), source, true, limiter)
	if err != nil || limiter.calls != 1 {
		t.Fatal("MAC2 not accepted", err)
	}
	resp, _, err := q.b.HandleInitiation(epoch.Add(5*time.Second), prepare(t, token), control())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.a.ConsumeCookie(epoch.Add(5*time.Second), challenge.Bytes()); !errors.Is(err, ErrCookie) {
		t.Fatal("obsolete MAC1/index cookie accepted")
	}
	// Response-cookie path uses response SENDER at offset 4, not its receiver.
	c2, err := q.aa.Challenge(epoch.Add(5*time.Second), resp.Bytes(), source, control())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.b.ConsumeCookie(epoch.Add(5*time.Second), c2.Bytes()); err != nil {
		t.Fatal("response challenge", err)
	}
	if _, err = q.ab.Admit(epoch.Add(CookieRefreshTime), init.Bytes(), source, true, limiter); !errors.Is(err, ErrCookieRequired) {
		t.Fatal("expired secret accepted")
	}
	if !bytes.Equal(challenge.Buffer[:11], bytes.Repeat([]byte{0xcc}, 11)) {
		t.Fatal("cookie prefix")
	}
}

type countingIdentity struct {
	Static
	calls       int
	rejectAfter int
}

func (s *countingIdentity) SharedSecret(key PublicKey) ([32]byte, error) {
	s.calls++
	if s.rejectAfter > 0 && s.calls > s.rejectAfter {
		return [32]byte{}, errors.New("unexpected repeated provider DH")
	}
	return s.Static.SharedSecret(key)
}
func TestAdmissionRejectsBeforeDH(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	counted := &countingIdentity{Static: q.ib}
	q.ab = admission(t, localIdentity(t, 1, counted))
	init, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		bad := clone(init)
		bad.Bytes()[len(bad.Bytes())-32] ^= 1
		token, err := q.ab.Admit(epoch, bad.Bytes(), nil, false, nil)
		if err == nil {
			_, _ = PrepareInitiation(token)
		}
		if !errors.Is(err, ErrMAC1) {
			t.Fatal(err)
		}
		if _, err = q.ab.Admit(epoch, init.Bytes(), []byte{byte(i)}, true, nil); !errors.Is(err, ErrCookieRequired) {
			t.Fatal(err)
		}
	}
	if counted.calls != 0 {
		t.Fatal("DH before admission")
	}
}

func TestParseHeaderAllLengthsAndReservedBytes(t *testing.T) {
	for typ, size := range map[uint32]int{1: 148, 2: 92, 3: 64, 4: 32} {
		for n := 0; n < size; n++ {
			b := make([]byte, n)
			if n >= 4 {
				binary.LittleEndian.PutUint32(b, typ)
			}
			if _, _, err := ParseHeader(b); err == nil {
				t.Fatalf("type %d accepted length %d", typ, n)
			}
		}
		b := make([]byte, size)
		binary.LittleEndian.PutUint32(b, typ)
		if _, _, err := ParseHeader(b); err != nil {
			t.Fatal(err)
		}
		for i := 1; i < 4; i++ {
			b[i] = 1
			if _, _, err := ParseHeader(b); err == nil {
				t.Fatal("reserved accepted")
			}
			b[i] = 0
		}
	}
	response := make([]byte, 92)
	binary.LittleEndian.PutUint32(response, 2)
	binary.LittleEndian.PutUint32(response[4:], 42)
	binary.LittleEndian.PutUint32(response[8:], 99)
	if _, index, err := ParseHeader(response); err != nil || index != 99 {
		t.Fatal("response demux read sender")
	}
}

func TestUnconfirmedIdentityRotationAndDelayedConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name           string
		retry, cleanup bool
	}{
		{"NoRetry/Close", false, false},
		{"NoRetry/Cleanup", false, true},
		{"Retry/Close", true, false},
		{"Retry/Cleanup", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := newPair(t, Config{HandshakePolicy: HandshakePolicy{Retry: tc.retry, EstablishForKeepalive: true}, PersistentKeepalive: time.Second})
			alloc := new(failingAllocator)
			q.a.alloc, q.b.alloc = alloc, alloc
			init, _, err := q.a.Initiate(epoch, control())
			if err != nil {
				t.Fatal(err)
			}
			resp, _, err := q.b.HandleInitiation(epoch, prepare(t, admit(t, q.ab, epoch, init)), control())
			if err != nil {
				t.Fatal(err)
			}
			confirm, _, err := q.a.HandleResponse(epoch, admit(t, q.aa, epoch, resp), control())
			if err != nil {
				t.Fatal(err)
			}
			old := q.b.keypairs.next
			oldIndex := old.localIndex
			sk, err := NewPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			at := epoch.Add(time.Second)
			if _, err = q.b.ReplaceIdentity(at, localIdentity(t, 2, NewIdentity(sk))); err != nil {
				t.Fatal(err)
			}
			if old.sendNonce.Load() != RejectAfterMessages {
				t.Fatal("next still send-capable")
			}
			// Drop the new-generation initiation. With retries enabled, also
			// drop one retry so confirmation must preserve a nonzero budget.
			if _, _, err = q.b.Initiate(at, control()); err != nil {
				t.Fatal(err)
			}
			if tc.retry {
				at = at.Add(RekeyTimeout)
				if r, err := q.b.HandleWake(at, []Packet{control()}); err != nil || r.N != 1 || q.b.timers.attempts != 1 {
					t.Fatal("first retry", r, err, q.b.timers.attempts)
				}
			}
			pending, timers := q.b.handshake, q.b.timers
			lastHandshake := q.b.LastHandshake()
			if !timers.attempted || !timers.refreshNeeded || pending.localIndex == 0 {
				t.Fatal("missing current-generation recovery episode")
			}
			// Both confirmation and later data remain receivable with the old
			// key, but neither may complete the new-generation recovery episode.
			data := seal(t, q.a, at, plaintext(12, 0))
			var results [2]ReceiveResult
			r, err := q.b.Receive(at.Add(time.Second), []Packet{confirm, data}, results[:])
			if err != nil || r.N != 2 || results[0].Err != nil || results[0].Disposition != Keepalive || results[1].Err != nil || results[1].Disposition != Data {
				t.Fatal("receive grace", r, results, err)
			}
			if q.b.keypairs.next != old || q.b.keypairs.current != nil || q.b.HasSession(at.Add(time.Second)) || q.b.LastHandshake() != lastHandshake {
				t.Fatal("old confirmation promoted or completed a send-invalidated key")
			}
			if q.b.handshake != pending || alloc.live[pending.localIndex] != q.b || alloc.live[oldIndex] != q.b {
				t.Fatal("old confirmation replaced the pending handshake or released a live index")
			}
			after := q.b.timers
			if after.attempted != timers.attempted || after.attempts != timers.attempts || after.lastAttempt != timers.lastAttempt || after.retransmit != timers.retransmit || after.refresh != timers.refresh || after.refreshNeeded != timers.refreshNeeded || after.handshakeExpiry != timers.handshakeExpiry {
				t.Fatal("old confirmation changed recovery history or scheduling", timers, after)
			}
			wantReasons := HandshakeNoSession | HandshakeRekey | HandshakeRetry
			if !r.Update.Handshake.Pending || r.Update.Handshake.Reasons != wantReasons {
				t.Fatal("old confirmation cleared recovery advice", r.Update)
			}
			r, err = q.b.HandleWake(at.Add(RekeyTimeout), []Packet{control()})
			if tc.retry {
				if err != nil || r.N != 1 || q.b.timers.attempts != timers.attempts+1 {
					t.Fatal("old confirmation canceled or restarted retries", r, err)
				}
			} else if !errors.Is(err, ErrNoSession) || r.N != 0 || q.b.handshake != pending || q.b.timers.attempts != timers.attempts || !q.b.timers.attempted {
				t.Fatal("old confirmation enabled an unpermitted retry", r, err)
			}
			pendingIndex := q.b.handshake.localIndex
			if tc.cleanup {
				// The old next key and new handshake retain independent hard
				// cleanup deadlines, even though the old key cannot be promoted.
				if _, err = q.b.Send(epoch.Add(3*RejectAfterTime), nil); err != nil {
					t.Fatal(err)
				}
				if q.b.keypairs.next != nil || alloc.releases[oldIndex] != 1 || alloc.live[pendingIndex] != q.b {
					t.Fatal("receive-grace cleanup released the wrong indices")
				}
				if _, err = q.b.Send(q.b.timers.handshakeExpiry, nil); err != nil {
					t.Fatal(err)
				}
				if q.b.handshake.localIndex != 0 || alloc.releases[pendingIndex] != 1 || !q.b.timers.attempted {
					t.Fatal("pending cleanup lost recovery history or leaked its index")
				}
			}
			q.a.Close()
			q.b.Close()
			q.a.Close()
			q.b.Close()
			if len(alloc.live) != 0 || len(alloc.releases) != int(alloc.next) {
				t.Fatal("index leak", alloc.live, alloc.releases)
			}
			for index, count := range alloc.releases {
				if count != 1 {
					t.Fatal("index not released exactly once", index, count)
				}
			}
		})
	}
}

func TestCrossedInitiationsRecoverWithoutLeakingIndexes(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	ai, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	bi, _, err := q.b.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	ar, _, err := q.a.HandleInitiation(epoch, prepare(t, admit(t, q.aa, epoch, bi)), control())
	if err != nil {
		t.Fatal(err)
	}
	br, _, err := q.b.HandleInitiation(epoch, prepare(t, admit(t, q.ab, epoch, ai)), control())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = q.a.HandleResponse(epoch, admit(t, q.aa, epoch, br), control()); !errors.Is(err, ErrHandshake) {
		t.Fatal("stale crossed response accepted")
	}
	if _, _, err = q.b.HandleResponse(epoch, admit(t, q.ab, epoch, ar), control()); !errors.Is(err, ErrHandshake) {
		t.Fatal("stale crossed response accepted")
	}
	establish(t, q, epoch.Add(5*time.Second))
	q.a.Close()
	q.b.Close()
	if q.indexes.Len() != 0 {
		t.Fatal("crossed index leak")
	}
}

func TestCookieFreshnessAndRatePolicy(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: manualPolicy})
	source := []byte("ip:port")
	init, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := q.ab.Challenge(epoch, init.Bytes(), source, control())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.b.ConsumeCookie(epoch, challenge.Bytes()); !errors.Is(err, ErrCookie) {
		t.Fatal("unsolicited cookie accepted")
	}
	if _, err = q.a.ConsumeCookie(epoch, challenge.Bytes()); err != nil {
		t.Fatal(err)
	}
	fresh, _, err := q.a.Initiate(epoch.Add(5*time.Second), control())
	if err != nil {
		t.Fatal(err)
	}
	limiter := &allowSource{}
	if _, err = q.ab.Admit(epoch.Add(5*time.Second), fresh.Bytes(), source, true, limiter); !errors.Is(err, ErrAdmission) || limiter.calls != 1 {
		t.Fatal("missing source admission enforcement")
	}
	if _, err = q.ab.Admit(epoch.Add(5*time.Second), fresh.Bytes(), source, true, nil); !errors.Is(err, ErrAdmission) {
		t.Fatal("nil underload limiter accepted")
	}
	// This latest MAC1 challenge is authentic, but must not refresh stale state.
	latest, err := q.ab.Challenge(epoch.Add(5*time.Second), fresh.Bytes(), source, control())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.a.ConsumeCookie(epoch.Add(5*time.Second+CookieRefreshTime), latest.Bytes()); !errors.Is(err, ErrCookie) {
		t.Fatal("stale challenge accepted")
	}
	expired, _, err := q.a.Initiate(epoch.Add(6*time.Second+CookieRefreshTime), control())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expired.Bytes()[len(expired.Bytes())-16:], make([]byte, 16)) {
		t.Fatal("expired generator cookie emitted MAC2")
	}
}

func TestMalformedNoiseAndWrongRemoteRollback(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	init, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	original := q.b.handshake
	for _, mutate := range []func([]byte){
		func(b []byte) { clear(b[8:40]) },
		func(b []byte) { b[40] ^= 1 },
		func(b []byte) { b[88] ^= 1 },
	} {
		bad := clone(init)
		mutate(bad.Bytes())
		q.a.cookieGen.addMACs(epoch, bad.Bytes())
		v, prepErr := PrepareInitiation(admit(t, q.ab, epoch, bad))
		if prepErr == nil {
			if _, _, err = q.b.HandleInitiation(epoch, v, control()); !errors.Is(err, ErrHandshake) {
				t.Fatal("bad Noise accepted", err)
			}
		}
		if q.b.handshake != original || q.indexes.Len() != 1 {
			t.Fatal("malformed Noise committed state")
		}
	}
	resp, _, err := q.b.HandleInitiation(epoch, prepare(t, admit(t, q.ab, epoch, init)), control())
	if err != nil {
		t.Fatal(err)
	}
	original = q.a.handshake
	bad := clone(resp)
	clear(bad.Bytes()[12:44])
	q.b.cookieGen.addMACs(epoch, bad.Bytes())
	if _, _, err = q.a.HandleResponse(epoch, admit(t, q.aa, epoch, bad), control()); !errors.Is(err, ErrHandshake) || q.a.handshake != original {
		t.Fatal("low-order response committed")
	}
	sk, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := New(epoch, localIdentity(t, 1, NewIdentity(sk)), q.indexes, q.ib.Public(), Config{HandshakePolicy: automaticPolicy})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	wrong, _, err := other.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = q.b.HandleInitiation(epoch, prepare(t, admit(t, q.ab, epoch, wrong)), control()); !errors.Is(err, ErrHandshake) {
		t.Fatal("wrong configured remote accepted")
	}
}

func TestCookieChallengeBackpressure(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	init, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.ab.Challenge(epoch, init.Bytes(), nil, Packet{Buffer: make([]byte, 63)}); !errors.Is(err, ErrShortBuffer) || !q.ab.secretSet.IsZero() {
		t.Fatal("short challenge mutated secret")
	}
	if _, err = q.ab.Challenge(epoch, init.Bytes(), nil, Packet{Buffer: init.Buffer, Offset: init.Offset}); !errors.Is(err, ErrOverlap) || !q.ab.secretSet.IsZero() {
		t.Fatal("aliased challenge")
	}
}
