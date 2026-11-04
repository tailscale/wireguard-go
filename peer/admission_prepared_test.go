// SPDX-License-Identifier: MIT

package peer

import (
	"errors"
	"testing"
	"time"
)

func TestAdmissionPreparationRejectsBeforeIdentityWork(t *testing.T) {
	q := newPair(t, Config{})
	counted := &countingIdentity{Static: q.ib}
	a := admission(t, localIdentity(t, 1, counted))
	init, _, e := q.a.Initiate(epoch, control())
	if e != nil {
		t.Fatal(e)
	}
	source := []byte("ip:port")
	bad := clone(init)
	bad.Bytes()[MessageInitiationSize-32] ^= 1
	limit := &allowSource{allowed: true}
	check := func(now time.Time, wire, src []byte, under bool, l SourceLimiter, want error) {
		t.Helper()
		admitted, e := a.Admit(now, wire, src, under, l)
		if e == nil {
			_, _ = PrepareInitiation(admitted)
		}
		if !errors.Is(e, want) || counted.calls != 0 || admitted != (AdmittedHandshake{}) {
			t.Fatal(e, counted.calls)
		}
	}
	check(epoch, []byte{1}, source, false, limit, ErrMAC1)
	check(epoch, bad.Bytes(), source, true, limit, ErrMAC1)
	check(epoch, init.Bytes(), source, true, limit, ErrCookieRequired)
	if limit.calls != 0 {
		t.Fatal("limiter before MACs")
	}
	cookie, e := a.Challenge(epoch, init.Bytes(), source, control())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.a.ConsumeCookie(epoch, cookie.Bytes()); e != nil {
		t.Fatal(e)
	}
	now := epoch.Add(RekeyTimeout)
	fresh, _, e := q.a.Initiate(now, control())
	if e != nil {
		t.Fatal(e)
	}
	check(now, fresh.Bytes(), []byte("other"), true, limit, ErrCookieRequired)
	if limit.calls != 0 {
		t.Fatal("limiter before MAC2")
	}
	check(now, fresh.Bytes(), source, true, nil, ErrAdmission)
	limit.allowed = false
	check(now, fresh.Bytes(), source, true, limit, ErrAdmission)
	if limit.calls != 1 {
		t.Fatal("missing limiter invocation")
	}
	check(epoch.Add(CookieRefreshTime), fresh.Bytes(), source, true, limit, ErrCookieRequired)
}

func TestPreparedInitiationForgedStaticRoutingHint(t *testing.T) {
	q := newPair(t, Config{})
	// The attacker needs only receiver and claimed remote PUBLIC keys. It can
	// construct a valid static encryption prefix without the claimed private key.
	ephemeral, e := NewPrivateKey()
	if e != nil {
		t.Fatal(e)
	}
	msg := messageInitiation{Type: MessageInitiationType, Sender: 123, Ephemeral: ephemeral.Public()}
	var hash, chain, key [32]byte
	pub := q.ib.Public()
	mixHash(&hash, &initialHash, pub[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chain, &initialChainKey, msg.Ephemeral[:])
	ss, e := ephemeral.sharedSecret(pub)
	if e != nil {
		t.Fatal(e)
	}
	kdf2(&chain, &key, chain[:], ss[:])
	aead, _ := newAEAD(key[:])
	claimed := q.ia.Public()
	aead.Seal(msg.Static[:0], zeroNonce[:], claimed[:], hash[:])
	wire := control()
	wire.Size = MessageInitiationSize
	if e = msg.marshal(wire.Bytes()); e != nil {
		t.Fatal(e)
	}
	q.a.cookieGen.addMACs(epoch, wire.Bytes()) // MAC1 is publicly computable
	prepared, e := PrepareInitiation(admit(t, q.ab, epoch, wire))
	if e != nil || prepared.RemoteStatic() != claimed {
		t.Fatal(e)
	}
	before := q.b.handshake
	_, u, e := q.b.HandleInitiation(epoch, prepared, control())
	if !errors.Is(e, ErrHandshake) || u.Handshake.Pending || q.b.handshake != before || q.indexes.Len() != 0 || !q.b.LastHandshake().IsZero() {
		t.Fatal(u, e)
	}
}

func TestPreparedUnknownRemoteDoesNotRegisterOrAllocate(t *testing.T) {
	q := newPair(t, Config{})
	other := newPair(t, Config{})
	sender, _, e := New(epoch, other.a.identity, q.indexes, q.ib.Public(), Config{})
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	init, _, e := sender.Initiate(epoch, control())
	if e != nil {
		t.Fatal(e)
	}
	before := q.indexes.Len()
	prepared := prepare(t, admit(t, q.ab, epoch, init))
	if prepared.RemoteStatic() == q.b.RemoteStatic() {
		t.Fatal("unexpected configured peer")
	}
	// The bounded owner lookup drops unknown hints. Preparation has no allocator.
	if q.indexes.Len() != before || q.b.handshake != (handshake{}) {
		t.Fatal("implicit registration")
	}
	// Even accidental dispatch to the known peer cannot cross the identity pair.
	if _, _, e = q.b.HandleInitiation(epoch, prepared, control()); !errors.Is(e, ErrHandshake) {
		t.Fatal(e)
	}
}
