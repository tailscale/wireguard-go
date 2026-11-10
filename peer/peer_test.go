// SPDX-License-Identifier: MIT

package peer

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/peerindex"
)

var epoch = time.Unix(1700000000, 0)

type pair struct {
	a, b    *Peer
	ia, ib  *Identity
	aa, ab  *Admission
	indexes *peerindex.Table[*Peer]
}

func newPair(t testing.TB, config Config) pair {
	t.Helper()
	ka, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	kb, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ia, ib := NewIdentity(ka), NewIdentity(kb)
	indexes := new(peerindex.Table[*Peer])
	a, _, err := New(epoch, localIdentity(t, 1, ia), indexes, ib.Public(), config)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := New(epoch, localIdentity(t, 1, ib), indexes, ia.Public(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.Close()
		b.Close()
		if indexes.Len() != 0 {
			t.Errorf("leaked %d indexes", indexes.Len())
		}
	})
	return pair{a, b, ia, ib, admission(t, a.identity), admission(t, b.identity), indexes}
}

func control() Packet {
	return Packet{Buffer: bytes.Repeat([]byte{0xcc}, 11+MessageHybridInitiationSize), Offset: 11}
}

func admit(t testing.TB, a *Admission, now time.Time, wire Packet) AdmittedHandshake {
	t.Helper()
	v, err := a.Admit(now, wire.Bytes(), nil, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func establish(t testing.TB, q pair, now time.Time) {
	t.Helper()
	init, _, err := q.a.Initiate(now, control())
	if err != nil {
		t.Fatal(err)
	}
	identified, err := PrepareInitiation(admit(t, q.ab, now, init))
	if err != nil || !identified.RemoteStatic().Equals(q.ia.Public()) {
		t.Fatalf("identify %v", err)
	}
	resp, _, err := q.b.HandleInitiation(now, identified, control())
	if err != nil {
		t.Fatal(err)
	}
	before := q.b.LastHandshake()
	conf, _, err := q.a.HandleResponse(now, admit(t, q.aa, now, resp), control())
	if err != nil {
		t.Fatal(err)
	}
	if !q.b.LastHandshake().Equal(before) {
		t.Fatal("response completed responder handshake")
	}
	var result [1]ReceiveResult
	if n, err := q.b.Receive(now, []Packet{conf}, result[:]); err != nil || n.N != 1 || result[0].Disposition != Keepalive {
		t.Fatalf("confirmation: %d %v %+v", n.N, err, result)
	}
	if !q.b.LastHandshake().Equal(now) || !q.a.LastHandshake().Equal(now) {
		t.Fatal("handshake completion status")
	}
	for _, p := range []Packet{init, resp, conf} {
		if !bytes.Equal(p.Buffer[:11], bytes.Repeat([]byte{0xcc}, 11)) {
			t.Fatal("control prefix corrupted")
		}
	}
}

func plaintext(size, prefix int) Packet {
	b := bytes.Repeat([]byte{0xa5}, prefix+16+size+31)
	for i := 0; i < size; i++ {
		b[prefix+16+i] = byte(i)
	}
	return Packet{b, prefix + 16, size}
}

func seal(t testing.TB, p *Peer, now time.Time, packet Packet) Packet {
	t.Helper()
	vec := []Packet{packet}
	if n, err := p.Send(now, vec); n.N != 1 || err != nil {
		t.Fatalf("send: %d %v", n.N, err)
	}
	return vec[0]
}

func clone(p Packet) Packet {
	b := append([]byte(nil), p.Buffer...)
	return Packet{b, p.Offset, p.Size}
}

func receive(t testing.TB, p *Peer, now time.Time, wire Packet) ReceiveResult {
	t.Helper()
	var results [1]ReceiveResult
	if n, err := p.Receive(now, []Packet{wire}, results[:]); n.N != 1 || err != nil {
		t.Fatalf("receive: %d %v", n.N, err)
	}
	return results[0]
}

func TestHandshakeBothDirectionsPSKAndPadding(t *testing.T) {
	var psk PresharedKey
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	q := newPair(t, Config{PresharedKey: psk, PaddingMTU: 1420})
	establish(t, q, epoch)
	for _, direction := range [][2]*Peer{{q.a, q.b}, {q.b, q.a}} {
		for _, size := range []int{0, 1, 15, 16, 17, 1419, 1420, 1421, 65535} {
			orig := plaintext(size, 37)
			want := append([]byte(nil), orig.Bytes()...)
			packet := seal(t, direction[0], epoch, orig)
			if packet.Offset != 37 || !bytes.Equal(packet.Buffer[:37], bytes.Repeat([]byte{0xa5}, 37)) {
				t.Fatal("prefix")
			}
			wireCopy := clone(packet)
			result := receive(t, direction[1], epoch, packet)
			if result.Err != nil || !bytes.Equal(result.Packet.Bytes()[:size], want) {
				t.Fatalf("size=%d result=%+v", size, result)
			}
			if result.Packet.Size != size+paddingSize(size, 1420) {
				t.Fatal("padding size")
			}
			if result := receive(t, direction[1], epoch, wireCopy); !errors.Is(result.Err, ErrReplay) || result.Packet.Buffer != nil {
				t.Fatal("replay exposed plaintext")
			}
		}
	}
}

func TestCloseAllSlotsAndPending(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	establish(t, q, epoch)
	establish(t, q, epoch.Add(6*time.Second))
	init, _, err := q.b.Initiate(epoch.Add(12*time.Second), control())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = q.a.HandleInitiation(epoch.Add(12*time.Second), prepare(t, admit(t, q.aa, epoch.Add(12*time.Second), init)), control())
	if err != nil {
		t.Fatal(err)
	}
	if q.a.keypairs.current == nil || q.a.keypairs.next == nil {
		t.Fatal("fixture slots")
	}
	// Populate previous with an independent allocation to exercise all lifetimes.
	index, err := q.indexes.Allocate(q.a)
	if err != nil {
		t.Fatal(err)
	}
	q.a.keypairs.previous = &keypair{localIndex: index, created: epoch}
	if _, _, err = q.a.Initiate(epoch.Add(18*time.Second), control()); err != nil {
		t.Fatal(err)
	}
	q.a.Close()
	q.a.Close()
	if !q.a.update().Wake.Earliest.IsZero() {
		t.Fatal("close scheduled work")
	}
	for _, op := range []func() error{
		func() error { _, e := q.a.Send(epoch.Add(18*time.Second), nil); return e },
		func() error { _, e := q.a.Receive(epoch.Add(18*time.Second), nil, nil); return e },
		func() error { _, _, e := q.a.Initiate(epoch.Add(18*time.Second), control()); return e },
		func() error { _, e := q.a.HandleWake(epoch.Add(18*time.Second), nil); return e },
	} {
		if !errors.Is(op(), ErrClosed) {
			t.Fatal("closed peer did protocol work")
		}
	}
	q.b.Close()
	if q.indexes.Len() != 0 {
		t.Fatal("close leaked mappings")
	}
}

func TestClockAndConfiguration(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	if _, _, err := q.a.Initiate(time.Time{}, control()); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	if _, _, err := q.a.Initiate(epoch, control()); err != nil {
		t.Fatal(err)
	}
	if _, err := q.a.Send(epoch.Add(-time.Nanosecond), nil); !errors.Is(err, ErrTime) {
		t.Fatal(err)
	}
	if _, err := q.a.SetPersistentKeepalive(epoch, -1, KeepaliveAfterInterval); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	if _, err := q.a.SetPersistentKeepalive(epoch, 1, KeepaliveStart(99)); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
}

var automaticPolicy = HandshakePolicy{Rekey: true, Retry: true, Silence: true, EstablishForKeepalive: true}

var manualPolicy = HandshakePolicy{}

func localIdentity(t testing.TB, epoch uint64, s Static) LocalIdentity {
	t.Helper()
	id, err := NewLocalIdentity(epoch, s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func admission(t testing.TB, id LocalIdentity) *Admission {
	t.Helper()
	a, err := NewAdmission(id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func prepare(t testing.TB, v AdmittedHandshake) PreparedInitiation {
	t.Helper()
	p, err := PrepareInitiation(v)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
