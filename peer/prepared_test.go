// SPDX-License-Identifier: MIT

package peer

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"
)

// Run this test alone with -covermode=count to count the single static AEAD Open
// in PrepareInitiation as well as the provider's ephemeral DH call below.
func TestPreparedInitiationSinglePreparation(t *testing.T) {
	q := newPair(t, Config{})
	counted := &countingIdentity{Static: q.ib}
	id := localIdentity(t, 2, counted)
	if _, e := q.b.ReplaceIdentity(epoch, id); e != nil {
		t.Fatal(e)
	}
	q.ab = admission(t, id)
	counted.calls = 0 // exclude configured static-static precomputation
	counted.rejectAfter = 1
	init, _, e := q.a.Initiate(epoch, control())
	if e != nil {
		t.Fatal(e)
	}
	v := admit(t, q.ab, epoch, init)
	// Owned admission survives immediate reuse of the incoming datagram buffer.
	clear(init.Bytes())
	prepared, e := PrepareInitiation(v)
	if e != nil || counted.calls != 1 || prepared.RemoteStatic() != q.ia.Public() {
		t.Fatal(counted.calls, e)
	}
	old := q.b.handshake
	before := q.b.cookieGen
	if _, u, e := q.b.HandleInitiation(epoch, prepared, Packet{}); !errors.Is(e, ErrShortBuffer) || u.Handshake.Pending || q.b.handshake != old || q.b.cookieGen != before {
		t.Fatal(u, e)
	}
	// Include a live independent local pending flight in allocation rollback.
	if _, _, e = q.b.Initiate(epoch, control()); e != nil {
		t.Fatal(e)
	}
	old = q.b.handshake
	alloc := &failingAllocator{fail: true}
	originalAlloc := q.b.alloc
	q.b.alloc = alloc
	out := control()
	canary := bytes.Clone(out.Buffer)
	if _, _, e = q.b.HandleInitiation(epoch, prepared, out); e == nil || q.b.handshake != old || !bytes.Equal(out.Buffer, canary) {
		t.Fatal("nontransactional failure", e)
	}
	// Restore allocator ownership before successful replacement of the live index.
	q.b.alloc = originalAlloc
	resp, u, e := q.b.HandleInitiation(epoch, prepared, Packet{Buffer: init.Buffer, Offset: init.Offset})
	if e != nil || resp.Size != MessageResponseSize || !u.Handshake.Pending || counted.calls != 1 {
		t.Fatal(resp, u, e, counted.calls)
	}
	if !bytes.Equal(resp.Buffer[:resp.Offset], bytes.Repeat([]byte{0xcc}, resp.Offset)) {
		t.Fatal("prefix")
	}
	if _, _, e = q.b.HandleInitiation(epoch, prepared, control()); !errors.Is(e, ErrHandshake) || counted.calls != 1 {
		t.Fatal("copied token replay", e, counted.calls)
	}
	// A response token also owns its input and permits overlapping output reuse.
	admitted := admit(t, q.aa, epoch, resp)
	clear(resp.Bytes())
	conf, _, e := q.a.HandleResponse(epoch, admitted, Packet{Buffer: resp.Buffer, Offset: resp.Offset})
	if e != nil || conf.Size != MessageKeepaliveSize {
		t.Fatal(conf, e)
	}
}

func TestPreparedInitiationGenerationAndRemoteIsolation(t *testing.T) {
	q := newPair(t, Config{})
	init, _, e := q.a.Initiate(epoch, control())
	if e != nil {
		t.Fatal(e)
	}
	token := prepare(t, admit(t, q.ab, epoch, init))
	reject := func(p *Peer, v PreparedInitiation) {
		t.Helper()
		before := p.handshake
		out := control()
		canary := bytes.Clone(out.Buffer)
		_, _, e := p.HandleInitiation(epoch, v, out)
		if !errors.Is(e, ErrHandshake) || p.handshake != before || !bytes.Equal(out.Buffer, canary) {
			t.Fatal("isolation failure", e)
		}
	}
	// Same provider/key/epoch independently wrapped is not the same capability.
	otherID := localIdentity(t, 1, NewIdentity(q.ib.private))
	other, _, e := New(epoch, otherID, q.indexes, q.ia.Public(), Config{})
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	reject(other, token)
	wrongRemote, _, e := New(epoch, q.b.identity, q.indexes, q.ib.Public(), Config{})
	if e != nil {
		t.Fatal(e)
	}
	defer wrongRemote.Close()
	reject(wrongRemote, token)
	old := q.b.identity
	sameKey := localIdentity(t, 2, q.ib)
	if _, e = q.b.ReplaceIdentity(epoch, sameKey); e != nil {
		t.Fatal(e)
	}
	reject(q.b, token)
	// An old/equal epoch fails closed and cannot reactivate prepared work.
	for _, id := range []LocalIdentity{old, sameKey} {
		u, e := q.b.ReplaceIdentity(epoch, id)
		if !errors.Is(e, ErrConfig) || !u.Handshake.InitiateAt.IsZero() || q.b.precomputedValid {
			t.Fatal(u, e)
		}
		reject(q.b, token)
	}
	failure := localIdentity(t, 3, errorIdentity{q.ib.Public()})
	if u, e := q.b.ReplaceIdentity(epoch, failure); e == nil || !u.Handshake.InitiateAt.IsZero() {
		t.Fatal(u, e)
	}
	if _, e = q.b.ReplaceIdentity(epoch, localIdentity(t, 3, q.ib)); !errors.Is(e, ErrConfig) {
		t.Fatal("failed epoch reusable", e)
	}
	// Rotate away and back. The original wire can be re-admitted, but not the old
	// in-process token. WireGuard carries no configuration generation on wire.
	if _, e = q.b.ReplaceIdentity(epoch, localIdentity(t, 4, q.ia)); e != nil {
		t.Fatal(e)
	}
	reject(q.b, token)
	freshID := localIdentity(t, 5, q.ib)
	if _, e = q.b.ReplaceIdentity(epoch, freshID); e != nil {
		t.Fatal(e)
	}
	reject(q.b, token)
	q.ab = admission(t, freshID)
	fresh := prepare(t, admit(t, q.ab, epoch, init))
	resp, _, e := q.b.HandleInitiation(epoch, fresh, control())
	if e != nil {
		t.Fatal(e)
	}
	conf, _, e := q.a.HandleResponse(epoch, admit(t, q.aa, epoch, resp), control())
	if e != nil {
		t.Fatal(e)
	}
	if r := receive(t, q.b, epoch, conf); r.Err != nil {
		t.Fatal(r.Err)
	}
	q.b.Close()
	if _, u, e := q.b.HandleInitiation(epoch, fresh, control()); !errors.Is(e, ErrClosed) || u != (Update{}) {
		t.Fatal(u, e)
	}
}

func TestPreparedInitiationMessageBindingAndReplayBoundaries(t *testing.T) {
	q := newPair(t, Config{})
	first, _, e := q.a.Initiate(epoch, control())
	if e != nil {
		t.Fatal(e)
	}
	old := prepare(t, admit(t, q.ab, epoch, first))
	nextAt := epoch.Add(RekeyTimeout)
	second, _, e := q.a.Initiate(nextAt, control())
	if e != nil {
		t.Fatal(e)
	}
	fresh := prepare(t, admit(t, q.ab, nextAt, second))
	copy(first.Bytes(), second.Bytes()) // cannot replace the message carried by old
	if _, _, e = q.b.HandleInitiation(nextAt, old, control()); e != nil {
		t.Fatal(e)
	}
	before := q.b.handshake
	// Inclusive 20ms flood boundary rejects a fresh timestamp without consuming it.
	if _, _, e = q.b.HandleInitiation(nextAt.Add(HandshakeInitRate), fresh, control()); !errors.Is(e, ErrHandshake) || q.b.handshake != before {
		t.Fatal(e)
	}
	if _, _, e = q.b.HandleInitiation(nextAt.Add(HandshakeInitRate+time.Nanosecond), fresh, control()); e != nil {
		t.Fatal(e)
	}
	if _, _, e = q.b.HandleInitiation(nextAt.Add(time.Second), old, control()); !errors.Is(e, ErrHandshake) {
		t.Fatal("out of order timestamp", e)
	}
}

func TestPreparedInitiationIncompleteAuthenticationAndKinds(t *testing.T) {
	q := newPair(t, Config{})
	init, _, e := q.a.Initiate(epoch, control())
	if e != nil {
		t.Fatal(e)
	}
	// A valid static-encryption prefix naming a known remote isn't proof of its
	// private key. Timestamp authentication remains mandatory at the selected peer.
	bad := clone(init)
	bad.Bytes()[88] ^= 1
	q.a.cookieGen.addMACs(epoch, bad.Bytes())
	v, e := PrepareInitiation(admit(t, q.ab, epoch, bad))
	if e != nil || v.RemoteStatic() != q.ia.Public() {
		t.Fatal(v, e)
	}
	before := q.b.handshake
	if _, _, e = q.b.HandleInitiation(epoch, v, control()); !errors.Is(e, ErrHandshake) || q.b.handshake != before || q.indexes.Len() != 1 {
		t.Fatal(e)
	}
	for _, token := range []AdmittedHandshake{{}, admit(t, q.ab, epoch, init)} {
		if _, _, e = q.b.HandleResponse(epoch, token, control()); !errors.Is(e, ErrHandshake) {
			t.Fatal(e)
		}
	}
	if v, e := PrepareInitiation(AdmittedHandshake{}); !errors.Is(e, ErrHandshake) || v != (PreparedInitiation{}) {
		t.Fatal(v, e)
	}
	if _, _, e = q.b.HandleInitiation(epoch, PreparedInitiation{}, control()); !errors.Is(e, ErrHandshake) {
		t.Fatal(e)
	}
	resp, _, e := q.b.HandleInitiation(epoch, prepare(t, admit(t, q.ab, epoch, init)), control())
	if e != nil {
		t.Fatal(e)
	}
	if v, e := PrepareInitiation(admit(t, q.aa, epoch, resp)); !errors.Is(e, ErrHandshake) || v != (PreparedInitiation{}) {
		t.Fatal(v, e)
	}
	// No exported token fields or retained packet slices (provider records are
	// immutable identity state, not packet storage).
	for _, typ := range []reflect.Type{reflect.TypeOf(AdmittedHandshake{}), reflect.TypeOf(PreparedInitiation{})} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.IsExported() || f.Type.Kind() == reflect.Slice {
				t.Fatal("mutable token field", f)
			}
		}
	}
}

type zeroIndexAllocator struct{}

func (zeroIndexAllocator) Allocate(*Peer) (uint32, error) { return 0, nil }
func (zeroIndexAllocator) Release(uint32, *Peer)          { panic("released unowned zero index") }

func TestPreparedInitiationZeroIndexAndLateRejectionCleanup(t *testing.T) {
	q := newPair(t, Config{})
	init, _, e := q.a.Initiate(epoch, control())
	if e != nil {
		t.Fatal(e)
	}
	v := prepare(t, admit(t, q.ab, epoch, init))
	original := q.b.alloc
	q.b.alloc = zeroIndexAllocator{}
	if _, _, e = q.b.HandleInitiation(epoch, v, control()); !errors.Is(e, ErrIndex) || q.b.handshake.lastTimestamp != ([12]byte{}) {
		t.Fatal(e)
	}
	q.b.alloc = original
	if _, _, e = q.b.HandleInitiation(epoch, v, control()); e != nil {
		t.Fatal(e)
	}
	_, u, e := q.b.HandleInitiation(epoch.Add(3*RejectAfterTime), v, control())
	if !errors.Is(e, ErrHandshake) || !u.Wake.Earliest.IsZero() || u.Handshake.Pending || q.b.keypairs.next != nil {
		t.Fatal(u, e)
	}
}
