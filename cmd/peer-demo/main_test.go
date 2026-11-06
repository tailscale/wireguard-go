// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/peer"
)

// The automated example uses the same dispatcher/scenario with bounded memory
// I/O, not loopback sleeps or assumptions about OS scheduling.
type memoryTransport struct {
	addresses []netip.AddrPort
	receive   [3][2048]byte
	sends     [3]int
}

func (m *memoryTransport) transfer(from, to int, dst netip.AddrPort, wire []byte) (peer.Packet, netip.AddrPort, error) {
	if dst != m.addresses[to] {
		return peer.Packet{}, netip.AddrPort{}, errRoute
	}
	m.sends[from]++
	b := m.receive[to][:]
	for i := 0; i < prefix; i++ {
		b[i] = 0xa7
	}
	copy(b[prefix:], wire)
	return peer.Packet{Buffer: b, Offset: prefix, Size: len(wire)}, m.addresses[from], nil
}
func fixture(t *testing.T) (*owner, *memoryTransport, time.Time) {
	t.Helper()
	m := &memoryTransport{addresses: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:10000"), netip.MustParseAddrPort("127.0.0.1:10001"), netip.MustParseAddrPort("127.0.0.1:10002")}}
	o, err := newOwner(time.Unix(1700000000, 0), m.addresses)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		o.close()
		if o.indexes.Len() != 0 {
			t.Fatal("indices leaked")
		}
	})
	return o, m, time.Unix(1700000000, 0)
}
func TestSharedSocketExample(t *testing.T) {
	o, m, now := fixture(t)
	n, err := run(m, o, now, func(time.Time) {})
	if err != nil || n != 2 {
		t.Fatalf("run: %d %v", n, err)
	}
	if o.indexes.Len() != 4 {
		t.Fatalf("indices %d", o.indexes.Len())
	}
	for socket, n := range m.sends {
		if n == 0 {
			t.Fatalf("unused application shard %d", socket)
		}
	}
	if o.locals[0].socket != o.locals[2].socket || o.locals[1].socket == o.locals[3].socket {
		t.Fatal("socket layout")
	}
	for _, r := range o.locals {
		if !r.p.HasSession(now.Add(time.Second)) {
			t.Fatal("independent session missing")
		}
	}
}
func TestDispatchBoundariesAndRekey(t *testing.T) {
	o, m, now := fixture(t)
	if _, err := run(m, o, now, func(time.Time) {}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Second)
	r := o.locals[0]
	// Prepare a valid indexed datagram but do not consume it yet.
	b := r.send[:]
	copy(b[prefix+16:], []byte{0, 1, 'x'})
	vec := []peer.Packet{{Buffer: b, Offset: prefix + 16, Size: 3}}
	result, err := r.p.Send(now, vec)
	r.update = result.Update
	if err != nil {
		t.Fatal(err)
	}
	held := bytes.Clone(vec[0].Bytes())
	input := peer.Packet{Buffer: held, Size: len(held)}
	if _, _, _, err := o.dispatch(now, 2, m.addresses[0], input); !errors.Is(err, errRoute) {
		t.Fatal("cross-shard route", err)
	}
	if _, _, _, err := o.dispatch(now, 1, m.addresses[2], input); !errors.Is(err, errRoute) {
		t.Fatal("wrong source", err)
	}
	_, _, payload, err := o.dispatch(now, 1, m.addresses[0], input)
	if err != nil || string(payload) != "x" {
		t.Fatal("valid dispatch", err)
	}
	// Unrelated application protocols are classified before any index/DH work.
	for _, wire := range [][]byte{[]byte("other-app"), {4, 1, 0, 0}, make([]byte, 3)} {
		if _, _, _, err := o.dispatch(now, 0, m.addresses[1], peer.Packet{Buffer: wire, Size: len(wire)}); err == nil {
			t.Fatal("malformed accepted")
		}
	}
	unknown := make([]byte, 32)
	binary.LittleEndian.PutUint32(unknown, 4)
	if _, _, _, err := o.dispatch(now, 0, m.addresses[1], peer.Packet{Buffer: unknown, Size: len(unknown)}); !errors.Is(err, errRoute) {
		t.Fatal("unknown index", err)
	}
	oldCount := o.indexes.Len()
	init, update, err := r.p.Initiate(now, r.output())
	r.update = update
	if err != nil {
		t.Fatal(err)
	}
	if _, err = o.exchange(m, now, r, init); err != nil {
		t.Fatal(err)
	}
	if o.indexes.Len() != oldCount+2 {
		t.Fatal("previous/current routing lifetime")
	}
	if err = o.record(m, now, o.locals[2], "other identity still progresses"); err != nil {
		t.Fatal(err)
	}
	if err = o.record(m, now, r, "fresh session"); err != nil {
		t.Fatal(err)
	}
}
func TestManualLossAndScheduler(t *testing.T) {
	o, _, now := fixture(t)
	r := o.locals[0]
	_, update, err := r.p.Initiate(now, r.output())
	r.update = update
	if err != nil {
		t.Fatal(err)
	} // dropped by application
	if r.update.Wake.Deadline.Before(now.Add(3 * peer.RejectAfterTime)) {
		t.Fatal("manual retry was armed")
	}
	emitted := 0
	if _, err := o.wake(now.Add(10*time.Second), func(*route, peer.Packet) error { emitted++; return nil }); err != nil {
		t.Fatal(err)
	}
	if emitted != 0 {
		t.Fatal("automatic retry under manual policy")
	}
	if !o.coalescedWake().Equal(now.Add(3 * peer.RejectAfterTime)) {
		t.Fatal("hard cleanup deadline postponed")
	}
	if _, err := o.wake(o.coalescedWake(), func(*route, peer.Packet) error { return errors.New("unexpected control") }); err != nil {
		t.Fatal(err)
	}
	if o.indexes.Len() != 0 {
		t.Fatal("lost attempt index not retired")
	}
}

func TestRecordStorageLimit(t *testing.T) {
	o, m, now := fixture(t)
	if _, err := run(m, o, now, func(time.Time) {}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	r := o.locals[0]
	maxSize := len(r.send) - prefix - peer.TransportOverhead - (peer.PaddingMultiple - 1) - 2
	before, update := r.send, r.update
	if err := o.record(m, now, r, strings.Repeat("x", maxSize+1)); !errors.Is(err, errRecordTooLarge) {
		t.Fatalf("oversized record: %v", err)
	}
	if r.send != before || r.update != update {
		t.Fatal("rejected record changed packet storage or peer update")
	}
	if err := o.record(m, now, r, strings.Repeat("x", maxSize)); err != nil {
		t.Fatalf("maximum record: %v", err)
	}
}

func TestMultipleIdentitiesSameEndpoint(t *testing.T) {
	o, m, now := fixture(t)
	// Choose a shared remote socket too. Neither endpoint nor socket alone
	// identifies a peer. MAC1/static identity and globally unique indices do.
	o.locals[3].socket = 1
	o.locals[2].destination = m.addresses[1]
	if n, err := run(m, o, now, func(time.Time) {}); err != nil || n != 2 {
		t.Fatalf("shared endpoints: %d %v", n, err)
	}
}

func TestWakeConsumesCommittedPrefixBeforeBackpressure(t *testing.T) {
	o, m, now := fixture(t)
	if _, err := run(m, o, now, func(time.Time) {}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(peer.RekeyAfterTime + time.Second)
	r := o.locals[0]
	var err error
	r.update, err = r.p.SetHandshakePolicy(now, peer.HandshakePolicy{Rekey: true})
	if err != nil {
		t.Fatal(err)
	}
	r.update, err = r.p.SetPersistentKeepalive(now, time.Second, peer.KeepaliveImmediate)
	if err != nil {
		t.Fatal(err)
	}
	emitted := 0
	n, err := o.wake(now, func(got *route, p peer.Packet) error {
		if got != r || p.Size != peer.MessageKeepaliveSize {
			t.Fatal("wrong prefix", p)
		}
		emitted++
		return nil
	})
	if !errors.Is(err, peer.ErrShortBuffer) || n != 1 || emitted != 1 || r.update.Wake.Earliest != now || r.update.Handshake.Reasons&peer.HandshakeRekey == 0 {
		t.Fatal(n, emitted, r.update, err)
	}
}
