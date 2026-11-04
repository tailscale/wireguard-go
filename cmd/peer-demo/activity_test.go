// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/peer"
)

func establishedFixture(t *testing.T) (*owner, *memoryTransport, time.Time) {
	t.Helper()
	o, io, now := fixture(t)
	if _, err := run(io, o, now, func(time.Time) {}); err != nil {
		t.Fatal(err)
	}
	return o, io, now.Add(2 * time.Second)
}

func checkNoPending(t *testing.T, o *owner) {
	t.Helper()
	for _, r := range o.locals {
		if r.nActivities != 0 {
			t.Fatal("undrained activities", r.nActivities)
		}
		for _, a := range r.activities {
			if a.Valid() {
				t.Fatal("retained applied receipt")
			}
		}
	}
}

func TestRecordActivitiesBatchUntilDrain(t *testing.T) {
	o, io, now := establishedFixture(t)
	r := o.locals[0]
	before := r.update
	for _, text := range []string{"first record", "reused storage"} {
		if err := o.record(io, now, r, text); err != nil {
			t.Fatal(err)
		}
	}
	if r.nActivities != 2 || r.remote.nActivities != 2 || r.update != before {
		t.Fatal("records were not accumulated into per-peer batches")
	}
	first := r.activities[0]
	if err := o.applyPending(now); err != nil {
		t.Fatal(err)
	}
	checkNoPending(t, o)
	if result, err := r.p.ApplyTransportBatch(now, []peer.TransportActivity{first}); !errors.Is(err, peer.ErrActivity) || result.N != 0 {
		t.Fatal("receipt was not applied exactly once", result, err)
	}
}

func TestActivityBatchCapacity(t *testing.T) {
	o, io, now := establishedFixture(t)
	r := o.locals[0]
	for i := 0; i < activityBatchSize; i++ {
		if err := o.record(io, now, r, "bounded batch"); err != nil {
			t.Fatal(err)
		}
	}
	if r.nActivities != activityBatchSize || r.remote.nActivities != activityBatchSize {
		t.Fatal("fixture did not fill both directional batches")
	}
	if err := o.record(io, now, r, "drain before next operation"); err != nil {
		t.Fatal(err)
	}
	if r.nActivities != 1 || r.remote.nActivities != 1 {
		t.Fatal("full batches were not drained before appending")
	}
	if err := o.applyPending(now); err != nil {
		t.Fatal(err)
	}
	checkNoPending(t, o)
}

func TestActivityDrainRetryableClock(t *testing.T) {
	o, io, now := establishedFixture(t)
	r := o.locals[0]
	if err := o.record(io, now, r, "retry clock"); err != nil {
		t.Fatal(err)
	}
	before := r.activities
	if err := r.applyPending(now.Add(-time.Nanosecond)); !errors.Is(err, peer.ErrTime) || r.nActivities != 1 || r.activities != before {
		t.Fatal("clock rejection consumed pending activity", err)
	}
	if err := o.applyPending(now); err != nil {
		t.Fatal(err)
	}
	checkNoPending(t, o)
}

func TestActivityDrainRetainsUnconsumedSuffix(t *testing.T) {
	o, io, now := establishedFixture(t)
	r := o.locals[0]
	if err := o.record(io, now, r, "partial consumption"); err != nil {
		t.Fatal(err)
	}
	foreign := r.remote.activities[0]
	r.saveActivity(foreign)
	if err := r.applyPending(now); !errors.Is(err, peer.ErrActivity) || r.nActivities != 1 || r.activities[0] != foreign {
		t.Fatal("unconsumed suffix was lost", err)
	}
	for _, a := range r.activities[1:] {
		if a.Valid() {
			t.Fatal("consumed slots were not cleared")
		}
	}
	// The foreign receipt is a routing bug, so this owner must close rather than
	// retry it on the wrong peer. The legitimate RX copy remains on its owner.
	o.close()
	checkNoPending(t, o)
}

func TestSchedulingDrainsActivity(t *testing.T) {
	o, io, now := establishedFixture(t)
	if err := o.record(io, now, o.locals[0], "update before scheduling"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.coalescedWake(now); err != nil {
		t.Fatal(err)
	}
	checkNoPending(t, o)
}

type failedTransport struct{ err error }

func (f failedTransport) transfer(int, int, netip.AddrPort, []byte) (peer.Packet, netip.AddrPort, error) {
	return peer.Packet{}, netip.AddrPort{}, f.err
}

func TestRecordTurnDrainsOnFailure(t *testing.T) {
	o, _, now := establishedFixture(t)
	failure := errors.New("transport failed")
	if err := o.records(failedTransport{failure}, now); !errors.Is(err, failure) {
		t.Fatal("lost I/O error", err)
	}
	checkNoPending(t, o)
}

func TestRecordTurnDrainsOnLaneFailure(t *testing.T) {
	o, io, now := fixture(t)
	if err := o.records(io, now); !errors.Is(err, peer.ErrNoSession) {
		t.Fatal("missing send session", err)
	}
	checkNoPending(t, o)
}

func TestRejectedDatagramActivityIsApplied(t *testing.T) {
	o, io, now := establishedFixture(t)
	r := o.locals[0]
	packets := []peer.Packet{{Buffer: r.send[:], Offset: prefix + peer.TransportHeaderSize, Size: 0}}
	result, err := r.p.Send(now, packets)
	r.update = result.Update
	if err != nil {
		t.Fatal(err)
	}
	wire := packets[0]
	wire.Bytes()[wire.Size-1] ^= 1
	if _, _, _, err := o.dispatch(now, r.remote.socket, io.addresses[r.socket], wire); !errors.Is(err, peer.ErrTransport) {
		t.Fatal("forgery accepted", err)
	}
	if r.remote.nActivities != 1 {
		t.Fatal("rejected datagram activity was dropped")
	}
	if err := o.applyPending(now); err != nil {
		t.Fatal(err)
	}
	if err := o.record(io, now, r, "valid packet after rejection"); err != nil {
		t.Fatal(err)
	}
	if err := o.applyPending(now); err != nil {
		t.Fatal(err)
	}
	checkNoPending(t, o)
}
