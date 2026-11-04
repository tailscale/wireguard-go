// SPDX-License-Identifier: MIT

package peer

import (
	"errors"
	"testing"
	"time"
)

func TestApplyTransportBatchMatchesSerial(t *testing.T) {
	type state struct {
		timers    timerState
		update    Update
		now, last time.Time
		tx, rx    uint64
	}
	var want [2]state
	for _, bulk := range []bool{false, true} {
		q := newPair(t, Config{PersistentKeepalive: 25 * time.Second})
		establish(t, q, epoch)
		var aa, ab []TransportActivity
		for i := range 4 {
			at := epoch.Add(time.Duration(i) * time.Millisecond)
			packets := []Packet{plaintext(64, 8)}
			tx, err := q.a.Transport().Send(at, packets)
			if err != nil {
				t.Fatal(err)
			}
			var results [1]ReceiveResult
			rx, err := q.b.Transport().Receive(at, packets, results[:])
			if err != nil || results[0].Disposition != Data {
				t.Fatal(results, err)
			}
			aa, ab = append(aa, tx.Activity), append(ab, rx.Activity)
			packets = []Packet{plaintext(64, 8)}
			tx, err = q.b.Transport().Send(at, packets)
			if err != nil {
				t.Fatal(err)
			}
			rx, err = q.a.Transport().Receive(at, packets, results[:])
			if err != nil || results[0].Disposition != Data {
				t.Fatal(results, err)
			}
			aa, ab = append(aa, rx.Activity), append(ab, tx.Activity)
		}
		for i, p := range []*Peer{q.a, q.b} {
			activities := aa
			if i == 1 {
				activities = ab
			}
			at := epoch.Add(time.Second)
			if bulk {
				r, err := p.ApplyTransportBatch(at, activities)
				if err != nil || r.N != len(activities) {
					t.Fatal(r, err)
				}
			} else {
				for _, a := range activities {
					if _, err := p.ApplyTransport(at, a); err != nil {
						t.Fatal(err)
					}
				}
			}
			checkWakeCache(t, p)
			got := state{p.timers, p.update(), p.now, p.lastHandshake, p.appliedTX, p.appliedRX}
			if bulk && got != want[i] {
				t.Fatalf("bulk/serial peer %d differs:\ngot %+v\nwant %+v", i, got, want[i])
			}
			want[i] = got
		}
	}
}

func TestApplyTransportBatchCommittedPrefixAndRetry(t *testing.T) {
	for _, failure := range []string{"duplicate", "foreign", "future", "out-of-order"} {
		t.Run(failure, func(t *testing.T) {
			q := newPair(t, Config{})
			tr := q.a.Transport()
			a, _ := tr.Send(epoch, nil)
			b, _ := tr.Send(epoch.Add(time.Second), nil)
			c, _ := tr.Send(epoch.Add(time.Second), nil)
			bad := a.Activity
			wantErr := ErrActivity
			at := epoch.Add(time.Second)
			switch failure {
			case "foreign":
				r, _ := q.b.Transport().Send(epoch, nil)
				bad = r.Activity
			case "future":
				bad = b.Activity
				at = epoch
				wantErr = ErrTime
			case "out-of-order":
				bad = c.Activity
			}
			r, err := q.a.ApplyTransportBatch(at, []TransportActivity{a.Activity, bad})
			if !errors.Is(err, wantErr) || r.N != 1 || q.a.appliedTX != 1 || q.a.now != at || r.Update != q.a.update() {
				t.Fatal("committed prefix", r, err)
			}
			// Repair the rejected slot/order and retry only unconsumed receipts.
			r, err = q.a.ApplyTransportBatch(epoch.Add(time.Second), []TransportActivity{b.Activity, c.Activity})
			if err != nil || r.N != 2 || q.a.appliedTX != 3 {
				t.Fatal("suffix retry", r, err)
			}
			checkWakeCache(t, q.a)
		})
	}
}

func TestApplyTransportBatchFirstFailureAndEmptyCleanup(t *testing.T) {
	q := newPair(t, Config{})
	establish(t, q, epoch)
	initial := q.a.update()
	a, _ := q.a.Transport().Send(epoch.Add(time.Second), nil)
	for _, at := range []time.Time{{}, epoch} {
		r, err := q.a.ApplyTransportBatch(at, []TransportActivity{a.Activity})
		if err != ErrTime || r.N != 0 || r.Update != initial || q.a.appliedTX != 0 || q.a.now != epoch {
			t.Fatal("first ErrTime mutated state", r, err)
		}
	}
	if r, err := q.a.ApplyTransportBatch(epoch.Add(time.Second), []TransportActivity{{}}); err != ErrActivity || r.N != 0 || q.a.now != epoch {
		t.Fatal("invalid first receipt advanced time", r, err)
	}
	key := q.a.keypairs.current
	at := epoch.Add(3 * RejectAfterTime)
	r, err := q.a.ApplyTransportBatch(at, nil)
	if err != nil || r.N != 0 || q.a.now != at || q.a.appliedTX != 0 || !r.Update.Wake.Earliest.IsZero() {
		t.Fatal("empty cleanup", r, err)
	}
	if _, ok := q.indexes.Lookup(key.localIndex); ok {
		t.Fatal("empty batch retained expired route")
	}
	// The earlier receipt remains sequence-valid but its retired key cannot
	// resurrect maintenance. Empty batches consume no directional sequences.
	r, err = q.a.ApplyTransportBatch(at, []TransportActivity{a.Activity})
	if err != nil || r.N != 1 {
		t.Fatal(r, err)
	}
	q.a.Close()
	for _, activities := range [][]TransportActivity{nil, {a.Activity}} {
		r, err := q.a.ApplyTransportBatch(time.Time{}, activities)
		if err != ErrClosed || r.N != 0 || r.Update != (Update{}) {
			t.Fatal("closed batch", r, err)
		}
	}
}

func TestApplyTransportBatchPublishesConfirmationBeforeError(t *testing.T) {
	q := newPair(t, Config{})
	init, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := q.b.HandleInitiation(epoch, prepare(t, admit(t, q.ab, epoch, init)), control())
	if err != nil {
		t.Fatal(err)
	}
	confirm, _, err := q.a.HandleResponse(epoch, admit(t, q.aa, epoch, response), control())
	if err != nil {
		t.Fatal(err)
	}
	var results [1]ReceiveResult
	rx, err := q.b.Transport().Receive(epoch, []Packet{confirm}, results[:])
	if err != nil || results[0].Disposition != Keepalive {
		t.Fatal(results, err)
	}
	at := epoch.Add(time.Second)
	r, err := q.b.ApplyTransportBatch(at, []TransportActivity{rx.Activity, {}})
	view := q.b.Transport().view.Load()
	if err != ErrActivity || r.N != 1 || view.keys.current == nil || view.keys.current != q.b.keypairs.current || view.keys.next != nil || q.b.LastHandshake() != at || r.Update.Handshake.Pending {
		t.Fatal("prefix confirmation not published", r, err)
	}
	checkWakeCache(t, q.b)
}

func TestApplyTransportBatchStaleGenerationAndZeroAllocations(t *testing.T) {
	q := newPair(t, Config{})
	establish(t, q, epoch)
	tr := q.a.Transport()
	r, err := tr.Send(epoch, []Packet{plaintext(64, 8)})
	if err != nil {
		t.Fatal(err)
	}
	at := epoch.Add(time.Second)
	if _, err := q.a.ReplaceIdentity(at, localIdentity(t, 2, q.ia)); err != nil {
		t.Fatal(err)
	}
	next, _ := tr.Send(at, nil)
	before := q.a.timers
	applied, err := q.a.ApplyTransportBatch(at, []TransportActivity{r.Activity, next.Activity})
	if err != nil || applied.N != 2 || before != q.a.timers || q.a.appliedTX != 2 {
		t.Fatal("stale generation bookkeeping", applied, err)
	}

	live := newPair(t, Config{PersistentKeepalive: 25 * time.Second})
	establish(t, live, epoch)
	packets := benchPackets(1, 64)
	activities := make([]TransportActivity, 16)
	allocs := testing.AllocsPerRun(100, func() {
		for i := range activities {
			resetPackets(packets, 64)
			r, err := live.a.Transport().Send(epoch, packets)
			if err != nil || r.N != 1 {
				t.Fatal(r, err)
			}
			activities[i] = r.Activity
		}
		r, err := live.a.ApplyTransportBatch(epoch, activities)
		if err != nil || r.N != len(activities) {
			t.Fatal(r, err)
		}
	})
	if allocs != 0 {
		t.Fatal("bulk receipt reconciliation allocated", allocs)
	}
}
