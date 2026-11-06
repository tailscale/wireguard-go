// SPDX-License-Identifier: MIT

package peer

import (
	"fmt"
	"testing"
	"time"
)

func TestPreviousKeyReceiveRefreshesCurrent(t *testing.T) {
	for _, duplex := range []bool{false, true} {
		for _, automatic := range []bool{false, true} {
			t.Run(fmt.Sprintf("transport=%t/automatic=%t", duplex, automatic), func(t *testing.T) {
				policy := HandshakePolicy{}
				if automatic {
					policy.Rekey = true
				}
				q := newPair(t, Config{HandshakePolicy: policy})
				establish(t, q, epoch)
				held := seal(t, q.b, epoch, plaintext(3, 0))
				establish(t, q, epoch.Add(RekeyTimeout))
				current := q.a.keypairs.current
				now := epoch.Add(171 * time.Second)
				open := func(wire Packet) ReceiveResult {
					t.Helper()
					if !duplex {
						return receive(t, q.a, now, wire)
					}
					var results [1]ReceiveResult
					r, err := q.a.Transport().Receive(now, []Packet{wire}, results[:])
					if err != nil || r.N != 1 {
						t.Fatalf("receive: %+v, %v", r, err)
					}
					if q.a.timers.refreshNeeded {
						t.Fatal("transport updated control state before receipt application")
					}
					applyActivity(t, q.a, now, r)
					return results[0]
				}
				bad := clone(held)
				bad.Bytes()[bad.Size-1] ^= 1
				if r := open(bad); r.Disposition != Dropped {
					t.Fatal("forgery accepted")
				}
				if q.a.timers.refreshNeeded || q.a.timers.receiveRefreshSent {
					t.Fatal("unauthenticated packet requested refresh")
				}
				if r := open(held); r.Disposition != Data || r.Err != nil {
					t.Fatalf("previous-key packet: %+v", r)
				}
				if q.a.keypairs.current != current || !q.a.timers.receiveRefreshSent {
					t.Fatal("previous-key receive did not request current-key refresh")
				}
				u := q.a.update()
				if u.Handshake.Reasons&HandshakeRekey == 0 {
					t.Fatal("missing manual refresh advice")
				}
				controls := []Packet{control()}
				n, err := q.a.HandleWake(now, controls)
				want := 0
				if automatic {
					want = 1
				}
				if err != nil || n.N != want {
					t.Fatalf("refresh output: %d, %v; want %d", n.N, err, want)
				}
				if automatic {
					typ, _, err := ParseHeader(controls[0].Bytes())
					if err != nil || typ != MessageInitiationType {
						t.Fatalf("refresh packet: type=%d, err=%v", typ, err)
					}
				}
			})
		}
	}
}

func TestRetiredPreviousReceiptDoesNotRefreshCurrent(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: HandshakePolicy{Rekey: true}})
	establish(t, q, epoch)
	held := seal(t, q.b, epoch, plaintext(3, 0))
	establish(t, q, epoch.Add(RekeyTimeout))
	now := epoch.Add(171 * time.Second)
	previous, current := q.a.keypairs.previous, q.a.keypairs.current
	var results [1]ReceiveResult
	r, err := q.a.Transport().Receive(now, []Packet{held}, results[:])
	if err != nil || r.N != 1 || results[0].Err != nil {
		t.Fatalf("previous-key receive: %+v, %+v, %v", r, results, err)
	}
	// Creating a responder-next session retires previous without replacing
	// current. The delayed receipt must not refresh the still-current key.
	init, _, err := q.b.Initiate(now, control())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := q.a.HandleInitiation(now, prepare(t, admit(t, q.aa, now, init)), control()); err != nil {
		t.Fatal(err)
	}
	if !previous.retired.Load() || q.a.keypairs.current != current {
		t.Fatal("expected retired previous and unchanged current")
	}
	u := applyActivity(t, q.a, now, r)
	if q.a.timers.receiveRefreshSent || u.Handshake.Reasons&HandshakeRekey != 0 {
		t.Fatal("retired-key receipt requested refresh")
	}
}
