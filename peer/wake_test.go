// SPDX-License-Identifier: MIT

package peer

import (
	"errors"
	"testing"
	"time"
)

func TestWakeMergeHardDeadline(t *testing.T) {
	soft := window(epoch, time.Second)
	hard := window(epoch.Add(10*time.Millisecond), 0)
	for _, w := range []Wake{soft.merge(hard), hard.merge(soft)} {
		if !w.Earliest.Equal(epoch) || !w.Deadline.Equal(hard.Deadline) {
			t.Fatal(w)
		}
	}
}

func TestPersistentEnableDisableAndReconfigure(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	if _, err := q.a.SetPersistentKeepalive(epoch, 20*time.Second, KeepaliveImmediate); err != nil {
		t.Fatal(err)
	}
	if !q.a.update().Wake.Earliest.Equal(epoch) {
		t.Fatal("enable did not arm immediately")
	}
	if n, err := q.a.HandleWake(epoch, nil); n.N != 0 || !errors.Is(err, ErrShortBuffer) {
		t.Fatal("missing output lost intent")
	}
	slots := []Packet{control()}
	if n, err := q.a.HandleWake(epoch, slots); n.N != 1 || err != nil {
		t.Fatalf("keepalive did not establish session: %d %v", n.N, err)
	}
	if typ, _, _ := ParseHeader(slots[0].Bytes()); typ != MessageInitiationType {
		t.Fatal("no-session persistence did not initiate")
	}
	if _, err := q.a.SetPersistentKeepalive(epoch, time.Minute, KeepaliveAfterInterval); err != nil {
		t.Fatal(err)
	}
	if !q.a.timers.persistent.Equal(epoch.Add(time.Minute)) {
		t.Fatal("increase")
	}
	if _, err := q.a.SetPersistentKeepalive(epoch, time.Second, KeepaliveAfterInterval); err != nil {
		t.Fatal(err)
	}
	if !q.a.timers.persistent.Equal(epoch.Add(time.Second)) {
		t.Fatal("decrease")
	}
	if _, err := q.a.SetPersistentKeepalive(epoch, 0, KeepaliveAfterInterval); err != nil {
		t.Fatal(err)
	}
	if _, err := q.a.SetHandshakePolicy(epoch, manualPolicy); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if n, err := q.a.HandleWake(epoch.Add(time.Second), nil); n.N != 0 || err != nil {
			t.Fatal("disabled keepalive woke")
		}
		if !q.a.update().Wake.Earliest.After(epoch.Add(time.Second)) {
			t.Fatal("zero-delay wake loop")
		}
	}
}

func TestManualSuppressesAllAutonomousHandshakes(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: manualPolicy})
	if _, _, err := q.a.Initiate(epoch, control()); err != nil {
		t.Fatal(err)
	}
	if !q.a.timers.retransmit.IsZero() {
		t.Fatal("manual retransmission armed")
	}
	if _, err := q.a.SetPersistentKeepalive(epoch, time.Second, KeepaliveImmediate); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		now := epoch.Add(time.Duration(i) * time.Second)
		if n, err := q.a.HandleWake(now, nil); n.N != 0 || !errors.Is(err, ErrNoSession) {
			t.Fatalf("manual emitted %d %v", n.N, err)
		}
		if q.a.update().Handshake.Reasons == 0 || !q.a.update().Wake.Earliest.After(now) {
			t.Fatal("manual intent invisible or looping")
		}
	}
	if _, err := q.a.SetPersistentKeepalive(epoch.Add(6*time.Second), 0, KeepaliveAfterInterval); err != nil {
		t.Fatal(err)
	}
	if _, err := q.a.SetHandshakePolicy(epoch.Add(6*time.Second), automaticPolicy); err != nil {
		t.Fatal(err)
	}
	if n, err := q.a.HandleWake(epoch.Add(6*time.Second), []Packet{control()}); n.N != 1 || err != nil {
		t.Fatal("reenabling did not retry")
	}
	if _, err := q.a.SetHandshakePolicy(epoch.Add(6*time.Second), manualPolicy); err != nil {
		t.Fatal(err)
	}
	if n, err := q.a.HandleWake(epoch.Add(12*time.Second), nil); n.N != 0 || err != nil {
		t.Fatal("disabled mid-attempt still retries")
	}
}

func TestRetryCountAndSharedRateGuard(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	if _, _, err := q.a.Initiate(epoch, control()); err != nil {
		t.Fatal(err)
	}
	count := 1
	now := epoch
	for i := 0; i < 25; i++ {
		now = now.Add(RekeyTimeout)
		slots := []Packet{control()}
		n, err := q.a.HandleWake(now, slots)
		if err != nil {
			t.Fatal(err)
		}
		count += n.N
	}
	// Device's attempts >18 means initial+19 retries (20 total).
	if count != MaxTimerHandshakes+2 {
		t.Fatalf("got %d initiations", count)
	}
	if !q.a.timers.retransmit.IsZero() || !q.a.timers.sendKeepalive.IsZero() {
		t.Fatal("giveup timers")
	}
	if !q.a.update().Wake.Deadline.Equal(q.a.handshake.lastSentHandshake.Add(3 * RejectAfterTime)) {
		t.Fatal("handshake material has no bounded cleanup")
	}
	// Receiving an initiation and sending a response updates the common guard.
	q2 := newPair(t, Config{HandshakePolicy: automaticPolicy})
	if _, _, err := q2.a.Initiate(epoch, control()); err != nil {
		t.Fatal(err)
	}
	crossed, _, err := q2.b.Initiate(epoch.Add(time.Second), control())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = q2.a.HandleInitiation(epoch.Add(time.Second), prepare(t, admit(t, q2.aa, epoch.Add(time.Second), crossed)), control()); err != nil {
		t.Fatal(err)
	}
	if n, err := q2.a.HandleWake(epoch.Add(5*time.Second), []Packet{control()}); n.N != 0 || err != nil {
		t.Fatal("retry bypassed response guard")
	}
	if !q2.a.timers.retransmit.Equal(epoch.Add(6 * time.Second)) {
		t.Fatal("retry not deferred")
	}
}

func TestKeepaliveRekeyExpiryAndCleanupRecovery(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	establish(t, q, epoch)
	if _, err := q.a.SetPersistentKeepalive(epoch, 25*time.Second, KeepaliveAfterInterval); err != nil {
		t.Fatal(err)
	}
	// Skip the immediate wake to test late processing.
	now := epoch.Add(121 * time.Second)
	slots := []Packet{control(), control()}
	n, err := q.a.HandleWake(now, slots)
	if err != nil || n.N != 2 {
		t.Fatalf("keepalive age rekey: %d %v", n.N, err)
	}
	typ, _, _ := ParseHeader(slots[0].Bytes())
	typ2, _, _ := ParseHeader(slots[1].Bytes())
	if typ != MessageTransportType || typ2 != MessageInitiationType {
		t.Fatal("keepalive skipped freshness bookkeeping")
	}
	// Cleanup must run BEFORE any coincident output, retaining persistence.
	now = epoch.Add(1000 * time.Second)
	slots = []Packet{control(), control()}
	n, err = q.a.HandleWake(now, slots)
	if !errors.Is(err, ErrNoSession) || n.N != 0 {
		t.Fatalf("cleanup must not restart an attempted episode: %d %v", n.N, err)
	}
	if q.a.keypairs.current != nil || q.a.persistent == 0 || q.a.timers.persistent.IsZero() {
		t.Fatal("cleanup lost persistence or retained old key")
	}
	if _, err = q.b.HandleWake(now, nil); err != nil {
		t.Fatal(err)
	}
	q.a.Close()
	if q.indexes.Len() != 0 {
		t.Fatal("key/index cleanup leaked")
	}
}

func TestPassiveKeepaliveCancelledByHandshakeAndBatchTimers(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	establish(t, q, epoch)
	packets := []Packet{plaintext(10, 0), plaintext(10, 0)}
	if _, err := q.a.Send(epoch, packets); err != nil {
		t.Fatal(err)
	}
	results := make([]ReceiveResult, 2)
	if _, err := q.b.Receive(epoch, packets, results); err != nil {
		t.Fatal(err)
	}
	if !q.b.timers.sendKeepalive.Equal(epoch.Add(KeepaliveTimeout)) {
		t.Fatal("passive keepalive")
	}
	if !q.b.timers.needAnotherKeepalive {
		t.Fatal("batch aggregation lost serial extra-keepalive intent")
	}
	if _, _, err := q.b.Initiate(epoch.Add(6*time.Second), control()); err != nil {
		t.Fatal(err)
	}
	if !q.b.timers.sendKeepalive.IsZero() {
		t.Fatal("initiation did not cancel passive keepalive")
	}
}

func TestKeyAndHandshakeIndexCleanup(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: manualPolicy})
	establish(t, q, epoch)
	at := epoch.Add(3 * RejectAfterTime)
	if n, err := q.a.HandleWake(at, nil); n.N != 0 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := q.b.HandleWake(at, nil); n.N != 0 || err != nil {
		t.Fatal(n, err)
	}
	if q.indexes.Len() != 0 || !q.a.update().Wake.Earliest.IsZero() {
		t.Fatal("key cleanup")
	}
	if _, _, err := q.a.Initiate(at, control()); err != nil {
		t.Fatal(err)
	}
	if _, err := q.a.HandleWake(at.Add(3*RejectAfterTime), nil); err != nil {
		t.Fatal(err)
	}
	if q.indexes.Len() != 0 {
		t.Fatal("pending handshake cleanup")
	}
}

func TestReceiveBatchKeepaliveIntentMatchesSerial(t *testing.T) {
	for _, pending := range []bool{false, true} {
		for _, dataPackets := range []int{0, 1, 2} {
			var batchTimers, serialTimers timerState
			for _, batch := range []bool{false, true} {
				q := newPair(t, Config{HandshakePolicy: automaticPolicy})
				establish(t, q, epoch)
				if pending {
					q.b.onDataReceived(epoch)
				}
				var packets []Packet
				for i := 0; i < dataPackets; i++ {
					packets = append(packets, seal(t, q.a, epoch, plaintext(3, 0)))
				}
				keep := seal(t, q.a, epoch, plaintext(0, 0))
				replay := clone(keep)
				if result := receive(t, q.b, epoch, keep); result.Err != nil {
					t.Fatal(result.Err)
				}
				packets = append(packets, replay, seal(t, q.a, epoch, plaintext(0, 0)), Packet{Buffer: make([]byte, 4), Size: 4})
				if batch {
					results := make([]ReceiveResult, len(packets))
					if _, err := q.b.Receive(epoch, packets, results); err != nil {
						t.Fatal(err)
					}
					batchTimers = q.b.timers
				} else {
					for _, packet := range packets {
						receive(t, q.b, epoch, packet)
					}
					serialTimers = q.b.timers
				}
			}
			if batchTimers != serialTimers {
				t.Fatalf("pending=%v data=%d batch=%+v serial=%+v", pending, dataPackets, batchTimers, serialTimers)
			}
			wantAnother := dataPackets > 1 || (pending && dataPackets > 0)
			if batchTimers.needAnotherKeepalive != wantAnother {
				t.Fatalf("non-data contributed to intent: pending=%v data=%d", pending, dataPackets)
			}
		}
	}
}

func TestReceiveBatchKeyPromotionRefreshMatchesSerial(t *testing.T) {
	for _, policy := range []struct {
		name  string
		value HandshakePolicy
	}{{"automaticPolicy", automaticPolicy}, {"manualPolicy", manualPolicy}} {
		t.Run(policy.name, func(t *testing.T) {
			for _, order := range []struct {
				name              string
				confirmationFirst bool
			}{{"OldThenConfirmation", false}, {"ConfirmationThenOld", true}} {
				t.Run(order.name, func(t *testing.T) {
					type state struct {
						timers         timerState
						needsHandshake bool
						wake           Wake
					}
					var serial, batch state
					for _, mode := range []string{"Serial", "Batch"} {
						t.Run(mode, func(t *testing.T) {
							q := newPair(t, Config{HandshakePolicy: policy.value})
							establish(t, q, epoch)
							now := epoch.Add(RejectAfterTime - KeepaliveTimeout - RekeyTimeout + time.Second)
							oldKey := q.a.keypairs.current
							old := seal(t, q.b, now, plaintext(3, 0))

							// Reverse the initiator role and retain both old-session data
							// and the fresh responder-next confirmation for one receive.
							init, _, err := q.b.Initiate(now, control())
							if err != nil {
								t.Fatal(err)
							}
							resp, _, err := q.a.HandleInitiation(now, prepare(t, admit(t, q.aa, now, init)), control())
							if err != nil {
								t.Fatal(err)
							}
							conf, _, err := q.b.HandleResponse(now, admit(t, q.ab, now, resp), control())
							if err != nil {
								t.Fatal(err)
							}
							newKey := q.a.keypairs.next
							if newKey == nil || newKey.isInitiator || q.a.keypairs.current != oldKey || !oldKey.isInitiator {
								t.Fatal("expected aged initiator-current and fresh responder-next")
							}
							packets := []Packet{old, conf}
							want := []Disposition{Data, Keepalive}
							if order.confirmationFirst {
								packets[0], packets[1] = packets[1], packets[0]
								want[0], want[1] = want[1], want[0]
							}
							results := make([]ReceiveResult, len(packets))
							if mode == "Batch" {
								if n, err := q.a.Receive(now, packets, results); n.N != len(packets) || err != nil {
									t.Fatal(n, err)
								}
							} else {
								for i, packet := range packets {
									results[i] = receive(t, q.a, now, packet)
									if i == 0 && !order.confirmationFirst && !q.a.timers.receiveRefreshSent {
										t.Fatal("old-current receive did not request refresh before confirmation")
									}
								}
							}
							for i, result := range results {
								if result.Err != nil || result.Disposition != want[i] {
									t.Fatalf("slot %d: %+v", i, result)
								}
							}
							if q.a.keypairs.current != newKey || q.a.keypairs.previous != oldKey || q.a.keypairs.next != nil || !q.a.LastHandshake().Equal(now) {
								t.Fatal("confirmation did not complete key promotion")
							}
							got := state{q.a.timers, (q.a.update().Handshake.Reasons != 0), q.a.update().Wake}
							if mode == "Batch" {
								batch = got
							} else {
								serial = got
							}
							if got.needsHandshake || got.timers.receiveRefreshSent || got.timers.refreshNeeded || !got.timers.refresh.IsZero() {
								t.Errorf("completed rekey retained stale freshness intent: %+v", got)
							}
							if got.wake != window(now.Add(KeepaliveTimeout), time.Second) {
								t.Errorf("expected only passive keepalive before cleanup, got %+v", got.wake)
							}
							if n, err := q.a.HandleWake(now.Add(RekeyTimeout), []Packet{control()}); n.N != 0 || err != nil {
								t.Errorf("completed rekey emitted work at handshake guard: %d %v", n.N, err)
							}
						})
					}
					if batch != serial {
						t.Fatalf("batch/serial state differs:\nbatch: %+v\nserial: %+v", batch, serial)
					}
				})
			}
		})
	}
}

func TestConfiguredPersistenceStartAndManualRefreshReenable(t *testing.T) {
	q := newPair(t, Config{PersistentKeepalive: 10 * time.Second, KeepaliveStart: KeepaliveImmediate, HandshakePolicy: manualPolicy})
	if !q.a.update().Wake.Earliest.Equal(epoch) {
		t.Fatal("configured persistence not armed")
	}
	establish(t, q, epoch)
	now := epoch.Add(RekeyAfterTime + time.Nanosecond)
	seal(t, q.a, now, plaintext(0, 0))
	if !q.a.timers.refreshNeeded || !q.a.timers.refresh.IsZero() {
		t.Fatal("manual refresh intent")
	}
	if _, err := q.a.SetHandshakePolicy(now, automaticPolicy); err != nil {
		t.Fatal(err)
	}
	if !q.a.timers.refresh.Equal(now) {
		t.Fatal("automatic policy lost pending manual refresh")
	}
	if n, err := q.a.HandleWake(now, []Packet{control()}); n.N != 1 || err != nil {
		t.Fatal(n, err)
	}
}
