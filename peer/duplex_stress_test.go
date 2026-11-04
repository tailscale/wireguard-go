// SPDX-License-Identifier: MIT

package peer

import (
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestTransportFullDuplexStress(t *testing.T) {
	for _, bulk := range []bool{false, true} {
		t.Run(fmt.Sprintf("bulk=%t", bulk), func(t *testing.T) {
			testTransportFullDuplexStress(t, bulk)
		})
	}
}

func testTransportFullDuplexStress(t *testing.T, bulk bool) {
	q := newPair(t, Config{PaddingMTU: 1420})
	establish(t, q, epoch)
	const turns, batch, depth = 128, 16, 4
	type receipt struct {
		owner *Peer
		r     TransportResult
		err   error
	}
	events := make(chan receipt, 16)
	errors := make(chan error, 4)
	var wg sync.WaitGroup
	for _, direction := range [][2]*Peer{{q.a, q.b}, {q.b, q.a}} {
		from, to := direction[0], direction[1]
		tx, rx := from.Transport(), to.Transport()
		free, wire := make(chan []Packet, depth), make(chan []Packet, depth)
		for range depth {
			free <- benchPackets(batch, 1280)
		}
		wg.Go(func() {
			for i := range turns {
				packets := <-free
				resetPackets(packets, 1280)
				for j, p := range packets {
					binary.LittleEndian.PutUint64(p.Bytes(), uint64(i*batch+j))
				}
				r, err := tx.Send(epoch, packets)
				events <- receipt{from, r, err}
				wire <- packets
			}
		})
		wg.Go(func() {
			results := make([]ReceiveResult, batch)
			var bad error
			for i := range turns {
				packets := <-wire
				r, err := rx.Receive(epoch, packets, results)
				events <- receipt{to, r, err}
				for j, rr := range results {
					if rr.Err != nil || rr.Disposition != Data || rr.Packet.Size != 1280 {
						bad = fmt.Errorf("bad receive turn %d slot %d: %v", i, j, rr.Err)
					} else if n := binary.LittleEndian.Uint64(rr.Packet.Bytes()); n != uint64(i*batch+j) {
						bad = fmt.Errorf("payload/order %d != %d", n, i*batch+j)
					}
				}
				free <- packets // The slab lease returns only after RX finishes.
			}
			errors <- bad
		})
	}
	// This goroutine is the serialized control owner of both peers. TX/RX and
	// configuration progress independently. All handoffs and slabs are bounded.
	var pendingA, pendingB [16]TransportActivity
	for handled := 0; handled < turns*4; {
		na, nb := 0, 0
	collect:
		for turn := 0; turn < 16 && handled < turns*4; turn++ {
			var e receipt
			if turn == 0 {
				e = <-events
			} else {
				select {
				case e = <-events:
				default:
					break collect
				}
			}
			handled++
			if e.err != nil || e.r.N != batch {
				t.Errorf("transport turn %d: %d %v", handled, e.r.N, e.err)
			}
			if !bulk {
				if _, err := e.owner.ApplyTransport(epoch, e.r.Activity); err != nil {
					t.Errorf("receipt turn %d: %v", handled, err)
				}
				break
			}
			if e.owner == q.a {
				pendingA[na] = e.r.Activity
				na++
			} else {
				pendingB[nb] = e.r.Activity
				nb++
			}
		}
		for i, p := range []*Peer{q.a, q.b} {
			activities := pendingA[:na]
			if i == 1 {
				activities = pendingB[:nb]
			}
			if len(activities) > 0 {
				if r, err := p.ApplyTransportBatch(epoch, activities); err != nil || r.N != len(activities) {
					t.Errorf("bulk receipt: %d %v", r.N, err)
				}
			}
			checkWakeCache(t, p)
			if _, err := p.SetPresharedKey(epoch, PresharedKey{}); err != nil {
				t.Error(err)
			}
		}
	}
	wg.Wait()
	for range 2 {
		if err := <-errors; err != nil {
			t.Error(err)
		}
	}
}

func TestTransportRekeyWhileTXPinned(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: HandshakePolicy{Rekey: true}})
	establish(t, q, epoch)
	old := q.a.keypairs.current
	g := gateCrypto(t, old.send, false)
	old.send = g
	tr := q.a.Transport()
	packets := []Packet{plaintext(1280, 8)}
	done := make(chan transportCompletion, 1)
	go func() {
		r, err := tr.Send(epoch, packets)
		done <- transportCompletion{r, err}
	}()
	waitGate(t, g)
	// Two complete rekeys retire even the previous key while old TX is pinned.
	at := epoch.Add(RekeyTimeout)
	establish(t, q, at)
	at = at.Add(RekeyTimeout)
	establish(t, q, at)
	if !old.retired.Load() || q.a.Transport().view.Load().keys.current == old {
		t.Fatal("old session not retired/unpublished")
	}
	close(g.release)
	r := waitTransport(t, done)
	if r.err != nil || r.result.N != 1 {
		t.Fatal(r)
	}
	u := applyActivity(t, q.a, at, r.result)
	if u.Handshake.Reasons&HandshakeRekey != 0 || q.a.LastHandshake() != at {
		t.Fatal("old TX disturbed fresh session", u)
	}
	if rr := receive(t, q.b, at, packets[0]); rr.Disposition != Dropped {
		t.Fatal("retired index accepted", rr)
	}
}

func TestTransportDoesNotUseKeysBeforeCreation(t *testing.T) {
	q := newPair(t, Config{})
	at := epoch.Add(time.Second)
	establish(t, q, at)
	tr := q.a.Transport()
	packets := []Packet{plaintext(64, 8)}
	before := clone(packets[0])
	r, err := tr.Send(epoch, packets)
	if err != ErrNoSession || r.N != 0 || packets[0].Offset != before.Offset {
		t.Fatal("future key used for TX", r, err)
	}
	applyActivity(t, q.a, at, r)
	wire := seal(t, q.b, at, plaintext(64, 8))
	var results [1]ReceiveResult
	r, err = tr.Receive(epoch, []Packet{wire}, results[:])
	if err != nil || results[0].Disposition != Dropped {
		t.Fatal("future key used for RX", results, err)
	}
	applyActivity(t, q.a, at, r)
}
