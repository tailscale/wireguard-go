// SPDX-License-Identifier: MIT

package peer

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type gatedAEAD struct {
	cipher.AEAD
	entered, release chan struct{}
	first            atomic.Bool
	open             bool
}

func (g *gatedAEAD) gate(open bool) {
	if g.open == open && g.first.CompareAndSwap(false, true) {
		close(g.entered)
		<-g.release
	}
}

func (g *gatedAEAD) Seal(dst, nonce, plaintext, additional []byte) []byte {
	g.gate(false)
	return g.AEAD.Seal(dst, nonce, plaintext, additional)
}

func (g *gatedAEAD) Open(dst, nonce, ciphertext, additional []byte) ([]byte, error) {
	g.gate(true)
	return g.AEAD.Open(dst, nonce, ciphertext, additional)
}

func gateCrypto(t *testing.T, a cipher.AEAD, open bool) *gatedAEAD {
	t.Helper()
	g := &gatedAEAD{AEAD: a, entered: make(chan struct{}), release: make(chan struct{}), open: open}
	t.Cleanup(func() {
		select {
		case <-g.release:
		default:
			close(g.release)
		}
	})
	return g
}

func waitGate(t *testing.T, g *gatedAEAD) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("crypto did not enter")
	}
}

type transportCompletion struct {
	result TransportResult
	err    error
}

func waitTransport(t *testing.T, done <-chan transportCompletion) transportCompletion {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("transport did not finish")
		return transportCompletion{}
	}
}

func applyActivity(t testing.TB, p *Peer, now time.Time, r TransportResult) Update {
	t.Helper()
	u, err := p.ApplyTransport(now, r.Activity)
	if err != nil {
		t.Fatal("apply transport", err)
	}
	return u
}

func TestTransportConcurrentLanesAndControl(t *testing.T) {
	q := newPair(t, Config{PaddingMTU: 1420})
	establish(t, q, epoch)
	incoming := seal(t, q.b, epoch, plaintext(1280, 8))
	k := q.a.keypairs.current
	g := gateCrypto(t, k.send, false)
	k.send = g // Before sharing the published key with any transport caller.
	tr := q.a.Transport()
	outgoing := benchPackets(64, 1280)
	first := k.sendNonce.Load()
	done := make(chan transportCompletion, 1)
	go func() {
		r, err := tr.Send(epoch, outgoing)
		done <- transportCompletion{r, err}
	}()
	waitGate(t, g)

	var results [1]ReceiveResult
	rx, err := tr.Receive(epoch, []Packet{incoming}, results[:])
	if err != nil || rx.N != 1 || results[0].Disposition != Data || results[0].Packet.Size != 1280 {
		t.Fatal("concurrent receive", rx, results, err)
	}
	at := epoch.Add(time.Second)
	applyActivity(t, q.a, at, rx)
	if _, err := q.a.SetPersistentKeepalive(at, time.Second, KeepaliveImmediate); err != nil {
		t.Fatal(err)
	}
	controls := []Packet{control()}
	wake, err := q.a.HandleWake(at, controls)
	if err != nil || wake.N != 1 {
		t.Fatal("concurrent keepalive", wake, err)
	}
	if got := binary.LittleEndian.Uint64(controls[0].Bytes()[8:]); got != first+64 {
		t.Fatalf("control reused TX nonce: got %d want %d", got, first+64)
	}
	if rr := receive(t, q.b, at, controls[0]); rr.Disposition != Keepalive {
		t.Fatal(rr)
	}
	close(g.release)
	tx := waitTransport(t, done)
	if tx.err != nil || tx.result.N != 64 {
		t.Fatal(tx)
	}
	applyActivity(t, q.a, at, tx.result)
	remoteResults := make([]ReceiveResult, 64)
	if r, err := q.b.Receive(at, outgoing, remoteResults); err != nil || r.N != 64 {
		t.Fatal(r, err)
	}
	for _, rr := range remoteResults {
		if rr.Err != nil || rr.Disposition != Data || rr.Packet.Size != 1280 {
			t.Fatal(rr)
		}
	}
}

func TestTransportPinnedKeyRetirement(t *testing.T) {
	for _, tx := range []bool{false, true} {
		for _, action := range []string{"Close", "Cleanup", "ReplaceIdentity"} {
			t.Run(action+map[bool]string{true: "/TX", false: "/RX"}[tx], func(t *testing.T) {
				q := newPair(t, Config{})
				establish(t, q, epoch)
				k := q.a.keypairs.current
				var g *gatedAEAD
				packets := []Packet{plaintext(64, 8)}
				var results [1]ReceiveResult
				if tx {
					g = gateCrypto(t, k.send, false)
					k.send = g
				} else {
					packets[0] = seal(t, q.b, epoch, packets[0])
					g = gateCrypto(t, k.receive, true)
					k.receive = g
				}
				tr := q.a.Transport()
				done := make(chan transportCompletion, 1)
				go func() {
					var r TransportResult
					var err error
					if tx {
						r, err = tr.Send(epoch, packets)
					} else {
						r, err = tr.Receive(epoch, packets, results[:])
					}
					done <- transportCompletion{r, err}
				}()
				waitGate(t, g)
				at := epoch.Add(time.Second)
				switch action {
				case "Close":
					q.a.Close()
				case "Cleanup":
					at = epoch.Add(3 * RejectAfterTime)
					if _, err := q.a.HandleWake(at, nil); err != nil {
						t.Fatal(err)
					}
				case "ReplaceIdentity":
					if _, err := q.a.ReplaceIdentity(at, localIdentity(t, 2, q.ia)); err != nil {
						t.Fatal(err)
					}
				}
				close(g.release)
				r := waitTransport(t, done)
				if r.err != nil || r.result.N != 1 {
					t.Fatal("pinned key was destroyed", r)
				}
				if !tx && (results[0].Err != nil || results[0].Disposition != Data) {
					t.Fatal(results)
				}
				beforeTimers := q.a.timers
				_, err := q.a.ApplyTransport(at, r.result.Activity)
				if action != "Close" && q.a.timers != beforeTimers {
					t.Fatal("late receipt resurrected retired/generation maintenance")
				}
				if action == "Close" {
					if !errors.Is(err, ErrClosed) {
						t.Fatal(err)
					}
					if _, err := tr.Send(at, nil); !errors.Is(err, ErrClosed) {
						t.Fatal("closed publication", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if action != "Close" && q.a.HasSession(at) {
					t.Fatal("retired key resurrected sending")
				}
			})
		}
	}
}

func TestTransportReceiptClockOrderingAndErrors(t *testing.T) {
	q := newPair(t, Config{})
	tr := q.a.Transport()
	bad := []Packet{{Offset: -1}}
	a, err := tr.Send(epoch.Add(2*time.Second), bad)
	if !errors.Is(err, ErrInvalidBuffer) || !a.Activity.Valid() {
		t.Fatal(a, err)
	}
	b, err := tr.Send(epoch.Add(3*time.Second), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.a.ApplyTransport(epoch.Add(3*time.Second), b.Activity); !errors.Is(err, ErrActivity) {
		t.Fatal("out-of-order accepted", err)
	}
	if _, err := q.b.ApplyTransport(epoch.Add(3*time.Second), a.Activity); !errors.Is(err, ErrActivity) {
		t.Fatal("foreign receipt", err)
	}
	if _, err := q.a.ApplyTransport(epoch, a.Activity); !errors.Is(err, ErrTime) {
		t.Fatal("receipt from future", err)
	}
	if q.a.now != epoch || q.a.appliedTX != 0 {
		t.Fatal("failed application mutated clock/sequence")
	}
	applyActivity(t, q.a, epoch.Add(3*time.Second), a)
	applyActivity(t, q.a, epoch.Add(3*time.Second), b)
	if _, err := q.a.ApplyTransport(epoch.Add(4*time.Second), b.Activity); !errors.Is(err, ErrActivity) || q.a.now != epoch.Add(3*time.Second) {
		t.Fatal("receipt replay", err)
	}
	if r, err := tr.Send(epoch, nil); !errors.Is(err, ErrTime) || r.Activity.Valid() {
		t.Fatal("TX backwards clock", r, err)
	}
	// RX's clock is independent of TX and the advanced control clock.
	rx, err := tr.Receive(epoch.Add(time.Second), nil, nil)
	if err != nil {
		t.Fatal("independent RX clock", err)
	}
	applyActivity(t, q.a, epoch.Add(3*time.Second), rx)
	if _, err := q.a.ApplyTransport(epoch, TransportActivity{}); !errors.Is(err, ErrActivity) {
		t.Fatal(err)
	}
}

func TestTransportConfirmationRequiresOwnerAndGeneration(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		t.Run(map[bool]string{false: "Confirm", true: "StaleGeneration"}[rotate], func(t *testing.T) {
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
			if err != nil || results[0].Disposition != Keepalive || q.b.HasSession(epoch) || !q.b.LastHandshake().IsZero() {
				t.Fatal("RX prematurely promoted", rx, results, err)
			}
			at := epoch.Add(time.Second)
			if rotate {
				if _, err := q.b.ReplaceIdentity(at, localIdentity(t, 2, q.ib)); err != nil {
					t.Fatal(err)
				}
				before := q.b.timers
				applyActivity(t, q.b, at, rx)
				if q.b.timers != before || q.b.HasSession(at) || !q.b.LastHandshake().IsZero() {
					t.Fatal("old generation completed recovery")
				}
			} else {
				u := applyActivity(t, q.b, at, rx)
				if !q.b.HasSession(at) || q.b.LastHandshake() != at || u.Handshake.Pending || u.Handshake.Reasons != 0 {
					t.Fatal("owner confirmation", u)
				}
			}
		})
	}
}

func TestTransportNonceExhaustionAndBounds(t *testing.T) {
	q := newPair(t, Config{})
	establish(t, q, epoch)
	k := q.a.keypairs.current
	tr := q.a.Transport()
	bad := []Packet{plaintext(64, 8), {Buffer: make([]byte, 16), Offset: 16, Size: 0}}
	before := clone(bad[0])
	nonce := k.sendNonce.Load()
	r, err := tr.Send(epoch, bad)
	if !errors.Is(err, ErrShortBuffer) || r.N != 0 || k.sendNonce.Load() != nonce || !bytes.Equal(bad[0].Buffer, before.Buffer) {
		t.Fatal("bounds mutated prefix", r, err)
	}
	applyActivity(t, q.a, epoch, r)
	k.sendNonce.Store(RejectAfterMessages - 1)
	packets := []Packet{plaintext(64, 8), plaintext(64, 8)}
	before = clone(packets[1])
	r, err = tr.Send(epoch, packets)
	if !errors.Is(err, ErrExhausted) || r.N != 1 || k.sendNonce.Load() != RejectAfterMessages || !bytes.Equal(packets[1].Buffer, before.Buffer) {
		t.Fatal("exhaustion prefix", r, err)
	}
	u := applyActivity(t, q.a, epoch, r)
	if u.Handshake.Reasons&HandshakeRekey == 0 {
		t.Fatal("counter exhaustion lost freshness", u)
	}
	if got := binary.LittleEndian.Uint64(packets[0].Bytes()[8:]); got != RejectAfterMessages-1 {
		t.Fatal("invalid nonce", got)
	}

	var key keypair
	key.sendNonce.Store(RejectAfterMessages - 8192)
	var wg sync.WaitGroup
	var reserved atomic.Uint64
	for range 16 {
		wg.Go(func() {
			_, n := key.reserve(8195)
			reserved.Add(uint64(n))
		})
	}
	wg.Wait()
	if reserved.Load() != 8192 || key.sendNonce.Load() != RejectAfterMessages {
		t.Fatal("reservation overflow", reserved.Load(), key.sendNonce.Load())
	}
}

func TestTransportReplayAndZeroAllocations(t *testing.T) {
	q := newPair(t, Config{})
	establish(t, q, epoch)
	a, b := q.a.Transport(), q.b.Transport()
	packets := benchPackets(16, 1280)
	results := make([]ReceiveResult, 16)
	allocs := testing.AllocsPerRun(100, func() {
		resetPackets(packets, 1280)
		tx, err := a.Send(epoch, packets)
		if err != nil || tx.N != 16 {
			t.Fatal(tx, err)
		}
		applyActivity(t, q.a, epoch, tx)
		rx, err := b.Receive(epoch, packets, results)
		if err != nil || rx.N != 16 {
			t.Fatal(rx, err)
		}
		applyActivity(t, q.b, epoch, rx)
		for _, rr := range results {
			if rr.Err != nil || rr.Disposition != Data || rr.Packet.Size != 1280 {
				t.Fatal(rr)
			}
		}
	})
	if allocs != 0 {
		t.Fatal("transport/reconciliation allocated", allocs)
	}
	resetPackets(packets, 1280)
	tx, err := a.Send(epoch, packets)
	if err != nil {
		t.Fatal(err)
	}
	applyActivity(t, q.a, epoch, tx)
	wireCopy := clone(packets[0])
	rx, err := b.Receive(epoch, packets, results)
	if err != nil {
		t.Fatal(err)
	}
	applyActivity(t, q.b, epoch, rx)
	rx, err = b.Receive(epoch, []Packet{wireCopy}, results[:1])
	if err != nil || results[0].Err != ErrReplay || results[0].Packet.Buffer != nil {
		t.Fatal("replay exposed plaintext", results[0], err)
	}
	applyActivity(t, q.b, epoch, rx)
}
