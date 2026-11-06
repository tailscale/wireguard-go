// SPDX-License-Identifier: MIT

package peer

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"
	"time"
)

// Packet ownership is established by the caller, not checked by the core.
// These fixtures use disjoint bounded slab regions in arbitrary vector order.
func TestUnorderedPacketBatches(t *testing.T) {
	for _, order := range []string{"ordered", "reversed", "shuffled"} {
		t.Run(order, func(t *testing.T) {
			q := newPair(t, Config{})
			establish(t, q, epoch)
			packets := benchPackets(64, 1280)
			prefix := bytes.Repeat([]byte{0xa7}, 24)
			for i, p := range packets {
				copy(p.Buffer[:24], prefix)
				for j := range p.Bytes() {
					p.Bytes()[j] = byte(i + j)
				}
			}
			switch order {
			case "reversed":
				for i, j := 0, len(packets)-1; i < j; i, j = i+1, j-1 {
					packets[i], packets[j] = packets[j], packets[i]
				}
			case "shuffled":
				rand.New(rand.NewSource(1)).Shuffle(len(packets), func(i, j int) {
					packets[i], packets[j] = packets[j], packets[i]
				})
			}
			want := make([][]byte, len(packets))
			for i, p := range packets {
				want[i] = bytes.Clone(p.Bytes())
			}
			if r, err := q.a.Send(epoch, packets); err != nil || r.N != len(packets) {
				t.Fatal("send", r, err)
			}
			// Delivery order need not match encryption order either.
			for i, j := 0, len(packets)-1; i < j; i, j = i+1, j-1 {
				packets[i], packets[j] = packets[j], packets[i]
				want[i], want[j] = want[j], want[i]
			}
			results := make([]ReceiveResult, len(packets))
			if r, err := q.b.Receive(epoch, packets, results); err != nil || r.N != len(packets) {
				t.Fatal("receive", r, err)
			}
			for i, result := range results {
				if result.Err != nil || result.Disposition != Data || !bytes.Equal(result.Packet.Bytes(), want[i]) {
					t.Fatalf("slot %d: %+v", i, result)
				}
				if !bytes.Equal(packets[i].Buffer[:24], prefix) {
					t.Fatalf("slot %d: prefix changed", i)
				}
			}
		})
	}
}

func TestReceiveBoundsBeforeMutation(t *testing.T) {
	q := newPair(t, Config{})
	establish(t, q, epoch)
	wire := seal(t, q.a, epoch, plaintext(64, 24))
	before := clone(wire)
	for _, bad := range []Packet{
		{Buffer: make([]byte, 40), Offset: -1, Size: 1},
		{Buffer: make([]byte, 40), Offset: 41},
		{Buffer: make([]byte, 40), Offset: 20, Size: -1},
		{Buffer: make([]byte, 40), Offset: 20, Size: int(^uint(0) >> 1)},
	} {
		results := []ReceiveResult{{Err: ErrClosed}, {Err: ErrClosed}}
		r, err := q.b.Receive(epoch, []Packet{wire, bad}, results)
		if !errors.Is(err, ErrInvalidBuffer) || r.N != 0 {
			t.Fatal("accepted invalid vector", r, err)
		}
		if !bytes.Equal(wire.Buffer, before.Buffer) || results[0].Err != ErrClosed || results[1].Err != ErrClosed {
			t.Fatal("bounds preflight mutated packet or result storage")
		}
	}
	if result := receive(t, q.b, epoch, wire); result.Err != nil {
		t.Fatal("bounds failure consumed replay state", result.Err)
	}
}

func TestWakeBoundsBeforeMutation(t *testing.T) {
	q := newPair(t, Config{})
	establish(t, q, epoch)
	if _, err := q.a.SetPersistentKeepalive(epoch, time.Second, KeepaliveImmediate); err != nil {
		t.Fatal(err)
	}
	first := control()
	before := clone(first)
	nonce := q.a.keypairs.current.sendNonce.Load()
	if r, err := q.a.HandleWake(epoch, []Packet{first, {Offset: -1}}); !errors.Is(err, ErrInvalidBuffer) || r.N != 0 {
		t.Fatal("accepted invalid output vector", r, err)
	}
	if !bytes.Equal(first.Buffer, before.Buffer) || q.a.keypairs.current.sendNonce.Load() != nonce {
		t.Fatal("bounds preflight emitted a partial control")
	}
	if r, err := q.a.HandleWake(epoch, []Packet{first}); err != nil || r.N != 1 {
		t.Fatal("bounds failure consumed due event", r, err)
	}
}
