// SPDX-License-Identifier: MIT

package peer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestSendBackpressureAndBounds(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	packets := []Packet{plaintext(27, 13)}
	before := clone(packets[0])
	if n, err := q.a.Send(epoch, packets); n.N != 0 || !errors.Is(err, ErrNoSession) {
		t.Fatalf("%d %v", n.N, err)
	}
	if !bytes.Equal(packets[0].Buffer, before.Buffer) || packets[0].Offset != before.Offset || q.indexes.Len() != 0 {
		t.Fatal("no-session retained/mutated input")
	}
	establish(t, q, epoch)
	short := plaintext(16, 0)
	short.Buffer = short.Buffer[:len(short.Buffer)-16]
	invalid := []Packet{
		{Buffer: make([]byte, 40), Offset: -1, Size: 2},
		{Buffer: make([]byte, 40), Offset: 20, Size: -1},
		{Buffer: make([]byte, 40), Offset: 20, Size: int(^uint(0) >> 1)},
		{Buffer: make([]byte, 40), Offset: 15, Size: 2}, short,
	}
	for _, bad := range invalid {
		first := plaintext(7, 11)
		want := clone(first)
		vec := []Packet{first, bad}
		nonce := q.a.keypairs.current.sendNonce.Load()
		if n, err := q.a.Send(epoch, vec); n.N != 0 || err == nil {
			t.Fatal("accepted invalid vector")
		}
		if !bytes.Equal(first.Buffer, want.Buffer) || q.a.keypairs.current.sendNonce.Load() != nonce {
			t.Fatal("partial validation mutation")
		}
	}
	// Distinct bounded regions of the same caller slab are supported.
	slab := make([]byte, 128)
	vec := []Packet{{slab[:64], 16, 20}, {slab[64:], 16, 20}}
	if n, err := q.a.Send(epoch, vec); n.N != 2 || err != nil {
		t.Fatalf("slab %d %v", n.N, err)
	}
	if n, err := q.b.Receive(epoch, vec, make([]ReceiveResult, 1)); n.N != 0 || !errors.Is(err, ErrShortBuffer) {
		t.Fatal("result capacity")
	}
	result := make([]ReceiveResult, 2)
	if n, err := q.b.Receive(epoch, vec, result); n.N != 2 || err != nil || result[0].Err != nil || result[1].Err != nil {
		t.Fatalf("slab receive %d %v %+v", n.N, err, result)
	}
}

func TestNonceExhaustionNeverWraps(t *testing.T) {
	for _, batch := range []int{1, 2, 8195} {
		t.Run(string(rune('A'+batch%26)), func(t *testing.T) {
			q := newPair(t, Config{HandshakePolicy: automaticPolicy})
			establish(t, q, epoch)
			q.a.keypairs.current.sendNonce.Store(RejectAfterMessages - 1)
			packets := make([]Packet, batch)
			for i := range packets {
				packets[i] = plaintext(0, 0)
			}
			n, err := q.a.Send(epoch, packets)
			if n.N != 1 || (batch > 1 && !errors.Is(err, ErrExhausted)) || (batch == 1 && err != nil) {
				t.Fatalf("batch %d: %d %v", batch, n.N, err)
			}
			if counter := binary.LittleEndian.Uint64(packets[0].Bytes()[8:16]); counter != RejectAfterMessages-1 {
				t.Fatal(counter)
			}
			if r := receive(t, q.b, epoch, packets[0]); r.Err != nil {
				t.Fatal(r.Err)
			}
			for _, p := range packets[1:] {
				if p.Offset != 16 || p.Size != 0 || !bytes.Equal(p.Buffer, bytes.Repeat([]byte{0xa5}, len(p.Buffer))) {
					t.Fatal("suffix changed")
				}
			}
			if q.a.keypairs.current.sendNonce.Load() != RejectAfterMessages {
				t.Fatal("wrapped nonce")
			}
			if n, err = q.a.Send(epoch, []Packet{plaintext(0, 0)}); n.N != 0 || !errors.Is(err, ErrNoSession) {
				t.Fatalf("exhausted: %d %v", n.N, err)
			}
		})
	}
}

func TestTransportUntrustedFramingAndReplay(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	establish(t, q, epoch)
	good := seal(t, q.a, epoch, plaintext(32, 5))
	before := q.b.timers
	for i := 0; i < 4; i++ {
		bad := clone(good)
		bad.Buffer[bad.Offset+i] ^= 0x80
		if r := receive(t, q.b, epoch, bad); r.Err == nil || r.Packet.Buffer != nil {
			t.Fatal("accepted mutated type/reserved")
		}
	}
	for n := 0; n < MessageKeepaliveSize; n++ {
		bad := clone(good)
		bad.Size = n
		if r := receive(t, q.b, epoch, bad); r.Err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	bad := clone(good)
	binary.LittleEndian.PutUint32(bad.Bytes()[4:8], 0)
	if r := receive(t, q.b, epoch, bad); r.Err == nil {
		t.Fatal("wrong index")
	}
	bad = clone(good)
	binary.LittleEndian.PutUint64(bad.Bytes()[8:16], RejectAfterMessages-1)
	if r := receive(t, q.b, epoch, bad); r.Err == nil {
		t.Fatal("forged high nonce")
	}
	if q.b.timers != before {
		t.Fatal("invalid packets changed timers")
	}
	if r := receive(t, q.b, epoch, clone(good)); r.Err != nil {
		t.Fatal("forgery advanced replay", r.Err)
	}
	if r := receive(t, q.b, epoch, clone(good)); !errors.Is(r.Err, ErrReplay) {
		t.Fatal("duplicate accepted")
	}
	// Out-of-order valid counters remain acceptable, but old window entries do not.
	low := seal(t, q.a, epoch, plaintext(3, 0))
	middle := seal(t, q.a, epoch, plaintext(3, 0))
	if r := receive(t, q.b, epoch, middle); r.Err != nil {
		t.Fatal(r.Err)
	}
	if r := receive(t, q.b, epoch, clone(low)); r.Err != nil {
		t.Fatal(r.Err)
	}
	q.a.keypairs.current.sendNonce.Add(10000)
	high := seal(t, q.a, epoch, plaintext(3, 0))
	if r := receive(t, q.b, epoch, high); r.Err != nil {
		t.Fatal(r.Err)
	}
	if r := receive(t, q.b, epoch, low); !errors.Is(r.Err, ErrReplay) {
		t.Fatal("window edge")
	}
}

func TestExpiredTransportIndependentOfWake(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: manualPolicy})
	establish(t, q, epoch)
	wire := seal(t, q.a, epoch, plaintext(12, 0))
	at := epoch.Add(RejectAfterTime)
	if r := receive(t, q.b, at, wire); r.Err == nil {
		t.Fatal("accepted expired key at boundary")
	}
	if n, err := q.a.Send(at, []Packet{plaintext(1, 0)}); n.N != 0 || !errors.Is(err, ErrNoSession) {
		t.Fatal("sent expired key")
	}
	if q.a.update().Handshake.Reasons == 0 {
		t.Fatal("manual renewal invisible")
	}
}

func TestTransportSteadyStateNoAllocations(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: manualPolicy})
	establish(t, q, epoch)
	packet := plaintext(1420, 32)
	vec := []Packet{packet}
	results := make([]ReceiveResult, 1)
	allocations := testing.AllocsPerRun(1000, func() {
		vec[0] = packet
		if n, err := q.a.Send(epoch, vec); n.N != 1 || err != nil {
			panic("send failed")
		}
		if n, err := q.b.Receive(epoch, vec, results); n.N != 1 || err != nil || results[0].Err != nil {
			panic("receive failed")
		}
	})
	if allocations != 0 {
		t.Fatalf("steady-state allocations: %g", allocations)
	}
}

func TestReceiveBatchMixedDispositionsAndPrefixes(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	establish(t, q, epoch)
	data := seal(t, q.a, epoch, plaintext(20, 21))
	keep := seal(t, q.a, epoch, plaintext(0, 7))
	invalid := Packet{Buffer: make([]byte, 31), Size: 31}
	packets := []Packet{data, invalid, keep}
	results := make([]ReceiveResult, 3)
	if n, err := q.b.Receive(epoch, packets, results); n.N != 3 || err != nil {
		t.Fatal(n, err)
	}
	if results[0].Disposition != Data || results[1].Disposition != Dropped || results[2].Disposition != Keepalive {
		t.Fatal(results)
	}
	if !bytes.Equal(data.Buffer[:21], bytes.Repeat([]byte{0xa5}, 21)) || !bytes.Equal(keep.Buffer[:7], bytes.Repeat([]byte{0xa5}, 7)) {
		t.Fatal("receive prefix modified")
	}
}

func TestSendAndReceiveRefreshThresholds(t *testing.T) {
	for _, manual := range []bool{false, true} {
		policy := automaticPolicy
		if manual {
			policy = manualPolicy
		}
		q := newPair(t, Config{HandshakePolicy: policy})
		establish(t, q, epoch)
		now := epoch.Add(RekeyAfterTime + time.Nanosecond)
		seal(t, q.a, now, plaintext(0, 0))
		if q.a.update().Handshake.Reasons == 0 {
			t.Fatal("send keepalive did not request rekey")
		}
		if manual != q.a.timers.refresh.IsZero() {
			t.Fatal("manual/autonomous freshness")
		}
		now = epoch.Add(RejectAfterTime - KeepaliveTimeout - RekeyTimeout + time.Nanosecond)
		wire := seal(t, q.b, now, plaintext(1, 0))
		if r := receive(t, q.a, now, wire); r.Err != nil {
			t.Fatal(r.Err)
		}
		if !q.a.timers.receiveRefreshSent {
			t.Fatal("missing receive refresh latch")
		}
	}
}

func TestReplayAcrossKeyRotationAndRetiredIndex(t *testing.T) {
	q := newPair(t, Config{HandshakePolicy: automaticPolicy})
	establish(t, q, epoch)
	old := seal(t, q.a, epoch, plaintext(7, 0))
	duplicate := clone(old)
	_, oldIndex, _ := ParseHeader(old.Bytes())
	establish(t, q, epoch.Add(5*time.Second))
	if r := receive(t, q.b, epoch.Add(5*time.Second), old); r.Err != nil {
		t.Fatal("previous key receive grace", r.Err)
	}
	if r := receive(t, q.b, epoch.Add(5*time.Second), clone(duplicate)); !errors.Is(r.Err, ErrReplay) {
		t.Fatal("previous key lost replay state")
	}
	establish(t, q, epoch.Add(10*time.Second))
	if _, ok := q.indexes.Lookup(oldIndex); ok {
		t.Fatal("retired index still routed")
	}
	if r := receive(t, q.b, epoch.Add(10*time.Second), duplicate); !errors.Is(r.Err, ErrTransport) {
		t.Fatal("retired index received")
	}
}

func TestExactFitAndTailCanaries(t *testing.T) {
	q := newPair(t, Config{PaddingMTU: 1420})
	establish(t, q, epoch)
	for _, size := range []int{0, 1, 16, 17, 1420} {
		prefix := 19
		padded := size + paddingSize(size, 1420)
		total := prefix + TransportHeaderSize + padded + 16
		backing := bytes.Repeat([]byte{0xfa}, total+17)
		packet := Packet{backing[:total], prefix + TransportHeaderSize, size}
		vec := []Packet{packet}
		if n, err := q.a.Send(epoch, vec); n.N != 1 || err != nil {
			t.Fatal(n, err)
		}
		if vec[0].Size != total-prefix || !bytes.Equal(backing[total:], bytes.Repeat([]byte{0xfa}, 17)) {
			t.Fatal("exact-fit overflow")
		}
		if r := receive(t, q.b, epoch, vec[0]); r.Err != nil {
			t.Fatal(r.Err)
		}
		if !bytes.Equal(backing[:prefix], bytes.Repeat([]byte{0xfa}, prefix)) || !bytes.Equal(backing[total:], bytes.Repeat([]byte{0xfa}, 17)) {
			t.Fatal("canary corrupted")
		}
	}
}
