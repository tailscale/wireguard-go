// SPDX-License-Identifier: MIT

package peer

import (
	"sync/atomic"
	"time"

	"golang.org/x/sys/cpu"
)

// Transport provides independent send and receive lanes for a [Peer].
// One [Transport.Send] and one [Transport.Receive] may run concurrently
// with each other and with serialized [Peer] control calls.
// Calls within each lane must be serialized.
// Serialize [Peer.Send] with [Transport.Send] and
// [Peer.Receive] with [Transport.Receive].
// Packet storage must satisfy [Packet]'s exclusivity rules.
//
// Each lane uses its own nonzero, nondecreasing clock starting at [New]'s time.
// Operations retain the published key state they start with, so an in-flight
// operation can finish after rekeying, identity replacement, or [Peer.Close].
// New operations return [ErrClosed] after [Peer.Close].
// Use [Peer.Transport] to obtain a Transport. It must not be copied.
type Transport struct {
	view atomic.Pointer[transportView]
	_    cpu.CacheLinePad
	tx   transportLane
	_    cpu.CacheLinePad
	rx   transportLane
}

type transportLane struct {
	now   time.Time
	seq   uint64
	nonce noiseNonce
}

type transportView struct {
	keys       keypairs
	generation *generation
	mtu        int
	closed     bool
}

// Transport returns p's transport lanes. The returned pointer is stable
// for the lifetime of p.
func (p *Peer) Transport() *Transport { return &p.transport }

// TransportActivity records a transport operation for application to its [Peer].
// Apply every valid activity exactly once, including activities returned with
// an error or from empty batches. Preserve operation order within each lane.
// Send and receive activities may be interleaved.
//
// Activity holds no packet buffers, so buffers may be reused after the
// operation and consumption of its packet results.
type TransportActivity struct {
	transport *Transport
	view      *transportView
	at        time.Time
	seq       uint64
	tx        bool
	sent      *keypair
	data      bool
	received  receiveActivity
}

// Valid reports whether a contains an operation to apply.
// It does not check whether that operation has already been applied.
func (a TransportActivity) Valid() bool { return a.transport != nil }

// TransportResult reports packet progress and activity for a transport operation.
type TransportResult struct {
	// N is the number of encrypted packets for [Transport.Send] or examined
	// packets for [Transport.Receive].
	N int
	// Activity must be applied to the owning [Peer] when [TransportActivity.Valid]
	// reports true, even if the transport call returned an error.
	Activity TransportActivity
}

func (p *Peer) transportGeneration() *generation {
	if p.identity.record == nil {
		return nil
	}
	return p.identity.record.marker
}

func (p *Peer) publishTransport() {
	v := transportView{keys: p.keypairs, generation: p.transportGeneration(), mtu: p.mtu, closed: p.closed}
	old := p.transport.view.Load()
	if old == nil || *old != v {
		// Key creation times are immutable. Only slot membership changes can
		// change their hard cleanup window. Generation and counter changes cannot.
		if old == nil || old.keys != v.keys || old.closed != v.closed {
			p.wakeValid = false
		}
		p.transport.view.Store(&transportView{keys: v.keys, generation: v.generation, mtu: v.mtu, closed: v.closed})
	}
}

func (t *Transport) begin(now time.Time, tx bool) (TransportActivity, error) {
	v := t.view.Load()
	if v == nil || v.closed {
		return TransportActivity{}, ErrClosed
	}
	lane := &t.rx
	if tx {
		lane = &t.tx
	}
	if now.IsZero() || now.Before(lane.now) {
		return TransportActivity{}, ErrTime
	}
	if lane.seq == ^uint64(0) {
		return TransportActivity{}, ErrExhausted
	}
	lane.now = now
	lane.seq++
	return TransportActivity{transport: t, view: v, at: now, seq: lane.seq, tx: tx}, nil
}

// Send encrypts a batch using the packet layout and result rules of [Peer.Send].
// It returns activity for later application instead of updating [Peer] timers.
func (t *Transport) Send(now time.Time, packets []Packet) (result TransportResult, err error) {
	result.Activity, err = t.begin(now, true)
	if err != nil {
		return
	}
	v := result.Activity.view
	if err = validatePackets(packets, v.mtu, true); err != nil || len(packets) == 0 {
		return
	}
	k := v.keys.current
	if !usable(k, now) {
		return result, ErrNoSession
	}
	first, n := k.reserve(len(packets))
	if n < len(packets) {
		err = ErrExhausted
	}
	for i := 0; i < n; i++ {
		result.Activity.data = result.Activity.data || packets[i].Size > 0
		packets[i] = encrypt(k, packets[i], v.mtu, first+uint64(i), &t.tx.nonce)
	}
	result.N = n
	if n > 0 {
		result.Activity.sent = k
	}
	return
}

// Receive decrypts a batch using the result and validation rules of [Peer.Receive].
// Session confirmation and timer changes take effect when its activity is applied.
func (t *Transport) Receive(now time.Time, packets []Packet, results []ReceiveResult) (result TransportResult, err error) {
	result.Activity, err = t.begin(now, false)
	if err != nil {
		return
	}
	if len(results) < len(packets) {
		return result, ErrShortBuffer
	}
	if err = validatePackets(packets, 0, false); err != nil {
		return
	}
	result.Activity.received = receivePackets(now, result.Activity.view.keys, packets, results, &t.rx.nonce)
	result.N = len(packets)
	return
}

// ApplyTransport applies a transport operation's activity to p at now.
// Timer effects use now rather than the operation's completion time.
// It returns [ErrActivity] for a foreign, duplicate, zero, or out-of-order activity,
// or [ErrTime] if now precedes the operation time or the [Peer] clock. A rejected
// activity is not consumed and does not advance the [Peer] clock. Activity from an
// earlier local generation is consumed without updating maintenance state.
// Retired-key activity is consumed without refreshing maintenance.
func (p *Peer) ApplyTransport(now time.Time, a TransportActivity) (u Update, err error) {
	defer func() { u = p.update() }()
	if err = p.checkTransportActivity(now, a); err != nil {
		return
	}
	if err = p.advance(now); err != nil {
		return
	}
	p.applyTransportActivity(now, a)
	return
}

// ApplyTransportBatch applies activities in slice order at now.
// N is the committed prefix length, including consumed activity from earlier
// local generations. On an error, the prefix remains applied and only the
// unconsumed suffix may be retried. Validation follows [Peer.ApplyTransport].
// An empty slice advances time and cleanup without consuming activity.
func (p *Peer) ApplyTransportBatch(now time.Time, activities []TransportActivity) (result BatchResult, err error) {
	defer func() { result.Update = p.update() }()
	if len(activities) == 0 {
		err = p.advance(now)
		return
	}
	for _, a := range activities {
		if err = p.checkTransportActivity(now, a); err != nil {
			return
		}
		if result.N == 0 {
			if err = p.advance(now); err != nil {
				return
			}
		}
		p.applyTransportActivity(now, a)
		result.N++
	}
	return
}

func (p *Peer) checkTransportActivity(now time.Time, a TransportActivity) error {
	if p.closed {
		return ErrClosed
	}
	seq := p.appliedRX
	if a.tx {
		seq = p.appliedTX
	}
	if a.transport != &p.transport || a.seq != seq+1 {
		return ErrActivity
	}
	if now.Before(a.at) {
		return ErrTime
	}
	return nil
}

func (p *Peer) applyTransportActivity(now time.Time, a TransportActivity) {
	if a.tx {
		p.appliedTX = a.seq
	} else {
		p.appliedRX = a.seq
	}
	if a.view.generation != p.transportGeneration() {
		return
	}
	if a.tx {
		// Retirement cannot be undone by late receipt application. A still-live
		// previous key may record TX activity, but cannot rekey the new current.
		if a.sent != nil && !a.sent.retired.Load() {
			p.sentTransport(now, a.data, a.sent)
		}
	} else {
		p.applyReception(now, a.received, a.view.keys)
	}
}
