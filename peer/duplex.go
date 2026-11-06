// SPDX-License-Identifier: MIT

package peer

import (
	"sync/atomic"
	"time"

	"golang.org/x/sys/cpu"
)

// Transport provides one send lane and one receive lane. Send and Receive may
// run concurrently with each other and with serialized Peer calls. Each lane
// requires one caller, including calls to Peer.Send or Peer.Receive. Calls
// require exclusive access to their buffers. Obtain Transport from Peer.
// It must not be copied.
//
// Transport checks counters, replay, and key age but does not update control
// timers or promote keys. Hand every valid Activity to the control owner promptly
// in per-direction order for ApplyTransport or ApplyTransportBatch.
//
// Each call pins a session view. Close and identity replacement publish new
// views, but in-flight calls may finish with pinned keys. Stop dispatch and
// drain lanes and writers for strong revocation. Discard outputs forbidden
// by application policy after revocation.
type Transport struct {
	view atomic.Pointer[transportView]
	_    cpu.CacheLinePad // Publication readers must not share TX's writable clock/scratch.
	tx   transportLane
	_    cpu.CacheLinePad // Independent directional owners must not false-share lane state.
	rx   transportLane
}

type transportLane struct {
	now   time.Time
	seq   uint64
	nonce [12]byte
}

type transportView struct {
	keys       keypairs
	generation *generation
	mtu        int
	closed     bool
}

// Transport returns this peer's transport handle.
// Obtain it on the control owner before sharing it with lane callers.
func (p *Peer) Transport() *Transport { return &p.transport }

// TransportActivity is an opaque control receipt retaining no packet buffers.
// Apply each valid receipt exactly once in per-direction order. Copies are the
// same event. Dropping a receipt blocks later receipts in that direction.
// Discard pending receipts only when closing the peer. Receipts can retain
// retired keys, so bound handoff queues and discard applied copies. Do not log
// or serialize them. The zero value needs no application.
//
// Timer effects use receipt application time, not crypto completion time. Notify the
// scheduler of pending receipts and apply them promptly. The control owner
// chooses cross-direction order. Each lane's clock is nondecreasing from
// construction and independent of control calls.
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

// Valid reports whether the receipt requires application. Storage and session
// errors can return valid receipts. ErrTime and ErrClosed do not.
func (a TransportActivity) Valid() bool { return a.transport != nil }

// TransportResult reports a committed packet prefix and its control receipt.
// N has the same meaning as in BatchResult for Send and Receive. Consume the
// prefix and apply a valid Activity even on error. It contains no schedule.
type TransportResult struct {
	N        int
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

// Send encrypts packets in place using one counter reservation per vector,
// shared safely with concurrent control output. Buffer, prefix, and partial
// progress rules match Peer.Send. It returns an Activity instead of an Update.
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

// Receive decrypts packets in place and updates receive-lane replay state.
// Packet and keepalive rules match Peer.Receive. It returns an Activity instead
// of an Update. Responder confirmation requires application by the control owner.
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

// ApplyTransport applies a receipt on the control owner and returns an Update.
// now must be nonzero and at least the control clock and receipt time. ErrTime
// leaves the receipt retryable. Foreign, duplicate, or out-of-order receipts
// return ErrActivity without consuming them or advancing time. Apply valid
// receipts even from failed transport calls to preserve sequence order.
//
// Old-generation receipts consume their sequence without updating timers or
// confirming keys. Retired keys cannot rearm activity. Returned plaintext is
// still authenticated to its old generation. Revocation is caller policy.
// After Close, ApplyTransport returns ErrClosed.
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

// ApplyTransportBatch applies receipts in order with one control time, cleanup,
// and final Update. ApplyTransport's clock and receipt rules apply. Input order
// determines cross-direction effects. Each direction must remain ordered.
// N counts consumed receipts, including old-generation receipts, not packets.
// On error the committed prefix remains applied. Retry only the suffix.
// ErrTime before the first receipt leaves the clock and Update unchanged.
//
// An empty slice advances the clock and performs cleanup without consuming
// sequences. After Close it returns N=0, an empty Update, and ErrClosed.
// It neither retains nor allocates receipt storage. Bound batch size and latency.
// Publication and scheduler updates wait for the call to finish. Caller wake
// deadlines still apply.
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

// Only called after validation and accepted-clock cleanup. Neither updates nor
// published session views are built here, so a batch can reduce them once.
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
	return
}
