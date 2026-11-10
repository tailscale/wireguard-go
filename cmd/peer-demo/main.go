// SPDX-License-Identifier: MIT

// Command peer-demo exchanges framed records between four WireGuard identities
// using three loopback UDP sockets and a shared receiver-index table. One pair
// uses classical handshakes and the other uses Tailscale hybrid handshakes.
// The control owner applies transport activity in bounded batches before
// control work, scheduling, and the end of each application turn.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/tailscale/wireguard-go/peer"
	"github.com/tailscale/wireguard-go/peerindex"
)

const (
	prefix            = 24
	activityBatchSize = 16
)

var (
	errRoute          = errors.New("demo: unknown index, identity, socket or pinned source")
	errRecordTooLarge = errors.New("demo: record exceeds packet storage")
)

type route struct {
	p           *peer.Peer
	transport   *peer.Transport
	activities  [activityBatchSize]peer.TransportActivity
	nActivities int
	identity    *peer.Identity
	generation  peer.LocalIdentity
	update      peer.Update
	admission   *peer.Admission
	socket      int
	destination netip.AddrPort
	remote      *route
	control     [prefix + peer.MessageHybridInitiationSize]byte
	send        [2048]byte
}

type owner struct {
	indexes peerindex.Table[*peer.Peer]
	routes  map[*peer.Peer]*route
	locals  []*route
}

func newOwner(now time.Time, addresses []netip.AddrPort) (*owner, error) {
	o := &owner{routes: make(map[*peer.Peer]*route)}
	// Generate independent demo keys rather than embedding private keys.
	for i := 0; i < 4; i++ {
		k, err := peer.NewPrivateKey()
		if err != nil {
			o.close()
			return nil, err
		}
		id := peer.NewIdentity(k)
		socket := 0
		if i%2 == 1 {
			socket = 1 + i/2
		}
		generation, err := peer.NewLocalIdentity(1, id)
		if err != nil {
			o.close()
			return nil, err
		}
		admission, err := peer.NewAdmission(generation)
		if err != nil {
			o.close()
			return nil, err
		}
		o.locals = append(o.locals, &route{identity: id, generation: generation, admission: admission, socket: socket})
	}
	for i, r := range o.locals {
		r.remote = o.locals[i^1]
		r.destination = addresses[r.remote.socket]
		var err error
		r.p, r.update, err = peer.New(now, r.generation, &o.indexes, r.remote.identity.Public(), peer.Config{PaddingMTU: 1420, Hybrid: i >= 2})
		if err != nil {
			o.close()
			return nil, err
		}
		r.transport = r.p.Transport()
		o.routes[r.p] = r
		for j := 0; j < prefix; j++ {
			r.control[j] = 0xa7
			r.send[j] = 0xa7
		}
	}
	return o, nil
}

func (o *owner) close() {
	// A concurrent adapter must stop dispatch and drain ownership transfers first.
	for _, r := range o.locals {
		if r.p != nil {
			delete(o.routes, r.p)
			clear(r.activities[:])
			r.nActivities = 0
			r.update = r.p.Close()
		}
	}
}

func (r *route) output() peer.Packet { return peer.Packet{Buffer: r.control[:], Offset: prefix} }

// transportReady makes room before starting another lane operation. It applies
// a full batch without waiting for more work or allocating receipt storage.
func (r *route) transportReady(now time.Time) error {
	if r.nActivities == len(r.activities) {
		return r.applyPending(now)
	}
	return nil
}

func (r *route) saveActivity(a peer.TransportActivity) {
	if a.Valid() {
		r.activities[r.nActivities] = a
		r.nActivities++
	}
}

func (r *route) applyPending(now time.Time) error {
	if r.nActivities == 0 {
		return nil
	}
	result, err := r.p.ApplyTransportBatch(now, r.activities[:r.nActivities])
	r.update = result.Update
	remaining := copy(r.activities[:], r.activities[result.N:r.nActivities])
	clear(r.activities[remaining:r.nActivities])
	r.nActivities = remaining
	return err
}

// applyPending drains activity before control or scheduling work. Applied
// receipts are cleared; a rejected suffix remains available for retry.
func (o *owner) applyPending(now time.Time) error {
	for _, r := range o.locals {
		if err := r.applyPending(now); err != nil {
			return err
		}
	}
	return nil
}

// dispatch routes input only when its identity, receiver index, socket, and
// pinned source match a configured route. It returns a control packet to send
// or a plaintext record borrowed from input. The record must be consumed before
// the receive buffer is reused.
func (o *owner) dispatch(now time.Time, socket int, source netip.AddrPort, input peer.Packet) (*route, peer.Packet, []byte, error) {
	typ, index, err := peer.ParseHeader(input.Bytes())
	if err != nil {
		return nil, peer.Packet{}, nil, err
	}
	var r *route
	var prepared peer.PreparedInitiation
	if typ == peer.MessageInitiationType {
		// For a small identity set, MAC1 cheaply selects a local identity before DH.
		// Large deployments should use an authenticated outer identity selector.
		for _, candidate := range o.locals {
			if candidate.socket != socket || candidate.destination != source {
				continue
			}
			v, e := candidate.admission.Admit(now, input.Bytes(), nil, false, nil)
			if e != nil {
				continue
			}
			work, e := peer.PrepareInitiation(v)
			if e == nil && work.RemoteStatic() == candidate.p.RemoteStatic() {
				r, prepared = candidate, work
				break
			}
		}
	} else {
		p, ok := o.indexes.Lookup(index)
		if ok {
			r = o.routes[p]
		}
	}
	if r == nil || r.socket != socket || r.destination != source {
		return nil, peer.Packet{}, nil, errRoute
	}
	if typ != peer.MessageTransportType {
		if err := o.applyPending(now); err != nil {
			return nil, peer.Packet{}, nil, err
		}
	}
	switch typ {
	case peer.MessageInitiationType:
		var out peer.Packet
		out, r.update, err = r.p.HandleInitiation(now, prepared, r.output())
		return r, out, nil, err
	case peer.MessageResponseType:
		admitted, err := r.admission.Admit(now, input.Bytes(), nil, false, nil)
		if err != nil {
			return nil, peer.Packet{}, nil, err
		}
		var out peer.Packet
		out, r.update, err = r.p.HandleResponse(now, admitted, r.output())
		return r, out, nil, err
	case peer.MessageCookieReplyType:
		r.update, err = r.p.ConsumeCookie(now, input.Bytes())
		return r, peer.Packet{}, nil, err
	case peer.MessageTransportType:
		if err := r.transportReady(now); err != nil {
			return nil, peer.Packet{}, nil, err
		}
		var results [1]peer.ReceiveResult
		result, err := r.transport.Receive(now, []peer.Packet{input}, results[:])
		r.saveActivity(result.Activity)
		if err != nil {
			return nil, peer.Packet{}, nil, err
		}
		if results[0].Err != nil {
			return nil, peer.Packet{}, nil, results[0].Err
		}
		if results[0].Disposition == peer.Keepalive {
			return r, peer.Packet{}, nil, nil
		}
		// Validate the application record length and trim WireGuard padding.
		b := results[0].Packet.Bytes()
		if len(b) < 2 {
			return nil, peer.Packet{}, nil, errors.New("short record")
		}
		n := int(binary.BigEndian.Uint16(b))
		if n > len(b)-2 {
			return nil, peer.Packet{}, nil, errors.New("bad record length")
		}
		return r, peer.Packet{}, b[2 : 2+n], nil
	}
	return nil, peer.Packet{}, nil, errRoute
}

// coalescedWake applies pending activity and returns the earliest maintenance
// deadline across routes, or zero if none is scheduled.
func (o *owner) coalescedWake(now time.Time) (time.Time, error) {
	if err := o.applyPending(now); err != nil {
		return time.Time{}, err
	}
	var at time.Time
	for _, r := range o.locals {
		w := r.update.Wake
		if !w.Deadline.IsZero() && (at.IsZero() || w.Deadline.Before(at)) {
			at = w.Deadline
		}
	}
	return at, nil
}

func (o *owner) wake(now time.Time, emit func(*route, peer.Packet) error) (count int, err error) {
	if err := o.applyPending(now); err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, o.applyPending(now)) }()
	for _, r := range o.locals {
		if err := o.applyPending(now); err != nil {
			return count, err
		}
		w := r.update.Wake
		if w.Earliest.IsZero() || now.Before(w.Earliest) {
			continue
		}
		// One reusable output suffices for this policy. General automatic policy can
		// emit several controls. Consume the successful prefix before handling errors.
		outputs := [1]peer.Packet{r.output()}
		result, err := r.p.HandleWake(now, outputs[:])
		r.update = result.Update
		for _, out := range outputs[:result.N] {
			if err := emit(r, out); err != nil {
				return count, err
			}
			count++
		}
		if err != nil {
			return count, err
		}
	}
	return count, nil
}

type transport interface {
	// transfer sends wire and receives into the destination socket's reusable
	// buffer. The returned packet must be consumed before the next transfer
	// to that socket.
	transfer(from, to int, destination netip.AddrPort, wire []byte) (peer.Packet, netip.AddrPort, error)
}

type udpTransport struct {
	sockets []*net.UDPConn
	receive [3][2048]byte
}

func (u *udpTransport) transfer(from, to int, destination netip.AddrPort, wire []byte) (peer.Packet, netip.AddrPort, error) {
	if err := u.sockets[from].SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return peer.Packet{}, netip.AddrPort{}, err
	}
	if _, err := u.sockets[from].WriteToUDPAddrPort(wire, destination); err != nil {
		return peer.Packet{}, netip.AddrPort{}, err
	}
	if err := u.sockets[to].SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return peer.Packet{}, netip.AddrPort{}, err
	}
	buffer := u.receive[to][:]
	for i := 0; i < prefix; i++ {
		buffer[i] = 0xa7
	}
	n, source, err := u.sockets[to].ReadFromUDPAddrPort(buffer[prefix:])
	return peer.Packet{Buffer: buffer, Offset: prefix, Size: n}, source, err
}

// exchange delivers up to three protocol flights. Any returned payload shares
// the transport's receive storage and must be consumed before the next transfer.
func (o *owner) exchange(io transport, now time.Time, sender *route, wire peer.Packet) ([]byte, error) {
	for flight := 0; flight < 3; flight++ {
		input, source, err := io.transfer(sender.socket, sender.remote.socket, sender.destination, wire.Bytes())
		if err != nil {
			return nil, err
		}
		next, out, payload, err := o.dispatch(now, sender.remote.socket, source, input)
		if err != nil {
			return nil, err
		}
		if out.Size == 0 {
			return payload, nil
		}
		sender, wire = next, out
	}
	return nil, errors.New("too many protocol flights")
}

// record queues transport activity for the current application turn. The caller
// drains it before control work, scheduling, or returning from the turn.
func (o *owner) record(io transport, now time.Time, r *route, text string) error {
	// Leave room for record framing and worst-case WireGuard padding.
	maxSize := len(r.send) - prefix - peer.TransportOverhead - (peer.PaddingMultiple - 1) - 2
	if len(text) > maxSize {
		return errRecordTooLarge
	}
	if err := r.transportReady(now); err != nil {
		return err
	}
	b := r.send[:]
	binary.BigEndian.PutUint16(b[prefix+16:], uint16(len(text)))
	copy(b[prefix+18:], text)
	packets := [1]peer.Packet{{Buffer: b, Offset: prefix + 16, Size: len(text) + 2}}
	result, sendErr := r.transport.Send(now, packets[:])
	r.saveActivity(result.Activity)
	if result.N != 1 {
		return fmt.Errorf("send %d: %w", result.N, sendErr)
	}
	got, err := o.exchange(io, now, r, packets[0])
	if err != nil {
		return err
	}
	if sendErr != nil {
		return sendErr
	}
	if string(got) != text {
		return fmt.Errorf("payload %q != %q", got, text)
	}
	if !bytes.Equal(b[:prefix], bytes.Repeat([]byte{0xa7}, prefix)) {
		return errors.New("outer prefix overwritten")
	}
	return nil
}

// records bounds one application turn and drains its activity even on failure.
func (o *owner) records(io transport, now time.Time) (err error) {
	defer func() { err = errors.Join(err, o.applyPending(now)) }()
	for round := 0; round < 2; round++ {
		for _, r := range o.locals {
			if err := o.record(io, now, r, "caller-owned buffer reused"); err != nil {
				return err
			}
		}
	}
	return nil
}

func run(io transport, o *owner, now time.Time, waitUntil func(time.Time)) (int, error) {
	if err := o.applyPending(now); err != nil {
		return 0, err
	}
	for _, i := range []int{0, 2} {
		r := o.locals[i]
		init, update, err := r.p.Initiate(now, r.output())
		r.update = update
		if err != nil {
			return 0, err
		}
		_, exchangeErr := o.exchange(io, now, r, init)
		if err := errors.Join(exchangeErr, o.applyPending(now)); err != nil {
			return 0, err
		}
	}
	if err := o.records(io, now); err != nil {
		return 0, err
	}
	// The application enables two compatible windows and selects one shared wake.
	for _, i := range []int{0, 2} {
		r := o.locals[i]
		var err error
		r.update, err = r.p.SetPersistentKeepalive(now, time.Second, peer.KeepaliveImmediate)
		if err != nil {
			return 0, err
		}
	}
	at, err := o.coalescedWake(now)
	if err != nil {
		return 0, err
	}
	waitUntil(at) // the caller, not Peer, owns the timer/coalescing policy
	return o.wake(at, func(r *route, p peer.Packet) error { _, err := o.exchange(io, at, r, p); return err })
}

func main() {
	u := new(udpTransport)
	addresses := make([]netip.AddrPort, 3)
	for i := range addresses {
		s, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer func() {
			if err := s.Close(); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
		u.sockets = append(u.sockets, s)
		addresses[i] = s.LocalAddr().(*net.UDPAddr).AddrPort()
	}
	o, err := newOwner(time.Now(), addresses)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer o.close()
	wakes, err := run(u, o, time.Now(), func(at time.Time) { time.Sleep(time.Until(at)) })
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("4 identities, 3 UDP sockets, 1 index namespace; classical and hybrid sessions; 8 records; %d coalesced keepalives; no automatic retries\n", wakes)
}
