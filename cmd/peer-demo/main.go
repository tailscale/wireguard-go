// SPDX-License-Identifier: MIT

// Command peer-demo demonstrates caller-owned WireGuard sessions over loopback
// UDP. One serial owner drives four identities across three sockets. All peers
// share one receiver-index namespace. Endpoints are pinned. Payloads are
// length-prefixed application records, not IP packets.
//
// The owner reuses packet buffers after synchronous I/O completes. It schedules
// updates and coalesces keepalives. The zero handshake policy leaves initiation
// to the caller. Lost flights return errors without automatic retries.
//
// This is a bounded example, not a VPN or a production UDP server. It uses
// ordinary-load admission without source limiting or cookie challenges. A public
// adapter needs load detection, source limits, cookie challenges, and reply
// budgets. Dynamic configuration must reject duplicate identity and remote-key
// pairs. Asynchronous adapters must transfer buffer ownership and drain work
// before shutdown or revocation.
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

const prefix = 24 // reserved outer header, not sent over UDP
var (
	errRoute          = errors.New("demo: unknown index, identity, socket or pinned source")
	errRecordTooLarge = errors.New("demo: record exceeds packet storage")
)

type route struct {
	p           *peer.Peer
	identity    *peer.Identity
	generation  peer.LocalIdentity
	update      peer.Update
	admission   *peer.Admission
	socket      int
	destination netip.AddrPort
	remote      *route // only the bounded scenario driver needs this link
	control     [prefix + peer.MessageInitiationSize]byte
	send        [2048]byte
}
type owner struct {
	indexes peerindex.Table[*peer.Peer] // one namespace across all sockets
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
		r.p, r.update, err = peer.New(now, r.generation, &o.indexes, r.remote.identity.Public(), peer.Config{PaddingMTU: 1420})
		if err != nil {
			o.close()
			return nil, err
		}
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
			r.update = r.p.Close()
		}
	}
}
func (r *route) output() peer.Packet { return peer.Packet{Buffer: r.control[:], Offset: prefix} }

// dispatch runs on the control owner. It rejects the wrong socket or pinned
// source even for a valid index. An index lookup does not authenticate the packet
// or grant concurrent access to Peer. This example does not implement roaming.
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
		var results [1]peer.ReceiveResult
		result, err := r.p.Receive(now, []peer.Packet{input}, results[:])
		r.update = result.Update
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

// coalescedWake chooses the earliest deadline. Every peer whose inclusive
// window contains that time can share one application wake. Never delay a hard
// cleanup deadline to fit another peer's preferred window. For large owner sets
// use a heap updated once after each batch/config operation instead of this scan.
func (o *owner) coalescedWake() time.Time {
	var at time.Time
	for _, r := range o.locals {
		w := r.update.Wake
		if !w.Deadline.IsZero() && (at.IsZero() || w.Deadline.Before(at)) {
			at = w.Deadline
		}
	}
	return at
}
func (o *owner) wake(now time.Time, emit func(*route, peer.Packet) error) (int, error) {
	count := 0
	for _, r := range o.locals {
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
	// Synchronous completion makes buffer reuse explicit. A real asynchronous
	// writer/reader must transfer buffer ownership and return it after completion.
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

// exchange runs at most three flights. A lost flight returns an error.
// The application can call Initiate again later.
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
func (o *owner) record(io transport, now time.Time, r *route, text string) error {
	// Leave room for record framing and worst-case WireGuard padding.
	maxSize := len(r.send) - prefix - peer.TransportOverhead - (peer.PaddingMultiple - 1) - 2
	if len(text) > maxSize {
		return errRecordTooLarge
	}
	b := r.send[:]
	binary.BigEndian.PutUint16(b[prefix+16:], uint16(len(text)))
	copy(b[prefix+18:], text)
	packets := [1]peer.Packet{{Buffer: b, Offset: prefix + 16, Size: len(text) + 2}}
	result, sendErr := r.p.Send(now, packets[:])
	r.update = result.Update
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
func run(io transport, o *owner, now time.Time, waitUntil func(time.Time)) (int, error) {
	for _, i := range []int{0, 2} {
		r := o.locals[i]
		init, update, err := r.p.Initiate(now, r.output())
		r.update = update
		if err != nil {
			return 0, err
		}
		if _, err = o.exchange(io, now, r, init); err != nil {
			return 0, err
		}
	}
	for round := 0; round < 2; round++ {
		for _, r := range o.locals {
			if err := o.record(io, now, r, "caller-owned buffer reused"); err != nil {
				return 0, err
			}
		}
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
	at := o.coalescedWake()
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
		defer s.Close()
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
	fmt.Printf("4 identities, 3 UDP sockets, 1 index namespace; 8 records; %d coalesced keepalives; no automatic retries\n", wakes)
}
