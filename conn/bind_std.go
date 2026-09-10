/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	_ Bind     = (*StdNetBind)(nil)
	_ Endpoint = (*StdNetEndpoint)(nil)
)

// StdNetBind implements Bind for all platforms. While Windows has its own Bind
// (see bind_windows.go), it may fall back to StdNetBind.
// TODO: Remove usage of ipv{4,6}.PacketConn when net.UDPConn has comparable
// methods for sending and receiving multiple datagrams per-syscall. See the
// proposal in https://github.com/golang/go/issues/45886#issuecomment-1218301564.
type StdNetBind struct {
	config // read-only post construction.

	mu sync.Mutex // protects all fields except as specified

	// v4 and v6 are fixed in size between Open and Close, safe to index without mu.
	v4 []*stdNetSocket
	v6 []*stdNetSocket

	// these two fields are not guarded by mu
	udpAddrPool sync.Pool
	messagePool

	blackhole4 bool
	blackhole6 bool
}

// stdNetSocket is one UDP socket. See [WithQueues].
type stdNetSocket struct {
	conn *net.UDPConn
	// pool is the owning [StdNetBind]'s message pool, shared by every socket.
	pool *messagePool
	// pc is the batched read/write view of conn, the intersection of
	// ipv4.PacketConn and ipv6.PacketConn. It is nil on non-Linux.
	pc interface {
		batchReader
		batchWriter
	}

	// txOffload records whether UDP GSO works on this socket. It is per-socket
	// rather than per-family because Send's GSO-disable fallback observes only
	// the socket it wrote to, and no shared lock is left to guard a wider flag.
	txOffload atomic.Bool
	rxOffload bool
}

func NewStdNetBind(opts ...Option) Bind {
	b := &StdNetBind{
		config: defaultConfig(),
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},

		messagePool: messagePool{
			pool: sync.Pool{
				New: func() any {
					msgs := make([]ipv6.Message, IdealBatchSize)
					for i := range msgs {
						msgs[i].Buffers = make(net.Buffers, 1)
						msgs[i].OOB = make([]byte, controlSize)
					}
					return &msgs
				},
			},
		},
	}
	for _, opt := range opts {
		opt.apply(&b.config)
	}
	return b
}

type StdNetEndpoint struct {
	// AddrPort is the endpoint destination.
	netip.AddrPort
	// src is the current sticky source address and interface index, if
	// supported. Typically this is a PKTINFO structure from/for control
	// messages, see unix.PKTINFO for an example.
	src []byte
}

var (
	_ Bind     = (*StdNetBind)(nil)
	_ Endpoint = &StdNetEndpoint{}
)

func (*StdNetBind) ParseEndpoint(s string) (Endpoint, error) {
	e, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &StdNetEndpoint{
		AddrPort: e,
	}, nil
}

func (e *StdNetEndpoint) ClearSrc() {
	if e.src != nil {
		// Truncate src, no need to reallocate.
		e.src = e.src[:0]
	}
}

func (e *StdNetEndpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}

// See sticky_default,linux, etc for implementations of SrcIP and SrcIfidx.

func (e *StdNetEndpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}

func (e *StdNetEndpoint) DstToString() string {
	return e.AddrPort.String()
}

func listenNet(network string, port int, ctrl ...controlFn) (*net.UDPConn, int, error) {
	conn, err := listenConfig(ctrl...).ListenPacket(context.Background(), network, ":"+strconv.Itoa(port))
	if err != nil {
		return nil, 0, err
	}

	// Retrieve port.
	laddr := conn.LocalAddr()
	uaddr, err := net.ResolveUDPAddr(
		laddr.Network(),
		laddr.String(),
	)
	if err != nil {
		return nil, 0, err
	}
	return conn.(*net.UDPConn), uaddr.Port, nil
}

// errEADDRINUSE is syscall.EADDRINUSE, boxed into an interface once
// in erraddrinuse.go on almost all platforms. For other platforms,
// it's at least non-nil.
var errEADDRINUSE error = errors.New("")

// bindGroup opens n [net.UDPConn]s sharing one local port via SO_REUSEPORT.
// If port is 0, all sockets join the same ephemeral port.
// The returned group is either empty or the full n.
// Error is not returned for unsupported address family.
func bindGroup(network string, port, n int, ctrl []controlFn) ([]*net.UDPConn, int, error) {
	var conns []*net.UDPConn
	for range n {
		c, p, err := listenNet(network, port, ctrl...)
		if err != nil {
			closeConns(conns)
			if errors.Is(err, syscall.EAFNOSUPPORT) {
				err = nil
			}
			return nil, p, err
		}
		conns, port = append(conns, c), p
	}
	return conns, port, nil
}

// firstConn returns the first socket of a group, or an error if the group is
// empty. It exists for the platform hooks that reach a socket outside Send.
func firstConn(socks []*stdNetSocket) (*net.UDPConn, error) {
	if len(socks) == 0 {
		return nil, syscall.EINVAL
	}
	return socks[0].conn, nil
}

func closeConns(conns []*net.UDPConn) {
	for _, c := range conns {
		c.Close()
	}
}

func (s *StdNetBind) Open(uport uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	var tries int

	if len(s.v4) > 0 || len(s.v6) > 0 {
		return nil, 0, ErrBindAlreadyOpen
	}
	// Only enable SO_REUSEPORT in multiqueue mode.
	// TODO: Deal with accidentally landing into another PIDs group when two
	// wireguard-go instances are run.
	nq, ctrl := 1, []controlFn(nil)
	if s.queues > 1 && reusePortFn != nil {
		nq, ctrl = s.queues, []controlFn{reusePortFn}
	}

	// Attempt to open ipv4 and ipv6 listeners on the same port.
	// If uport is 0, we can retry on failure.
again:
	port := int(uport)
	var v4conns, v6conns []*net.UDPConn

	v4conns, port, err = bindGroup("udp4", port, nq, ctrl)
	if err != nil {
		return nil, 0, err
	}

	// Listen on the same port as we're using for ipv4.
	v6conns, port, err = bindGroup("udp6", port, nq, ctrl)
	if uport == 0 && errors.Is(err, errEADDRINUSE) && tries < 100 {
		closeConns(v4conns)
		tries++
		goto again
	}
	if err != nil {
		closeConns(v4conns)
		return nil, 0, err
	}

	var fns []ReceiveFunc
	for _, c := range v4conns {
		sock := &stdNetSocket{conn: c, pool: &s.messagePool}
		tx, rx := supportsUDPOffload(c)
		sock.txOffload.Store(tx)
		sock.rxOffload = rx
		if runtime.GOOS == "linux" {
			sock.pc = ipv4.NewPacketConn(c)
		}
		fns = append(fns, sock.makeReceiveIPv4())
		s.v4 = append(s.v4, sock)
	}
	for _, c := range v6conns {
		sock := &stdNetSocket{conn: c, pool: &s.messagePool}
		tx, rx := supportsUDPOffload(c)
		sock.txOffload.Store(tx)
		sock.rxOffload = rx
		if runtime.GOOS == "linux" {
			sock.pc = ipv6.NewPacketConn(c)
		}
		fns = append(fns, sock.makeReceiveIPv6())
		s.v6 = append(s.v6, sock)
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}

	return fns, uint16(port), nil
}

// messagePool recycles the [ipv6.Message] batches that the read and write
// paths hand to the kernel. It is shared by every socket of a [StdNetBind].
type messagePool struct {
	pool sync.Pool
}

// putMessages resets each message in (*msgs)[:usedMsgs] for reuse, then returns
// msgs to its [sync.Pool].
func (p *messagePool) putMessages(msgs *[]ipv6.Message, usedMsgs int) {
	for i := range (*msgs)[:usedMsgs] {
		// Clear references to previously used packet buffers, otherwise they
		// may never be GC'd.
		clear((*msgs)[i].Buffers)
		(*msgs)[i] = ipv6.Message{
			Buffers: (*msgs)[i].Buffers[:1], // Non-coalesced write paths require a single element.
			OOB:     (*msgs)[i].OOB,
		}
	}
	p.pool.Put(msgs)
}

func (p *messagePool) getMessages() *[]ipv6.Message {
	return p.pool.Get().(*[]ipv6.Message)
}

var (
	// If compilation fails here these are no longer the same underlying type.
	_ ipv6.Message = ipv4.Message{}
)

type batchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type batchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

const maxDatagramSize = 1<<16 - 1

func (s *stdNetSocket) receiveIP(
	slab []byte,
	packets []ReceivedPacket,
) (n int, err error) {
	msgs := s.pool.getMessages()
	usedMsgs := 1
	if runtime.GOOS == "linux" {
		// set a floor of 1 in case len(slab) < maxDatagramSize
		usedMsgs = max(1, len(slab)/maxDatagramSize)
		// we can't read more datagrams than what we can describe in packets
		usedMsgs = min(len(packets), usedMsgs)
	}
	defer s.pool.putMessages(msgs, usedMsgs)
	var numMsgs int
	if runtime.GOOS == "linux" {
		rem := slab
		for i := range usedMsgs {
			end := maxDatagramSize
			if len(rem) < maxDatagramSize {
				end = len(rem)
			}
			(*msgs)[i].Buffers[0] = rem[:end]
			(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
			rem = rem[end:]
		}
		numMsgs, err = s.pc.ReadBatch((*msgs)[:usedMsgs], 0)
		if err != nil {
			return 0, err
		}
	} else {
		msg := &(*msgs)[0]
		msg.Buffers[0] = slab
		msg.OOB = msg.OOB[:cap(msg.OOB)]
		msg.N, msg.NN, _, msg.Addr, err = s.conn.ReadMsgUDP(msg.Buffers[0], msg.OOB)
		if err != nil {
			return 0, err
		}
		numMsgs = 1
	}
	return fillReceivedPackets((*msgs)[:numMsgs], maxDatagramSize, packets, s.rxOffload, getGSOSize)
}

// TODO: [ReceiveFunc.PrettyName] recovers log labels by reflecting on
// the enclosing function. Two make funcs below distinguish address families,
// but this doesn't expose queue numbers when [StdNetBind.queues] > 1.

func (s *stdNetSocket) makeReceiveIPv4() ReceiveFunc {
	return func(slab []byte, packets []ReceivedPacket) (n int, err error) {
		return s.receiveIP(slab, packets)
	}
}

func (s *stdNetSocket) makeReceiveIPv6() ReceiveFunc {
	return func(slab []byte, packets []ReceivedPacket) (n int, err error) {
		return s.receiveIP(slab, packets)
	}
}

// TODO: When all Binds handle IdealBatchSize, remove this dynamic function and
// rename the IdealBatchSize constant to BatchSize.
func (s *StdNetBind) BatchSize() int {
	if runtime.GOOS == "linux" {
		return IdealBatchSize
	}
	return 1
}

func (s *StdNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs error
	for _, sock := range s.v4 {
		errs = errors.Join(errs, sock.conn.Close())
	}
	for _, sock := range s.v6 {
		errs = errors.Join(errs, sock.conn.Close())
	}
	s.v4 = nil
	s.v6 = nil
	s.blackhole4 = false
	s.blackhole6 = false
	return errs
}

type ErrUDPGSODisabled struct {
	onLaddr  string
	RetryErr error
}

func (e ErrUDPGSODisabled) Error() string {
	return fmt.Sprintf("disabled UDP GSO on %s, NIC(s) may not support checksum offload", e.onLaddr)
}

func (e ErrUDPGSODisabled) Unwrap() error {
	return e.RetryErr
}

// dstQueue picks a socket from a group of n for the given destination.
// See [WithQueues].
//
// Maphash is chosen for a stronger avalanche effect over low bits compared to FNV.
func dstQueue(ap netip.AddrPort, n int, seed maphash.Seed) int {
	return int(maphash.Comparable(seed, ap) % uint64(n))
}

func (s *StdNetBind) Send(bufs [][]byte, endpoint Endpoint, offset int) error {
	s.mu.Lock()
	blackhole := s.blackhole4
	socks := s.v4
	is6 := false
	if endpoint.DstIP().Is6() {
		blackhole = s.blackhole6
		socks = s.v6
		is6 = true
	}
	s.mu.Unlock()

	if blackhole {
		return nil
	}
	if len(socks) == 0 {
		return syscall.EAFNOSUPPORT
	}
	sock := socks[dstQueue(endpoint.(*StdNetEndpoint).AddrPort, len(socks), s.seed)]
	conn := sock.conn
	br := sock.pc
	offload := sock.txOffload.Load()

	msgs := s.getMessages()
	usedMsgs := len(bufs)
	defer s.putMessages(msgs, usedMsgs)
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)
	if is6 {
		as16 := endpoint.DstIP().As16()
		copy(ua.IP, as16[:])
		ua.IP = ua.IP[:16]
	} else {
		as4 := endpoint.DstIP().As4()
		copy(ua.IP, as4[:])
		ua.IP = ua.IP[:4]
	}
	ua.Port = int(endpoint.(*StdNetEndpoint).Port())
	var (
		retried bool
		err     error
	)
retry:
	if offload {
		n := coalesceMessages(ua, endpoint.(*StdNetEndpoint), bufs, offset, *msgs, setGSOSize)
		err = s.send(conn, br, (*msgs)[:n])
		if err != nil && offload && errShouldDisableUDPGSO(err) {
			offload = false
			sock.txOffload.Store(false)
			retried = true
			goto retry
		}
	} else {
		for i := range bufs {
			(*msgs)[i].Addr = ua
			(*msgs)[i].Buffers[0] = bufs[i][offset:]
			setSrcControl(&(*msgs)[i].OOB, endpoint.(*StdNetEndpoint))
		}
		err = s.send(conn, br, (*msgs)[:len(bufs)])
	}
	if retried {
		return ErrUDPGSODisabled{onLaddr: conn.LocalAddr().String(), RetryErr: err}
	}
	return err
}

func (s *StdNetBind) send(conn *net.UDPConn, pc batchWriter, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	if runtime.GOOS == "linux" {
		for {
			n, err = pc.WriteBatch(msgs[start:], 0)
			if err != nil || n == len(msgs[start:]) {
				break
			}
			start += n
		}
	} else {
		for _, msg := range msgs {
			_, _, err = conn.WriteMsgUDP(msg.Buffers[0], msg.OOB, msg.Addr.(*net.UDPAddr))
			if err != nil {
				break
			}
		}
	}
	return err
}

const (
	// Exceeding these values results in EMSGSIZE. They account for layer3 and
	// layer4 headers. IPv6 does not need to account for itself as the payload
	// length field is self excluding.
	maxIPv4PayloadLen = 1<<16 - 1 - 20 - 8
	maxIPv6PayloadLen = 1<<16 - 1 - 8

	// This is a hard limit imposed by the kernel.
	// As long as we use one fragment per datagram, this also serves as a
	// limit for the number of fragments we can coalesce during scatter-gather writes.
	//
	// 64 is below the 1024 of IOV_MAX (Linux) or UIO_MAXIOV (BSD),
	// and the 256 of WSABUF_MAX_COUNT (Windows).
	//
	// (2026-04) If we begin shipping datagrams in more than one fragment,
	// an independent fragment count limit needs to be implemented.
	udpSegmentMaxDatagrams = 64
)

type setGSOFunc func(control *[]byte, gsoSize uint16)

// coalesceMessages iterates 'buffs', setting and coalescing them in 'msgs'
// where possible while maintaining datagram order.
//
// It aggregates message components as a list of buffers without copying,
// and expects to be used only on Linux with scatter-gather writes via sendmmsg(2).
//
// All msgs[i].Buffers len must be one. Will panic if there is not enough msgs
// to coalesce all buffs.
func coalesceMessages(addr *net.UDPAddr, ep *StdNetEndpoint, bufs [][]byte, offset int, msgs []ipv6.Message, setGSO setGSOFunc) int {
	var (
		base         = -1 // index of msg we are currently coalescing into
		gsoSize      int  // segmentation size of msgs[base]
		dgramCnt     int  // number of dgrams coalesced into msgs[base]
		endBatch     bool // tracking flag to start a new batch on next iteration of bufs
		coalescedLen int  // bytes coalesced into msgs[base]
	)
	maxPayloadLen := maxIPv4PayloadLen
	if ep.DstIP().Is6() {
		maxPayloadLen = maxIPv6PayloadLen
	}
	for i, buf := range bufs {
		buf = buf[offset:]
		if i > 0 {
			msgLen := len(buf)
			if msgLen+coalescedLen <= maxPayloadLen &&
				msgLen <= gsoSize &&
				dgramCnt < udpSegmentMaxDatagrams &&
				!endBatch {
				// msgs[base].Buffers[0] is set to buf[i] when a new base is set.
				// This appends a struct iovec element in the underlying struct msghdr (scatter-gather).
				msgs[base].Buffers = append(msgs[base].Buffers, buf)
				if i == len(bufs)-1 {
					setGSO(&msgs[base].OOB, uint16(gsoSize))
				}
				dgramCnt++
				coalescedLen += msgLen
				if msgLen < gsoSize {
					// A smaller than gsoSize packet on the tail is legal, but
					// it must end the batch.
					endBatch = true
				}
				continue
			}
		}
		if dgramCnt > 1 {
			setGSO(&msgs[base].OOB, uint16(gsoSize))
		}
		// Reset prior to incrementing base since we are preparing to start a
		// new potential batch.
		endBatch = false
		base++
		gsoSize = len(buf)
		setSrcControl(&msgs[base].OOB, ep)
		msgs[base].Buffers[0] = buf
		msgs[base].Addr = addr
		dgramCnt = 1
		coalescedLen = len(buf)
	}
	return base + 1
}

type getGSOFunc func(control []byte) (int, error)

func fillReceivedPackets(msgs []ipv6.Message, slabOffset int, packets []ReceivedPacket, rxOffload bool, getGSO getGSOFunc) (n int, err error) {
	for i, msg := range msgs {
		var (
			gsoSize    int
			start      int
			numToSplit = 1
		)
		if rxOffload {
			gsoSize, err = getGSO(msg.OOB[:msg.NN])
			if err != nil {
				return n, err
			}
			if gsoSize > 0 {
				numToSplit = (msg.N + gsoSize - 1) / gsoSize
			}
		}
		addrPort := msg.Addr.(*net.UDPAddr).AddrPort()
		ep := &StdNetEndpoint{AddrPort: addrPort} // TODO: remove allocation
		getSrcFromControl(msg.OOB[:msg.NN], ep)
		regionOffset := i * slabOffset // region may contain multiple coalesced packets
		for j := 0; j < numToSplit; j++ {
			if n >= len(packets) {
				return n, fmt.Errorf("%w: filling received packet metadata resulted in overflow", io.ErrShortBuffer)
			}
			end := msg.N
			if gsoSize > 0 && start+gsoSize < end {
				end = start + gsoSize
			}
			packets[n] = ReceivedPacket{
				Offset:   regionOffset + start,
				Size:     end - start,
				Endpoint: ep,
			}
			n++
			start = end
		}
	}
	return n, nil
}
