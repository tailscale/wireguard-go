//go:build unix && !aix && !solaris && !illumos

package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

/*
ConnectedSockets keeps one UDP socket per address pair in use, each bound to the caller's port on one local address and connected to one remote address.

A connected socket settles the route once rather than per send, and gives each remote address its own receive queue. This matters most where an unconnected socket cannot batch (darwin has neither sendmmsg nor UDP GSO).

The sockets share the caller's port (see [ReusePortControl]), so NAT mappings are unaffected. The kernel delivers each datagram to the most specific matching socket, so the caller must read each connected socket as well as its own, through [ConnectedConfig.Reader].

Addresses past the socket limit, or that cannot be dialled, are left to the caller's socket. A nil *ConnectedSockets is valid and takes nothing.
*/
type ConnectedSockets struct {
	cfg ConnectedConfig

	mu      sync.Mutex
	socks   map[pairKey]*connectedSocket  // one per address pair that has carried traffic
	routes  map[netip.AddrPort]netip.Addr // the local address the route to each remote address picks
	failed  map[pairKey]time.Time         // pairs whose last dial failed, and when
	pending map[pairKey]int               // bytes each pair without a socket has carried since the last idle check
	dialMu  sync.Mutex                    // held for the length of a dial; see open
	port    int
	gen     uint64                                   // incremented by reset, so that a dial that raced it is discarded
	route   func(netip.AddrPort) (netip.Addr, error) // routeSource, replaced in tests
	closed  bool

	done    chan struct{}
	closing sync.Once
	running sync.WaitGroup // the idle check

	slots     []int // receive slot sizes a socket steps through, smallest first; see reader
	oversize  atomic.Uint64
	coalesced atomic.Uint64 // reads the kernel coalesced with GRO
}

const (
	// Receive slots grow per socket from connectedSmallSlot up to connectedHugeSlot, since datagram size depends on the remote MTU: the first datagram that fills a slot is dropped and moves the socket up a size. GRO sockets always use connectedHugeSlot.
	connectedSmallSlot   = 2048      // a WireGuard datagram from a peer with any tunnel MTU up to about 2000
	connectedJumboSlot   = 9216 + 1  // a 9000-byte tunnel MTU and its overhead
	connectedHugeSlot    = 1<<16 - 1 // the largest UDP datagram
	connectedSlabSize    = IdealBatchSize * connectedJumboSlot
	connectedGROSlabSize = connectedGROSlots * connectedHugeSlot

	// connectedGROSlots is how many 64 KiB slots one GRO read takes. A poorly merged flow puts only one to three datagrams in each, so a read needs many.
	connectedGROSlots = 64

	// groMaxSegments is UDP_GRO_CNT_MAX, the most datagrams the kernel coalesces into one read.
	groMaxSegments = 64

	// connectedIdle is the idle check interval. A socket unused for a whole interval is closed.
	connectedIdle = 30 * time.Second

	// connectedRetry is how long a pair whose dial failed is left to the caller's socket before it is dialled again.
	connectedRetry = 5 * time.Second

	// connectedBufSize is each socket's send buffer, smaller than socketBufferSize because there is one per remote address.
	connectedBufSize = 1 << 20

	// coalesceMin is how many datagrams a read must return, without filling its batch, before the reader sleeps for coalesceDelay to collect a fuller one. Idle traffic never pauses, and neither does a full batch.
	coalesceMin = 4
)

// pairKey is the address pair a socket carries: one of this host's addresses and a remote address.
type pairKey struct {
	local  netip.Addr
	remote netip.AddrPort
}

// connectedSocket is one remote address's socket.
type connectedSocket struct {
	key pairKey
	c   *net.UDPConn
	gro bool        // the kernel coalesces what it receives; see reader
	bs  batchSender // nil where the platform has no batched send
	br  batchReader

	// used is set on every send and every read that returns data, and cleared by the idle check.
	used atomic.Bool
}

// batchSender writes several datagrams to one connected socket in as few syscalls as the platform allows.
type batchSender interface {
	sendBatch(bufs [][]byte, offset int) error
}

// NewConnectedSockets returns a set of connected sockets sharing cfg.Port, or nil where the platform cannot support them. Every method is nil-safe.
func NewConnectedSockets(cfg ConnectedConfig) *ConnectedSockets {
	if cfg.MaxSockets <= 0 {
		cfg.MaxSockets = DefaultMaxConnectedSockets
	}
	if cfg.OpenAfter <= 0 {
		cfg.OpenAfter = DefaultOpenAfter
	}

	s := &ConnectedSockets{
		cfg:     cfg,
		socks:   make(map[pairKey]*connectedSocket),
		routes:  make(map[netip.AddrPort]netip.Addr),
		failed:  make(map[pairKey]time.Time),
		pending: make(map[pairKey]int),
		port:    cfg.Port,
		done:    make(chan struct{}),
	}
	for _, slot := range []int{connectedSmallSlot, connectedJumboSlot, connectedHugeSlot} {
		if slot > cfg.MaxDatagram { // start at the first size that holds the caller's hint
			s.slots = append(s.slots, slot)
		}
	}
	if len(s.slots) == 0 {
		s.slots = []int{connectedHugeSlot}
	}
	s.route = s.routeSource
	s.running.Add(1)
	go func() {
		defer s.running.Done()
		t := time.NewTicker(connectedIdle)
		defer t.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-t.C:
				s.closeIdle()
				s.recheckRoutes()
			}
		}
	}()
	return s
}

// Send writes each bufs[i][offset:] to dst on dst's connected socket, dialling one if needed. It reports whether it took the batch; false, always with a nil error, means the caller should send on its own socket.
func (s *ConnectedSockets) Send(dst netip.AddrPort, bufs [][]byte, offset int) (bool, error) {
	return s.SendFrom(dst, netip.Addr{}, bufs, offset)
}

// SendFrom is Send from a local address the caller has chosen, such as the one the peer last sent to. An invalid local behaves like Send.
func (s *ConnectedSockets) SendFrom(dst netip.AddrPort, local netip.Addr, bufs [][]byte, offset int) (bool, error) {
	if s == nil {
		return false, nil
	}
	n := 0
	for _, b := range bufs {
		n += len(b) - offset
	}
	for retried := false; ; retried = true {
		var cs *connectedSocket
		if local.IsValid() {
			cs = s.open(pairKey{local: localKey(local, dst), remote: dst}, n)
		} else {
			cs = s.socketFor(dst, n)
		}
		if cs == nil {
			return false, nil
		}
		cs.used.Store(true)
		err := cs.send(bufs, offset)
		if errors.Is(err, net.ErrClosed) && !retried {
			// Closed since the lookup by the idle check, reset or Rebind. Dial again once, skipping OpenAfter since the pair already carries traffic.
			s.remove(cs)
			n = s.cfg.OpenAfter
			continue
		}
		return true, s.classify(cs, err)
	}
}

// Dial opens a socket for the pair from dst to local, on which the caller has received size bytes, and reports whether it has one. A connected socket receives only its exact pair, and a peer may send to any local address, not just the one Send's route picks (IPv6 addresses rotate). An invalid local opens the pair Send would.
//
// size counts towards OpenAfter, so the caller calls Dial for each datagram received on a pair without a socket until it reports true.
func (s *ConnectedSockets) Dial(dst netip.AddrPort, local netip.Addr, size int) bool {
	if s == nil {
		return false
	}
	if !local.IsValid() {
		return s.socketFor(dst, size) != nil
	}
	return s.open(pairKey{local: localKey(local, dst), remote: dst}, size) != nil
}

func (cs *connectedSocket) send(bufs [][]byte, offset int) error {
	if cs.bs != nil {
		return cs.bs.sendBatch(bufs, offset)
	}
	for _, b := range bufs {
		if _, err := cs.c.Write(b[offset:]); err != nil {
			return err
		}
	}
	return nil
}

// Rebind closes every socket so each is redialled on its next send, bound to port. Call it after the caller's socket is rebound and after any network change, including a change of interface that keeps the source address; port 0 means the set takes nothing until the next Rebind.
func (s *ConnectedSockets) Rebind(port int) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.port = port
	s.mu.Unlock()
	s.reset()
}

// reset closes every socket, so each is redialled on its next send with the current port and Control. A dial in progress is discarded, since it may have used the old ones.
func (s *ConnectedSockets) reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.gen++
	for _, cs := range s.socks {
		cs.c.Close()
	}
	clear(s.socks)
	clear(s.routes)
	clear(s.failed)
	clear(s.pending)
	s.mu.Unlock()
}

// Close closes every socket, which makes every ConnectedReadFunc return net.ErrClosed, and stops the idle check.
func (s *ConnectedSockets) Close() error {
	if s == nil {
		return nil
	}
	s.closing.Do(func() { close(s.done) })
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.reset()
	s.running.Wait()
	return nil
}

// socketFor returns the socket for the pair the route to dst picks, counting n bytes towards opening it, or nil when the caller should use its own socket.
func (s *ConnectedSockets) socketFor(dst netip.AddrPort, n int) *connectedSocket {
	s.mu.Lock()
	local, known := s.routes[dst]
	if cs := s.socks[pairKey{local, dst}]; known && cs != nil {
		s.mu.Unlock()
		return cs
	}
	probe := pairKey{remote: dst} // stands for dst's route while it is unknown
	if !known && !s.mayDial(probe) {
		s.mu.Unlock()
		return nil
	}
	gen := s.gen
	s.mu.Unlock()
	if !known {
		src, err := s.route(dst)
		s.mu.Lock()
		switch {
		case s.gen != gen: // a reset meanwhile, so the route found may be stale
			s.mu.Unlock()
			return nil
		case err != nil:
			s.failed[probe] = time.Now()
			s.mu.Unlock()
			return nil
		}
		local = localKey(src, dst)
		s.routes[dst] = local
		s.mu.Unlock()
	}
	return s.open(pairKey{local, dst}, n)
}

// open returns the socket for k, dialling it once k has carried OpenAfter bytes, or nil when the caller should use its own socket.
// One dial runs at a time, and other callers fall back rather than wait: on darwin and the BSDs a socket cannot bind an address and port while another there is unconnected.
func (s *ConnectedSockets) open(k pairKey, n int) *connectedSocket {
	s.mu.Lock()
	cs := s.socks[k]
	if cs == nil {
		s.pending[k] += n
	}
	may := cs == nil && s.pending[k] >= s.cfg.OpenAfter && s.mayDial(k) && ConnectedDeliveryCheck() == nil
	s.mu.Unlock()
	if cs != nil || !may {
		return cs
	}
	if !s.dialMu.TryLock() {
		return nil
	}
	defer s.dialMu.Unlock()
	s.mu.Lock()
	if cs := s.socks[k]; cs != nil || !s.mayDial(k) { // opened, or the limit reached, by the dial that held the lock
		s.mu.Unlock()
		return cs
	}
	port, gen := s.port, s.gen
	s.mu.Unlock()

	c, err := s.dialFrom(k.remote, &net.UDPAddr{IP: k.local.AsSlice(), Port: port, Zone: k.local.Zone()})
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		if s.gen == gen {
			s.failed[k] = time.Now()
		}
		return nil
	}
	if s.closed || s.gen != gen {
		c.Close()
		return nil
	}
	delete(s.pending, k)
	delete(s.failed, k)
	return s.adopt(k, c)
}

// routeSource is the local address the route to dst picks, found by connecting a throwaway socket with the caller's Control so fwmarks and interface bindings apply.
// Sockets bind that address because connect pins a UDP socket's local address even after a wildcard bind, on Linux as on darwin.
func (s *ConnectedSockets) routeSource(dst netip.AddrPort) (netip.Addr, error) {
	d := net.Dialer{Control: s.cfg.Control}
	c, err := d.Dial(network(dst), dst.String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr(), nil
}

// localKey is local as a pairKey holds it: unmapped, and for a link-local address with the zone of the peer it talks to, which binding it needs.
func localKey(local netip.Addr, dst netip.AddrPort) netip.Addr {
	local = local.Unmap()
	if local.Is6() && local.IsLinkLocalUnicast() {
		return local.WithZone(dst.Addr().Zone())
	}
	return local.WithZone("")
}

// mayDial reports whether k may be dialled now. s.mu must be held.
func (s *ConnectedSockets) mayDial(k pairKey) bool {
	t, failed := s.failed[k]
	return !s.closed && s.port != 0 && !s.full() && !(failed && time.Since(t) < connectedRetry)
}

// full reports whether the socket limit is reached. s.mu must be held.
// It is checked before a dial, not after, because closing a new socket loses the datagrams it caught between bind and connect.
func (s *ConnectedSockets) full() bool {
	return len(s.socks) >= s.cfg.MaxSockets
}

func network(dst netip.AddrPort) string {
	if dst.Addr().Is6() {
		return "udp6"
	}
	return "udp4"
}

// dialFrom opens a socket from local to dst.
func (s *ConnectedSockets) dialFrom(dst netip.AddrPort, local *net.UDPAddr) (*net.UDPConn, error) {
	d := net.Dialer{LocalAddr: local, Control: s.control}
	nc, err := d.Dial(network(dst), dst.String())
	if err != nil {
		return nil, err
	}
	return nc.(*net.UDPConn), nil
}

// adopt makes c the socket for k and hands it to cfg.Reader. s.mu must be held, and s not closed.
func (s *ConnectedSockets) adopt(k pairKey, c *net.UDPConn) *connectedSocket {
	cs := &connectedSocket{key: k, c: c, gro: hasGRO(c), bs: newBatchSender(c, k.remote), br: newBatchReader(c, k.remote)}
	cs.used.Store(true)
	slab, batch := connectedSlabSize, IdealBatchSize
	if cs.gro {
		slab, batch = connectedGROSlabSize, connectedGROSlots*groMaxSegments
	}
	if s.cfg.Reader == nil || !s.cfg.Reader(s.reader(cs), slab, batch) {
		c.Close() // unread, it would swallow the peer's traffic
		return nil
	}
	s.socks[k] = cs
	return cs
}

// connectedSupported is whether this platform has [ConnectedSockets] at all.
const connectedSupported = true

// ReusePortControl lets a socket share its port with [ConnectedSockets]. Apply it to the caller's own socket before it binds. It sets SO_REUSEPORT on Linux and SO_REUSEADDR elsewhere (see sharePort).
func ReusePortControl(network, address string, c syscall.RawConn) error { return sharePort(c) }

// control is every socket's Control: share the port, size the buffers, then whatever the caller asked for.
func (s *ConnectedSockets) control(network, address string, c syscall.RawConn) error {
	if err := sharePort(c); err != nil {
		return err
	}
	enableGRO(c)
	c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, connectedBufSize)
		// Only ever raise the receive buffer, never lower a larger system default.
		if cur, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF); err == nil && cur < connectedRecvBufSize {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, connectedRecvBufSize)
			forceRecvBuf(fd)
		}
	})
	if s.cfg.Control != nil {
		return s.cfg.Control(network, address, c)
	}
	return nil
}

// classify handles a send error on cs. ECONNREFUSED (ICMP port unreachable, typically a restarting peer) is ignored.
// EADDRNOTAVAIL, ENETUNREACH and, on Linux, EINVAL mean the source address is gone, so the socket is closed and the next send redials.
func (s *ConnectedSockets) classify(cs *connectedSocket, err error) error {
	switch {
	case err == nil, errors.Is(err, unix.ECONNREFUSED):
		return nil
	case errors.Is(err, unix.EADDRNOTAVAIL), errors.Is(err, unix.ENETUNREACH), errors.Is(err, net.ErrClosed), runtime.GOOS == "linux" && errors.Is(err, unix.EINVAL):
		s.remove(cs)
	}
	return err
}

// remove closes cs and forgets it, if it is still in the set.
func (s *ConnectedSockets) remove(cs *connectedSocket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.socks[cs.key] == cs {
		delete(s.socks, cs.key)
		cs.c.Close()
	}
}

// transientRecvErr reports whether a read error is an ICMP report about an earlier datagram, such as ECONNREFUSED from a restarting peer, which must not end the reader.
func transientRecvErr(err error) bool {
	for _, e := range []error{unix.ECONNREFUSED, unix.EHOSTUNREACH, unix.ENETUNREACH, unix.EHOSTDOWN, unix.EMSGSIZE} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// closeIdle closes sockets unused since the previous call, and forgets failed dials old enough to retry.
func (s *ConnectedSockets) closeIdle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	inUse := make(map[netip.AddrPort]bool, len(s.socks))
	for k, cs := range s.socks {
		if !cs.used.Swap(false) {
			cs.c.Close()
			delete(s.socks, k)
			continue
		}
		inUse[k.remote] = true
	}
	for dst := range s.routes {
		if !inUse[dst] {
			delete(s.routes, dst) // looked up afresh on the next send
		}
	}
	clear(s.pending) // only recent traffic counts towards opening a pair
	for k, t := range s.failed {
		if time.Since(t) >= connectedRetry {
			delete(s.failed, k)
		}
	}
}

// recheckRoutes redoes the route lookup for every address in s.routes and moves any whose local address changed to the new pair. The old pair's socket stays until the idle check closes it.
func (s *ConnectedSockets) recheckRoutes() {
	s.mu.Lock()
	gen := s.gen
	old := make(map[netip.AddrPort]netip.Addr, len(s.routes))
	for dst, local := range s.routes {
		old[dst] = local
	}
	s.mu.Unlock()
	for dst, local := range old {
		src, err := s.route(dst)
		if err != nil {
			continue // left to the next send, which fails over to the caller's socket if the old address is gone
		}
		now := localKey(src, dst)
		if now == local {
			continue
		}
		s.mu.Lock()
		if s.gen == gen && s.routes[dst] == local {
			s.routes[dst] = now
		}
		s.mu.Unlock()
	}
}

// reader returns cs's ConnectedReadFunc, which reads a batch straight into the caller's slab, splitting GRO reads back into datagrams in place.
func (s *ConnectedSockets) reader(cs *connectedSocket) ConnectedReadFunc {
	msgs := make([]ipv6.Message, max(IdealBatchSize, connectedGROSlots))
	for i := range msgs {
		msgs[i].Buffers = make(net.Buffers, 1)
		if cs.gro {
			msgs[i].OOB = make([]byte, controlSize)
		}
	}
	tier := 0
	if cs.gro {
		tier = len(s.slots) - 1 // see connectedGROSlots
	}
	pause := false
	return func(slab []byte, packets []ConnectedPacket) (int, error) {
		for {
			if pause {
				time.Sleep(coalesceDelay)
				pause = false
			}
			slot := s.slots[tier]
			segs := 1
			if cs.gro {
				segs = groMaxSegments
			}
			m := msgs[:min(len(msgs), len(slab)/slot, len(packets)/segs)]
			if len(m) == 0 {
				return 0, fmt.Errorf("connected socket read: slab of %d bytes or %d packets too small for one %d-byte slot", len(slab), len(packets), slot)
			}
			for i := range m {
				m[i].Buffers[0] = slab[i*slot : (i+1)*slot]
				m[i].OOB = m[i].OOB[:cap(m[i].OOB)]
				m[i].N, m[i].NN, m[i].Flags = 0, 0, 0
				m[i].Addr = nil
			}
			n, err := cs.br.ReadBatch(m, 0)
			if err != nil {
				switch {
				case errors.Is(err, net.ErrClosed):
					return 0, net.ErrClosed // closed by the idle check, a send error, reset or Close
				case transientRecvErr(err):
					continue
				}
				// Anything else leaves the socket unusable; forget it so the next send dials a new one.
				s.remove(cs)
				return 0, net.ErrClosed
			}
			total := 0
			for i := 0; i < n; i++ {
				size := m[i].N
				// Truncated: drop it and use the next slot size. Without MSG_TRUNC a full slot counts as truncated, except for GRO, where it is legitimate.
				if m[i].Flags&unix.MSG_TRUNC != 0 || !cs.gro && size >= slot {
					s.oversize.Add(1)
					tier = min(tier+1, len(s.slots)-1)
					continue
				}
				src := cs.key.remote
				if a, ok := m[i].Addr.(*net.UDPAddr); ok && a != nil {
					src = a.AddrPort() // as StdNetBind reports the source of what its own socket reads
				}
				seg := size
				if cs.gro {
					if g, err := getGSOSize(m[i].OOB[:m[i].NN]); err == nil && g > 0 && g < size {
						seg = g // coalesced: datagrams of g bytes, the last perhaps shorter
						s.coalesced.Add(1)
					}
				}
				for o := 0; o < size && total < len(packets); o += seg {
					packets[total] = ConnectedPacket{Offset: i*slot + o, Size: min(seg, size-o), Source: src, Local: cs.key.local}
					total++
				}
			}
			pause = n >= coalesceMin && n < len(m)
			if total > 0 {
				cs.used.Store(true) // a receive-only socket from Dial is in use too
				return total, nil
			}
		}
	}
}

// newPacketConnReader reads through x/net, which batches with recvmmsg on Linux and reads one datagram per call elsewhere.
func newPacketConnReader(c *net.UDPConn, is6 bool) batchReader {
	if is6 {
		return ipv6.NewPacketConn(c)
	}
	return ipv4.NewPacketConn(c)
}
