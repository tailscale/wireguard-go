/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/conn/bindtest"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

// boundedPoolOptions returns the options tailscale uses on iOS
// (wgengine/wgcfg/mem_ios.go), with the given staged queue size. With a
// bounded pool, the TUN readers and the receive path share one pool of 64
// packet buffers.
func boundedPoolOptions(stagedSize int) []Option {
	return []Option{
		WithQueueStagedSize(stagedSize),
		WithQueueOutboundSize(64),
		WithQueueInboundSize(64),
		WithQueueHandshakeSize(64),
		WithPreallocatedBuffersPerPool(64),
	}
}

// A memNet connects memNetBinds in memory, so that tests can run in a
// synctest bubble. Packets to a port with no bind, or across a cut link, are
// dropped, like UDP to an unreachable host.
type memNet struct {
	mu    sync.Mutex
	binds map[uint16]*memNetBind
	cut   map[[2]uint16]bool
	delay map[[2]uint16]time.Duration
}

func memNetLink(a, b uint16) [2]uint16 {
	if a > b {
		a, b = b, a
	}
	return [2]uint16{a, b}
}

// setCut cuts or restores the link between ports a and b.
func (n *memNet) setCut(a, b uint16, cut bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.cut == nil {
		n.cut = make(map[[2]uint16]bool)
	}
	n.cut[memNetLink(a, b)] = cut
}

// setDelay sets the one-way delay of the link between ports a and b.
func (n *memNet) setDelay(a, b uint16, d time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.delay == nil {
		n.delay = make(map[[2]uint16]time.Duration)
	}
	n.delay[memNetLink(a, b)] = d
}

func (n *memNet) newBind(port uint16) *memNetBind {
	b := &memNetBind{net: n, port: port, rx: make(chan memNetPacket, 1024)}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.binds == nil {
		n.binds = make(map[uint16]*memNetBind)
	}
	n.binds[port] = b
	return b
}

func (n *memNet) deliver(from, to uint16, b []byte) {
	n.mu.Lock()
	dst := n.binds[to]
	cut := n.cut[memNetLink(from, to)]
	delay := n.delay[memNetLink(from, to)]
	n.mu.Unlock()
	if dst == nil || cut {
		return
	}
	p := memNetPacket{b: bytes.Clone(b), from: from}
	send := func() {
		select {
		case dst.rx <- p:
		default:
		}
	}
	if delay > 0 {
		time.AfterFunc(delay, send)
	} else {
		send()
	}
}

type memNetPacket struct {
	b    []byte
	from uint16
}

type memNetBind struct {
	net  *memNet
	port uint16
	rx   chan memNetPacket

	mu     sync.Mutex
	closed chan struct{}
}

var _ conn.Bind = (*memNetBind)(nil)

func (b *memNetBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	closed := make(chan struct{})
	b.mu.Lock()
	b.closed = closed
	b.mu.Unlock()
	recv := func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		select {
		case <-closed:
			return 0, net.ErrClosed
		case p := <-b.rx:
			packets[0] = conn.ReceivedPacket{
				Size:     copy(slab, p.b),
				Endpoint: bindtest.ChannelEndpoint(p.from),
			}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{recv}, b.port, nil
}

func (b *memNetBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed != nil {
		select {
		case <-b.closed:
		default:
			close(b.closed)
		}
	}
	return nil
}

func (b *memNetBind) SetMark(uint32) error { return nil }

func (b *memNetBind) BatchSize() int { return 1 }

func (b *memNetBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	for _, buf := range bufs {
		b.net.deliver(b.port, uint16(ep.(bindtest.ChannelEndpoint)), buf[offset:])
	}
	return nil
}

func (b *memNetBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return bindtest.ChannelEndpoint(ap.Port()), nil
}

// A memNetNode is a Device on a memNet, with a channel TUN.
type memNetNode struct {
	dev  *Device
	tun  *tuntest.ChannelTUN
	key  NoisePrivateKey
	port uint16
	ip   netip.Addr
}

func newMemNetNode(tb testing.TB, n *memNet, port uint16, ip string, opts ...Option) *memNetNode {
	tb.Helper()
	key, err := newPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}
	node := &memNetNode{
		tun:  tuntest.NewChannelTUN(),
		key:  key,
		port: port,
		ip:   netip.MustParseAddr(ip),
	}
	node.dev = NewDevice(node.tun.TUN(), n.newBind(port), NewLogger(LogLevelError, fmt.Sprintf("dev%d: ", port)), opts...)
	tb.Cleanup(func() {
		// Flush staged packets first. Without a limit on them, they can
		// hold every pool item, and Close would wait forever for goroutines
		// that are waiting for one, so that tests fail instead of finishing.
		node.dev.peers.RLock()
		for _, peer := range node.dev.peers.keyMap {
			peer.FlushStagedPackets()
		}
		node.dev.peers.RUnlock()
		node.dev.Close()
	})
	if err := node.dev.IpcSet(uapiCfg(
		"private_key", hex.EncodeToString(key[:]),
		"listen_port", strconv.Itoa(int(port)),
	)); err != nil {
		tb.Fatal(err)
	}
	if err := node.dev.Up(); err != nil {
		tb.Fatal(err)
	}
	return node
}

// addPeer adds a peer with the given public key and memNet port to n.
func (n *memNetNode) addPeer(tb testing.TB, pk NoisePublicKey, port uint16, allowedIPs ...string) *Peer {
	tb.Helper()
	cfg := []string{
		"public_key", hex.EncodeToString(pk[:]),
		"endpoint", fmt.Sprintf("127.0.0.1:%d", port),
	}
	for _, ip := range allowedIPs {
		cfg = append(cfg, "allowed_ip", ip)
	}
	if err := n.dev.IpcSet(uapiCfg(cfg...)); err != nil {
		tb.Fatal(err)
	}
	return n.dev.LookupPeer(pk)
}

// connect adds each node as a peer of the other, with allowed IPs aIPs for b
// on a and the IP of a for a on b.
func connect(tb testing.TB, a, b *memNetNode, aIPs ...string) *Peer {
	tb.Helper()
	b.addPeer(tb, a.key.publicKey(), a.port, netip.PrefixFrom(a.ip, 32).String())
	return a.addPeer(tb, b.key.publicKey(), b.port, aIPs...)
}

// addUnreachablePeer adds a peer to n at a port where nothing listens.
func (n *memNetNode) addUnreachablePeer(tb testing.TB, port uint16, allowedIP string) *Peer {
	tb.Helper()
	key, err := newPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}
	return n.addPeer(tb, key.publicKey(), port, allowedIP)
}

// write writes packet to n's TUN, reporting false if the TUN reader does not
// take it within a second.
func (n *memNetNode) write(packet []byte) bool {
	select {
	case n.tun.Outbound <- packet:
		return true
	case <-time.After(time.Second):
		return false
	}
}

// ping sends a packet from src to dst and fails the test if it does not
// arrive within 5s, which allows for one handshake retry.
func ping(tb testing.TB, src, dst *memNetNode) {
	tb.Helper()
	pingAddrs(tb, src, src.ip, dst, dst.ip)
}

// pingAddrs is like ping, with the given source and destination addresses.
func pingAddrs(tb testing.TB, src *memNetNode, srcIP netip.Addr, dst *memNetNode, dstIP netip.Addr) {
	tb.Helper()
	msg := tuntest.Ping(dstIP, srcIP)
	if !src.write(msg) {
		tb.Fatalf("ping %v -> %v: TUN reader is blocked; %s", srcIP, dstIP, poolState(src.dev))
	}
	select {
	case got := <-dst.tun.Inbound:
		if !bytes.Equal(got, msg) {
			tb.Fatalf("ping %v -> %v: got a different packet", srcIP, dstIP)
		}
	case <-time.After(5 * time.Second):
		tb.Fatalf("ping %v -> %v did not arrive; %s", srcIP, dstIP, poolState(src.dev))
	}
}

// poolState describes the packet buffers of dev that are in use and staged.
func poolState(dev *Device) string {
	p := dev.pool.packetBufs
	p.lock.Lock()
	inUse := p.count
	p.lock.Unlock()
	return fmt.Sprintf("%d/%d packet buffers in use, %d staged", inUse, p.max, stagedLen(dev))
}

// stagedLen returns the number of batches in the staged queues of dev's
// peers. With a batch size of 1, that is the number of staged packets.
func stagedLen(dev *Device) int {
	dev.peers.RLock()
	defer dev.peers.RUnlock()
	n := 0
	for _, peer := range dev.peers.keyMap {
		n += len(peer.queue.staged)
	}
	return n
}

// TestStagedPacketsBoundedPool checks that traffic to peers that cannot
// complete a handshake does not take every buffer of a bounded pool, which
// stops the TUN reader and the receive path for all peers.
// See tailscale/tailscale#21773.
func TestStagedPacketsBoundedPool(t *testing.T) {
	tests := []struct {
		name        string
		unreachable int
		stagedSize  int
	}{
		{"one_unreachable_peer", 1, 64},
		// A smaller staged queue per peer is not enough on its own: several
		// unreachable peers together can still take every buffer.
		{"eight_unreachable_peers_staged_16", 8, 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var n memNet
				phone := newMemNetNode(t, &n, 1, "1.0.0.1", boundedPoolOptions(tt.stagedSize)...)
				healthy := newMemNetNode(t, &n, 2, "1.0.0.2")
				late := newMemNetNode(t, &n, 3, "1.0.0.3")
				connect(t, phone, healthy, "1.0.0.2/32")
				connect(t, phone, late, "1.0.0.3/32")
				for i := range tt.unreachable {
					phone.addUnreachablePeer(t, uint16(100+i), fmt.Sprintf("10.0.0.%d/32", i+1))
				}
				ping(t, phone, healthy)
				ping(t, healthy, phone)

				// Send twice the pool size to each unreachable peer, faster than
				// handshake attempts can give up.
				const perPeer = 2 * 64
				for i := range perPeer {
					for j := range tt.unreachable {
						dst := netip.AddrFrom4([4]byte{10, 0, 0, byte(j + 1)})
						if !phone.write(tuntest.Ping(dst, phone.ip)) {
							t.Fatalf("TUN reader blocked after %d packets to unreachable peers; %s",
								i*tt.unreachable+j, poolState(phone.dev))
						}
					}
				}
				synctest.Wait()

				// The healthy peer is still reachable both ways.
				ping(t, phone, healthy)
				ping(t, healthy, phone)
				// A peer that still needs a handshake gets its first packet
				// through, rather than having it dropped to make room.
				ping(t, phone, late)

				if staged, limit := stagedLen(phone.dev), 64/2; staged > limit {
					t.Errorf("%d packets staged, want at most %d", staged, limit)
				}
			})
		})
	}
}

// TestStagedPacketsExitNode covers the worst case of
// TestStagedPacketsBoundedPool: the peer that cannot be reached is an exit
// node, over a relayed path. All of the device's traffic is for it and keeps
// coming, and traffic keeps coming back once the exit node is reachable
// again. Without a limit on staged packets, the healthy peer is cut off as
// soon as the session with the exit node expires, and traffic with the exit
// node does not reliably resume when the link comes back: the handshake
// response competes with that traffic for a buffer on the receive path.
func TestStagedPacketsExitNode(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var n memNet
		phone := newMemNetNode(t, &n, 1, "1.0.0.1", boundedPoolOptions(64)...)
		healthy := newMemNetNode(t, &n, 2, "1.0.0.2")
		exit := newMemNetNode(t, &n, 3, "1.0.0.3")
		connect(t, phone, healthy, "1.0.0.2/32")
		connect(t, phone, exit, "0.0.0.0/0")
		n.setDelay(phone.port, exit.port, 100*time.Millisecond)
		internet := netip.MustParseAddr("8.8.8.8")

		// Establish sessions, one direction at a time.
		ping(t, phone, healthy)
		ping(t, healthy, phone)
		pingAddrs(t, phone, phone.ip, exit, internet)
		pingAddrs(t, exit, internet, phone, phone.ip)

		done := make(chan struct{})
		defer close(done)
		// count counts the packets that node's TUN receives, in the counter
		// that counter returns for their source address.
		count := func(node *memNetNode, counter func(src netip.Addr) *atomic.Int64) {
			go func() {
				for {
					select {
					case p := <-node.tun.Inbound:
						counter(netip.AddrFrom4([4]byte(p[12:16]))).Add(1)
					case <-done:
						return
					}
				}
			}()
		}
		var toExit, fromExit, toHealthy, fromHealthy atomic.Int64
		count(exit, func(netip.Addr) *atomic.Int64 { return &toExit })
		count(healthy, func(netip.Addr) *atomic.Int64 { return &toHealthy })
		count(phone, func(src netip.Addr) *atomic.Int64 {
			if src == healthy.ip {
				return &fromHealthy
			}
			return &fromExit
		})
		flow := func(dst *memNetNode, every time.Duration, packet func(i int) []byte) {
			go func() {
				ticker := time.NewTicker(every)
				defer ticker.Stop()
				for i := 0; ; i++ {
					select {
					case <-ticker.C:
					case <-done:
						return
					}
					select {
					case dst.tun.Outbound <- packet(i):
					case <-done:
						return
					}
				}
			}()
		}
		// Traffic from the phone to the internet, and replies back.
		flow(phone, 10*time.Millisecond, func(i int) []byte {
			return tuntest.Ping(netip.AddrFrom4([4]byte{8, 8, byte(i >> 8), byte(i)}), phone.ip)
		})
		flow(exit, 20*time.Millisecond, func(int) []byte {
			return tuntest.Ping(phone.ip, internet)
		})

		// probe sends one packet each way between the phone and the healthy
		// peer, and reports whether both arrived within a second.
		probe := func() bool {
			to, from := toHealthy.Load(), fromHealthy.Load()
			phone.write(tuntest.Ping(healthy.ip, phone.ip))
			healthy.write(tuntest.Ping(phone.ip, healthy.ip))
			time.Sleep(time.Second)
			return toHealthy.Load() > to && fromHealthy.Load() > from
		}

		// Cut the exit node off for longer than the session lasts.
		start := time.Now()
		n.setCut(phone.port, exit.port, true)
		outage := RejectAfterTime + 30*time.Second
		var down int
		for time.Since(start) < outage {
			if !probe() {
				down++
			}
		}
		t.Logf("exit node unreachable for %v: healthy peer unreachable for %d s; %s",
			outage, down, poolState(phone.dev))
		if down > 0 {
			t.Errorf("healthy peer unreachable for %d s while the exit node was unreachable", down)
		}

		// Restore the link. Traffic must resume within a handshake retry
		// or two, while it keeps coming.
		n.setCut(phone.port, exit.port, false)
		restored := time.Now()
		to, from := toExit.Load(), fromExit.Load()
		for toExit.Load() == to || fromExit.Load() == from {
			if time.Since(restored) > 2*(RekeyTimeout+time.Second) {
				t.Fatalf("traffic with the exit node did not resume within %v of the link coming back; %s",
					time.Since(restored), poolState(phone.dev))
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Logf("traffic with the exit node resumed %v after the link came back", time.Since(restored))
		if !probe() {
			t.Errorf("healthy peer unreachable after the exit node came back")
		}
	})
}

// TestStagedPacketsCount checks the count of staged packets that
// [Device.trimStagedPackets] relies on against the staged queues.
func TestStagedPacketsCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var n memNet
		// Staged queues of 2 for 20 peers can hold more than the limit, so
		// that both drops of a peer's oldest staged batch and trimming
		// happen.
		phone := newMemNetNode(t, &n, 1, "1.0.0.1", boundedPoolOptions(2)...)
		healthy := newMemNetNode(t, &n, 2, "1.0.0.2")
		connect(t, phone, healthy, "1.0.0.2/32")
		var unreachable []*Peer
		for i := range 20 {
			unreachable = append(unreachable, phone.addUnreachablePeer(t, uint16(100+i), fmt.Sprintf("10.0.0.%d/32", i+1)))
		}
		check := func(when string) {
			t.Helper()
			synctest.Wait()
			if got, want := phone.dev.staged.count.Load(), int64(stagedLen(phone.dev)); got != want {
				t.Errorf("%s: staged count is %d, but %d packets are staged", when, got, want)
			}
		}
		check("initially")

		for i := range 3 * 64 {
			dst := netip.AddrFrom4([4]byte{10, 0, 0, byte(i%len(unreachable) + 1)})
			if !phone.write(tuntest.Ping(dst, phone.ip)) {
				t.Fatalf("TUN reader blocked; %s", poolState(phone.dev))
			}
		}
		check("after trimming")
		if staged := stagedLen(phone.dev); staged == 0 || int64(staged) > phone.dev.staged.limit {
			t.Errorf("%d packets staged, want between 1 and %d", staged, phone.dev.staged.limit)
		}

		// Sent after a handshake, along with a keepalive in reply to data,
		// and flushed when handshakes give up.
		ping(t, phone, healthy)
		ping(t, healthy, phone)
		check("after a handshake")
		time.Sleep((MaxTimerHandshakes + 2) * (RekeyTimeout + time.Second))
		check("after handshakes gave up")
		if staged := stagedLen(phone.dev); staged != 0 {
			t.Errorf("%d packets staged after handshakes gave up, want 0", staged)
		}

		// Flushed when a peer is removed.
		for i := range 2 * 64 {
			dst := netip.AddrFrom4([4]byte{10, 0, 0, byte(i%len(unreachable) + 1)})
			if !phone.write(tuntest.Ping(dst, phone.ip)) {
				t.Fatalf("TUN reader blocked; %s", poolState(phone.dev))
			}
		}
		check("before removing peers")
		for _, peer := range unreachable {
			phone.dev.RemovePeer(peer.handshake.remoteStatic)
		}
		check("after removing peers")
		if got := phone.dev.staged.count.Load(); got != 0 {
			t.Errorf("staged count is %d after removing all peers with staged packets, want 0", got)
		}
	})
}

// TestStagedPacketsCountConcurrent checks the count of staged packets while
// several TUN readers stage and send packets for the same peer at once.
func TestStagedPacketsCountConcurrent(t *testing.T) {
	const queues = 4
	pair := genTestPairQueues(t, false, queues, boundedPoolOptions(64)...)
	go func() {
		for range pair[1].tun.Inbound {
		}
	}()
	var wg sync.WaitGroup
	for range queues {
		wg.Go(func() {
			for range 2000 {
				pair[0].tun.Outbound <- tuntest.Ping(pair[1].ip, pair[0].ip)
			}
		})
	}
	wg.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		count, staged := pair[0].dev.staged.count.Load(), stagedLen(pair[0].dev)
		if count == int64(staged) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("staged count is %d, but %d packets are staged", count, staged)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
