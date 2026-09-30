/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/conn/bindtest"
)

// bulkPacket returns a minimal IPv4 packet of size bytes from src to dst.
func bulkPacket(src, dst netip.Addr, size int, seq uint32) []byte {
	b := make([]byte, size)
	b[0] = 0x45 // IPv4, 20-byte header
	binary.BigEndian.PutUint16(b[2:], uint16(size))
	b[8] = 64 // TTL
	b[9] = 17 // UDP; the device ignores the rest
	s4, d4 := src.As4(), dst.As4()
	copy(b[12:], s4[:])
	copy(b[16:], d4[:])
	binary.BigEndian.PutUint32(b[20:], seq)
	return b
}

// sendBulk sends n packets of size bytes from pair[from] to the other peer and reports how many arrived.
func sendBulk(t *testing.T, pair *testPair, from, n, size int) int {
	t.Helper()
	src, dst := pair[from], pair[from^1]
	got := make(chan int)
	go func() {
		c := 0
		for {
			select {
			case <-dst.tun.Inbound:
				c++
				if c == n {
					got <- c
					return
				}
			case <-time.After(2 * time.Second):
				got <- c
				return
			}
		}
	}()
	for i := range n {
		src.tun.Outbound <- bulkPacket(src.ip, dst.ip, size, uint32(i))
		if i%64 == 63 {
			time.Sleep(time.Millisecond) // pace it so loopback drops nothing
		}
	}
	return <-got
}

func startedRoutines(d *Device) int {
	d.net.started.Lock()
	defer d.net.started.Unlock()
	return d.net.started.count
}

// With connected sockets, devices receive through routines the Bind starts per socket, and a rebind replaces them.
func TestConnectedSocketsStartReceiveRoutines(t *testing.T) {
	binds := [2]conn.Bind{conn.NewStdNetBind(conn.WithConnectedSockets(true)), conn.NewStdNetBind(conn.WithConnectedSockets(true))}
	if _, ok := binds[0].(conn.ReceiveFuncStarter); !ok {
		t.Skip("StdNetBind has no ReceiveFuncStarter")
	}
	pair := genTestPairBinds(t, binds, 1)
	pair.Send(t, Ping, nil)
	const n, size = 1200, 1200 // 1.4 MB each way, past conn.DefaultOpenAfter
	exchange := func(stage string) {
		t.Helper()
		for from := range 2 {
			if got := sendBulk(t, &pair, from, n, size); got < n*9/10 {
				t.Fatalf("%s: %d of %d packets from device %d arrived", stage, got, n, from)
			}
		}
	}
	exchange("opening the pairs")
	exchange("on connected sockets")
	s0, s1 := startedRoutines(pair[0].dev), startedRoutines(pair[1].dev)
	if s0 == 0 || s1 == 0 {
		t.Fatalf("started receive routines: %d and %d; each device should have started one for its connected socket", s0, s1)
	}
	if err := pair[0].dev.BindUpdate(); err != nil {
		t.Fatal(err)
	}
	exchange("after a rebind")
	exchange("on the new connected sockets")
	if s := startedRoutines(pair[0].dev); s <= s0 {
		t.Fatalf("device 0 started no receive routine after its rebind (%d before, %d after)", s0, s)
	}
}

// batchingBind is a ChannelBind whose started receive routines return up to 64 packets per call, more than the device's batch size.
type batchingBind struct {
	*bindtest.ChannelBind
	start   func(fn conn.ReceiveFunc, slabSize, batchSize int) bool
	batched atomic.Int32 // calls that returned more than one packet
}

func (b *batchingBind) SetReceiveFuncStarter(start func(fn conn.ReceiveFunc, slabSize, batchSize int) bool) {
	b.start = start
}

func (b *batchingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.ChannelBind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	for _, fn := range fns {
		type rx struct {
			data []byte
			ep   conn.Endpoint
		}
		ch := make(chan rx, 256)
		go func() {
			defer close(ch)
			slab := make([]byte, 2048)
			pkts := make([]conn.ReceivedPacket, 1)
			for {
				n, err := fn(slab, pkts)
				if err != nil {
					return
				}
				for _, p := range pkts[:n] {
					ch <- rx{append([]byte(nil), slab[p.Offset:p.Offset+p.Size]...), p.Endpoint}
				}
			}
		}()
		batched := func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
			r, ok := <-ch
			n, off := 0, 0
			for ok {
				copy(slab[off:], r.data)
				packets[n] = conn.ReceivedPacket{Offset: off, Size: len(r.data), Endpoint: r.ep}
				off += len(r.data)
				n++
				if n == len(packets) {
					break
				}
				select {
				case r, ok = <-ch:
				case <-time.After(time.Millisecond):
					ok = false
				}
			}
			if n == 0 {
				return 0, net.ErrClosed
			}
			if n > 1 {
				b.batched.Add(1)
			}
			return n, nil
		}
		if !b.start(batched, 64*2048, 64) {
			return nil, 0, errors.New("the device refused a receive routine during Open")
		}
	}
	return nil, actual, nil
}

// The device splits a started receive routine's oversized batch into containers of at most its batch size, in order.
func TestStartedReceiveFuncLargerThanBatch(t *testing.T) {
	cb := bindtest.NewChannelBinds()
	b0, b1 := &batchingBind{ChannelBind: cb[0].(*bindtest.ChannelBind)}, &batchingBind{ChannelBind: cb[1].(*bindtest.ChannelBind)}
	pair := genTestPairBinds(t, [2]conn.Bind{b0, b1}, 1)
	pair.Send(t, Ping, nil)
	const n = 600
	got := make(chan int)
	go func() {
		c := 0
		for c < n {
			select {
			case <-pair[1].tun.Inbound:
				c++
			case <-time.After(2 * time.Second):
				got <- c
				return
			}
		}
		got <- c
	}()
	for i := range n {
		pair[0].tun.Outbound <- bulkPacket(pair[0].ip, pair[1].ip, 200, uint32(i))
	}
	if c := <-got; c < n*9/10 {
		t.Fatalf("%d of %d packets arrived", c, n)
	}
	if b1.batched.Load() == 0 {
		t.Fatal("no receive call returned more than one packet, so the test did not exercise the split")
	}
}
