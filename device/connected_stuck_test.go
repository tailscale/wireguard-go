// Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT

package device

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

// stuckTUN counts what a device writes by source address, and holds writes of packets from stuck while it's frozen.
type stuckTUN struct {
	tun.Device
	stuck, other netip.Addr
	fromOther    atomic.Int64
	fromStuck    atomic.Int64
	mu           sync.Mutex
	thaw         chan struct{} // closed while not frozen
	done         chan struct{}
	closeOnce    sync.Once
}

func (s *stuckTUN) freeze() {
	s.mu.Lock()
	s.thaw = make(chan struct{})
	s.mu.Unlock()
}

func (s *stuckTUN) unfreeze() {
	s.mu.Lock()
	close(s.thaw)
	s.mu.Unlock()
}

func (s *stuckTUN) Write(packets [][]byte, offset int) (int, error) {
	for _, p := range packets {
		if len(p) < offset+20 {
			continue
		}
		switch netip.AddrFrom4([4]byte(p[offset+12 : offset+16])) {
		case s.stuck:
			s.mu.Lock()
			thaw := s.thaw
			s.mu.Unlock()
			select {
			case <-thaw:
			case <-s.done:
				return 0, os.ErrClosed
			}
			s.fromStuck.Add(1)
		case s.other:
			s.fromOther.Add(1)
		}
	}
	return len(packets), nil
}

func (s *stuckTUN) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	return s.Device.Close()
}

/*
A peer whose packets don't drain must not stall the other peers sharing the receiver's slab pool.

Receiver R has peers A and B on connected sockets, so it reads each through its own started routine. R's TUN holds B's packets, which pins every big slab they sit in, and A has to keep getting through.
*/
func TestConnectedSocketsStuckPeerDoesNotStallOthers(t *testing.T) {
	if _, ok := conn.NewStdNetBind(conn.WithConnectedSockets(true)).(conn.ReceiveFuncStarter); !ok {
		t.Skip("StdNetBind has no ReceiveFuncStarter")
	}
	key := func() (priv, pub string) {
		var k NoisePrivateKey
		if _, err := rand.Read(k[:]); err != nil {
			t.Fatal(err)
		}
		p := k.publicKey()
		return hex.EncodeToString(k[:]), hex.EncodeToString(p[:])
	}
	rPriv, rPub := key()
	aPriv, aPub := key()
	bPriv, bPub := key()
	rIP, aIP, bIP := netip.MustParseAddr("1.0.0.1"), netip.MustParseAddr("1.0.0.2"), netip.MustParseAddr("1.0.0.3")
	newDev := func(t tun.Device, name string) *Device {
		return NewDevice(t, conn.NewStdNetBind(conn.WithConnectedSockets(true)), NewLogger(LogLevelError, name+": "))
	}

	rTUN := tuntest.NewChannelTUN()
	st := &stuckTUN{Device: rTUN.TUN(), stuck: bIP, other: aIP, thaw: make(chan struct{}), done: make(chan struct{})}
	close(st.thaw)
	r := newDev(st, "R")
	t.Cleanup(r.Close)
	if err := r.IpcSet(uapiCfg(
		"private_key", rPriv, "listen_port", "0", "replace_peers", "true",
		"public_key", aPub, "protocol_version", "1", "allowed_ip", aIP.String()+"/32",
		"public_key", bPub, "protocol_version", "1", "allowed_ip", bIP.String()+"/32",
	)); err != nil {
		t.Fatal(err)
	}
	if err := r.Up(); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	defer close(stop)
	var ports [2]uint16
	for i, s := range []struct {
		priv string
		ip   netip.Addr
	}{{aPriv, aIP}, {bPriv, bIP}} {
		ct := tuntest.NewChannelTUN()
		d := newDev(ct.TUN(), s.ip.String())
		t.Cleanup(d.Close)
		if err := d.IpcSet(uapiCfg(
			"private_key", s.priv, "listen_port", "0", "replace_peers", "true",
			"public_key", rPub, "protocol_version", "1", "allowed_ip", rIP.String()+"/32",
			"endpoint", fmt.Sprintf("127.0.0.1:%d", r.net.port),
		)); err != nil {
			t.Fatal(err)
		}
		if err := d.Up(); err != nil {
			t.Fatal(err)
		}
		ports[i] = d.net.port
		go func() {
			for {
				select {
				case <-ct.Inbound:
				case <-stop:
					return
				}
			}
		}()
		go func() {
			for seq := uint32(0); ; seq++ {
				select {
				case ct.Outbound <- bulkPacket(s.ip, rIP, 1280, seq):
				case <-stop:
					return
				}
			}
		}()
	}
	// This fork doesn't roam to a peer's source address, so R needs explicit endpoints.
	if err := r.IpcSet(uapiCfg(
		"public_key", aPub, "endpoint", fmt.Sprintf("127.0.0.1:%d", ports[0]),
		"public_key", bPub, "endpoint", fmt.Sprintf("127.0.0.1:%d", ports[1]),
	)); err != nil {
		t.Fatal(err)
	}

	// R needs sends of its own to open connected sockets, as StdNetBind only counts sends towards OpenAfter. Start once A and B have handshaken, so R never initiates at the same moment.
	go func() {
		for st.fromOther.Load() == 0 || st.fromStuck.Load() == 0 {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
		for seq := uint32(0); ; seq++ {
			dst := aIP
			if seq%2 == 1 {
				dst = bIP
			}
			select {
			case rTUN.Outbound <- bulkPacket(rIP, dst, 200, seq):
			case <-stop:
				return
			}
			if seq%64 == 63 {
				time.Sleep(200 * time.Microsecond)
			}
		}
	}()

	deadline := time.Now().Add(10 * time.Second)
	for startedRoutines(r) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("R started %d receive routines; want one per peer's connected socket", startedRoutines(r))
		}
		time.Sleep(50 * time.Millisecond)
	}

	st.freeze()
	defer st.unfreeze()
	time.Sleep(time.Second) // long enough for B's held packets to pin every big slab
	before := st.fromOther.Load()
	time.Sleep(time.Second)
	if got := st.fromOther.Load() - before; got < 1000 {
		t.Fatalf("A delivered %d packets in 1s while B was stuck; it should keep getting through", got)
	}
}
