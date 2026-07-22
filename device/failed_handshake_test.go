/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tailscale/wireguard-go/conn/bindtest"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

// newSynctestCapableDevice returns a [Device] that is safe to use within a
// synctest bubble. It uses channel-based [conn.Bind]s instead of goroutines
// performing "real" I/O, which can never durably block. The returned [Device]
// is registered to Close() at tb.Cleanup time.
func newSynctestCapableDevice(tb testing.TB) *Device {
	tb.Helper()
	sk, err := newPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}
	binds := bindtest.NewChannelBinds()
	tun := tuntest.NewChannelTUN()
	dev := NewDevice(tun.TUN(), binds[0], NewLogger(LogLevelError, ""))
	dev.SetPrivateKey(sk)
	tb.Cleanup(dev.Close)
	return dev
}

func TestLazyPeerReaping(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dev := newSynctestCapableDevice(t)
		dev.SetPeerLookupFunc(func(pk NoisePublicKey) (*NewPeerConfig, bool) {
			ip := netip.AddrFrom4([4]byte{10, pk[0], pk[1], pk[2]})
			return &NewPeerConfig{AllowedIPs: []netip.Prefix{netip.PrefixFrom(ip, 32)}}, true
		})
		var pk NoisePublicKey
		pk[0] = 0x42

		// LookupPeer creates the peer and calls Start(), which arms the
		// reaping timer for a lazy peer that never completes a handshake.
		peer := dev.LookupPeer(pk)
		if peer == nil {
			t.Fatal("LookupPeer returned nil")
		}
		synctest.Wait() // let startup goroutines settle to durable block

		if !peer.timers.zeroKeyMaterial.IsPending() {
			t.Fatal("zeroKeyMaterial not armed; lazy peer would never be reaped")
		}

		// The timer fires only at the deadline: still present just before.
		time.Sleep(RejectAfterTime*3 - time.Second)
		synctest.Wait()
		if _, ok := dev.LookupActivePeer(pk); !ok {
			t.Fatal("peer reaped before RejectAfterTime*3")
		}

		// Cross the deadline: expiredZeroKeyMaterial -> RemovePeer.
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if _, ok := dev.LookupActivePeer(pk); ok {
			t.Fatal("peer NOT reaped after RejectAfterTime*3")
		}
	})
}
