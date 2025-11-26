/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

// newTestDevice creates a minimal Device suitable for unit tests that exercise
// LookupFromPacket and related paths. The caller must call dev.Close when done.
func newTestDevice(tb testing.TB) *Device {
	tb.Helper()
	sk, err := newPrivateKey()
	if err != nil {
		tb.Fatal(err)
	}
	tun := tuntest.NewChannelTUN()
	dev := NewDevice(tun.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	dev.SetPrivateKey(sk)
	tb.Cleanup(dev.Close)
	return dev
}

func TestLookupFromPacketCallback(t *testing.T) {
	dev := newTestDevice(t)

	// Create a peer on the device so LookupPeer can find it by key.
	peerKey := NoisePublicKey{1} // arbitrary non-zero key
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	peer.Start()

	// Track what the callback receives.
	type call struct {
		src, dst netip.Addr
		ipPkt    []byte
	}
	var calls []call

	dev.SetPeerByIPPacketFunc(func(src, dst netip.Addr, ipPkt []byte) (NoisePublicKey, bool) {
		calls = append(calls, call{src, dst, ipPkt})
		return peerKey, true
	})

	src := netip.MustParseAddr("192.168.1.1")
	dst := netip.MustParseAddr("10.0.0.1")
	pkt := []byte{0x45, 0x00, 0x00, 0x14, 0xab, 0xcd} // minimal fake IPv4 header bytes

	got := dev.allowedips.LookupFromPacket(src, dst, pkt)
	if got != peer {
		t.Fatalf("LookupFromPacket returned %v, want %v", got, peer)
	}
	if len(calls) != 1 {
		t.Fatalf("callback called %d times, want 1", len(calls))
	}
	if calls[0].src != src {
		t.Errorf("callback src = %v, want %v", calls[0].src, src)
	}
	if calls[0].dst != dst {
		t.Errorf("callback dst = %v, want %v", calls[0].dst, dst)
	}
	if &calls[0].ipPkt[0] != &pkt[0] {
		t.Error("callback ipPkt is not the same slice as the input")
	}
}

func TestLookupFromPacketCallbackIPv6(t *testing.T) {
	dev := newTestDevice(t)

	peerKey := NoisePublicKey{2}
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	peer.Start()

	var gotSrc, gotDst netip.Addr
	dev.SetPeerByIPPacketFunc(func(src, dst netip.Addr, ipPkt []byte) (NoisePublicKey, bool) {
		gotSrc, gotDst = src, dst
		return peerKey, true
	})

	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("fd00::2")

	got := dev.allowedips.LookupFromPacket(src, dst, nil)
	if got != peer {
		t.Fatalf("LookupFromPacket returned %v, want %v", got, peer)
	}
	if gotSrc != src {
		t.Errorf("callback src = %v, want %v", gotSrc, src)
	}
	if gotDst != dst {
		t.Errorf("callback dst = %v, want %v", gotDst, dst)
	}
}

func TestLookupFromPacketCallbackNotFound(t *testing.T) {
	dev := newTestDevice(t)

	called := false
	dev.SetPeerByIPPacketFunc(func(src, dst netip.Addr, ipPkt []byte) (NoisePublicKey, bool) {
		called = true
		return NoisePublicKey{}, false
	})

	got := dev.allowedips.LookupFromPacket(
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
		nil,
	)
	if got != nil {
		t.Fatalf("LookupFromPacket = %v, want nil", got)
	}
	if !called {
		t.Fatal("callback was not called")
	}
}

func TestLookupFromPacketCallbackUnknownKey(t *testing.T) {
	dev := newTestDevice(t)

	// Return a key that doesn't match any peer on the device.
	unknownKey := NoisePublicKey{99}
	dev.SetPeerByIPPacketFunc(func(src, dst netip.Addr, ipPkt []byte) (NoisePublicKey, bool) {
		return unknownKey, true
	})

	got := dev.allowedips.LookupFromPacket(
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
		nil,
	)
	if got != nil {
		t.Fatalf("LookupFromPacket = %v, want nil for unknown key", got)
	}
}

func TestLookupFromPacketTrieFallbackIPv4(t *testing.T) {
	// No callback registered — should fall back to trie.
	peer := &Peer{}
	var table AllowedIPs
	table.Insert(netip.MustParsePrefix("10.0.0.0/24"), peer)

	dst := netip.MustParseAddr("10.0.0.42")
	src := netip.MustParseAddr("192.168.1.1")
	pkt := []byte{0x45} // content doesn't matter for trie path

	got := table.LookupFromPacket(src, dst, pkt)
	if got != peer {
		t.Fatalf("trie fallback: got %v, want %v", got, peer)
	}

	// Miss.
	got = table.LookupFromPacket(src, netip.MustParseAddr("10.0.1.1"), pkt)
	if got != nil {
		t.Fatalf("trie fallback miss: got %v, want nil", got)
	}
}

func TestLookupFromPacketTrieFallbackIPv6(t *testing.T) {
	peer := &Peer{}
	var table AllowedIPs
	table.Insert(netip.MustParsePrefix("fd00::/64"), peer)

	got := table.LookupFromPacket(
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("fd00::99"),
		nil,
	)
	if got != peer {
		t.Fatalf("trie fallback IPv6: got %v, want %v", got, peer)
	}

	got = table.LookupFromPacket(
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("fd01::1"),
		nil,
	)
	if got != nil {
		t.Fatalf("trie fallback IPv6 miss: got %v, want nil", got)
	}
}
