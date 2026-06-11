/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"

	"github.com/tailscale/wireguard-go/conn"
)

func TestLookupPeerPinsEndpoint(t *testing.T) {
	dev := newTestDevice(t)
	peerKey := NoisePublicKey{1}
	initial, err := CreateDummyEndpoint()
	if err != nil {
		t.Fatalf("CreateDummyEndpoint: %v", err)
	}
	dev.SetPeerLookupFunc(func(pk NoisePublicKey) (*NewPeerConfig, bool) {
		if pk != peerKey {
			return nil, false
		}
		return &NewPeerConfig{Endpoint: initial}, true
	})

	peer := dev.LookupPeer(peerKey)
	if peer == nil {
		t.Fatal("LookupPeer returned nil")
	}
	t.Cleanup(func() { dev.RemovePeer(peerKey) })

	if peer.endpoint.val != conn.Endpoint(initial) {
		t.Fatalf("initial endpoint = %v, want %v", peer.endpoint.val, initial)
	}
}
