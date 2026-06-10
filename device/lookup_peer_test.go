/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"

	"github.com/tailscale/wireguard-go/conn"
)

func TestLookupPeerEndpointRoaming(t *testing.T) {
	tests := []struct {
		name            string
		wantUnchanged   bool
		wantDisableRoam bool
	}{
		{name: "BrokenRoaming", wantUnchanged: true, wantDisableRoam: true},
		{name: "Default", wantUnchanged: false, wantDisableRoam: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := newTestDevice(t)
			if tt.wantDisableRoam {
				dev.DisableSomeRoamingForBrokenMobileSemantics()
			}
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
			// Not concurrency safe, ignoring peer.endpoint.mu.

			// LookupPeer should return a peer with the initial endpoint and the expected roaming setting.
			peer := dev.LookupPeer(peerKey)
			if peer == nil {
				t.Fatal("LookupPeer returned nil")
			}
			t.Cleanup(func() { dev.RemovePeer(peerKey) })

			if peer.endpoint.disableRoaming != tt.wantDisableRoam {
				t.Fatalf("disableRoaming = %v, want %v", peer.endpoint.disableRoaming, tt.wantDisableRoam)
			}
			if peer.endpoint.val != conn.Endpoint(initial) {
				t.Fatalf("initial endpoint = %v, want %v", peer.endpoint.val, initial)
			}

			// SetEndpointFromPacket should update the endpoint to the new value unless roaming is disabled.
			other, err := CreateDummyEndpoint()
			if err != nil {
				t.Fatalf("CreateDummyEndpoint: %v", err)
			}
			peer.SetEndpointFromPacket(other)
			want := conn.Endpoint(other)
			if tt.wantUnchanged {
				want = conn.Endpoint(initial)
			}
			if peer.endpoint.val != want {
				t.Fatalf("after SetEndpointFromPacket: endpoint = %v, want %v",
					peer.endpoint.val, want)
			}
		})
	}
}
