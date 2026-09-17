/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"testing"

	"github.com/tailscale/wireguard-go/conn/bindtest"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

func TestPeerTunQueueAssignment(t *testing.T) {
	const peers = 200

	for _, queues := range []int{1, 4} {
		tun := tuntest.NewMultiQueueChannelTUN(queues)
		binds := bindtest.NewChannelBinds()
		dev := NewDevice(tun.TUN(), binds[0], NewLogger(LogLevelError, "dev: "))
		t.Cleanup(dev.Close)

		seen := make(map[int]int, queues)
		for range peers {
			var pk NoisePublicKey
			if _, err := rand.Read(pk[:]); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}
			peer, err := dev.NewPeer(pk)
			if err != nil {
				t.Fatalf("NewPeer: %v", err)
			}
			seen[int(uint(peer.flowID)%uint(queues))]++
		}
		if len(seen) != queues {
			t.Errorf("queues=%d: peers landed on %d distinct queues, want %d (%v)",
				queues, len(seen), queues, seen)
		}
	}
}
