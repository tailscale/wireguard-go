/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestTimerModAfterPeerStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dev := newSynctestCapableDevice(t)
		peerKey := NoisePublicKey{1}
		peer, err := dev.NewPeer(peerKey)
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		peer.Start()
		peer.Stop()

		fired := make(chan struct{}, 1)
		timer := peer.NewTimer(func(*Peer) { fired <- struct{}{} })
		timer.Mod(time.Millisecond)
		select {
		case <-fired:
			t.Error("timer fired on stopped peer")
		case <-time.After(time.Second):
		}
	})
}
