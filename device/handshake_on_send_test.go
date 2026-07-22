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

func TestScheduleHandshakeOnUserSend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dev := newSynctestCapableDevice(t)
		peerKey := NoisePublicKey{1}
		peer, err := dev.NewPeer(peerKey)
		if err != nil {
			t.Fatal(err)
		}

		synctest.Wait() // peer.Start() must return before we continue, since it mutates lastSentHandshake

		// known peer but no key material yet, flag stays false
		dev.ScheduleHandshakeOnUserSend(peerKey)
		if peer.handshakeOnUserSend.Load() {
			t.Fatal("flag armed without key material")
		}

		// set some key material, then it should arm
		peer.keypairs.Lock()
		peer.keypairs.current = &Keypair{}
		peer.keypairs.Unlock()
		dev.ScheduleHandshakeOnUserSend(peerKey)
		if !peer.handshakeOnUserSend.Load() {
			t.Fatal("flag not armed despite key material")
		}

		// a handshake sent at the same time as previous should not clear the flag
		peer.handshake.mutex.Lock()
		peer.handshake.lastSentHandshake = time.Now()
		peer.handshake.mutex.Unlock()
		_ = peer.SendHandshakeInitiation(false)
		if !peer.handshakeOnUserSend.Load() {
			t.Fatal("flag cleared while inside RekeyTimeout window")
		}

		// advance clock by RekeyTimeout
		time.Sleep(RekeyTimeout)

		// we are now outside the RekeyTimeout window, the flag should clear
		_ = peer.SendHandshakeInitiation(false)
		if peer.handshakeOnUserSend.Load() {
			t.Fatal("flag not cleared after outside RekeyTimeout window")
		}

		// advance clock by RekeyTimeout and capture bubble wall clock
		time.Sleep(RekeyTimeout)
		now := time.Now()

		// this should not trigger a new handshake as:
		//  a. handshakeOnUserSend is unarmed
		//  b. nonce is not exhausted
		//  c. peer is not initiator
		peer.keepKeyFreshSending()
		peer.handshake.mutex.Lock()
		lastHandshake := peer.handshake.lastSentHandshake
		peer.handshake.mutex.Unlock()
		if lastHandshake.Equal(now) {
			t.Fatal("unexpected handshake sent around keepKeyFreshSending")
		}

		// arm the flag and try again, a handshake should fire
		dev.ScheduleHandshakeOnUserSend(peerKey)
		peer.keepKeyFreshSending()
		peer.handshake.mutex.Lock()
		lastHandshake = peer.handshake.lastSentHandshake
		peer.handshake.mutex.Unlock()
		if !lastHandshake.Equal(now) {
			t.Fatal("expected handshake sent around keepKeyFreshSending")
		}
	})
}
