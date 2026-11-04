/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) Tailscale Inc & contributors
 */

package device

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// handshakeInitCooldown is the time to wait after each Initiation,
// because the responder will reject it as a flood or a replay
// if [HandshakeInitationRate] or less has passed since the last one.
const handshakeInitCooldown = HandshakeInitationRate + time.Millisecond

type side struct {
	dev  *Device
	peer *Peer
}

// newPeerPair returns two devices that know each other as peers.
// The init side sends Initiations, and the resp side answers with Responses.
func newPeerPair(t *testing.T) (init, resp side) {
	t.Helper()

	init.dev = randDevice(t)
	resp.dev = randDevice(t)
	t.Cleanup(init.dev.Close)
	t.Cleanup(resp.dev.Close)

	var err error
	init.peer, err = init.dev.NewPeer(resp.dev.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	resp.peer, err = resp.dev.NewPeer(init.dev.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	init.peer.Start()
	resp.peer.Start()

	return init, resp
}

// sendTwice hands the same message to two handshake consumers at once,
// like magicsock sending packets over both DERP and direct UDP.
// It reports an error unless exactly one of them accepts the message.
func sendTwice(t *testing.T, name string, consume func() (accepted bool)) {
	t.Helper()
	var accepted [2]bool
	var wg sync.WaitGroup

	// Hold both consumers until both have started,
	// to improve the chances of triggering a race.
	start := make(chan struct{})
	for i := range accepted {
		wg.Go(func() {
			<-start
			accepted[i] = consume()
		})
	}
	close(start)

	wg.Wait()
	switch accepted {
	case [2]bool{false, false}:
		t.Errorf("%s rejected", name)
	case [2]bool{true, true}:
		t.Errorf("duplicated %s accepted twice", name)
	}
}

// TestDuplicateHandshakeResponse checks that a duplicate [MessageResponse]
// is only accepted once.
// See tailscale/tailscale#21884.
//
// The second [Peer.BeginSymmetricSession] could evict the retiring keypair.
// The peer keeps using the retiring keypair until it sees traffic on the new one,
// which incorrectly drops those packets.
func TestDuplicateHandshakeResponse(t *testing.T) {
	initiator, responder := newPeerPair(t)
	for i := range 5 {
		retiring := initiator.peer.keypairs.Current()

		init, err := initiator.dev.CreateMessageInitiation(initiator.peer)
		if err != nil {
			t.Fatal(err)
		}
		if responder.dev.ConsumeMessageInitiation(init, &initAwareEP{}) == nil {
			t.Fatalf("handshake %d: initiation rejected", i)
		}
		resp, err := responder.dev.CreateMessageResponse(responder.peer)
		if err != nil {
			t.Fatal(err)
		}
		if err := responder.peer.BeginSymmetricSession(); err != nil {
			t.Fatal(err)
		}

		// Handle each copy the way [Device.RoutineHandshake] does.
		sendTwice(t, fmt.Sprintf("response %d", i), func() bool {
			if initiator.dev.ConsumeMessageResponse(resp) == nil {
				return false
			}
			// RoutineHandshake logs an error here and continues.
			if err := initiator.peer.BeginSymmetricSession(); err != nil {
				t.Logf("handshake %d: ignored error: %v", i, err)
			}
			return true
		})
		if cur := initiator.peer.keypairs.Current(); cur.localIndex == 0 {
			t.Errorf("handshake %d: current keypair has receive index 0", i)
		}

		// The first handshake has no keypair to retire.
		if retiring != nil && initiator.dev.indexTable.Lookup(retiring.localIndex).keypair != retiring {
			t.Errorf("handshake %d: retiring keypair %#x evicted from index table", i, retiring.localIndex)
		}
		if t.Failed() {
			return
		}
		time.Sleep(handshakeInitCooldown)
	}
}

// TestDuplicateHandshakeResponseConsumedFirst checks that
// a duplicate [MessageResponse] is rejected
// if another copy of it was consumed while it waited for the write lock.
// This changes the handshake.state,
// but handshake.localIndex doesn't until [Peer.BeginSymmetricSession] runs.
func TestDuplicateHandshakeResponseConsumedFirst(t *testing.T) {
	initiator, responder := newPeerPair(t)
	init, err := initiator.dev.CreateMessageInitiation(initiator.peer)
	if err != nil {
		t.Fatal(err)
	}
	if responder.dev.ConsumeMessageInitiation(init, &initAwareEP{}) == nil {
		t.Fatal("initiation rejected")
	}
	resp, err := responder.dev.CreateMessageResponse(responder.peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := responder.peer.BeginSymmetricSession(); err != nil {
		t.Fatal(err)
	}

	// Consume another copy of the [MessageResponse]
	// after [Device.ConsumeMessageResponse] verified the response
	// but before it updates the handshake.
	initiator.dev.testHookResponseVerified = func() {
		initiator.dev.testHookResponseVerified = nil
		if initiator.dev.ConsumeMessageResponse(resp) == nil {
			t.Error("other copy of response rejected")
		}
	}
	if initiator.dev.ConsumeMessageResponse(resp) != nil {
		t.Error("response accepted after the other copy was consumed")
	}
}

// TestStaleHandshakeResponse checks that a [MessageResponse] is rejected
// if a retried [MessageInitiation] replaced the one it was answering
// while waiting for the write lock.
// This is caught by the wrong handshake.localIndex,
// since the new Initiation resets the handshake.state.
func TestStaleHandshakeResponse(t *testing.T) {
	initiator, responder := newPeerPair(t)
	init, err := initiator.dev.CreateMessageInitiation(initiator.peer)
	if err != nil {
		t.Fatal(err)
	}
	if responder.dev.ConsumeMessageInitiation(init, &initAwareEP{}) == nil {
		t.Fatal("initiation rejected")
	}
	resp, err := responder.dev.CreateMessageResponse(responder.peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := responder.peer.BeginSymmetricSession(); err != nil {
		t.Fatal(err)
	}

	// Replace the [MessageInitiation]
	// by calling [Device.CreateMessageInitiation] again
	// after [Device.ConsumeMessageResponse] verified the response
	// but before it updates the handshake.
	initiator.dev.testHookResponseVerified = func() {
		initiator.dev.testHookResponseVerified = nil
		if _, err := initiator.dev.CreateMessageInitiation(initiator.peer); err != nil {
			t.Error(err)
		}
	}
	if initiator.dev.ConsumeMessageResponse(resp) != nil {
		t.Error("response to a replaced initiation was accepted")
	}
}
