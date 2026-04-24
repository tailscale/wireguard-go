/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

// TestSetPrivateKeyConsumeInitiationDeadlock verifies that SetPrivateKey and
// ConsumeMessageInitiation do not deadlock.
//
// ConsumeMessageInitiation holds staticIdentity.RLock (noise-protocol.go:352)
// for the duration of the call. When processing an unknown peer, it calls
// LookupPeer -> PeerLookupFunc -> NewPeer, and NewPeer attempts a reentrant
// staticIdentity.RLock (peer.go:82). If SetPrivateKey has called
// staticIdentity.Lock (device.go:235) in between, the pending writer blocks
// the reentrant reader, while the writer waits for the original reader to
// release, a classic sync.RWMutex reentrant-reader deadlock.
//
// We would like to use testing/synctest to eliminate the wall-clock sleep
// and 5-second timeout, but sync.RWMutex is not bubble-aware as of Go 1.26,
// so a goroutine blocked in RWMutex.Lock is not classified as "durably
// blocked" and synctest cannot detect this deadlock. Revisit once the sync
// package participates in synctest bubbles.
func TestSetPrivateKeyConsumeInitiationDeadlock(t *testing.T) {
	// Create the receiver device. We intentionally avoid t.Cleanup(Close)
	// because in the deadlock case the locks are permanently held and
	// Close would block.
	recvSK, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	receiver := NewDevice(
		tuntest.NewChannelTUN().TUN(),
		conn.NewDefaultBind(),
		NewLogger(LogLevelError, ""),
	)
	receiver.SetPrivateKey(recvSK)

	// Create the initiator device and add receiver as a peer so we can
	// produce a valid MessageInitiation.
	initiator := randDevice(t)
	defer initiator.Close()

	peer, err := initiator.NewPeer(recvSK.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer.Start()

	msg, err := initiator.CreateMessageInitiation(peer)
	if err != nil {
		t.Fatal(err)
	}

	newSK, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// PeerLookupFunc is the synchronization point: when it fires,
	// ConsumeMessageInitiation is holding staticIdentity.RLock and we are
	// between the two RLock acquisitions (the second one is inside NewPeer).
	inLookup := make(chan struct{})
	proceed := make(chan struct{})
	receiver.SetPeerLookupFunc(func(pk NoisePublicKey) (_ *NewPeerConfig, ok bool) {
		close(inLookup)
		<-proceed
		return &NewPeerConfig{}, true
	})

	// Goroutine A: ConsumeMessageInitiation holds staticIdentity.RLock.
	go receiver.ConsumeMessageInitiation(msg, nil)
	<-inLookup

	// Goroutine B: SetPrivateKey calls staticIdentity.Lock (write);
	// blocks because A holds the read lock.
	setKeyDone := make(chan error, 1)
	go func() {
		setKeyDone <- receiver.SetPrivateKey(newSK)
	}()

	// Give B time to reach staticIdentity.Lock (the very first operation
	// in SetPrivateKey), so it becomes a pending writer.
	time.Sleep(20 * time.Millisecond)

	// A proceeds: LookupPeer → NewPeer → staticIdentity.RLock (reentrant).
	// With B's write pending, the reentrant read lock blocks. Deadlock.
	close(proceed)

	select {
	case err := <-setKeyDone:
		if err != nil {
			t.Fatal(err)
		}
		receiver.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: ConsumeMessageInitiation holds staticIdentity.RLock, " +
			"SetPrivateKey is pending staticIdentity.Lock (write), and NewPeer's " +
			"reentrant staticIdentity.RLock is blocked by the pending writer")
	}
}
