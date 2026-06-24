/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"
)

type sessionStateEvent struct {
	peer  NoisePublicKey
	state PeerSessionState
}

func TestSessionStateFuncTransitions(t *testing.T) {
	dev := newTestDevice(t)
	peerKey := NoisePublicKey{1}
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatal(err)
	}

	var got []sessionStateEvent
	dev.SetSessionStateFunc(func(peer NoisePublicKey, state PeerSessionState) {
		got = append(got, sessionStateEvent{peer, state})
	})
	defer dev.SetSessionStateFunc(nil)

	peer.noteSessionHandshakeStarted()
	peer.noteSessionHandshakeStarted()
	peer.timersSessionDerived()
	peer.timersSessionDerived()
	peer.sessionState.Lock()
	peer.sessionState.sessionExpires = time.Now().Add(-time.Second)
	peer.sessionState.Unlock()
	expiredSession(peer)
	expiredSession(peer)
	peer.ZeroAndFlushAll()
	peer.ZeroAndFlushAll()

	want := []sessionStateEvent{
		{peerKey, PeerSessionHandshake},
		{peerKey, PeerSessionEstablished},
		{peerKey, PeerSessionExpired},
		{peerKey, PeerSessionNone},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("session events = %#v; want %#v", got, want)
	}
}

func TestSessionStateHandshakeWhileEstablished(t *testing.T) {
	dev := newTestDevice(t)
	peerKey := NoisePublicKey{2}
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatal(err)
	}

	var got []PeerSessionState
	dev.SetSessionStateFunc(func(peer NoisePublicKey, state PeerSessionState) {
		if peer != peerKey {
			t.Fatalf("callback peer = %v; want %v", peer, peerKey)
		}
		got = append(got, state)
	})
	defer dev.SetSessionStateFunc(nil)

	peer.timersSessionDerived()
	peer.noteSessionHandshakeStarted()

	want := []PeerSessionState{PeerSessionEstablished}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("session states = %#v; want %#v", got, want)
	}
}

func TestSetSessionStateFuncNil(t *testing.T) {
	dev := newTestDevice(t)
	peerKey := NoisePublicKey{4}
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatal(err)
	}

	var got []PeerSessionState
	dev.SetSessionStateFunc(func(peer NoisePublicKey, state PeerSessionState) {
		got = append(got, state)
	})

	peer.noteSessionHandshakeStarted()

	// Clearing the callback must not panic (a nil func value must store a nil
	// pointer, not a pointer to a nil func) and must stop delivery.
	dev.SetSessionStateFunc(nil)
	peer.timersSessionDerived()

	want := []PeerSessionState{PeerSessionHandshake}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("session states = %#v, want %#v", got, want)
	}
}

func TestSessionStateHandshakeStopped(t *testing.T) {
	dev := newTestDevice(t)
	peerKey := NoisePublicKey{3}
	peer, err := dev.NewPeer(peerKey)
	if err != nil {
		t.Fatal(err)
	}

	var got []PeerSessionState
	dev.SetSessionStateFunc(func(peer NoisePublicKey, state PeerSessionState) {
		if peer != peerKey {
			t.Fatalf("callback peer = %v; want %v", peer, peerKey)
		}
		got = append(got, state)
	})
	defer dev.SetSessionStateFunc(nil)

	peer.noteSessionHandshakeStarted()
	peer.noteSessionHandshakeStopped()
	peer.noteSessionHandshakeStarted()
	peer.keypairs.Lock()
	peer.keypairs.current = &Keypair{}
	peer.keypairs.Unlock()
	peer.noteSessionHandshakeStopped()

	want := []PeerSessionState{
		PeerSessionHandshake,
		PeerSessionNone,
		PeerSessionHandshake,
		PeerSessionExpired,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("session states = %#v; want %#v", got, want)
	}
}

// TestExpiredSessionRaceWithRefresh is a regression test for the TOCTOU race
// where expiredSession decided "expired" outside peer.sessionState, allowing a
// concurrent refresh to be clobbered by a stale Expired emission.
//
// We race expiredSession against a refresh from two goroutines and assert the
// post-fix invariant: final state is always Established. Pre-fix can leave
// final state at Expired (T1 reads stale, T2 stores fresh and emits no event
// because state was already Established, T1 then emits Expired). Synctest does
// not help — sync.Mutex.Lock is not durably blocking — so we rely on stress.

// The pre-fix bug surfaces well within the 5_000 trial budget on any
// multi-core machine but is not a guarantee. Subject to the runtime implementation.
func TestExpiredSessionRaceWithRefresh(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("requires GOMAXPROCS >= 2 to interleave expiredSession and refresh")
	}
	for i := range 5_000 {
		dev := &Device{log: NewLogger(LogLevelError, "")}
		peer := &Peer{device: dev}
		peer.handshake.remoteStatic = NoisePublicKey{5}

		var (
			mu  sync.Mutex
			got []PeerSessionState // guarded by mu
		)
		dev.SetSessionStateFunc(func(_ NoisePublicKey, s PeerSessionState) {
			mu.Lock()
			got = append(got, s)
			mu.Unlock()
		})

		// Prime: Established with an already-past expiry. expiredSession would
		// like to emit Expired; a concurrent refresh bumps expiry forward and
		// (in production code) would emit Established to confirm refresh.
		peer.sessionState.Lock()
		peer.sessionState.current = PeerSessionEstablished
		peer.sessionState.sessionExpires = time.Now().Add(-time.Second)
		peer.sessionState.Unlock()

		future := time.Now().Add(time.Hour)

		var start sync.WaitGroup
		start.Add(1)
		var done sync.WaitGroup

		done.Go(func() {
			start.Wait()
			peer.sessionState.Lock()
			peer.sessionState.sessionExpires = future
			peer.noteSessionStateLocked(PeerSessionEstablished)
			peer.sessionState.Unlock()
		})
		done.Go(func() {
			start.Wait()
			expiredSession(peer)
		})

		start.Done()
		done.Wait()

		peer.sessionState.Lock()
		finalState := peer.sessionState.current
		peer.sessionState.Unlock()

		if finalState != PeerSessionEstablished {
			mu.Lock()
			gotCopy := append([]PeerSessionState(nil), got...)
			mu.Unlock()
			t.Fatalf("trial %d: final state = %v, want Established (got=%v)", i, finalState, gotCopy)
		}
	}
}
