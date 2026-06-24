/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"reflect"
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
