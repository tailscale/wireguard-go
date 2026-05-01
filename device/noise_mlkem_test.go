/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2024 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"
)

// TestMLKEMHandshake exercises the hybrid ML-KEM-768 + Noise_IKpsk2 handshake
// at the message-level API (CreateMessageInitiationMLKEM /
// ConsumeMessageInitiationMLKEM / CreateMessageResponseMLKEM /
// ConsumeMessageResponseMLKEM).  It verifies that:
//
//   - Both sides arrive at the same chain key and hash after the initiation.
//   - Both sides arrive at the same chain key and hash after the response.
//   - The derived session keypairs can encrypt/decrypt in both directions.
func TestMLKEMHandshake(t *testing.T) {
	dev1 := randDevice(t) // initiator
	dev2 := randDevice(t) // responder

	defer dev1.Close()
	defer dev2.Close()

	// Cross-configure peers.
	peer1, err := dev2.NewPeer(dev1.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := dev1.NewPeer(dev2.staticIdentity.privateKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer1.Start()
	peer2.Start()

	assertEqual(t,
		peer1.handshake.precomputedStaticStatic[:],
		peer2.handshake.precomputedStaticStatic[:],
	)

	// --- Initiation ---

	t.Log("creating ML-KEM initiation message")
	msg1, err := dev1.CreateMessageInitiationMLKEM(peer2)
	if err != nil {
		t.Fatal("CreateMessageInitiationMLKEM:", err)
	}
	if msg1.Type != MessageInitiationMLKEMType {
		t.Fatalf("wrong message type: got %d, want %d", msg1.Type, MessageInitiationMLKEMType)
	}

	// Verify marshal/unmarshal round-trip.
	buf := make([]byte, MessageInitiationMLKEMSize)
	if err := msg1.marshal(buf); err != nil {
		t.Fatal("marshal:", err)
	}
	var msg1rt MessageInitiationMLKEM
	if err := msg1rt.unmarshal(buf); err != nil {
		t.Fatal("unmarshal:", err)
	}
	if msg1rt.Sender != msg1.Sender {
		t.Fatal("round-trip Sender mismatch")
	}
	if msg1rt.MLKEMPublicKey != msg1.MLKEMPublicKey {
		t.Fatal("round-trip MLKEMPublicKey mismatch")
	}

	t.Log("consuming ML-KEM initiation message")
	initEP := &initAwareEP{}
	consumedPeer := dev2.ConsumeMessageInitiationMLKEM(msg1, initEP)
	if consumedPeer == nil {
		t.Fatal("ConsumeMessageInitiationMLKEM returned nil")
	}
	if initEP.calledWith == nil {
		t.Fatal("InitiationAwareEndpoint was not called")
	}
	if *initEP.calledWith != dev1.staticIdentity.publicKey {
		t.Fatalf("InitiationAwareEndpoint called with wrong key: got %x, want %x",
			*initEP.calledWith, dev1.staticIdentity.publicKey)
	}

	// After consuming the initiation both sides must share chain key and hash.
	assertEqual(t, peer1.handshake.chainKey[:], peer2.handshake.chainKey[:])
	assertEqual(t, peer1.handshake.hash[:], peer2.handshake.hash[:])

	// responder must have stored the ML-KEM public key.
	if peer1.handshake.remoteMLKEMPubKey == nil {
		t.Fatal("responder's remoteMLKEMPubKey is nil after ConsumeMessageInitiationMLKEM")
	}
	// initiator must have stored the ML-KEM private key.
	if !peer2.handshake.localMLKEMPrivKeySet {
		t.Fatal("initiator's localMLKEMPrivKey not set after CreateMessageInitiationMLKEM")
	}

	// --- Response ---

	t.Log("creating ML-KEM response message")
	msg2, err := dev2.CreateMessageResponseMLKEM(peer1)
	if err != nil {
		t.Fatal("CreateMessageResponseMLKEM:", err)
	}
	if msg2.Type != MessageResponseMLKEMType {
		t.Fatalf("wrong message type: got %d, want %d", msg2.Type, MessageResponseMLKEMType)
	}

	// Verify marshal/unmarshal round-trip.
	buf2 := make([]byte, MessageResponseMLKEMSize)
	if err := msg2.marshal(buf2); err != nil {
		t.Fatal("marshal:", err)
	}
	var msg2rt MessageResponseMLKEM
	if err := msg2rt.unmarshal(buf2); err != nil {
		t.Fatal("unmarshal:", err)
	}
	if msg2rt.Sender != msg2.Sender || msg2rt.MLKEMCiphertext != msg2.MLKEMCiphertext {
		t.Fatal("response round-trip mismatch")
	}

	t.Log("consuming ML-KEM response message")
	consumedPeer = dev1.ConsumeMessageResponseMLKEM(msg2)
	if consumedPeer == nil {
		t.Fatal("ConsumeMessageResponseMLKEM returned nil")
	}

	// After consuming the response both sides must share chain key and hash.
	assertEqual(t, peer1.handshake.chainKey[:], peer2.handshake.chainKey[:])
	assertEqual(t, peer1.handshake.hash[:], peer2.handshake.hash[:])

	// ML-KEM keys should have been cleared after use.
	if peer1.handshake.remoteMLKEMPubKey != nil {
		t.Fatal("responder's remoteMLKEMPubKey not cleared after CreateMessageResponseMLKEM")
	}
	if peer2.handshake.localMLKEMPrivKeySet {
		t.Fatal("initiator's localMLKEMPrivKey not cleared after ConsumeMessageResponseMLKEM")
	}
	if !isZero(peer2.handshake.localMLKEMPrivKey[:]) {
		t.Fatal("initiator's localMLKEMPrivKey bytes not zeroed after ConsumeMessageResponseMLKEM")
	}

	// --- Session key derivation ---

	t.Log("deriving session keys")
	if err := peer2.BeginSymmetricSession(); err != nil {
		t.Fatal("BeginSymmetricSession (initiator):", err)
	}
	if err := peer1.BeginSymmetricSession(); err != nil {
		t.Fatal("BeginSymmetricSession (responder):", err)
	}

	key1 := peer2.keypairs.current     // initiator's send key
	key2 := peer1.keypairs.next.Load() // responder's next key

	// --- Encrypt / decrypt in both directions ---

	t.Log("verifying encryption")
	func() {
		testMsg := []byte("mlkem wireguard test 1")
		var nonce [12]byte
		sealed := key1.send.Seal(nil, nonce[:], testMsg, nil)
		plain, err := key2.receive.Open(nil, nonce[:], sealed, nil)
		if err != nil {
			t.Fatal("decrypt initiator→responder:", err)
		}
		assertEqual(t, plain, testMsg)
	}()

	func() {
		testMsg := []byte("mlkem wireguard test 2")
		var nonce [12]byte
		sealed := key2.send.Seal(nil, nonce[:], testMsg, nil)
		plain, err := key1.receive.Open(nil, nonce[:], sealed, nil)
		if err != nil {
			t.Fatal("decrypt responder→initiator:", err)
		}
		assertEqual(t, plain, testMsg)
	}()
}

// TestMLKEMMessageSizes confirms the wire-size constants.
func TestMLKEMMessageSizes(t *testing.T) {
	if MessageInitiationMLKEMSize != MessageInitiationSize+MLKEMPublicKeySize {
		t.Fatalf("MessageInitiationMLKEMSize = %d, want %d",
			MessageInitiationMLKEMSize, MessageInitiationSize+MLKEMPublicKeySize)
	}
	if MessageResponseMLKEMSize != MessageResponseSize+MLKEMCiphertextSize {
		t.Fatalf("MessageResponseMLKEMSize = %d, want %d",
			MessageResponseMLKEMSize, MessageResponseSize+MLKEMCiphertextSize)
	}

	// Verify against expected absolute values for documentation purposes.
	const wantInitSize = 1332
	const wantRespSize = 1180
	if MessageInitiationMLKEMSize != wantInitSize {
		t.Errorf("MessageInitiationMLKEMSize = %d, want %d", MessageInitiationMLKEMSize, wantInitSize)
	}
	if MessageResponseMLKEMSize != wantRespSize {
		t.Errorf("MessageResponseMLKEMSize = %d, want %d", MessageResponseMLKEMSize, wantRespSize)
	}
	// Both fit in MaxMessageSize buffers.
	if MessageInitiationMLKEMSize > MaxMessageSize {
		t.Errorf("MessageInitiationMLKEMSize %d > MaxMessageSize %d", MessageInitiationMLKEMSize, MaxMessageSize)
	}
	if MessageResponseMLKEMSize > MaxMessageSize {
		t.Errorf("MessageResponseMLKEMSize %d > MaxMessageSize %d", MessageResponseMLKEMSize, MaxMessageSize)
	}
}
