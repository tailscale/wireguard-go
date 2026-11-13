// SPDX-License-Identifier: MIT

package peer

import (
	"bytes"
	"crypto/mlkem"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestHybridHandshakeAndModeChanges(t *testing.T) {
	q := newPair(t, Config{Hybrid: true})
	establish(t, q, epoch)
	for _, p := range []*Peer{q.a, q.b} {
		if !p.HasHybridSession(epoch) || p.handshake.localKEM != nil || p.handshake.remoteKEM != nil {
			t.Fatal("missing hybrid session or retained handshake KEM")
		}
	}
	oldWire := seal(t, q.a, epoch, plaintext(37, 11))
	now := epoch.Add(6 * time.Second)
	for _, p := range []*Peer{q.a, q.b} {
		if _, err := p.SetHybridHandshake(now, false); err != nil {
			t.Fatal(err)
		}
		if !p.HasHybridSession(now) {
			t.Fatal("mode change replaced existing session")
		}
	}
	establish(t, q, now)
	for _, p := range []*Peer{q.a, q.b} {
		if !p.HasSession(now) || p.HasHybridSession(now) {
			t.Fatal("missing classical session")
		}
	}
	if r := receive(t, q.b, now, oldWire); r.Err != nil {
		t.Fatal("mode change revoked previous receive keys:", r.Err)
	}
	now = now.Add(6 * time.Second)
	for _, p := range []*Peer{q.a, q.b} {
		if _, err := p.SetHybridHandshake(now, true); err != nil {
			t.Fatal(err)
		}
	}
	establish(t, q, now)
	if !q.a.HasHybridSession(now) || !q.b.HasHybridSession(now) || q.a.HasHybridSession(now.Add(RejectAfterTime)) {
		t.Fatal("hybrid session status")
	}
	q.a.Close()
	if q.a.HasHybridSession(now) {
		t.Fatal("closed hybrid session")
	}
}

func TestHybridModeMismatch(t *testing.T) {
	for _, hybrid := range []bool{false, true} {
		t.Run(fmt.Sprint(hybrid), func(t *testing.T) {
			q := newPair(t, Config{Hybrid: hybrid})
			if _, err := q.b.SetHybridHandshake(epoch, !hybrid); err != nil {
				t.Fatal(err)
			}
			init, _, err := q.a.Initiate(epoch, control())
			if err != nil {
				t.Fatal(err)
			}
			prepared := prepare(t, admit(t, q.ab, epoch, init))
			before := q.b.handshake
			if _, _, err := q.b.HandleInitiation(epoch, prepared, control()); !errors.Is(err, ErrHandshake) || q.b.handshake != before || q.indexes.Len() != 1 {
				t.Fatal("mode mismatch accepted or changed state", err)
			}
			// A response with the other mode's framing must not consume the pending initiation.
			size := MessageHybridResponseSize
			if hybrid {
				size = MessageResponseSize
			}
			wire := Packet{Buffer: make([]byte, size), Size: size}
			binary.LittleEndian.PutUint32(wire.Bytes(), MessageResponseType)
			binary.LittleEndian.PutUint32(wire.Bytes()[8:], q.a.handshake.localIndex)
			q.b.cookieGen.addMACs(epoch, wire.Bytes())
			before = q.a.handshake
			if _, _, err := q.a.HandleResponse(epoch, admit(t, q.aa, epoch, wire), control()); !errors.Is(err, ErrHandshake) || q.a.handshake != before {
				t.Fatal("response mode mismatch consumed initiation", err)
			}
		})
	}
}

func TestHybridRetryAndBackpressure(t *testing.T) {
	for _, hybrid := range []bool{false, true} {
		for _, automatic := range []bool{false, true} {
			t.Run(fmt.Sprintf("hybrid=%t/automatic=%t", hybrid, automatic), func(t *testing.T) {
				q := newPair(t, Config{Hybrid: hybrid, HandshakePolicy: HandshakePolicy{Retry: automatic}})
				short := control()
				short.Buffer = short.Buffer[:short.Offset+q.a.initiationSize()-1]
				beforeBytes := bytes.Clone(short.Buffer)
				if _, _, err := q.a.Initiate(epoch, short); !errors.Is(err, ErrShortBuffer) || q.a.handshake.localKEM != nil || q.indexes.Len() != 0 || !bytes.Equal(short.Buffer, beforeBytes) {
					t.Fatal("short initiation changed state or storage", err)
				}
				first, _, err := q.a.Initiate(epoch, control())
				if err != nil || PacketIsRetry(first.Bytes()) {
					t.Fatal("initial packet marked retry", err)
				}
				before := q.a.handshake
				if _, err := q.a.SetHybridHandshake(epoch, hybrid); err != nil || q.a.handshake != before {
					t.Fatal("same-mode configuration discarded pending work", err)
				}
				now := epoch.Add(RekeyTimeout)
				var retry Packet
				if automatic {
					slots := []Packet{short}
					if r, err := q.a.HandleWake(now, slots); !errors.Is(err, ErrShortBuffer) || r.N != 0 || q.a.handshake != before || q.a.timers.attempts != 0 {
						t.Fatal("short retry consumed pending work", err)
					}
					slots[0] = control()
					if r, err := q.a.HandleWake(now, slots); err != nil || r.N != 1 {
						t.Fatal("automatic retry", r, err)
					}
					retry = slots[0]
				} else {
					if _, _, err := q.a.RetryInitiation(now, short); !errors.Is(err, ErrShortBuffer) || q.a.handshake != before || q.a.timers.attempts != 0 {
						t.Fatal("short manual retry consumed pending work", err)
					}
					retry, _, err = q.a.RetryInitiation(now, control())
					if err != nil {
						t.Fatal(err)
					}
				}
				if PacketIsRetry(retry.Bytes()) != hybrid || q.a.timers.attempts != 1 || q.a.handshake.localIndex == before.localIndex || q.indexes.Len() != 1 {
					t.Fatal("retry flag, budget, or index replacement")
				}
				if hybrid && q.a.handshake.localKEM == before.localKEM {
					t.Fatal("retry reused KEM key")
				}
				prepared := prepare(t, admit(t, q.ab, now, retry))
				short = control()
				short.Buffer = short.Buffer[:short.Offset+q.b.responseSize()-1]
				if _, _, err := q.b.HandleInitiation(now, prepared, short); !errors.Is(err, ErrShortBuffer) || q.b.handshake.remoteKEM != nil {
					t.Fatal("short response consumed KEM", err)
				}
				response, _, err := q.b.HandleInitiation(now, prepared, control())
				if err != nil || response.Size != q.b.responseSize() || PacketIsRetry(response.Bytes()) != hybrid {
					t.Fatal("response did not echo hybrid retry", err)
				}
				token := admit(t, q.aa, now, response)
				confirmation, _, err := q.a.HandleResponse(now, token, control())
				if err != nil {
					t.Fatal(err)
				}
				if r := receive(t, q.b, now, confirmation); r.Err != nil || r.Disposition != Keepalive {
					t.Fatal(r)
				}
				current := q.a.keypairs.current
				if _, _, err := q.a.HandleResponse(now, token, control()); !errors.Is(err, ErrHandshake) || q.a.keypairs.current != current {
					t.Fatal("duplicate response rotated session", err)
				}
			})
		}
	}
}

func TestHybridKEMCleanup(t *testing.T) {
	for _, action := range []string{"close", "expiry", "identity", "mode"} {
		t.Run(action, func(t *testing.T) {
			q := newPair(t, Config{Hybrid: true})
			if _, _, err := q.a.Initiate(epoch, control()); err != nil || q.a.handshake.localKEM == nil {
				t.Fatal("no pending KEM", err)
			}
			switch action {
			case "close":
				q.a.Close()
			case "expiry":
				if _, err := q.a.HandleWake(epoch.Add(3*RejectAfterTime), nil); err != nil {
					t.Fatal(err)
				}
			case "identity":
				if _, err := q.a.ReplaceIdentity(epoch, localIdentity(t, 2, q.ia)); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if _, err := q.a.SetHybridHandshake(epoch, false); err != nil {
					t.Fatal(err)
				}
			}
			if q.a.handshake.localKEM != nil || q.a.handshake.remoteKEM != nil || q.indexes.Len() != 0 {
				t.Fatal("retained pending KEM or index")
			}
		})
	}
}

func TestHybridAuthenticatedFieldTampering(t *testing.T) {
	q := newPair(t, Config{Hybrid: true})
	init, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{8, 40, 1240, 1288} {
		bad := clone(init)
		bad.Bytes()[offset] ^= 1
		q.a.cookieGen.addMACs(epoch, bad.Bytes())
		token := admit(t, q.ab, epoch, bad)
		before := q.b.handshake
		v, err := PrepareInitiation(token)
		if err == nil {
			_, _, err = q.b.HandleInitiation(epoch, v, control())
		}
		if !errors.Is(err, ErrHandshake) || q.b.handshake != before || q.indexes.Len() != 1 {
			t.Fatalf("accepted initiation tampering at %d: %v", offset, err)
		}
	}
	response, _, err := q.b.HandleInitiation(epoch, prepare(t, admit(t, q.ab, epoch, init)), control())
	if err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{12, 44, 1148} {
		bad := clone(response)
		bad.Bytes()[offset] ^= 1
		q.b.cookieGen.addMACs(epoch, bad.Bytes())
		before := q.a.handshake
		if _, _, err := q.a.HandleResponse(epoch, admit(t, q.aa, epoch, bad), control()); !errors.Is(err, ErrHandshake) || q.a.handshake != before {
			t.Fatalf("accepted response tampering at %d: %v", offset, err)
		}
	}
	if _, _, err := q.a.HandleResponse(epoch, admit(t, q.aa, epoch, response), control()); err != nil {
		t.Fatal("tampering consumed original response:", err)
	}
}

func TestHybridInvalidEncapsulationKey(t *testing.T) {
	q := newPair(t, Config{Hybrid: true})
	wire, _, err := q.a.Initiate(epoch, control())
	if err != nil {
		t.Fatal(err)
	}
	var msg messageInitiation
	if err := msg.unmarshal(wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	var hash, chainKey, key [32]byte
	pub := q.ib.Public()
	mixHash(&hash, &hybridInitialHash, pub[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &hybridInitialChainKey, msg.Ephemeral[:])
	ss, err := q.a.handshake.localEphemeral.sharedSecret(pub)
	if err != nil {
		t.Fatal(err)
	}
	kdf2(&chainKey, &key, chainKey[:], ss[:])
	aead, _ := newAEAD(key[:])
	invalid := bytes.Repeat([]byte{0xff}, mlkem.EncapsulationKeySize768)
	aead.Seal(msg.EphemeralKEM[:0], zeroNonce[:], invalid, hash[:])
	if err := msg.marshal(wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	q.a.cookieGen.addMACs(epoch, wire.Bytes())
	if _, err := PrepareInitiation(admit(t, q.ab, epoch, wire)); !errors.Is(err, ErrHandshake) {
		t.Fatal("accepted invalid ML-KEM encoding", err)
	}
}

func TestHybridFraming(t *testing.T) {
	for typ, size := range map[uint32]int{MessageInitiationType: MessageHybridInitiationSize, MessageResponseType: MessageHybridResponseSize} {
		wire := make([]byte, size)
		putTypeField(wire, typ, true)
		if got, _, err := ParseHeader(wire); err != nil || got != typ || !PacketIsRetry(wire) {
			t.Fatal("hybrid retry framing", got, err)
		}
		for n := 0; n < size+2; n++ {
			if n == size || (typ == MessageInitiationType && n == MessageInitiationSize) || (typ == MessageResponseType && n == MessageResponseSize) {
				continue
			}
			bad := make([]byte, n)
			copy(bad, wire)
			if _, _, err := ParseHeader(bad); err == nil {
				t.Fatalf("accepted type %d length %d", typ, n)
			}
		}
		wire[1] = 1
		if _, _, err := ParseHeader(wire); err == nil {
			t.Fatal("accepted other reserved bits")
		}
	}
	for n := 0; n < 4; n++ {
		if PacketIsRetry([]byte{0xff, 0xff, 0xff}[:n]) {
			t.Fatal("short retry hint")
		}
	}
}
