/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import (
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/tailscale/wireguard-go/tai64n"
)

const (
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	labelMAC1         = "mac1----"
	labelCookie       = "cookie--"
)

const (
	// MessageInitiationType, MessageResponseType, MessageCookieReplyType, and
	// MessageTransportType are the WireGuard message type values.
	MessageInitiationType = 1

	MessageResponseType = 2

	MessageCookieReplyType = 3

	MessageTransportType = 4
)

const (
	// MessageInitiationSize, MessageResponseSize, and MessageCookieReplySize
	// are the exact wire lengths of their handshake and cookie messages.
	MessageInitiationSize = 148

	MessageResponseSize = 92

	MessageCookieReplySize = 64

	// TransportHeaderSize is the wire header length before encrypted payload.
	TransportHeaderSize = 16

	// TransportOverhead is the header and authentication tag length added to
	// a padded transport payload.
	TransportOverhead = TransportHeaderSize + chacha20poly1305.Overhead

	// MessageKeepaliveSize is the wire length of an empty transport message.
	MessageKeepaliveSize = TransportOverhead

	// PaddingMultiple is the transport plaintext padding alignment in bytes.
	PaddingMultiple = 16
)

type messageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral PublicKey
	// Static is the encrypted static public key and authentication tag.
	Static [PublicKeySize + chacha20poly1305.Overhead]byte
	// Timestamp is the encrypted replay timestamp and authentication tag.
	Timestamp [tai64n.TimestampSize + chacha20poly1305.Overhead]byte
	// MAC1 is the message MAC keyed from the receiver's public key.
	MAC1 [blake2s.Size128]byte
	// MAC2 is the message MAC keyed from the source cookie.
	MAC2 [blake2s.Size128]byte
}

type messageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral PublicKey
	// Empty authenticates the empty response payload.
	Empty [chacha20poly1305.Overhead]byte
	// MAC1 is the message MAC keyed from the receiver's public key.
	MAC1 [blake2s.Size128]byte
	// MAC2 is the message MAC keyed from the source cookie.
	MAC2 [blake2s.Size128]byte
}

var errMessageLengthMismatch = errors.New("message length mismatch")

func (msg *messageInitiation) unmarshal(b []byte) error {
	if len(b) != MessageInitiationSize {
		return errMessageLengthMismatch
	}
	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	copy(msg.Ephemeral[:], b[8:])
	copy(msg.Static[:], b[8+len(msg.Ephemeral):])
	copy(msg.Timestamp[:], b[8+len(msg.Ephemeral)+len(msg.Static):])
	copy(msg.MAC1[:], b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp):])
	copy(msg.MAC2[:], b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp)+len(msg.MAC1):])
	return nil
}

func (msg *messageInitiation) marshal(b []byte) error {
	if len(b) != MessageInitiationSize {
		return errMessageLengthMismatch
	}
	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	copy(b[8:], msg.Ephemeral[:])
	copy(b[8+len(msg.Ephemeral):], msg.Static[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static):], msg.Timestamp[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp):], msg.MAC1[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp)+len(msg.MAC1):], msg.MAC2[:])
	return nil
}

func (msg *messageResponse) unmarshal(b []byte) error {
	if len(b) != MessageResponseSize {
		return errMessageLengthMismatch
	}
	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	msg.Receiver = binary.LittleEndian.Uint32(b[8:])
	copy(msg.Ephemeral[:], b[12:])
	copy(msg.Empty[:], b[12+len(msg.Ephemeral):])
	copy(msg.MAC1[:], b[12+len(msg.Ephemeral)+len(msg.Empty):])
	copy(msg.MAC2[:], b[12+len(msg.Ephemeral)+len(msg.Empty)+len(msg.MAC1):])
	return nil
}

func (msg *messageResponse) marshal(b []byte) error {
	if len(b) != MessageResponseSize {
		return errMessageLengthMismatch
	}
	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	binary.LittleEndian.PutUint32(b[8:], msg.Receiver)
	copy(b[12:], msg.Ephemeral[:])
	copy(b[12+len(msg.Ephemeral):], msg.Empty[:])
	copy(b[12+len(msg.Ephemeral)+len(msg.Empty):], msg.MAC1[:])
	copy(b[12+len(msg.Ephemeral)+len(msg.Empty)+len(msg.MAC1):], msg.MAC2[:])
	return nil
}

func msgType(dgram []byte) uint32 {
	if len(dgram) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(dgram[:4])
}

// ParseHeader returns the message type and receiver index after checking framing.
// Initiations return receiver zero because they carry no receiver index.
// It returns an error for an unknown type, a wrong fixed message length, or a
// transport shorter than [MessageKeepaliveSize]. It does not authenticate the
// message. Use the index only to select the [Peer] that will validate it.
func ParseHeader(wire []byte) (typ, receiver uint32, err error) {
	typ = msgType(wire)
	switch typ {
	case MessageInitiationType:
		if len(wire) != MessageInitiationSize {
			return 0, 0, errMessageLengthMismatch
		}
	case MessageResponseType:
		if len(wire) != MessageResponseSize {
			return 0, 0, errMessageLengthMismatch
		}
		receiver = binary.LittleEndian.Uint32(wire[8:12])
	case MessageCookieReplyType:
		if len(wire) != MessageCookieReplySize {
			return 0, 0, errMessageLengthMismatch
		}
		receiver = binary.LittleEndian.Uint32(wire[4:8])
	case MessageTransportType:
		if len(wire) < MessageKeepaliveSize {
			return 0, 0, errMessageLengthMismatch
		}
		receiver = binary.LittleEndian.Uint32(wire[4:8])
	default:
		return 0, 0, ErrTransport
	}
	return typ, receiver, nil
}

var (
	initialChainKey [blake2s.Size]byte
	initialHash     [blake2s.Size]byte
	zeroNonce       noiseNonce
)

func init() {
	initialChainKey = blake2s.Sum256([]byte(noiseConstruction))
	mixHash(&initialHash, &initialChainKey, []byte(wgIdentifier))
}

const (
	// RekeyAfterMessages is the send counter threshold for requesting renewal.
	RekeyAfterMessages = (1 << 60)

	// RejectAfterMessages is the exclusive upper bound on transport counters.
	RejectAfterMessages = (1 << 64) - (1 << 13) - 1

	// RekeyAfterTime is the initiator key age threshold for requesting renewal.
	RekeyAfterTime = time.Second * 120

	// RekeyAttemptTime is the nominal WireGuard handshake retry duration.
	RekeyAttemptTime = time.Second * 90

	// RekeyTimeout is the minimum interval between sent handshake initiations.
	RekeyTimeout = time.Second * 5

	// MaxTimerHandshakes is the retry counter threshold for stopping automatic retries.
	MaxTimerHandshakes = 90 / 5

	// RekeyTimeoutJitter is the scheduling slack for handshake wake windows.
	RekeyTimeoutJitter = time.Millisecond * 334

	// RejectAfterTime is the key age at which transport use is rejected.
	// Retained keys are released at three times this age.
	RejectAfterTime = time.Second * 180

	// KeepaliveTimeout is the delay before acknowledging received data with
	// a keepalive when no authenticated packet has been sent.
	KeepaliveTimeout = time.Second * 10

	// HandshakeInitRate is the interval that must be exceeded between consumed
	// initiations.
	HandshakeInitRate = time.Second / 50
)
