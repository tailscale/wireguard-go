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
	"golang.org/x/crypto/poly1305"

	"github.com/tailscale/wireguard-go/tai64n"
)

// WireGuard Noise protocol parameters.
const (
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	labelMAC1         = "mac1----"
	labelCookie       = "cookie--"
)

// Message types are encoded as little-endian uint32 values.
const (
	// MessageInitiationType identifies a handshake initiation.
	MessageInitiationType = 1
	// MessageResponseType identifies a handshake response.
	MessageResponseType = 2
	// MessageCookieReplyType identifies a cookie reply.
	MessageCookieReplyType = 3
	// MessageTransportType identifies an encrypted transport packet.
	MessageTransportType = 4
)

// Message sizes and framing sizes are in bytes.
const (
	// MessageInitiationSize is the size of a handshake initiation.
	MessageInitiationSize = 148
	// MessageResponseSize is the size of a handshake response.
	MessageResponseSize = 92
	// MessageCookieReplySize is the size of a cookie reply.
	MessageCookieReplySize = 64

	// TransportHeaderSize covers the type, receiver index, and counter.
	TransportHeaderSize = 16

	// TransportOverhead is the header and Poly1305 tag, excluding padding.
	// Padding adds at most PaddingMultiple-1 bytes.
	TransportOverhead = TransportHeaderSize + poly1305.TagSize

	// MessageKeepaliveSize is the size of an empty transport message.
	MessageKeepaliveSize = TransportOverhead

	// PaddingMultiple is the plaintext padding alignment, subject to PaddingMTU.
	PaddingMultiple = 16
)

type messageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral PublicKey
	Static    [PublicKeySize + poly1305.TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type messageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral PublicKey
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
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

// msgType reads the leading little-endian message type tag, or 0 if the buffer
// is too short.
func msgType(dgram []byte) uint32 {
	if len(dgram) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(dgram[:4])
}

// ParseHeader checks framing and reserved type bytes and returns the message
// type and receiver index. Initiations return a zero receiver index. Handshake
// and cookie lengths must be exact. Transport packets must be at least
// MessageKeepaliveSize bytes. ParseHeader does not authenticate packets.
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

// Initial Noise state, set in init.
var (
	initialChainKey [blake2s.Size]byte
	initialHash     [blake2s.Size]byte
	zeroNonce       [chacha20poly1305.NonceSize]byte
)

func init() {
	initialChainKey = blake2s.Sum256([]byte(noiseConstruction))
	mixHash(&initialHash, &initialChainKey, []byte(wgIdentifier))
}

// WireGuard rekey, rejection, and keepalive limits.
const (
	// RekeyAfterMessages is the sent-message threshold for requesting a rekey.
	RekeyAfterMessages = (1 << 60)
	// RejectAfterMessages is the exclusive transport counter limit.
	RejectAfterMessages = (1 << 64) - (1 << 13) - 1
	// RekeyAfterTime is the initiator's send-key age threshold for rekeying.
	RekeyAfterTime = time.Second * 120
	// RekeyAttemptTime is the protocol's handshake retry interval budget.
	RekeyAttemptTime = time.Second * 90
	// RekeyTimeout is the minimum delay from a sent handshake to a new initiation.
	RekeyTimeout = time.Second * 5
	// MaxTimerHandshakes is the retry threshold. Retries stop once it is exceeded.
	MaxTimerHandshakes = 90 / 5
	// RekeyTimeoutJitter is the allowed handshake wake coalescing slack.
	RekeyTimeoutJitter = time.Millisecond * 334
	// RejectAfterTime is the exclusive transport key-age limit.
	RejectAfterTime = time.Second * 180
	// KeepaliveTimeout is the passive keepalive delay after receiving data.
	KeepaliveTimeout = time.Second * 10
	// HandshakeInitRate is the minimum spacing between consumed initiations.
	// Initiations at the exact limit are rejected.
	HandshakeInitRate = time.Second / 50
)
