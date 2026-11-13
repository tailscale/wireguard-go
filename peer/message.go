/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import (
	"crypto/mlkem"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/tailscale/wireguard-go/tai64n"
)

const (
	noiseConstruction       = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	hybridNoiseConstruction = "Noise_IKhfs+psk2_25519+MLKEM768_ChaChaPoly_BLAKE2s"
	wgIdentifier            = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	labelMAC1               = "mac1----"
	labelCookie             = "cookie--"
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
	// are the exact wire lengths of classical handshakes and cookie replies.
	MessageInitiationSize = 148

	MessageResponseSize = 92

	// MessageHybridInitiationSize is the hybrid initiation wire length.
	MessageHybridInitiationSize = MessageInitiationSize + mlkem.EncapsulationKeySize768 + chacha20poly1305.Overhead

	// MessageHybridResponseSize is the hybrid response wire length.
	MessageHybridResponseSize = MessageResponseSize + mlkem.CiphertextSize768 + chacha20poly1305.Overhead

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
	Type         uint32
	IsRetry      bool
	Sender       uint32
	Ephemeral    PublicKey
	HasKEM       bool
	EphemeralKEM [mlkem.EncapsulationKeySize768 + chacha20poly1305.Overhead]byte
	Static       [PublicKeySize + chacha20poly1305.Overhead]byte
	Timestamp    [tai64n.TimestampSize + chacha20poly1305.Overhead]byte
	MAC1         [blake2s.Size128]byte
	MAC2         [blake2s.Size128]byte
}

type messageResponse struct {
	Type         uint32
	IsRetry      bool
	Sender       uint32
	Receiver     uint32
	Ephemeral    PublicKey
	HasKEM       bool
	EphemeralKEM [mlkem.CiphertextSize768 + chacha20poly1305.Overhead]byte
	Empty        [chacha20poly1305.Overhead]byte
	MAC1         [blake2s.Size128]byte
	MAC2         [blake2s.Size128]byte
}

var errMessageLengthMismatch = errors.New("message length mismatch")

func (msg *messageInitiation) unmarshal(b []byte) error {
	if len(b) != MessageInitiationSize && len(b) != MessageHybridInitiationSize {
		return errMessageLengthMismatch
	}

	msg.Type, msg.IsRetry = parseTypeField(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	copy(msg.Ephemeral[:], b[8:])
	off := 8 + len(msg.Ephemeral)
	msg.HasKEM = len(b) == MessageHybridInitiationSize
	if msg.HasKEM {
		copy(msg.EphemeralKEM[:], b[off:])
		off += len(msg.EphemeralKEM)
	}
	copy(msg.Static[:], b[off:])
	copy(msg.Timestamp[:], b[off+len(msg.Static):])
	copy(msg.MAC1[:], b[off+len(msg.Static)+len(msg.Timestamp):])
	copy(msg.MAC2[:], b[off+len(msg.Static)+len(msg.Timestamp)+len(msg.MAC1):])

	return nil
}

func (msg *messageInitiation) marshal(b []byte) error {
	if (msg.HasKEM && len(b) != MessageHybridInitiationSize) || (!msg.HasKEM && len(b) != MessageInitiationSize) {
		return errMessageLengthMismatch
	}

	putTypeField(b, msg.Type, msg.IsRetry)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	copy(b[8:], msg.Ephemeral[:])
	off := 8 + len(msg.Ephemeral)
	if msg.HasKEM {
		copy(b[off:], msg.EphemeralKEM[:])
		off += len(msg.EphemeralKEM)
	}
	copy(b[off:], msg.Static[:])
	copy(b[off+len(msg.Static):], msg.Timestamp[:])
	copy(b[off+len(msg.Static)+len(msg.Timestamp):], msg.MAC1[:])
	copy(b[off+len(msg.Static)+len(msg.Timestamp)+len(msg.MAC1):], msg.MAC2[:])

	return nil
}

func (msg *messageResponse) unmarshal(b []byte) error {
	if len(b) != MessageResponseSize && len(b) != MessageHybridResponseSize {
		return errMessageLengthMismatch
	}

	msg.Type, msg.IsRetry = parseTypeField(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	msg.Receiver = binary.LittleEndian.Uint32(b[8:])
	copy(msg.Ephemeral[:], b[12:])
	off := 12 + len(msg.Ephemeral)
	msg.HasKEM = len(b) == MessageHybridResponseSize
	if msg.HasKEM {
		copy(msg.EphemeralKEM[:], b[off:])
		off += len(msg.EphemeralKEM)
	}
	copy(msg.Empty[:], b[off:])
	copy(msg.MAC1[:], b[off+len(msg.Empty):])
	copy(msg.MAC2[:], b[off+len(msg.Empty)+len(msg.MAC1):])

	return nil
}

func (msg *messageResponse) marshal(b []byte) error {
	if (msg.HasKEM && len(b) != MessageHybridResponseSize) || (!msg.HasKEM && len(b) != MessageResponseSize) {
		return errMessageLengthMismatch
	}

	putTypeField(b, msg.Type, msg.IsRetry)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	binary.LittleEndian.PutUint32(b[8:], msg.Receiver)
	copy(b[12:], msg.Ephemeral[:])
	off := 12 + len(msg.Ephemeral)
	if msg.HasKEM {
		copy(b[off:], msg.EphemeralKEM[:])
		off += len(msg.EphemeralKEM)
	}
	copy(b[off:], msg.Empty[:])
	copy(b[off+len(msg.Empty):], msg.MAC1[:])
	copy(b[off+len(msg.Empty)+len(msg.MAC1):], msg.MAC2[:])

	return nil
}

const handshakeRetryMask = uint32(1 << 31)

// PacketIsRetry reports whether a packet carries the Tailscale handshake retry hint.
// The hint is unauthenticated and must not be used for authorization.
// Standard WireGuard packets and inputs shorter than four bytes return false.
func PacketIsRetry(b []byte) bool {
	_, retry := parseTypeField(b)
	return retry
}

func parseTypeField(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(b)
	return v &^ handshakeRetryMask, v&handshakeRetryMask != 0
}

func putTypeField(b []byte, typ uint32, retry bool) {
	if retry {
		typ |= handshakeRetryMask
	}
	binary.LittleEndian.PutUint32(b, typ)
}

// ParseHeader returns the message type and receiver index after checking framing.
// Initiations return receiver zero because they carry no receiver index.
// It returns an error for an unknown type, a wrong fixed message length, or a
// transport shorter than [MessageKeepaliveSize]. It does not authenticate the
// message. Use the index only to select the [Peer] that will validate it.
// Handshake framing accepts classical and hybrid lengths and strips the retry
// hint from typ. Other reserved bits and retry hints on non-handshakes are rejected.
func ParseHeader(wire []byte) (typ, receiver uint32, err error) {
	typ, retry := parseTypeField(wire)
	if retry && typ != MessageInitiationType && typ != MessageResponseType {
		return 0, 0, ErrTransport
	}
	switch typ {
	case MessageInitiationType:
		if len(wire) != MessageInitiationSize && len(wire) != MessageHybridInitiationSize {
			return 0, 0, errMessageLengthMismatch
		}
	case MessageResponseType:
		if len(wire) != MessageResponseSize && len(wire) != MessageHybridResponseSize {
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
	initialChainKey       [blake2s.Size]byte
	initialHash           [blake2s.Size]byte
	hybridInitialChainKey [blake2s.Size]byte
	hybridInitialHash     [blake2s.Size]byte
	oneNonce              noiseNonce
	zeroNonce             noiseNonce
)

func init() {
	initialChainKey = blake2s.Sum256([]byte(noiseConstruction))
	mixHash(&initialHash, &initialChainKey, []byte(wgIdentifier))
	hybridInitialChainKey = blake2s.Sum256([]byte(hybridNoiseConstruction))
	mixHash(&hybridInitialHash, &hybridInitialChainKey, []byte(wgIdentifier))
	oneNonce[4] = 1
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
