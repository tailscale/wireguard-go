/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import (
	"encoding/binary"
	"time"
)

// Send encrypts packets in place and replaces the completed prefix with wire
// packet ranges. Each input needs [TransportHeaderSize] bytes of headroom and
// tailroom for up to [PaddingMultiple] - 1 padding bytes plus the 16-byte
// authentication tag. An empty payload produces a keepalive. Bounds for the
// entire batch are checked before mutation.
//
// It returns [ErrInvalidBuffer] for invalid ranges or missing headroom,
// [ErrShortBuffer] for missing tailroom, or [ErrNoSession] if no send key is usable.
// If counters run out partway through, it returns [ErrExhausted] with N set to the
// completed prefix length. The remaining packet entries and buffers are unchanged.
func (p *Peer) Send(now time.Time, packets []Packet) (result BatchResult, err error) {
	defer func() { result.Update = p.update() }()
	if err := p.advance(now); err != nil {
		return result, err
	}
	if err := validatePackets(packets, p.mtu, true); err != nil {
		return result, err
	}
	if len(packets) == 0 {
		return result, nil
	}
	k := p.keypairs.current
	if !usable(k, now) {
		return result, ErrNoSession
	}
	first, n := k.reserve(len(packets))
	if n < len(packets) {
		err = ErrExhausted
	}
	data := false
	for i := 0; i < n; i++ {
		data = data || packets[i].Size > 0
		packets[i] = encrypt(k, packets[i], p.mtu, first+uint64(i), &p.sendNonceBuf)
	}
	if n > 0 {
		p.sentTransport(now, data, k)
	}
	return BatchResult{N: n}, err
}

func encrypt(k *keypair, packet Packet, mtu int, counter uint64, nonce *noiseNonce) Packet {
	// The caller reserves the counter and validates the range before entry.
	wire, _ := sendRange(packet, mtu)
	padded := packet.Size + paddingSize(packet.Size, mtu)
	content := packet.Buffer[packet.Offset : packet.Offset+padded]
	clear(content[packet.Size:])
	header := wire.Bytes()[:TransportHeaderSize]
	binary.LittleEndian.PutUint32(header, MessageTransportType)
	binary.LittleEndian.PutUint32(header[4:], k.remoteIndex)
	binary.LittleEndian.PutUint64(header[8:], counter)
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	// Destination starts at plaintext, ensuring exact AEAD overlap. Capacity was
	// checked before entry, so Seal cannot allocate a fallback output buffer.
	k.send.Seal(content[:0], nonce[:], content, nil)
	return wire
}

// Disposition classifies a received transport packet.
type Disposition uint8

const (
	// Dropped means the packet was rejected and has no usable plaintext.
	Dropped Disposition = iota

	// Data means the authenticated plaintext is nonempty.
	Data

	// Keepalive means the authenticated plaintext is empty.
	Keepalive
)

// ReceiveResult describes one examined transport packet.
// Only a nil Err permits using Packet. [Data] packets include WireGuard padding,
// which the caller must trim using its payload framing before delivery.
type ReceiveResult struct {
	// Packet is the plaintext range sharing the input buffer.
	// It is zero for a dropped packet.
	Packet Packet
	// Disposition distinguishes dropped packets, data, and keepalives.
	Disposition Disposition
	// Err is nil for authenticated packets. [ErrReplay] rejects a duplicate or
	// old authenticated counter. [ErrTransport] covers other packet rejections.
	Err error
}

// Receive decrypts packets in place and writes one result per packet.
// N counts examined packets, including drops. Packet rejections are reported
// in results rather than the batch error. Callers must enforce their payload
// validation and authorization rules before delivering plaintext.
//
// It returns [ErrShortBuffer] if len(results) is less than len(packets), or
// [ErrInvalidBuffer] for an invalid input range. These checks precede changes
// to packet bytes or results. Authentication failures may overwrite input bytes.
// An authenticated replay has its decrypted bytes cleared.
func (p *Peer) Receive(now time.Time, packets []Packet, results []ReceiveResult) (result BatchResult, err error) {
	defer func() { result.Update = p.update() }()
	if err := p.advance(now); err != nil {
		return result, err
	}
	if len(results) < len(packets) {
		return result, ErrShortBuffer
	}
	if err := validatePackets(packets, 0, false); err != nil {
		return result, err
	}
	keys := p.keypairs
	a := receivePackets(now, keys, packets, results, &p.recvNonceBuf)
	p.applyReception(now, a, keys)
	return BatchResult{N: len(packets)}, nil
}

type receiveActivity struct {
	confirmed *keypair
	refresh   *keypair
	auth      [3]bool
	data      [3]uint8
}

func receivePackets(now time.Time, keys keypairs, packets []Packet, results []ReceiveResult, nonce *noiseNonce) (a receiveActivity) {
	original := keys
	confirmable := keys.next
	if !usable(confirmable, now) {
		confirmable = nil
	}
	refreshKey := keys.current
	if refreshKey == nil || !refreshKey.isInitiator || refreshKey.sendDisabled.Load() || now.Sub(refreshKey.created) <= RejectAfterTime-KeepaliveTimeout-RekeyTimeout {
		refreshKey = nil
	}
	for i, packet := range packets {
		results[i] = ReceiveResult{Err: ErrTransport}
		wire := packet.Bytes()
		typ, index, err := ParseHeader(wire)
		if err != nil || typ != MessageTransportType {
			continue
		}
		k := keys.lookup(index)
		if k == nil || now.Before(k.created) || now.Sub(k.created) >= RejectAfterTime {
			continue
		}
		counter := binary.LittleEndian.Uint64(wire[8:16])
		if counter >= RejectAfterMessages {
			continue
		}
		binary.LittleEndian.PutUint64(nonce[4:], counter)
		content := wire[TransportHeaderSize:]
		plaintext, err := k.receive.Open(content[:0], nonce[:], content, nil)
		if err != nil {
			continue
		}
		if !k.replayFilter.ValidateCounter(counter, RejectAfterMessages) {
			clear(plaintext)
			results[i].Err = ErrReplay
			continue
		}
		if keys.next == k && confirmable == k {
			a.confirmed = k
			keys.previous, keys.current, keys.next = keys.current, k, nil
			a.refresh, refreshKey = nil, nil
			if k.isInitiator && now.Sub(k.created) > RejectAfterTime-KeepaliveTimeout-RekeyTimeout {
				refreshKey = k
			}
		}
		// Any authenticated packet can request refresh of the current key,
		// including traffic received with a retained previous key.
		a.refresh = refreshKey
		slot := 2
		if k == original.current {
			slot = 0
		} else if k == original.previous {
			slot = 1
		}
		kind := Keepalive
		if len(plaintext) > 0 {
			kind = Data
			if a.data[slot] < 2 {
				a.data[slot]++
			}
		}
		results[i] = ReceiveResult{Packet: Packet{packet.Buffer, packet.Offset + TransportHeaderSize, len(plaintext)}, Disposition: kind}
		a.auth[slot] = true
	}
	return
}

func (p *Peer) applyReception(now time.Time, a receiveActivity, keys keypairs) {
	auth, data := false, 0
	for i, k := range [...]*keypair{keys.current, keys.previous, keys.next} {
		// A delayed receipt must not resurrect maintenance for retired keys.
		// Still-live receive-only identity grace keys retain ordinary activity.
		if k != nil && !k.retired.Load() {
			auth = auth || a.auth[i]
			data += int(a.data[i])
		}
	}
	if a.confirmed != nil && p.receivedWithKeypair(a.confirmed) {
		p.onHandshakeComplete(now)
	}
	if auth {
		p.onAuthReceived(now)
	}
	if data > 0 {
		p.onDataReceived(now)
		if data > 1 {
			p.timers.needAnotherKeepalive = true
		}
	}
	if auth && a.refresh != nil && a.refresh == p.keypairs.current && !a.refresh.sendDisabled.Load() && !p.timers.receiveRefreshSent {
		p.timers.receiveRefreshSent = true
		p.requestRefresh()
	}
}
