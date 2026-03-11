/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/buffer"
	"github.com/tailscale/wireguard-go/conn"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type QueueHandshakeElement struct {
	msgType  uint32
	endpoint conn.Endpoint
	stack    buffer.Stack
}

type QueueInboundElement struct {
	stack    buffer.Stack
	keypair  *Keypair
	endpoint conn.Endpoint
}

type QueueInboundElementsContainer struct {
	sync.Mutex
	elems []*QueueInboundElement
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.stack = buffer.Stack{}
	elem.keypair = nil
	elem.endpoint = nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > (RejectAfterTime-KeepaliveTimeout-RekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Store(true)
		peer.SendHandshakeInitiation(false)
	}
}

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */

func (device *Device) RoutineReceiveIncoming(maxBatchSize int, recv conn.ReceiveFunc) {
	recvName := recv.PrettyName()
	defer func() {
		device.log.Verbosef("Routine: receive incoming %s - stopped", recvName)
		device.queue.decryption.wg.Done()
		device.queue.handshake.wg.Done()
		device.net.stopping.Done()
	}()

	device.log.Verbosef("Routine: receive incoming %s - started", recvName)

	// receive datagrams until conn is closed

	var (
		stacks      = make([]buffer.Stack, maxBatchSize)
		err         error
		count       int
		endpoints   = make([]conn.Endpoint, maxBatchSize)
		deathSpiral int
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize)
	)

	defer func() {
		buffer.ReleaseStacks(stacks)
	}()

	for {
		count, err = recv(stacks, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			device.log.Verbosef("Failed to receive %s packet: %v", recvName, err)
			if neterr, ok := err.(net.Error); ok && !neterr.Temporary() {
				return
			}
			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		deathSpiral = 0

		// handle each packet in the batch
		for i := 0; i < count; i++ {
			if stacks[i].Size() < MinMessageSize {
				continue
			}

			// check size of packet — peek first segment

			packet := stacks[i].Data()
			msgType := binary.LittleEndian.Uint32(packet[:4])

			switch msgType {

			// check if transport

			case MessageTransportType:

				// check size

				if len(packet) < MessageTransportSize {
					continue
				}

				// lookup key pair from first segment

				receiver := binary.LittleEndian.Uint32(
					packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
				)
				value := device.indexTable.Lookup(receiver)
				keypair := value.keypair
				if keypair == nil {
					continue
				}

				// check keypair expiry

				if keypair.created.Add(RejectAfterTime).Before(time.Now()) {
					continue
				}

				// create work element
				peer := value.peer
				elem := device.GetInboundElement()
				elem.stack = stacks[i]
				elem.keypair = keypair
				elem.endpoint = endpoints[i]
				stacks[i] = buffer.Stack{} // transfer ownership

				elemsForPeer, ok := elemsByPeer[peer]
				if !ok {
					elemsForPeer = device.GetInboundElementsContainer()
					elemsForPeer.Lock()
					elemsByPeer[peer] = elemsForPeer
				}
				elemsForPeer.elems = append(elemsForPeer.elems, elem)
				continue

			// otherwise it is a fixed size & handshake related packet

			case MessageInitiationType:
				if len(packet) != MessageInitiationSize {
					continue
				}

			case MessageResponseType:
				if len(packet) != MessageResponseSize {
					continue
				}

			case MessageCookieReplyType:
				if len(packet) != MessageCookieReplySize {
					continue
				}

			default:
				device.log.Verbosef("Received message with unknown type")
				continue
			}

			select {
			case device.queue.handshake.c <- QueueHandshakeElement{
				msgType:  msgType,
				stack:    stacks[i],
				endpoint: endpoints[i],
			}:
				stacks[i] = buffer.Stack{} // transfer ownership
			default:
			}
		}
		for i := 0; i < count; i++ {
			stacks[i].Release()
		}
		for peer, elemsContainer := range elemsByPeer {
			if peer.isRunning.Load() {
				peer.queue.inbound.c <- elemsContainer
				device.queue.decryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					elem.stack.Release()
					device.PutInboundElement(elem)
				}
				device.PutInboundElementsContainer(elemsContainer)
			}
			delete(elemsByPeer, peer)
		}
	}
}

func (device *Device) RoutineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: decryption worker %d - stopped", id)
	device.log.Verbosef("Routine: decryption worker %d - started", id)

	for elemsContainer := range device.queue.decryption.c {
		for _, elem := range elemsContainer.elems {
			// Decrypt each segment in-place. For GSO stacks, all segments
			// share the same keypair. If any segment fails, release the stack.
			failed := false
			for frame := range elem.stack.SegmentFrames() {
				if len(frame) < MessageTransportSize {
					failed = true
					break
				}
				counter := frame[MessageTransportOffsetCounter:MessageTransportOffsetContent]
				content := frame[MessageTransportOffsetContent:]

				binary.LittleEndian.PutUint64(nonce[0x4:0xc], binary.LittleEndian.Uint64(counter))
				_, err := elem.keypair.receive.Open(
					content[:0],
					nonce[:],
					content,
					nil,
				)
				if err != nil {
					failed = true
					break
				}
			}
			if failed {
				elem.stack.Release()
			}
		}
		elemsContainer.Unlock()
	}
}

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake(id int) {
	defer func() {
		device.log.Verbosef("Routine: handshake worker %d - stopped", id)
		device.queue.encryption.wg.Done()
	}()
	device.log.Verbosef("Routine: handshake worker %d - started", id)

	for elem := range device.queue.handshake.c {
		packet := elem.stack.Data()

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			err := reply.unmarshal(packet)
			if err != nil {
				device.log.Verbosef("Failed to decode cookie reply")
				goto skip
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Load() {
				device.log.Verbosef("Receiving cookie response from %s", elem.endpoint.DstToString())
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					device.log.Verbosef("Could not decrypt invalid cookie response")
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(packet) {
				device.log.Verbosef("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			if device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(packet, elem.endpoint.DstToBytes()) {
					device.SendHandshakeCookie(&elem)
					goto skip
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			device.log.Errorf("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			var msg MessageInitiation
			err := msg.unmarshal(packet)
			if err != nil {
				device.log.Errorf("Failed to decode initiation message")
				goto skip
			}

			// consume initiation

			peer := device.ConsumeMessageInitiation(&msg, elem.endpoint)
			if peer == nil {
				device.log.Verbosef("Received invalid initiation message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake initiation", peer)
			peer.rxBytes.Add(uint64(len(packet)))

			peer.SendHandshakeResponse()

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			err := msg.unmarshal(packet)
			if err != nil {
				device.log.Errorf("Failed to decode response message")
				goto skip
			}

			// consume response

			peer := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid response message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake response", peer)
			peer.rxBytes.Add(uint64(len(packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()

			if err != nil {
				device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendKeepalive()
		}
	skip:
		elem.stack.Release()
	}
}

func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	device := peer.device
	defer func() {
		device.log.Verbosef("%v - Routine: sequential receiver - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential receiver - started", peer)

	legacyBufs := make([][]byte, 0, maxBatchSize)

	for elemsContainer := range peer.queue.inbound.c {
		if elemsContainer == nil {
			return
		}
		elemsContainer.Lock()
		validTailPacket := -1
		dataPacketReceived := false
		rxBytesLen := uint64(0)
		for i, elem := range elemsContainer.elems {
			if elem.stack.Data() == nil {
				// decryption failed
				continue
			}

			elemHasValidSegment := false
			for frame := range elem.stack.SegmentFrames() {
				counter := binary.LittleEndian.Uint64(
					frame[MessageTransportOffsetCounter:MessageTransportOffsetContent],
				)
				if !elem.keypair.replayFilter.ValidateCounter(counter, RejectAfterMessages) {
					continue
				}

				if !elemHasValidSegment {
					elemHasValidSegment = true
					validTailPacket = i
					if peer.ReceivedWithKeypair(elem.keypair) {
						peer.SetEndpointFromPacket(elem.endpoint)
						peer.timersHandshakeComplete()
						peer.SendStagedPackets()
					}
				}

				// Compute decrypted content length from frame size.
				contentLen := len(frame) - MessageTransportOffsetContent - chacha20poly1305.Overhead
				rxBytesLen += uint64(contentLen + MinMessageSize)

				if contentLen == 0 {
					device.log.Verbosef("%v - Receiving keepalive packet", peer)
					continue
				}
				dataPacketReceived = true

				packet := frame[MessageTransportOffsetContent : MessageTransportOffsetContent+contentLen]

				switch packet[0] >> 4 {
				case 4:
					if len(packet) < ipv4.HeaderLen {
						continue
					}
					field := packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
					length := binary.BigEndian.Uint16(field)
					if int(length) > len(packet) || int(length) < ipv4.HeaderLen {
						continue
					}
					packet = packet[:length]
					src := packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
					srcAddr, _ := netip.AddrFromSlice(src)
					if !peer.AllowedPeerSourceIP(srcAddr) {
						device.log.Verbosef("IPv4 packet with disallowed source address from %v", peer)
						continue
					}

				case 6:
					if len(packet) < ipv6.HeaderLen {
						continue
					}
					field := packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
					length := binary.BigEndian.Uint16(field)
					length += ipv6.HeaderLen
					if int(length) > len(packet) {
						continue
					}
					packet = packet[:length]
					src := packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
					srcAddr, _ := netip.AddrFromSlice(src)
					if !peer.AllowedPeerSourceIP(srcAddr) {
						device.log.Verbosef("IPv6 packet with disallowed source address from %v", peer)
						continue
					}

				default:
					device.log.Verbosef("Packet with invalid IP version from %v", peer)
					continue
				}

				legacyBufs = append(legacyBufs, frame[:MessageTransportOffsetContent+len(packet)])
			}

			if elemHasValidSegment {
				if ep, ok := elem.endpoint.(conn.PeerAwareEndpoint); ok {
					ep.FromPeer(peer.handshake.remoteStatic)
				}
			}

			// Write once per stack: all segments in a single Write must be
			// backed by the same contiguous buffer for the TUN's handleGRO.
			if len(legacyBufs) > 0 {
				_, err := device.tun.device.Write(legacyBufs, MessageTransportOffsetContent)
				if err != nil && !device.isClosed() {
					device.log.Errorf("Failed to write packets to TUN device: %v", err)
				}
			}
			elem.stack.Release()
			legacyBufs = legacyBufs[:0]
		}

		peer.rxBytes.Add(rxBytesLen)
		if validTailPacket >= 0 {
			peer.SetEndpointFromPacket(elemsContainer.elems[validTailPacket].endpoint)
			peer.keepKeyFreshReceiving()
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()
		}
		if dataPacketReceived {
			peer.timersDataReceived()
		}
		for _, elem := range elemsContainer.elems {
			device.PutInboundElement(elem)
		}
		device.PutInboundElementsContainer(elemsContainer)
	}
}
