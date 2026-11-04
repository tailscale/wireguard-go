/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

// Package peer implements WireGuard without I/O or internal workers.
// The caller supplies routing, packet storage, queues, scheduling, admission
// policy, IP validation, AllowedIPs checks, and endpoint roaming policy.
//
// The caller must serialize all Peer methods. Transport provides separate send
// and receive lanes that may run concurrently with each other and with Peer.
// Each lane has one caller. Peer and Transport must not be copied.
//
// New takes a LocalIdentity shared with ingress and an IndexAllocator whose
// namespace spans all identities using that ingress. Admission checks handshake
// MACs before PrepareInitiation extracts a routing hint. HandleInitiation
// authenticates the configured remote and timestamp. ParseHeader returns receiver
// indices for responses, cookies, and transport packets. Routing is not authentication.
//
// Packet storage belongs to the caller and is not retained. Send and Receive
// operate in place. Admission and preparation tokens hold their own snapshots.
// Receive returns authenticated, padded plaintext, not validated or authorized IP.
//
// Clocks must be nonzero and nondecreasing. Use a consistent clock with monotonic
// components. Its wall time also supplies initiation timestamps. Peer does not
// read the clock or manufacture newer timestamps. Each transport lane has a
// clock independent of the control clock.
//
// State-changing Peer methods return a post-call Update, including on error or
// partial progress. Apply valid transport receipts promptly in per-direction
// order and notify the scheduler when receipts are pending. Timer effects and
// responder confirmation take effect when the control owner applies a receipt.
//
// Call HandleWake within Update.Wake's inclusive window. Output backpressure
// leaves events due. Replenish storage before retrying. Key rejection does not
// depend on wakes. Cleanup is due after 3*RejectAfterTime. In-flight transport
// calls can finish with pinned keys. Stop dispatch and drain lanes and writers
// for strong revocation on Close or identity replacement.
//
// The zero HandshakePolicy leaves initiation to the caller. Explicit Initiate,
// authenticated keepalives, key rejection, and cleanup remain available under
// every policy. Update.Handshake reports demand and the next legal initiation time.
package peer
