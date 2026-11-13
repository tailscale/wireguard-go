/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

// Package peer implements WireGuard handshakes and in-place transport encryption
// for one configured remote key. The caller supplies packet storage, receiver
// index allocation, routing, and scheduling of returned maintenance windows.
// Incoming handshakes pass through [Admission] before preparation and [Peer] handling.
//
// Handshakes use standard WireGuard by default. [Config.Hybrid] enables the
// Tailscale X25519 + ML-KEM-768 hybrid construction. Both endpoints must select
// the same mode. Hybrid initiations and responses need larger output buffers,
// as specified by [MessageHybridInitiationSize] and [MessageHybridResponseSize].
// [Peer.RetryInitiation] and automatic retries mark hybrid packets with the
// routing hint exposed by [PacketIsRetry].
package peer
