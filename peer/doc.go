/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

// Package peer implements WireGuard handshakes and in-place transport encryption
// for one configured remote key. The caller supplies packet storage, receiver
// index allocation, routing, and scheduling of returned maintenance windows.
// Incoming handshakes pass through [Admission] before preparation and [Peer] handling.
package peer
