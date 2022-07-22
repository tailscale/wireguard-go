//go:build !linux
// +build !linux

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 */

package conn

// getSrcFromControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func getSrcFromControl(control []byte, ep *StdNetEndpoint) {
}

// setSrcControl parses the control for PKTINFO and if found updates ep with
// the source information found.
func setSrcControl(control *[]byte, ep *StdNetEndpoint) {
}

// srcControlSize returns the recommended buffer size for pooling sticky control
// data.
const srcControlSize = 0
