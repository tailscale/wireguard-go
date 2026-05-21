/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"github.com/tailscale/wireguard-go/device/afalg"
)

// On Linux, run the shared AEAD compatibility test suite against the
// AF_ALG-backed implementation in addition to the Go reference.
func init() {
	if afalg.SelfTest() != nil {
		// Same as [chacha20poly1305New], skip when the kernel module is unavailable.
		return
	}
	aeadCtors = append(aeadCtors, aeadCtorEntry{"af_alg", afalg.New})
}
