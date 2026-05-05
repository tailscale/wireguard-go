/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"log"
	"sync"

	"github.com/tailscale/wireguard-go/device/afalg"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

// On 32-bit ARM Linux, golang.org/x/crypto/chacha20poly1305 ships no
// assembly and the pure-Go fallback is much slower than the kernel's
// NEON-accelerated rfc7539(chacha20-neon,poly1305-neon). We route the
// data-path AEAD through AF_ALG to pick that up. Handshake/cookie
// crypto stays on the Go implementation.
//
// AF_ALG is only the right choice when the kernel can pick a NEON
// driver: on a NEON-less ARMv6 the kernel falls back to scalar
// chacha20-arm/poly1305-arm which is roughly on par with Go's pure-Go
// implementation, and the per-op syscall overhead then turns into a
// net loss (measured ~1.3x slower on a Pi 1). We therefore gate AF_ALG
// on HWCAP_NEON and additionally probe with a known-answer self-test
// in case the kernel lacks the algorithm or produces wrong output.
//
// See https://github.com/tailscale/wireguard-go/pull/57 for the
// real-hardware benchmark numbers behind this policy.

var (
	aeadCtor     func([]byte) (cipher.AEAD, error)
	aeadCtorOnce sync.Once
)

func chacha20poly1305New(key []byte) (cipher.AEAD, error) {
	aeadCtorOnce.Do(func() {
		aeadCtor = chacha20poly1305.New
		if !cpu.ARM.HasNEON {
			return
		}
		if err := afalg.SelfTest(); err != nil {
			log.Printf("wireguard-go: AF_ALG ChaCha20-Poly1305 unavailable (%v), using Go crypto", err)
			return
		}
		aeadCtor = afalg.New
	})
	return aeadCtor(key)
}
