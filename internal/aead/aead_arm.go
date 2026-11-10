//go:build arm

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package aead

import (
	"crypto/cipher"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	asmAEAD "github.com/tailscale/wireguard-go/tsasm/arm/chacha20poly1305"
)

// New returns a ChaCha20-Poly1305 AEAD. On GOARCH=arm
// (32-bit, any GOOS) it uses the assembly kernels from tsasm/arm/.
// The cookie path (which uses the extended-nonce variant via
// chacha20poly1305.NewX) is left on the x/crypto path because it is
// not on the per-packet hot path.
//
// As an escape hatch for hardware regressions or asm bugs, setting
// the environment variable TS_WG_ASM=0 forces the pure-Go x/crypto
// implementation instead.
func New(key []byte) (cipher.AEAD, error) {
	// Apply x/crypto's key and FIPS policy checks before selecting assembly.
	fallback, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if os.Getenv("TS_WG_ASM") == "0" {
		return fallback, nil
	}
	return asmAEAD.New(key)
}
