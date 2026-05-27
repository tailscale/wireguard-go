//go:build mips || mipsle

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	asmAEAD "github.com/tailscale/wireguard-go/tsasm/mips32/chacha20poly1305"
)

// chacha20poly1305New returns a ChaCha20-Poly1305 AEAD. On
// big-endian GOARCH=mips it uses the hand-written scalar mips32r2
// kernels in tsasm/mips32/, both for ChaCha20 and Poly1305 -- the
// 5x26 layout maps cleanly onto the 32-bit registers and the
// pure-Go path emulates uint64 multiplies, so both halves win in
// asm here.
//
// As an escape hatch for hardware regressions or asm bugs, setting
// the environment variable TS_WG_ASM=0 forces the pure-Go x/crypto
// implementation instead.
func chacha20poly1305New(key []byte) (cipher.AEAD, error) {
	if os.Getenv("TS_WG_ASM") == "0" {
		return chacha20poly1305.New(key)
	}
	return asmAEAD.New(key)
}
