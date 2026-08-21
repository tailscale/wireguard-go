//go:build mips64

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	asmAEAD "github.com/tailscale/wireguard-go/tsasm/mips64/chacha20poly1305"
)

// chacha20poly1305New returns a ChaCha20-Poly1305 AEAD. On
// GOARCH=mips64 / mips64le it uses the hand-written scalar
// mips64r2 ChaCha20 from tsasm/mips64/, paired with the pure-Go
// Poly1305 from golang.org/x/crypto. ChaCha20 is the dominant cost
// (~70% of the AEAD on Octeon II) so this is the right slice to
// optimize first.
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
