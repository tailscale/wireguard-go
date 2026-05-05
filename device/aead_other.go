//go:build !(linux && arm)

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

// chacha20poly1305New constructs the data-path ChaCha20-Poly1305 AEAD.
//
// AF_ALG is only worth the syscall overhead on platforms where Go's
// chacha20poly1305 lacks an optimized assembly path, which today
// means linux/arm (32-bit). Everywhere else (amd64/arm64/etc., or
// non-Linux), Go's implementation wins and we use it directly.
func chacha20poly1305New(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}
