//go:build !arm && !(amd64 && gc && !purego)

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package aead

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

// New returns a ChaCha20-Poly1305 AEAD for the 32-byte key.
func New(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}
