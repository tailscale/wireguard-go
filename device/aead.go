// SPDX-License-Identifier: MIT

package device

import (
	"crypto/cipher"

	"github.com/tailscale/wireguard-go/internal/aead"
)

func chacha20poly1305New(key []byte) (cipher.AEAD, error) {
	return aead.New(key)
}
