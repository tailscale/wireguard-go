//go:build amd64 && gc && !purego

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"

	asmAEAD "github.com/tailscale/wireguard-go/tsasm/amd64/chacha20poly1305"
)

// useTSAsm reports whether the data-path AEAD should come from
// tsasm/amd64 rather than from x/crypto.
//
// x/crypto gates its only remaining amd64 kernel on
// HasSSSE3 && HasAVX2 && HasBMI2 and otherwise runs generic Go, so a CPU
// with SSSE3 but without AVX2 gets no assembly at all. Those CPUs, and
// only those, are routed here. Anything with AVX2 keeps x/crypto's
// maintained AVX2 kernel, so this changes nothing for the majority of
// amd64 machines.
var useTSAsm = asmAEAD.Available() && !(cpu.X86.HasAVX2 && cpu.X86.HasBMI2)

// chacha20poly1305New returns a ChaCha20-Poly1305 AEAD. On amd64 CPUs
// with SSSE3 but no AVX2 it uses the assembly kernel from
// tsasm/amd64/chacha20poly1305.
//
// The cookie path (which uses the extended-nonce variant via
// chacha20poly1305.NewX) is left on the x/crypto path because it is not
// on the per-packet hot path.
//
// As an escape hatch for hardware regressions or asm bugs, setting the
// environment variable TS_WG_ASM=0 forces the x/crypto implementation
// instead.
func chacha20poly1305New(key []byte) (cipher.AEAD, error) {
	if !useTSAsm || os.Getenv("TS_WG_ASM") == "0" {
		return chacha20poly1305.New(key)
	}
	return asmAEAD.New(key)
}
