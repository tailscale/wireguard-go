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

// shouldUseTSAsm is kept pure so every feature combination can be tested
// without mutating the process-wide CPU feature variables.
func shouldUseTSAsm(hasSSSE3, hasAVX2, hasBMI2 bool) bool {
	return hasSSSE3 && !(hasAVX2 && hasBMI2)
}

// x/crypto's amd64 kernel requires SSSE3, AVX2, and BMI2. Use the restored SSE
// kernel only when x/crypto cannot use its newer kernel.
var useTSAsm = shouldUseTSAsm(cpu.X86.HasSSSE3, cpu.X86.HasAVX2, cpu.X86.HasBMI2)

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
