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

/*
shouldUseTSAsm reports whether the data-path AEAD should come from tsasm/amd64. Pure so a test can cover every combination; the CPU variables cannot be written.

Two disjoint populations reach tsasm, for opposite reasons.

A CPU that can run the fused AVX-512 kernel (AVX512F, AVX512BW and BMI2; see AvailableAVX512) goes there because tsasm's fused kernel is faster than the AVX2 kernel it would otherwise get. Fusing Poly1305 into the cipher rounds is what buys it: on Intel the scalar MAC is 31 to 44 percent of the fused total, so hiding it under the rounds is most of the win. Measured per core against x/crypto's AVX2 at 1280-byte packets, Seal and Open: 1.30x and 1.38x on a Xeon D-2143IT, 1.27x and 1.42x on a Xeon 8375C, 1.29x and 1.51x on a Xeon 8488C, 1.38x and 1.44x on a Ryzen 9800X3D, 1.15x and 1.22x on a Xeon W-3245M. At 8920 bytes the range is 1.17x to 1.55x.

A CPU with SSSE3 and no AVX2 goes there because x/crypto has nothing for it at all: x/crypto gates its remaining amd64 kernel on HasSSSE3 && HasAVX2 && HasBMI2 and otherwise runs generic Go, which is 3.5x to 6.4x slower than assembly.

Everything in between, which is most amd64 hardware, keeps x/crypto's AVX2 kernel.

In a running tunnel at Tailscale's 1280-byte MTU the crypto's share of wireguard-go's CPU drops by about those factors. Skylake-D and Cascade Lake-W run sustained 512-bit code at a lower clock, which on a Xeon D-2143IT costs 2 to 3 percent on the non-crypto work, less than the crypto saving. The gate stays on what the kernel needs rather than on microarchitecture, and TS_WG_ASM=0 turns the whole thing off for anyone who measures otherwise on their own workload.
*/
func shouldUseTSAsm(hasSSSE3, hasAVX2, hasBMI2, hasAVX512 bool) bool {
	return hasAVX512 || (hasSSSE3 && !(hasAVX2 && hasBMI2))
}

// The AVX-512 feature rule lives in one place, AvailableAVX512, next to the kernel whose instructions it describes.
var useTSAsm = shouldUseTSAsm(asmAEAD.Available(), cpu.X86.HasAVX2, cpu.X86.HasBMI2, asmAEAD.AvailableAVX512())

/*
chacha20poly1305New returns a ChaCha20-Poly1305 AEAD. On amd64 CPUs with AVX-512, and on CPUs with SSSE3 but no AVX2, it uses the assembly kernels from tsasm/amd64/chacha20poly1305.

The cookie path (which uses the extended-nonce variant via chacha20poly1305.NewX) is left on the x/crypto path because it is not on the per-packet hot path.

As an escape hatch for hardware regressions or asm bugs, setting the environment variable TS_WG_ASM=0 forces the x/crypto implementation instead.
*/
func chacha20poly1305New(key []byte) (cipher.AEAD, error) {
	if !useTSAsm || os.Getenv("TS_WG_ASM") == "0" {
		return chacha20poly1305.New(key)
	}
	return asmAEAD.New(key)
}
