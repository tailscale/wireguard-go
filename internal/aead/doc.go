// SPDX-License-Identifier: MIT

// Package aead selects the ChaCha20-Poly1305 implementation shared by Device
// and peer. It uses the repository assembly on supported ARM32 and pre-AVX2
// amd64 CPUs. TS_WG_ASM=0 selects x/crypto instead.
package aead
