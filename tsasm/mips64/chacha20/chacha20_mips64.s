// SPDX-License-Identifier: BSD-3-Clause

//go:build mips64

#include "textflag.h"

// chacha20BlocksASM(out, in unsafe.Pointer, state *[16]uint32, blocks uintptr)
//
// Hand-written scalar mips64r2 ChaCha20. All 16 u32 state words live
// in registers (R2..R17) for the duration of each block. The four
// rotate counts (16, 12, 8, 7) are folded to right-rotates (16, 20,
// 24, 25) using the MIPS r2 ROTR instruction. Each output word is
// byte-swapped on store with WSBH+ROTR16 so the keystream comes out
// in little-endian order regardless of host endianness; the same
// dance on the load side lets us XOR plaintext into the state
// register before the swap-and-store.
//
// Register usage:
//   R2..R17  = x[0..15] working state.
//   R18      = out pointer.
//   R19      = in pointer.
//   R20      = state pointer.
//   R21      = remaining-blocks counter.
//   R22      = scratch.
//   R24      = round-pair counter (10 -> 0).
TEXT ·chacha20BlocksASM(SB), NOSPLIT|NOFRAME, $0-32
	MOVV	out+0(FP), R18
	MOVV	in+8(FP), R19
	MOVV	state+16(FP), R20
	MOVV	blocks+24(FP), R21

	BEQ	R21, done

block_loop:
	// Load 16-word state into x[0..15] (R2..R17).
	MOVW	0(R20), R2
	MOVW	4(R20), R3
	MOVW	8(R20), R4
	MOVW	12(R20), R5
	MOVW	16(R20), R6
	MOVW	20(R20), R7
	MOVW	24(R20), R8
	MOVW	28(R20), R9
	MOVW	32(R20), R10
	MOVW	36(R20), R11
	MOVW	40(R20), R12
	MOVW	44(R20), R13
	MOVW	48(R20), R14
	MOVW	52(R20), R15
	MOVW	56(R20), R16
	MOVW	60(R20), R17

	MOVV	$10, R24

round_loop:
	// Column round.
	// QR(0, 4, 8, 12)  -> R2, R6, R10, R14
	ADDU	R6, R2, R2
	XOR	R2, R14, R14
	ROTR	$16, R14, R14
	ADDU	R14, R10, R10
	XOR	R10, R6, R6
	ROTR	$20, R6, R6
	ADDU	R6, R2, R2
	XOR	R2, R14, R14
	ROTR	$24, R14, R14
	ADDU	R14, R10, R10
	XOR	R10, R6, R6
	ROTR	$25, R6, R6

	// QR(1, 5, 9, 13)  -> R3, R7, R11, R15
	ADDU	R7, R3, R3
	XOR	R3, R15, R15
	ROTR	$16, R15, R15
	ADDU	R15, R11, R11
	XOR	R11, R7, R7
	ROTR	$20, R7, R7
	ADDU	R7, R3, R3
	XOR	R3, R15, R15
	ROTR	$24, R15, R15
	ADDU	R15, R11, R11
	XOR	R11, R7, R7
	ROTR	$25, R7, R7

	// QR(2, 6, 10, 14) -> R4, R8, R12, R16
	ADDU	R8, R4, R4
	XOR	R4, R16, R16
	ROTR	$16, R16, R16
	ADDU	R16, R12, R12
	XOR	R12, R8, R8
	ROTR	$20, R8, R8
	ADDU	R8, R4, R4
	XOR	R4, R16, R16
	ROTR	$24, R16, R16
	ADDU	R16, R12, R12
	XOR	R12, R8, R8
	ROTR	$25, R8, R8

	// QR(3, 7, 11, 15) -> R5, R9, R13, R17
	ADDU	R9, R5, R5
	XOR	R5, R17, R17
	ROTR	$16, R17, R17
	ADDU	R17, R13, R13
	XOR	R13, R9, R9
	ROTR	$20, R9, R9
	ADDU	R9, R5, R5
	XOR	R5, R17, R17
	ROTR	$24, R17, R17
	ADDU	R17, R13, R13
	XOR	R13, R9, R9
	ROTR	$25, R9, R9

	// Diagonal round.
	// QR(0, 5, 10, 15) -> R2, R7, R12, R17
	ADDU	R7, R2, R2
	XOR	R2, R17, R17
	ROTR	$16, R17, R17
	ADDU	R17, R12, R12
	XOR	R12, R7, R7
	ROTR	$20, R7, R7
	ADDU	R7, R2, R2
	XOR	R2, R17, R17
	ROTR	$24, R17, R17
	ADDU	R17, R12, R12
	XOR	R12, R7, R7
	ROTR	$25, R7, R7

	// QR(1, 6, 11, 12) -> R3, R8, R13, R14
	ADDU	R8, R3, R3
	XOR	R3, R14, R14
	ROTR	$16, R14, R14
	ADDU	R14, R13, R13
	XOR	R13, R8, R8
	ROTR	$20, R8, R8
	ADDU	R8, R3, R3
	XOR	R3, R14, R14
	ROTR	$24, R14, R14
	ADDU	R14, R13, R13
	XOR	R13, R8, R8
	ROTR	$25, R8, R8

	// QR(2, 7, 8, 13)  -> R4, R9, R10, R15
	ADDU	R9, R4, R4
	XOR	R4, R15, R15
	ROTR	$16, R15, R15
	ADDU	R15, R10, R10
	XOR	R10, R9, R9
	ROTR	$20, R9, R9
	ADDU	R9, R4, R4
	XOR	R4, R15, R15
	ROTR	$24, R15, R15
	ADDU	R15, R10, R10
	XOR	R10, R9, R9
	ROTR	$25, R9, R9

	// QR(3, 4, 9, 14)  -> R5, R6, R11, R16
	ADDU	R6, R5, R5
	XOR	R5, R16, R16
	ROTR	$16, R16, R16
	ADDU	R16, R11, R11
	XOR	R11, R6, R6
	ROTR	$20, R6, R6
	ADDU	R6, R5, R5
	XOR	R5, R16, R16
	ROTR	$24, R16, R16
	ADDU	R16, R11, R11
	XOR	R11, R6, R6
	ROTR	$25, R6, R6

	SUBVU	$1, R24
	BNE	R24, round_loop

	// Add the original state back into x[0..15]. We just reload
	// state[i] from memory through R22; the in-memory copy is
	// untouched until the counter bump at the end of this block.
	MOVW	0(R20), R22
	ADDU	R22, R2, R2
	MOVW	4(R20), R22
	ADDU	R22, R3, R3
	MOVW	8(R20), R22
	ADDU	R22, R4, R4
	MOVW	12(R20), R22
	ADDU	R22, R5, R5
	MOVW	16(R20), R22
	ADDU	R22, R6, R6
	MOVW	20(R20), R22
	ADDU	R22, R7, R7
	MOVW	24(R20), R22
	ADDU	R22, R8, R8
	MOVW	28(R20), R22
	ADDU	R22, R9, R9
	MOVW	32(R20), R22
	ADDU	R22, R10, R10
	MOVW	36(R20), R22
	ADDU	R22, R11, R11
	MOVW	40(R20), R22
	ADDU	R22, R12, R12
	MOVW	44(R20), R22
	ADDU	R22, R13, R13
	MOVW	48(R20), R22
	ADDU	R22, R14, R14
	MOVW	52(R20), R22
	ADDU	R22, R15, R15
	MOVW	56(R20), R22
	ADDU	R22, R16, R16
	MOVW	60(R20), R22
	ADDU	R22, R17, R17

	// XOR with input and store.
	// in_le = byteswap(LW(in+4i))
	// out_le = x[i] XOR in_le
	// SW(out+4i, byteswap(out_le))
	//
	// On big-endian MIPS, LW reads bytes [b0,b1,b2,b3] as the BE
	// integer 0xb0b1b2b3; we want 0xb3b2b1b0 (the LE
	// interpretation). WSBH+ROTR16 effects a full 32-bit byte swap.
	// On little-endian MIPS the byte swaps are wasted work but
	// correct -- the asm is shared between both targets.
	MOVW	0(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R2, R2
	WSBH	R2, R2
	ROTR	$16, R2, R2
	MOVW	R2, 0(R18)

	MOVW	4(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R3, R3
	WSBH	R3, R3
	ROTR	$16, R3, R3
	MOVW	R3, 4(R18)

	MOVW	8(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R4, R4
	WSBH	R4, R4
	ROTR	$16, R4, R4
	MOVW	R4, 8(R18)

	MOVW	12(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R5, R5
	WSBH	R5, R5
	ROTR	$16, R5, R5
	MOVW	R5, 12(R18)

	MOVW	16(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R6, R6
	WSBH	R6, R6
	ROTR	$16, R6, R6
	MOVW	R6, 16(R18)

	MOVW	20(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R7, R7
	WSBH	R7, R7
	ROTR	$16, R7, R7
	MOVW	R7, 20(R18)

	MOVW	24(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R8, R8
	WSBH	R8, R8
	ROTR	$16, R8, R8
	MOVW	R8, 24(R18)

	MOVW	28(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R9, R9
	WSBH	R9, R9
	ROTR	$16, R9, R9
	MOVW	R9, 28(R18)

	MOVW	32(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R10, R10
	WSBH	R10, R10
	ROTR	$16, R10, R10
	MOVW	R10, 32(R18)

	MOVW	36(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R11, R11
	WSBH	R11, R11
	ROTR	$16, R11, R11
	MOVW	R11, 36(R18)

	MOVW	40(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R12, R12
	WSBH	R12, R12
	ROTR	$16, R12, R12
	MOVW	R12, 40(R18)

	MOVW	44(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R13, R13
	WSBH	R13, R13
	ROTR	$16, R13, R13
	MOVW	R13, 44(R18)

	MOVW	48(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R14, R14
	WSBH	R14, R14
	ROTR	$16, R14, R14
	MOVW	R14, 48(R18)

	MOVW	52(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R15, R15
	WSBH	R15, R15
	ROTR	$16, R15, R15
	MOVW	R15, 52(R18)

	MOVW	56(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R16, R16
	WSBH	R16, R16
	ROTR	$16, R16, R16
	MOVW	R16, 56(R18)

	MOVW	60(R19), R22
	WSBH	R22, R22
	ROTR	$16, R22, R22
	XOR	R22, R17, R17
	WSBH	R17, R17
	ROTR	$16, R17, R17
	MOVW	R17, 60(R18)

	// Bump the in-memory counter by one.
	MOVW	48(R20), R22
	ADDU	$1, R22, R22
	MOVW	R22, 48(R20)

	// Advance pointers; loop while blocks remain.
	ADDV	$64, R18
	ADDV	$64, R19
	SUBVU	$1, R21
	BNE	R21, block_loop

done:
	RET
