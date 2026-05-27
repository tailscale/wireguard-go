// SPDX-License-Identifier: BSD-3-Clause

//go:build mips64

#include "textflag.h"

// poly1305Update(state *macState, msg unsafe.Pointer, blocks uintptr, padbit uintptr)
//
// Hand-translated from openssl/Linux poly1305-mips.pl (Andy Polyakov,
// dual-licensed BSD-3-Clause / OpenSSL); the 64-bit code path. 3x64
// saturated h, 2x64 saturated r, plus precomputed s1 = r1 + (r1>>2)
// folded into the multiply to absorb the 2^130 ≡ 5 reduction.
//
// Per 16-byte block:
//
//   * Modulo-scheduled fold of h2's high bits back into h0 via *5
//     (h2 keeps its low 2 bits, the rest contributes (h2>>2)*5 to
//     h0 ahead of the input add).
//   * d = h + input + residue, with carry chained into d2 (= h2 +
//     padbit). For full blocks padbit=1 (the implicit bit at 2^128);
//     the final partial block is padded by the caller and passes
//     padbit=0.
//   * h = d * r mod (2^130-5) via 6 DMULTU partial products
//     (d0*r0, d1*s1, d0*r1, d1*r0, d2*s1, d2*r0). Each multiply is
//     followed only by MFLO/MFHI -- no MADD-into-accumulator that
//     would chain through the multiplier's HI/LO state in a way the
//     spec's hardware-interlock doesn't cleanly cover.
//
// Register usage (Plan 9 names):
//
//   R4  state ptr     R8   h0          R14  d0 / in0
//   R5  msg ptr       R9   h1          R15  d1 / in1
//   R6  blocks count  R10  h2          R16  d2
//   R7  padbit        R11  r0          R17  tmp0
//                     R12  r1          R18  tmp1
//                     R13  s1          R19  tmp2
//                                      R20  tmp3
//
// R22 (REGCTXT) is left alone -- this asm runs from a //go:noescape
// direct call so REGCTXT is unset on entry, but staying off it keeps
// the function safe to call through a function-value too.
TEXT ·poly1305Update(SB), NOSPLIT|NOFRAME, $0-32
	MOVV	state+0(FP), R4
	MOVV	msg+8(FP), R5
	MOVV	blocks+16(FP), R6
	MOVV	padbit+24(FP), R7

	BEQ	R6, done

	// Load h, r, s1 from the macState struct.
	MOVV	0(R4), R8
	MOVV	8(R4), R9
	MOVV	16(R4), R10
	MOVV	24(R4), R11
	MOVV	32(R4), R12
	MOVV	40(R4), R13

block_loop:
	// Read 16 bytes of input as 2 little-endian u64s. On big-endian
	// MIPS, MOVV reads BE byte order; DSBH+DSHD swap to LE.
	MOVV	0(R5), R14
	DSBH	R14, R14
	DSHD	R14, R14
	MOVV	8(R5), R15
	DSBH	R15, R15
	DSHD	R15, R15

	// Modulo-scheduled reduction: fold h2's bits >=2 back into the
	// low limb via *5 ahead of the input add. After this h2 has at
	// most 2 bits left.
	SRLV	$2, R10, R18      // R18 = h2 >> 2
	AND	$3, R10, R10      // h2 &= 3
	SLLV	$2, R18, R17      // R17 = (h2 >> 2) << 2

	// d0 = h0 + in0 + 5*(h2>>2). The 5*(h2>>2) factor is built as
	// (h2>>2)*4 + (h2>>2) below.
	ADDVU	R8, R14, R14      // d0 = h0 + in0
	ADDVU	R17, R18          // R18 = (h2>>2)*5
	SGTU	R8, R14, R17      // R17 = carry from d0 = h0 + in0
	ADDVU	R18, R14          // d0 += residue
	SGTU	R18, R14, R18     // R18 = carry from d0 += residue

	// d1 = h1 + in1 + (carry chain).
	ADDVU	R9, R15, R15      // d1 = h1 + in1
	ADDVU	R18, R17          // R17 += R18 (combine carries)
	SGTU	R9, R15, R18      // R18 = carry from d1 = h1 + in1
	ADDVU	R17, R15          // d1 += R17 (carries from d0)

	// First multiply: d0 * r0. h0 := lo, h1 := hi.
	MULVU	R11, R14
	ADDVU	R10, R7, R16      // d2 = h2 + padbit (uses R7=padbit)
	SGTU	R17, R15, R17     // R17 = carry from d1 += R17
	MOVV	LO, R8
	MOVV	HI, R9

	// Second multiply: d1 * s1. The s1 = r1 + (r1>>2) form makes
	// (d1 * s1) * 4 = d1 * 5 * r1, i.e. multiplying by s1 absorbs
	// the *5 reduction at 2^130 (the missing /4 falls out of the
	// limb shift).
	MULVU	R13, R15
	ADDVU	R18, R16          // d2 += carry (from d1=h1+in1)
	ADDVU	R17, R16          // d2 += carry (from d1 += R17)
	MOVV	LO, R17
	MOVV	HI, R18

	// Third multiply: d0 * r1. tmp2 := lo, h2 := hi.
	MULVU	R12, R14
	MOVV	LO, R19
	MOVV	HI, R10
	ADDVU	R17, R8           // h0 += lo(d1*s1)
	ADDVU	R18, R9           // h1 += hi(d1*s1)
	SGTU	R17, R8, R17      // carry from h0 += lo(d1*s1)

	// Fourth multiply: d1 * r0.
	MULVU	R11, R15
	ADDVU	R17, R9           // h1 += carry
	ADDVU	R19, R9           // h1 += lo(d0*r1)
	MOVV	LO, R17
	MOVV	HI, R18

	// Fifth multiply: d2 * s1. Only LO is used; HI is bounded
	// small and folded by the carry propagation below.
	MULVU	R13, R16
	SGTU	R19, R9, R19      // carry from h1 += lo(d0*r1)
	ADDVU	R19, R10          // h2 += that carry
	MOVV	LO, R19

	// Sixth multiply: d2 * r0. tmp3 := lo (HI is out of bounds
	// for the saturated layout).
	MULVU	R11, R16
	ADDVU	R17, R9           // h1 += lo(d1*r0)
	ADDVU	R18, R10          // h2 += hi(d1*r0)
	MOVV	LO, R20
	SGTU	R17, R9, R17      // carry from h1 += lo(d1*r0)
	ADDVU	R17, R10          // h2 += that carry

	// Final two cross-product chunks fold in.
	ADDVU	R19, R9           // h1 += lo(d2*s1)
	SGTU	R19, R9, R19      // carry from h1 += lo(d2*s1)
	ADDVU	R19, R10          // h2 += that carry
	ADDVU	R20, R10          // h2 += lo(d2*r0)

	// Loop.
	ADDV	$16, R5
	SUBVU	$1, R6
	BNE	R6, block_loop

	// Store h back into state.
	MOVV	R8, 0(R4)
	MOVV	R9, 8(R4)
	MOVV	R10, 16(R4)

done:
	RET
