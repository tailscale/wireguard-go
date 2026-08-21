// SPDX-License-Identifier: BSD-3-Clause

//go:build mipsle

#include "textflag.h"

// poly1305Update(state *macState, msg unsafe.Pointer, blocks uintptr, padbit uintptr)
//
// Hand-translated from openssl/Linux poly1305-mips.pl (Andy Polyakov,
// dual-licensed BSD-3-Clause / OpenSSL); the 32-bit non-MADDU code
// path. 5x32 saturated h, 4x32 saturated r, plus precomputed
// s_i = r_i + (r_i >> 2) for i in 1..3 to fold the 2^130 ≡ 5
// reduction into the multiplication.
//
// 20 partial products per 16-byte block. Each is MULTU + MFLO +
// MFHI + manual ADDU/SLTU(SGTU) carry chain -- no MADDU into the
// HI/LO accumulator. The earlier 5x26 attempt that DID use MADDU
// gave occasional wrong tags (~7%) on real Cavium Octeon II and
// Ingenic JZ4780 silicon; this layout avoids the multi-MADDU
// chain entirely.
//
// LE variant: input is loaded with plain MOVW (LWU equivalent on
// 32-bit MIPS); on a little-endian host that already gives an LE
// u32. The BE variant in poly1305_mips_be.s adds a WSBH+ROTR16
// pair after each input load.
//
// Register usage (Plan 9 names, MIPS o32 ABI labels in parens):
//
//   R16 (s0)  ctx ptr        R7  (a3)  r0
//   R17 (s1)  msg ptr        R8  (t0)  r1
//   R18 (s2)  blocks count   R9  (t1)  r2
//   R19 (s3)  padbit         R10 (t2)  r3
//                            R11 (t3)  s1
//   R2  (v0)  h0             R12 (t4)  s2
//   R3  (v1)  h1             R13 (t5)  s3
//   R4  (a0)  h2
//   R5  (a1)  h3             R14, R15, R20, R21  d0..d3
//   R6  (a2)  h4             R24..R19  scratch (at, t0, t1, a3)
//
// R22 (REGCTXT) and R23 (REGTMP) are left alone.
TEXT ·poly1305Update(SB), NOSPLIT, $0-16
	MOVW	state+0(FP), R16
	MOVW	msg+4(FP), R17
	MOVW	blocks+8(FP), R18
	MOVW	padbit+12(FP), R19

	BEQ	R18, done

	// Load h[0..4] and r[0..3] and s[1..3] from state.
	MOVW	0(R16), R2     // h0
	MOVW	4(R16), R3     // h1
	MOVW	8(R16), R4     // h2
	MOVW	12(R16), R5    // h3
	MOVW	16(R16), R6    // h4
	MOVW	20(R16), R7    // r0
	MOVW	24(R16), R8    // r1
	MOVW	28(R16), R9    // r2
	MOVW	32(R16), R10   // r3
	MOVW	36(R16), R11   // s1
	MOVW	40(R16), R12   // s2
	MOVW	44(R16), R13   // s3

block_loop:
	// padbit lives in R19 only briefly each block (ADDU R19, R6
	// below); we then reuse R19 as the `a3` scratch slot to fit
	// inside the no-R26/R27 register budget. Reload from the args
	// frame at the top of every block.
	MOVW	padbit+12(FP), R19

	// Read 16 bytes of input as 4 LE u32 words. On mipsle, MOVW
	// gives the LE value directly.
	MOVW	0(R17), R14    // d0
	MOVW	4(R17), R15    // d1
	MOVW	8(R17), R20    // d2
	MOVW	12(R17), R21   // d3

	// Modulo-scheduled fold of h4's high bits back into h0 via *5
	// before the input add.
	SRL	$2, R6, R25    // t0 = h4 >> 2
	AND	$3, R6, R6     // h4 &= 3
	SLL	$2, R25, R24   // at = t0 * 4

	// d0 = (in0 + h0) + (h4>>2)*5 (residue).
	ADDU	R2, R14        // d0 += h0   (R14 = R2 + R14)
	ADDU	R24, R25       // t0 += at  → t0 = (h4>>2)*5
	SGTU	R2, R14, R2    // h0 = carry from d0 += h0_old (= h0_old > d0)
	ADDU	R25, R14       // d0 += residue
	SGTU	R25, R14, R24  // at = carry from d0 += residue

	// d1 = in1 + h1 + carry-chain.
	ADDU	R3, R15        // d1 += h1
	ADDU	R24, R2        // h0 += at (combine carries)
	SGTU	R3, R15, R3    // h1 = carry from d1 += h1
	ADDU	R2, R15        // d1 += h0 (combined carry)
	SGTU	R2, R15, R2    // h0 = carry from d1 += h0

	// d2 = in2 + h2 + carry.
	ADDU	R4, R20        // d2 += h2
	ADDU	R2, R3         // h1 += h0 (combine)
	SGTU	R4, R20, R4    // h2 = carry from d2 += h2
	ADDU	R3, R20        // d2 += h1
	SGTU	R3, R20, R3    // h1 = carry from d2 += h1

	// d3 = in3 + h3 + carry.
	ADDU	R5, R21        // d3 += h3
	ADDU	R3, R4         // h2 += h1
	SGTU	R5, R21, R5    // h3 = carry from d3 += h3
	ADDU	R4, R21        // d3 += h2

	// First multiply: d0 * r0.
	MULU	R7, R14
	SGTU	R4, R21, R4    // h2 = carry from d3 += h2 (final)
	ADDU	R4, R5         // h3 += h2 (final carry into h3)
	MOVW	LO, R2         // h0 = lo(d0*r0)
	MOVW	HI, R3         // h1 = hi(d0*r0)

	// Second multiply: d1 * s3.
	MULU	R13, R15
	ADDU	R19, R6        // h4 += padbit
	ADDU	R5, R6         // h4 += h3 (final carry)
	MOVW	LO, R24        // at = lo(d1*s3)
	MOVW	HI, R25        // t0 = hi(d1*s3)

	// Third multiply: d2 * s2.
	MULU	R12, R20
	MOVW	LO, R19        // a3 = lo(d2*s2)
	MOVW	HI, R22        // t1 = hi(d2*s2)
	ADDU	R24, R2        // h0 += at = lo(d1*s3)
	ADDU	R25, R3        // h1 += t0 = hi(d1*s3)

	// Fourth multiply: d3 * s1.
	MULU	R11, R21
	SGTU	R24, R2, R24   // at = carry from h0 += lo(d1*s3)
	ADDU	R24, R3        // h1 += that carry
	MOVW	LO, R24        // at = lo(d3*s1)
	MOVW	HI, R25        // t0 = hi(d3*s1)
	ADDU	R19, R2        // h0 += a3 = lo(d2*s2)
	ADDU	R22, R3        // h1 += t1 = hi(d2*s2)

	// Fifth multiply: d0 * r1.
	MULU	R8, R14
	SGTU	R19, R2, R19   // a3 = carry from h0 += lo(d2*s2)
	ADDU	R19, R3        // h1 += that carry
	MOVW	LO, R19        // a3 = lo(d0*r1)
	MOVW	HI, R4         // h2 = hi(d0*r1)
	ADDU	R24, R2        // h0 += at = lo(d3*s1)
	ADDU	R25, R3        // h1 += t0 = hi(d3*s1)

	// Sixth multiply: d1 * r0.
	MULU	R7, R15
	SGTU	R24, R2, R24   // at = carry from h0 += lo(d3*s1)
	ADDU	R24, R3        // h1 += that carry
	MOVW	LO, R24        // at = lo(d1*r0)
	MOVW	HI, R25        // t0 = hi(d1*r0)
	ADDU	R19, R3        // h1 += a3 = lo(d0*r1)
	SGTU	R19, R3, R19   // a3 = carry from h1 += lo(d0*r1)

	// Seventh multiply: d2 * s3.
	MULU	R13, R20
	ADDU	R19, R4        // h2 += that carry
	MOVW	LO, R19        // a3 = lo(d2*s3)
	MOVW	HI, R22        // t1 = hi(d2*s3)
	ADDU	R24, R3        // h1 += at = lo(d1*r0)
	ADDU	R25, R4        // h2 += t0 = hi(d1*r0)

	// Eighth multiply: d3 * s2.
	MULU	R12, R21
	SGTU	R24, R3, R24   // at = carry from h1 += lo(d1*r0)
	ADDU	R24, R4        // h2 += that carry
	MOVW	LO, R24        // at = lo(d3*s2)
	MOVW	HI, R25        // t0 = hi(d3*s2)
	ADDU	R19, R3        // h1 += a3 = lo(d2*s3)
	ADDU	R22, R4        // h2 += t1 = hi(d2*s3)

	// Ninth multiply: h4 * s1. Bounded: h4 ≤ 5, s1 < 2^30, so
	// product fits in LO and we ignore HI.
	MULU	R11, R6
	SGTU	R19, R3, R19   // a3 = carry from h1 += lo(d2*s3)
	ADDU	R19, R4        // h2 += that carry
	MOVW	LO, R19        // a3 = lo(h4*s1)
	ADDU	R24, R3        // h1 += at = lo(d3*s2)
	ADDU	R25, R4        // h2 += t0 = hi(d3*s2)

	// Tenth multiply: d0 * r2.
	MULU	R9, R14
	SGTU	R24, R3, R24   // at = carry from h1 += lo(d3*s2)
	ADDU	R24, R4        // h2 += that carry
	MOVW	LO, R24        // at = lo(d0*r2)
	MOVW	HI, R5         // h3 = hi(d0*r2)
	ADDU	R19, R3        // h1 += a3 = lo(h4*s1)
	SGTU	R19, R3, R19   // a3 = carry from h1 += lo(h4*s1)
	ADDU	R19, R4        // h2 += that carry

	// Eleventh multiply: d1 * r1.
	MULU	R8, R15
	MOVW	LO, R19        // a3 = lo(d1*r1)
	MOVW	HI, R22        // t1 = hi(d1*r1)
	ADDU	R24, R4        // h2 += at = lo(d0*r2)
	SGTU	R24, R4, R24   // at = carry from h2 += lo(d0*r2)
	ADDU	R24, R5        // h3 += that carry

	// Twelfth multiply: d2 * r0.
	MULU	R7, R20
	MOVW	LO, R24        // at = lo(d2*r0)
	MOVW	HI, R25        // t0 = hi(d2*r0)
	ADDU	R19, R4        // h2 += a3 = lo(d1*r1)
	ADDU	R22, R5        // h3 += t1 = hi(d1*r1)

	// Thirteenth multiply: d3 * s3.
	MULU	R13, R21
	SGTU	R19, R4, R19   // a3 = carry from h2 += lo(d1*r1)
	ADDU	R19, R5        // h3 += that carry
	MOVW	LO, R19        // a3 = lo(d3*s3)
	MOVW	HI, R22        // t1 = hi(d3*s3)
	ADDU	R24, R4        // h2 += at = lo(d2*r0)
	ADDU	R25, R5        // h3 += t0 = hi(d2*r0)

	// Fourteenth multiply: h4 * s2. h4 ≤ 5, s2 < 2^30 → fits LO.
	MULU	R12, R6
	SGTU	R24, R4, R24   // at = carry from h2 += lo(d2*r0)
	ADDU	R24, R5        // h3 += that carry
	MOVW	LO, R24        // at = lo(h4*s2)
	ADDU	R19, R4        // h2 += a3 = lo(d3*s3)
	ADDU	R22, R5        // h3 += t1 = hi(d3*s3)

	// Fifteenth multiply: d0 * r3.
	MULU	R10, R14
	SGTU	R19, R4, R19   // a3 = carry from h2 += lo(d3*s3)
	ADDU	R19, R5        // h3 += that carry
	MOVW	LO, R19        // a3 = lo(d0*r3)
	MOVW	HI, R22        // t1 = hi(d0*r3)
	ADDU	R24, R4        // h2 += at = lo(h4*s2)
	SGTU	R24, R4, R24   // at = carry from h2 += lo(h4*s2)
	ADDU	R24, R5        // h3 += that carry

	// Sixteenth multiply: d1 * r2.
	MULU	R9, R15
	MOVW	LO, R24        // at = lo(d1*r2)
	MOVW	HI, R25        // t0 = hi(d1*r2)
	ADDU	R19, R5        // h3 += a3 = lo(d0*r3)
	SGTU	R19, R5, R19   // a3 = carry from h3 += lo(d0*r3)
	ADDU	R19, R22       // t1 += that carry

	// Seventeenth multiply: d3 * r0.
	MULU	R7, R21
	MOVW	LO, R19        // a3 = lo(d3*r0)
	MOVW	HI, R21        // d3 = hi(d3*r0) -- d3 dead, reused
	ADDU	R24, R5        // h3 += at = lo(d1*r2)
	ADDU	R25, R22       // t1 += t0 = hi(d1*r2)

	// Eighteenth multiply: d2 * r1.
	MULU	R8, R20
	SGTU	R24, R5, R24   // at = carry from h3 += lo(d1*r2)
	ADDU	R24, R22       // t1 += that carry
	MOVW	LO, R24        // at = lo(d2*r1)
	MOVW	HI, R25        // t0 = hi(d2*r1)
	ADDU	R19, R5        // h3 += a3 = lo(d3*r0)
	ADDU	R21, R22       // t1 += hi(d3*r0)

	// Nineteenth multiply: h4 * s3. h4 ≤ 5, s3 < 2^30 → fits LO.
	MULU	R13, R6
	SGTU	R19, R5, R19   // a3 = carry from h3 += lo(d3*r0)
	ADDU	R19, R22       // t1 += that carry
	MOVW	LO, R19        // a3 = lo(h4*s3)
	ADDU	R24, R5        // h3 += at = lo(d2*r1)
	ADDU	R25, R22       // t1 += t0 = hi(d2*r1)

	// Twentieth multiply: h4 * r0. After this h4 will be replaced
	// with lo(h4*r0) plus the accumulated t1 carry chain.
	MULU	R7, R6
	SGTU	R24, R5, R24   // at = carry from h3 += lo(d2*r1)
	ADDU	R24, R22       // t1 += that carry
	MOVW	LO, R6         // h4 = lo(h4*r0)
	ADDU	R19, R5        // h3 += a3 = lo(h4*s3)
	SGTU	R19, R5, R19   // a3 = carry from h3 += lo(h4*s3)
	ADDU	R19, R22       // t1 += that carry
	ADDU	R22, R6        // h4 += t1

	// Loop control. Upstream re-arms padbit=1 here; for our wrapper
	// padbit only ever changes when blocks=1 (the final partial), so
	// we don't need the re-arm.
	ADDU	$16, R17
	SUBU	$1, R18
	BNE	R18, block_loop

	// Store h back into state.
	MOVW	R2, 0(R16)
	MOVW	R3, 4(R16)
	MOVW	R4, 8(R16)
	MOVW	R5, 12(R16)
	MOVW	R6, 16(R16)

done:
	RET
