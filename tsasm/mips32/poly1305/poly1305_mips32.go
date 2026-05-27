// SPDX-License-Identifier: BSD-3-Clause

//go:build mips || mipsle

// Package poly1305 implements Poly1305 with a hand-written scalar
// mips32r2 inner loop modeled on Andy Polyakov's poly1305-mips.pl
// (the 32-bit code path; openssl/Linux upstream).
//
// The state is held in 5 saturated 32-bit limbs of h
// (h = h0 + h1*2^32 + h2*2^64 + h3*2^96 + h4*2^128, h4 carries the
// few bits at and above 2^128), 4 saturated 32-bit limbs of the
// clamped key r, plus precomputed s_i = r_i + (r_i >> 2) for i in
// 1..3 to absorb the 2^130 ≡ 5 reduction inside the inner loop.
//
// The inner loop is the upstream non-MADDU variant: 20 individual
// MULTU partial products, each followed by MFLO + MFHI and a
// manual ADDU + SLTU carry chain. No MADDU-into-accumulator -- my
// earlier 5x26 + MULU/MADDU layout matched the pure-Go mirror in
// algorithm-vs-algorithm tests but gave occasional wrong tags
// (~7%) on real Cavium Octeon II and Ingenic JZ4780 silicon.
// MULTU/MFLO/MFHI without intervening MADDUs sidesteps any
// hazard between successive HI/LO writers entirely.
//
// Builds on both GOARCH=mips (BE) and GOARCH=mipsle (LE). The
// shared Go wrapper drives the right BE-only / LE-only .s file via
// build tags. mipsle is hardware-validated on the Ingenic CI20
// (kernel 3.18); mips BE has no hardware available so it is
// build-only.
package poly1305

import (
	"encoding/binary"
	"unsafe"
)

const (
	KeySize = 32
	TagSize = 16
)

// macState matches the upstream poly1305-mips.pl 32-bit ctx layout:
//
//	offset  0: h0    offset 20: r0    offset 36: s1
//	offset  4: h1    offset 24: r1    offset 40: s2
//	offset  8: h2    offset 28: r2    offset 44: s3
//	offset 12: h3    offset 32: r3
//	offset 16: h4
//
// The asm hard-codes these offsets.
type macState struct {
	h [5]uint32 // saturated 32-bit limbs of the running hash
	r [4]uint32 // saturated 32-bit limbs of the clamped key
	s [3]uint32 // s[i-1] = r[i] + (r[i] >> 2) for i in 1..3
}

// MAC is an incremental Poly1305 message-authentication code computer.
// Single-use; not safe for concurrent use. Zero-value is not usable --
// call Init first.
type MAC struct {
	state  macState
	pad    [4]uint32 // saved key[16:32], added in Sum.
	buffer [TagSize]byte
	offset int
}

// New returns a fresh MAC keyed with key. Prefer (*MAC).Init for hot
// paths; this constructor heap-allocates.
func New(key *[KeySize]byte) *MAC {
	m := new(MAC)
	m.Init(key)
	return m
}

// Init keys an existing (typically stack-allocated) MAC with key.
// Clamps r per RFC 8439 (mask 0x0ffffffc0ffffffc0ffffffc0fffffff).
func (m *MAC) Init(key *[KeySize]byte) {
	*m = MAC{}
	r0 := binary.LittleEndian.Uint32(key[0:4]) & 0x0FFFFFFF
	r1 := binary.LittleEndian.Uint32(key[4:8]) & 0x0FFFFFFC
	r2 := binary.LittleEndian.Uint32(key[8:12]) & 0x0FFFFFFC
	r3 := binary.LittleEndian.Uint32(key[12:16]) & 0x0FFFFFFC
	m.state.r[0] = r0
	m.state.r[1] = r1
	m.state.r[2] = r2
	m.state.r[3] = r3
	m.state.s[0] = r1 + (r1 >> 2)
	m.state.s[1] = r2 + (r2 >> 2)
	m.state.s[2] = r3 + (r3 >> 2)
	m.pad[0] = binary.LittleEndian.Uint32(key[16:20])
	m.pad[1] = binary.LittleEndian.Uint32(key[20:24])
	m.pad[2] = binary.LittleEndian.Uint32(key[24:28])
	m.pad[3] = binary.LittleEndian.Uint32(key[28:32])
}

// poly1305Update processes blocks 16-byte chunks of msg into state.
// padbit is 1 for full blocks (the implicit 1 at bit 128) or 0 for
// the last partial block, which the caller has already padded with
// a 0x01 byte.
//
//go:noescape
func poly1305Update(state *macState, msg unsafe.Pointer, blocks uintptr, padbit uintptr)

// Write feeds bytes into the MAC. Returns len(p), nil.
func (m *MAC) Write(p []byte) (int, error) {
	n := len(p)
	if m.offset > 0 {
		k := copy(m.buffer[m.offset:], p)
		m.offset += k
		if m.offset == TagSize {
			poly1305Update(&m.state, unsafe.Pointer(&m.buffer[0]), 1, 1)
			m.offset = 0
		}
		p = p[k:]
	}
	if blocks := len(p) / TagSize; blocks > 0 {
		poly1305Update(&m.state, unsafe.Pointer(&p[0]), uintptr(blocks), 1)
		p = p[blocks*TagSize:]
	}
	if len(p) > 0 {
		m.offset = copy(m.buffer[:], p)
	}
	return n, nil
}

// Sum flushes any buffered partial block and writes the 16-byte tag
// to out. Sum may be called multiple times; it does not consume the
// state.
func (m *MAC) Sum(out *[TagSize]byte) {
	state := m.state
	if m.offset > 0 {
		var buf [TagSize]byte
		copy(buf[:], m.buffer[:m.offset])
		buf[m.offset] = 1
		poly1305Update(&state, unsafe.Pointer(&buf[0]), 1, 0)
	}
	finalize(out, &state.h, &m.pad)
}

// Sum computes a Poly1305 MAC of m under key, writing the 16-byte tag
// to out.
func Sum(out *[TagSize]byte, m []byte, key *[KeySize]byte) {
	var mac MAC
	mac.Init(key)
	mac.Write(m)
	mac.Sum(out)
}

// finalize fully reduces h mod (2^130 - 5), adds the pad, and emits
// the 16-byte tag in little-endian byte order.
//
// Like the mips64 sibling, the asm leaves h4 holding the running
// limb 4 value at end of inner loop -- upstream's modulo-scheduled
// reduction lives at *block start*, so finalize replays it once
// more before subtracting p. After that h4 is in canonical 0..4
// range and the standard saturated-32 tail (subtract p,
// constant-time select, add pad) takes over.
func finalize(out *[TagSize]byte, h *[5]uint32, pad *[4]uint32) {
	h0, h1, h2, h3, h4 := h[0], h[1], h[2], h[3], h[4]

	// One more modulo-scheduled fold of h4's high bits back via *5.
	high := h4 >> 2
	h4 &= 3
	// residue = high * 5 = high*4 + high. high*4 (= high<<2) fits in
	// 32 bits since h4 < 2^32 implies high < 2^30. So high*5 fits
	// in 33 bits; track with a small carry.
	res4 := high << 2 // < 2^32
	resCarry := high >> 30
	residue, c := bitsAdd32(res4, high, 0)
	resCarry += c

	h0, c = bitsAdd32(h0, residue, 0)
	h1, c = bitsAdd32(h1, resCarry, c)
	h2, c = bitsAdd32(h2, 0, c)
	h3, c = bitsAdd32(h3, 0, c)
	h4 += c

	// Compute t = h - p where p = 2^130 - 5; if no borrow, h >= p.
	const (
		p0 uint32 = 0xFFFFFFFB
		p1 uint32 = 0xFFFFFFFF
		p2 uint32 = 0xFFFFFFFF
		p3 uint32 = 0xFFFFFFFF
		p4 uint32 = 0x00000003
	)
	var b uint32
	t0, b := bitsSub32(h0, p0, 0)
	var t1, t2, t3 uint32
	t1, b = bitsSub32(h1, p1, b)
	t2, b = bitsSub32(h2, p2, b)
	t3, b = bitsSub32(h3, p3, b)
	_, b = bitsSub32(h4, p4, b)

	// Constant-time select: keep h if h < p (b=1), else use t.
	h0 = select32(b, h0, t0)
	h1 = select32(b, h1, t1)
	h2 = select32(b, h2, t2)
	h3 = select32(b, h3, t3)

	// tag = (h + pad) mod 2^128. pad is 4 LE u32 from key[16:32].
	h0, c = bitsAdd32(h0, pad[0], 0)
	h1, c = bitsAdd32(h1, pad[1], c)
	h2, c = bitsAdd32(h2, pad[2], c)
	h3, _ = bitsAdd32(h3, pad[3], c)

	binary.LittleEndian.PutUint32(out[0:], h0)
	binary.LittleEndian.PutUint32(out[4:], h1)
	binary.LittleEndian.PutUint32(out[8:], h2)
	binary.LittleEndian.PutUint32(out[12:], h3)
}

// bitsAdd32 / bitsSub32 / select32 are the 32-bit equivalents of
// math/bits.{Add64,Sub64} and the standard constant-time select
// pattern; inlined here to avoid the broader math/bits dependency
// on this package and to keep the implementation transparent.

func bitsAdd32(x, y, carry uint32) (sum, carryOut uint32) {
	sum = x + y + carry
	carryOut = ((x & y) | ((x | y) & ^sum)) >> 31
	return
}

func bitsSub32(x, y, borrow uint32) (diff, borrowOut uint32) {
	diff = x - y - borrow
	borrowOut = ((^x & y) | (^(x ^ y) & diff)) >> 31
	return
}

func select32(v, x, y uint32) uint32 {
	mask := ^(v - 1)
	return (x & mask) | (y & ^mask)
}
