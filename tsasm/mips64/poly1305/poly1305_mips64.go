// SPDX-License-Identifier: BSD-3-Clause

//go:build mips64

// Package poly1305 implements Poly1305 with a hand-written scalar
// mips64r2 inner loop modeled on Andy Polyakov's poly1305-mips.pl
// (the 64-bit code path; openssl/Linux upstream).
//
// The state is held in 3 saturated 64-bit limbs
// (h = h0 + h1*2^64 + h2*2^128, h2 ≤ ~5 with carry slack), the key
// in 2 saturated 64-bit limbs (r = r0 + r1*2^64, with the standard
// rMask clamp clearing the top 4 bits of each plus the bottom 2
// of r1), and a precomputed s1 = r1 + (r1 >> 2). The s1 form lets
// the inner loop fold the 2^130 ≡ 5 reduction into the multiplication
// itself by replacing a multiply-by-r1 with multiply-by-s1 wherever
// the product crosses 2^130: s1 * 4 = 5 * r1, and the missing factor
// of 4 falls out of the limb alignment.
//
// Inner loop is 6 DMULTU partial products per 16-byte block (h*r is
// 3x2 = 6 products), each followed by MFLO/MFHI + manual carry chain
// using DADDU + SLTU. No DMADD: every accumulator step is explicit so
// the only HI/LO traffic is the multiply itself and the immediately
// following MFLO/MFHI -- which the MIPS r2 hardware-interlock
// guarantees handles. (My earlier 5x26 + MULU/MADD attempts got
// occasional wrong tags on real Cavium Octeon II and Ingenic JZ4780
// silicon; the saturated layout sidesteps the MADD-into-accumulator
// hazards entirely.)
//
// Only builds on big-endian GOARCH=mips64. The input load uses a
// MIPS r2 DSBH+DSHD pair to byte-swap doublewords from BE memory
// to LE numeric order; mips64le would need a separate asm without
// that swap.
package poly1305

import (
	"encoding/binary"
	"unsafe"
)

const (
	KeySize = 32
	TagSize = 16
)

// macState is the layout the asm reads. r and s1 are constant after
// Init; h is the running accumulator. Field offsets are hard-coded
// in poly1305_mips64.s.
type macState struct {
	h  [3]uint64 // saturated 64-bit limbs of the running hash; offsets 0, 8, 16
	r  [2]uint64 // saturated 64-bit limbs of the clamped key;    offsets 24, 32
	s1 uint64    // r[1] + (r[1] >> 2); offset 40
}

// MAC is an incremental Poly1305 message-authentication code computer.
// Single-use; not safe for concurrent use. Zero-value is not usable --
// call Init first.
type MAC struct {
	state  macState
	pad    [2]uint64 // saved key[16:32], added in Sum.
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
func (m *MAC) Init(key *[KeySize]byte) {
	*m = MAC{}
	r0 := binary.LittleEndian.Uint64(key[0:8]) & 0x0FFFFFFC0FFFFFFF
	r1 := binary.LittleEndian.Uint64(key[8:16]) & 0x0FFFFFFC0FFFFFFC
	m.state.r[0] = r0
	m.state.r[1] = r1
	m.state.s1 = r1 + (r1 >> 2)
	m.pad[0] = binary.LittleEndian.Uint64(key[16:24])
	m.pad[1] = binary.LittleEndian.Uint64(key[24:32])
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
// the 16-byte tag in little-endian byte order. This is the same
// algorithm as x/crypto's saturated-64 finalize, with one extra
// upstream-style reduction step at entry: the asm inner loop puts
// the modulo-scheduled reduction at *block start*, so when we
// finish the message h2 still holds whatever the last multiply put
// there (often a full 64 bits). The first three lines below replay
// that reduction one last time to bring h2 down to its canonical
// 0..5-ish range.
func finalize(out *[TagSize]byte, h *[3]uint64, pad *[2]uint64) {
	h0, h1, h2 := h[0], h[1], h[2]

	// Reduce h2's high bits back into h0 via the 2^130 ≡ 5 fold.
	residue := (h2 >> 2) + ((h2 >> 2) << 2) // = (h2 >> 2) * 5
	h2 &= 3
	var c uint64
	h0, c = bitsAdd64(h0, residue, 0)
	h1, c = bitsAdd64(h1, 0, c)
	h2 += c

	// Constants for h - p where p = 2^130 - 5.
	const (
		p0 uint64 = 0xFFFFFFFFFFFFFFFB
		p1 uint64 = 0xFFFFFFFFFFFFFFFF
		p2 uint64 = 0x0000000000000003
	)

	// t = h - p with borrow tracking. If t doesn't borrow out of
	// the high limb we're in canonical form already.
	var b uint64
	t0, b := bitsSub64(h0, p0, 0)
	var t1 uint64
	t1, b = bitsSub64(h1, p1, b)
	_, b = bitsSub64(h2, p2, b)

	// Constant-time select: h if h < p (b=1), else t.
	h0 = select64(b, h0, t0)
	h1 = select64(b, h1, t1)

	// tag = (h + pad) mod 2^128.
	h0, c = bitsAdd64(h0, pad[0], 0)
	h1, _ = bitsAdd64(h1, pad[1], c)

	binary.LittleEndian.PutUint64(out[0:], h0)
	binary.LittleEndian.PutUint64(out[8:], h1)
}

// bitsSub64 mirrors math/bits.Sub64; inlined here to keep this
// package free of any unusual import surface.
func bitsSub64(x, y, borrow uint64) (diff, borrowOut uint64) {
	diff = x - y - borrow
	borrowOut = ((^x & y) | (^(x ^ y) & diff)) >> 63
	return
}

func bitsAdd64(x, y, carry uint64) (sum, carryOut uint64) {
	sum = x + y + carry
	carryOut = ((x & y) | ((x | y) & ^sum)) >> 63
	return
}

func select64(v, x, y uint64) uint64 {
	mask := ^(v - 1)
	return (x & mask) | (y & ^mask)
}
