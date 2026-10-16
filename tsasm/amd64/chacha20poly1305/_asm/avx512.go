// SPDX-License-Identifier: BSD-3-Clause

/*
A fused AVX-512 ChaCha20-Poly1305 for amd64, in a separate file so the SSE generator it sits beside is touched only by the tier branch added to main().

The vector half uses the same layout as this package's SSSE3 kernel: one 128-bit lane per block, so a ZMM register holds one row of the ChaCha matrix for four blocks and four registers hold four complete block states. That is a group, 256 bytes.

The scalar half reuses this package's existing Poly1305 emitters unchanged, so the carry-sensitive limb arithmetic is code that has already been fuzzed and audited; only the scheduling here is new, plus a BMI2 form of the multiply.

Poly1305 can only hash ciphertext that already exists, and within a multi-group iteration every round runs before every output, so a group's MAC work has to hide under a later group's rounds. Seal keeps two groups in flight (see avx512Groups); Open hashes its own input and has no such lag.
*/
package main

import (
	"fmt"

	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

const (
	avx512BlocksPerGroup = 4
	avx512GroupBytes     = avx512BlocksPerGroup * 64 // 256
	avx512PolyBlocks     = avx512GroupBytes / 16     // 16 Poly1305 blocks per group
)

// Stack layout, BP-relative. r and s must sit at BP+0 and BP+16 because polyMulBMI2 and sealSSEFinalize already read them there.
var (
	avx512RSStore    = Mem{Base: BP}.Offset(0)   // r at +0, s at +16
	avx512TailStore  = Mem{Base: BP}.Offset(256) // 256 bytes: buffered partial tail
	avx512ShortStore = Mem{Base: BP}.Offset(512) // 704 bytes: the short path's zero-padded ciphertext, for Poly1305
)

// avx512Group is one block-group's working state: four rows, four blocks per row.
type avx512Group struct {
	a, b, c, d VecVirtual
}

// chachaQR_AVX512 is ChaCha's quarter round. VPROLD rotates in one instruction and needs no scratch register, unlike chachaQR_AVX2 which spends two VPSHUFB plus four shifts and two xors on the same rotations and needs a temporary.
func chachaQR_AVX512(a, b, c, d VecVirtual) {
	VPADDD(b, a, a)
	VPXORD(a, d, d)
	VPROLD(U8(16), d, d)

	VPADDD(d, c, c)
	VPXORD(c, b, b)
	VPROLD(U8(12), b, b)

	VPADDD(b, a, a)
	VPXORD(a, d, d)
	VPROLD(U8(8), d, d)

	VPADDD(d, c, c)
	VPXORD(c, b, b)
	VPROLD(U8(7), b, b)
}

// diagonaliseAVX512 turns the column round into the diagonal round. VPSHUFD permutes dwords inside each 128-bit lane, and a lane is exactly one block's row.
func diagonaliseAVX512(b, c, d VecVirtual, forward bool) {
	if forward {
		VPSHUFD(U8(0x39), b, b)
		VPSHUFD(U8(0x4e), c, c)
		VPSHUFD(U8(0x93), d, d)
		return
	}
	VPSHUFD(U8(0x93), b, b)
	VPSHUFD(U8(0x4e), c, c)
	VPSHUFD(U8(0x39), d, d)
}

// avx512RoundClosures returns the group's twenty rounds as a list of emitters, so the caller can interleave another instruction stream between them.
func avx512RoundClosures(g avx512Group) []func() {
	var out []func()
	for r := 0; r < 10; r++ {
		out = append(out,
			func() { chachaQR_AVX512(g.a, g.b, g.c, g.d) },
			func() { diagonaliseAVX512(g.b, g.c, g.d, true) },
			func() { chachaQR_AVX512(g.a, g.b, g.c, g.d) },
			func() { diagonaliseAVX512(g.b, g.c, g.d, false) },
		)
	}
	return out
}

/*
avx512RoundClosuresBatch round-robins several groups' closure lists so consecutive emissions come from different groups. One group is a single dependency chain of vector work; n groups interleaved is n independent chains, which is what a wide out-of-order core needs to fill its vector units.

It is not free. Poly1305 can only hash ciphertext that already exists, and no output exists until a batch's rounds are all done, so widening the batch directly shrinks how much poly work can hide under rounds. At 1280 bytes, which is five groups, a four-group batch leaves four of the five groups' poly unoverlapped. Measured, two and four land within 1% of each other on every part tested, which is why two ships.
*/
func avx512RoundClosuresBatch(groups []avx512Group) []func() {
	per := make([][]func(), len(groups))
	for i, g := range groups {
		per[i] = avx512RoundClosures(g)
	}
	var out []func()
	for step := range per[0] {
		for i := range per {
			out = append(out, per[i][step])
		}
	}
	return out
}

// avx512NewBatch builds n groups on consecutive counters. Group 0 reuses dRow, so with n == 1 this is exactly avx512NewGroup and the caller's counter advance is unchanged.
func avx512NewBatch(n int, initA, initB, initC, dRow VecVirtual, inc4 Mem) (work, init []avx512Group) {
	d := dRow
	for j := 0; j < n; j++ {
		if j > 0 {
			nd := ZMM()
			VPADDD(inc4, d, nd)
			d = nd
		}
		w, i := avx512NewGroup(initA, initB, initC, d)
		work = append(work, w)
		init = append(init, i)
	}
	return work, init
}

// avx512EmitHashing emits a list of round emitters with polyBlocks Poly1305 block absorptions spread evenly through them; hashAt gives the address of the i'th 16-byte block. Spreading is arithmetic over the two stream lengths rather than hand placement, which is the reason to want a generator here at all.
func avx512EmitHashing(rounds []func(), polyBlocks int, hashAt func(i int) Mem) {
	next := 0
	absorb := func(upto int) {
		for next < upto {
			polyAdd(hashAt(next))
			polyMulBMI2()
			next++
		}
	}
	for i, emit := range rounds {
		emit()
		absorb((i + 1) * polyBlocks / len(rounds))
	}
	absorb(polyBlocks)
}

/*
avx512FinalBatch emits the last batch of a payload: `whole` whole groups (0 to 2) and then a partial group of inl bytes, 0 < inl < 256, with all their rounds interleaved. The caller has already taken the whole groups out of inl.

Pairing the partial group with a whole one is the point when there is one. A partial group run on its own is a full group of rounds with nothing to interleave against, which measured as costing more than an entire extra whole group. The partial group is loaded, XORed and stored under byte masks, and its ciphertext goes to a buffer with everything past inl zeroed, which is the padding Poly1305's final block needs.

What hides under the rounds differs by direction. Seal hashes the backlog of groups it wrote earlier, since this batch's own ciphertext does not exist yet, and hashes this batch afterwards with nothing to hide under, which is inherent to encrypt-then-MAC. Open hashes this batch's own whole group under the rounds and its partial group after, and writes nothing until it has hashed, so decrypting in place stays safe.
*/
func avx512FinalBatch(prefix string, sealing bool, whole, backlogGroups int, initA, initB, initC, dRow VecVirtual, inc4 Mem) {
	part := whole * avx512GroupBytes // offset of the partial group
	var masks [avx512BlocksPerGroup]OpmaskVirtual
	for i := range masks {
		masks[i] = avx512BlockMask(i)
	}
	var srcs [avx512BlocksPerGroup]VecVirtual
	if !sealing {
		Comment("Stage the partial group's ciphertext, zero-padded, for Poly1305")
		for i := range srcs {
			srcs[i] = ZMM()
			VMOVDQU8_Z(Mem{Base: inp}.Offset(part+i*64), masks[i], srcs[i])
			VMOVDQU32(srcs[i], avx512TailStore.Offset(i*64))
		}
	}

	work, init := avx512NewBatch(whole+1, initA, initB, initC, dRow, inc4)
	rounds := avx512RoundClosuresBatch(work)
	if sealing {
		avx512EmitHashing(rounds, backlogGroups*avx512PolyBlocks, func(i int) Mem {
			return Mem{Base: oup}.Offset(-backlogGroups*avx512GroupBytes + i*16)
		})
	} else {
		avx512EmitHashing(rounds, whole*avx512PolyBlocks, func(i int) Mem {
			return Mem{Base: inp}.Offset(i * 16)
		})
	}

	for j := range work {
		avx512AddInit(work[j], init[j])
		blocks := avx512Transpose(work[j])
		for i := 0; i < avx512BlocksPerGroup; i++ {
			at := j*avx512GroupBytes + i*64
			if j < whole {
				VPXORD(Mem{Base: inp}.Offset(at), blocks[i], blocks[i])
				VMOVDQU32(blocks[i], Mem{Base: oup}.Offset(at))
				continue
			}
			if sealing {
				src := ZMM()
				VMOVDQU8_Z(Mem{Base: inp}.Offset(at), masks[i], src)
				VPXORD(src, blocks[i], blocks[i])
				VMOVDQU8(blocks[i], masks[i], Mem{Base: oup}.Offset(at))
				VMOVDQU8_Z(blocks[i], masks[i], blocks[i])
				VMOVDQU32(blocks[i], avx512TailStore.Offset(i*64))
			} else {
				VPXORD(srcs[i], blocks[i], blocks[i])
				VMOVDQU8(blocks[i], masks[i], Mem{Base: oup}.Offset(at))
			}
		}
	}

	if sealing {
		Comment("Hash this batch: any whole group in place, then the partial one from the buffer")
		for i := 0; i < whole*avx512PolyBlocks; i++ {
			polyAdd(Mem{Base: oup}.Offset(i * 16))
			polyMulBMI2()
		}
	}
	avx512HashBufferAt(fmt.Sprint(prefix, "Final", whole), avx512TailStore, inl)

	// The caller finalises from oup (Seal's tag store) or inp (Open's tag compare), so both have to end up just past the payload. The hashing above addresses off the un-advanced pointers, so this comes last.
	if whole > 0 {
		ADDQ(U32(part), oup)
		ADDQ(U32(part), inp)
	}
	ADDQ(inl, oup)
	ADDQ(inl, inp)
}

// avx512Groups is how many groups the batched loops keep in flight. Four was measured and landed within 1% of two on every part tested: the cipher gains width and the interleaved Poly1305 gives back almost exactly as much.
const avx512Groups = 2

// avx512Transpose exchanges 128-bit lanes so each block's sixteen words land contiguously in one register, and returns the four per-block registers in block order.
//
// Going in, register a holds row 0 for blocks 0 to 3, so block j's keystream is lane j of a, b, c and d. VSHUFI64X2 takes its low two output lanes from src1 and its high two from src2, which is where the 0x44/0xEE then 0x88/0xDD immediates come from.
func avx512Transpose(g avx512Group) [4]VecVirtual {
	ab0, ab1, cd0, cd1 := ZMM(), ZMM(), ZMM(), ZMM()
	VSHUFI64X2(U8(0x44), g.b, g.a, ab0) // a0 a1 b0 b1
	VSHUFI64X2(U8(0xee), g.b, g.a, ab1) // a2 a3 b2 b3
	VSHUFI64X2(U8(0x44), g.d, g.c, cd0) // c0 c1 d0 d1
	VSHUFI64X2(U8(0xee), g.d, g.c, cd1) // c2 c3 d2 d3

	var blocks [4]VecVirtual
	for i, sel := range []struct {
		imm    uint8
		lo, hi VecVirtual
	}{
		{0x88, ab0, cd0},
		{0xdd, ab0, cd0},
		{0x88, ab1, cd1},
		{0xdd, ab1, cd1},
	} {
		blocks[i] = ZMM()
		VSHUFI64X2(U8(sel.imm), sel.hi, sel.lo, blocks[i])
	}
	return blocks
}

// avx512AddInit adds the original state back, which ChaCha requires before the keystream is usable.
func avx512AddInit(work, init avx512Group) {
	VPADDD(init.a, work.a, work.a)
	VPADDD(init.b, work.b, work.b)
	VPADDD(init.c, work.c, work.c)
	VPADDD(init.d, work.d, work.d)
}

// avx512NewGroup builds a group's initial state from the sixteen-word ChaCha state at keyp, with dRow supplying row 3 so the caller controls the block counters.
func avx512NewGroup(initA, initB, initC, dRow VecVirtual) (work, init avx512Group) {
	init = avx512Group{a: initA, b: initB, c: initC, d: dRow}
	work = avx512Group{a: ZMM(), b: ZMM(), c: ZMM(), d: ZMM()}
	VMOVDQA32(initA, work.a)
	VMOVDQA32(initB, work.b)
	VMOVDQA32(initC, work.c)
	VMOVDQA32(dRow, work.d)
	return work, init
}

/*
Both entry points use Implement rather than TEXT. Implement takes the signature from the Go declaration in chacha20poly1305.go, which Package() resolved, so the argument offsets and frame size are derived from the one authoritative declaration. Passing a signature string to TEXT instead would put the same prototype in two files with nothing checking they agree, and a later edit to either one would silently move the arguments. It is also what the SSSE3 generator beside this does.
*/
func chacha20Poly1305SealAVX512() {
	Implement("chacha20Poly1305SealAVX512")
	Attributes(0)
	Doc("chacha20Poly1305SealAVX512 seals with a fused AVX-512 ChaCha20 and scalar Poly1305.",
		"Any length works, including zero.")
	initA, initB, initC, dRow, dRowKey := avx512SetupState()
	inc4 := avx512Inc4_DATA()

	// One group of ciphertext is always written before any of it can be hashed, so the first group carries no Poly1305 work and the steady loop then hashes the group behind it. The caller guarantees at least one whole group, so the first group always runs; the steady loop runs once per group after that and may run zero times. The epilogue hashes the last full group, which has no rounds left to hide under, and the tail below handles any bytes past it, so no alignment beyond the one-group minimum is required. encryptBatch emits n groups with their rounds interleaved, hashing polyBlocks of already-written output starting hashBack bytes behind the output pointer. With n == 1 and hashBack one group it is the original single-group schedule exactly.
	// withKey runs the counter-0 group as one more chain beside the batch and takes the Poly1305 key from it. Only a first batch does that, and a first batch hashes nothing, so the key is ready before anything needs it.
	encryptBatch := func(n, polyBlocks, hashBack int, withKey bool) {
		work, init := avx512NewBatch(n, initA, initB, initC, dRow, inc4)
		hashAt := func(i int) Mem {
			return Mem{Base: oup}.Offset(-hashBack + i*16)
		}
		chains := work
		var keyWork, keyInit avx512Group
		if withKey {
			keyWork, keyInit = avx512NewGroup(initA, initB, initC, dRowKey)
			chains = append(append([]avx512Group{}, work...), keyWork)
		}
		rounds := avx512RoundClosuresBatch(chains)
		if polyBlocks > 0 {
			avx512EmitHashing(rounds, polyBlocks, hashAt)
		} else {
			for _, emit := range rounds {
				emit()
			}
		}
		for j := 0; j < n; j++ {
			avx512AddInit(work[j], init[j])
			blocks := avx512Transpose(work[j])
			for i := 0; i < avx512BlocksPerGroup; i++ {
				at := j*avx512GroupBytes + i*64
				VPXORD(Mem{Base: inp}.Offset(at), blocks[i], blocks[i])
				VMOVDQU32(blocks[i], Mem{Base: oup}.Offset(at))
			}
		}
		VPADDD(inc4, init[n-1].d, dRow)
		if withKey {
			avx512KeyAndAD(keyWork, keyInit)
		}
		ADDQ(U32(n*avx512GroupBytes), inp)
		ADDQ(U32(n*avx512GroupBytes), oup)
		SUBQ(U32(n*avx512GroupBytes), inl)
	}

	hashBacklog := func(groups int) {
		for i := 0; i < groups*avx512PolyBlocks; i++ {
			polyAdd(Mem{Base: oup}.Offset(-groups*avx512GroupBytes + i*16))
			polyMulBMI2()
		}
	}

	// The short path is emitted after this function's RET, so the main path pays one compare and an untaken branch and its own layout is unchanged.
	Comment("Payloads of up to 704 bytes take the short path")
	CMPQ(inl, U32(avx512ShortMax))
	JBE(LabelRef("sealAVX512Short"))

	n, batchBytes := avx512Groups, avx512Groups*avx512GroupBytes

	// Past the short path's 704 bytes there is always at least one whole batch.
	Comment("First batch: nothing has been written yet, so there is nothing to hash")
	encryptBatch(n, 0, 0, true)

	Comment("Steady state: hash the batch behind this one under this batch's rounds")
	Label("sealAVX512BatchLoop")
	CMPQ(inl, U32(batchBytes))
	JB(LabelRef("sealAVX512DrainEntry"))
	encryptBatch(n, n*avx512PolyBlocks, batchBytes, false)
	JMP(LabelRef("sealAVX512BatchLoop"))

	/*
		Fewer than a batch of bytes is left, and the batch before it is still to be hashed. The remainder is tested once, here, and the two cases get separate contiguous paths: sharing one path and branching at the end measured as a flat 215 ns penalty on every exact-multiple length on Zen 5, on a hot loop that was byte-for-byte identical, from the common path having to jump forward over the whole masked-pair block.
	*/
	Comment("Less than a batch left. An exact multiple of a group keeps its own path.")
	Label("sealAVX512DrainEntry")
	MOVQ(inl, itr1)
	ANDQ(U32(avx512GroupBytes-1), itr1)
	JNZ(LabelRef("sealAVX512PairOrTail"))

	// One whole group may remain. Ciphering it with the whole backlog spread under its rounds leaves only this group's own blocks for the end, with nothing to hide under; 1280, Tailscale's MTU, ends this way.
	CMPQ(inl, U32(avx512GroupBytes))
	JB(LabelRef("sealAVX512DrainHashAll"))
	Comment("One whole group left: cipher it while hashing the whole backlog")
	encryptBatch(1, n*avx512PolyBlocks, batchBytes, false)
	hashBacklog(1)
	JMP(LabelRef("sealAVX512Reduce"))

	Comment("Nothing left to cipher: hash the backlog with no rounds to hide it under")
	Label("sealAVX512DrainHashAll")
	hashBacklog(n)
	JMP(LabelRef("sealAVX512Reduce"))

	// A partial group follows. With a whole group left it rides along with that one, because a partial group emitted alone costs more than an entire extra whole group.
	Comment("A partial group follows: pair it with a whole one if there is one")
	Label("sealAVX512PairOrTail")
	CMPQ(inl, U32(avx512GroupBytes))
	JB(LabelRef("sealAVX512SmallTail"))
	SUBQ(U32(avx512GroupBytes), inl)
	avx512FinalBatch("seal", true, 1, n, initA, initB, initC, dRow, inc4)
	JMP(LabelRef("sealAVX512Reduce"))

	Comment("Only a partial group left: cipher it while hashing the backlog")
	Label("sealAVX512SmallTail")
	avx512FinalBatch("seal", true, 0, n, initA, initB, initC, dRow, inc4)

	Label("sealAVX512Reduce")
	avx512Reduce()

	storeTag := func() {
		Comment("Store the tag at the end of the message")
		MOVQ(acc0, Mem{Base: oup}.Offset(0))
		MOVQ(acc1, Mem{Base: oup}.Offset(8))
		VZEROUPPER()
		RET()
	}
	storeTag()

	Comment("Short path: up to 704 bytes in one pass of rounds")
	Label("sealAVX512Short")
	avx512ShortPath("seal", true, initA, initB, initC, dRowKey, inc4)
	avx512Reduce()
	storeTag()
}

// The three counter constants are memoised the same way the existing generator memoises its own DATA symbols: both directions ask for them, and emitting a GLOBL twice produces "overlapping DATA entry" at assembly time.
var (
	avx512IncMask_DATA_ptr *Mem
	avx512Inc4_DATA_ptr    *Mem
	avx512Inc1_DATA_ptr    *Mem
)

func avx512IncMask_DATA() Mem {
	if avx512IncMask_DATA_ptr != nil {
		return *avx512IncMask_DATA_ptr
	}
	g := GLOBL(ThatPeskyUnicodeDot+"avx512IncMask", NOPTR|RODATA)
	avx512IncMask_DATA_ptr = &g
	for lane := 0; lane < 4; lane++ {
		DATA(16*lane, U32(uint32(lane)))
		DATA(16*lane+4, U32(0))
		DATA(16*lane+8, U32(0))
		DATA(16*lane+12, U32(0))
	}
	return g
}

func avx512Inc4_DATA() Mem {
	if avx512Inc4_DATA_ptr != nil {
		return *avx512Inc4_DATA_ptr
	}
	g := GLOBL(ThatPeskyUnicodeDot+"avx512Inc4", NOPTR|RODATA)
	avx512Inc4_DATA_ptr = &g
	for lane := 0; lane < 4; lane++ {
		DATA(16*lane, U32(avx512BlocksPerGroup))
		DATA(16*lane+4, U32(0))
		DATA(16*lane+8, U32(0))
		DATA(16*lane+12, U32(0))
	}
	return g
}

func avx512Inc1_DATA() Mem {
	if avx512Inc1_DATA_ptr != nil {
		return *avx512Inc1_DATA_ptr
	}
	g := GLOBL(ThatPeskyUnicodeDot+"avx512Inc1", NOPTR|RODATA)
	avx512Inc1_DATA_ptr = &g
	for lane := 0; lane < 4; lane++ {
		DATA(16*lane, U32(1))
		DATA(16*lane+4, U32(0))
		DATA(16*lane+8, U32(0))
		DATA(16*lane+12, U32(0))
	}
	return g
}

// avx512SetupState emits the shared prologue for both directions: align BP, load the pointers, broadcast the three constant rows, and build row 3 twice, once at counters 0-3 for the group that yields the Poly1305 key and once at counters 1-4 where the payload starts.
//
// The key group is not run here. Seal runs it as one more chain beside its first batch, which hashes nothing and so does not need the key yet; Open runs it alone first, because every Open batch hashes its own ciphertext and needs the key from the start. Both finish it with avx512KeyAndAD.
func avx512SetupState() (initA, initB, initC, dRow, dRowKey VecVirtual) {
	/*
		The frame is declared here rather than at each entry point because both directions need exactly this layout and neither should be able to drift from it. Its size is fixed by the BP-relative map above: the short path's buffer ends at 1216, plus up to 64 bytes of alignment. BP is aligned to 64 because every buffer is read and written as whole 64-byte ZMM blocks, which would otherwise split a cache line on about half of all calls.
	*/
	AllocLocal(1280)
	MOVQ(RSP, RBP)
	ADDQ(Imm(64), RBP)
	ANDQ(I32(-64), RBP)

	Load(Param("dst").Base(), oup)
	Load(Param("key").Base(), keyp)
	Load(Param("src").Base(), inp)
	Load(Param("src").Len(), inl)

	initA, initB, initC, dRowKey = ZMM(), ZMM(), ZMM(), ZMM()
	VBROADCASTI32X4(chacha20Constants_DATA(), initA)
	VBROADCASTI32X4(Mem{Base: keyp}.Offset(16), initB)
	VBROADCASTI32X4(Mem{Base: keyp}.Offset(32), initC)
	VBROADCASTI32X4(Mem{Base: keyp}.Offset(48), dRowKey)
	VPADDD(avx512IncMask_DATA(), dRowKey, dRowKey)

	// The payload starts at counter 1, so row 3 for the first payload group is counters 1-4.
	dRow = ZMM()
	VPADDD(avx512Inc1_DATA(), dRowKey, dRow)
	return initA, initB, initC, dRow, dRowKey
}

/*
avx512KeyAndAD finishes the counter-0 group: block 0 becomes the Poly1305 key, and then the accumulator is zeroed and the additional data hashed. Blocks 1 to 3 of that group are not used; the payload starts at counter 1.

Only block 0 is pulled out, which is lane 0 of each row, so three shuffles rather than the eight of a full transpose. The AD pointer is reloaded because adp shares RCX with itr1, and nothing guarantees RCX survived the batch.
*/
func avx512KeyAndAD(work, init avx512Group) {
	avx512AddInit(work, init)
	ab, cd, block0 := ZMM(), ZMM(), ZMM()
	VSHUFI64X2(U8(0x44), work.b, work.a, ab) // a0 a1 b0 b1
	VSHUFI64X2(U8(0x44), work.d, work.c, cd) // c0 c1 d0 d1
	VSHUFI64X2(U8(0x88), cd, ab, block0)     // a0 b0 c0 d0
	avx512StoreKeyAndAD(block0)
}

/*
avx512StoreKeyAndAD stores the Poly1305 key from the counter-0 block and hashes the additional data. The whole block is stored at BP+0, which puts r at +0 and s at +16 where the Poly1305 emitters read them; its other 32 bytes land in stack nothing else uses. r is then clamped in place with two scalar ANDs, so the key path needs no XMM register, whose encoding would otherwise depend on which register avo picked. polyHashADInternal zeroes the accumulator itself.
*/
func avx512StoreKeyAndAD(block0 VecVirtual) {
	VMOVDQU32(block0, avx512RSStore)
	Comment("Clamp r in place")
	MOVQ(U64(0x0ffffffc0fffffff), t0)
	ANDQ(t0, avx512RSStore)
	MOVQ(U64(0x0ffffffc0ffffffc), t0)
	ANDQ(t0, avx512RSStore.Offset(8))

	Comment("Hash the additional data")
	Load(Param("ad").Base(), adp)
	Load(Param("ad").Len(), itr2)
	CALL(LabelRef("polyHashADInternal<>(SB)"))
}

// avx512Reduce emits the shared tail: fold in the two lengths, reduce mod 2^130-5 and add s.
func avx512Reduce() {
	Comment("Hash in the buffer lengths")
	Load(Param("ad").Len(), t0)
	Load(Param("src").Len(), t1)
	ADDQ(t0, acc0)
	ADCQ(t1, acc1)
	ADCQ(Imm(1), acc2)
	polyMul()

	Comment("Final reduce")
	MOVQ(acc0, t0)
	MOVQ(acc1, t1)
	MOVQ(acc2, t2)
	SUBQ(I8(-5), acc0)
	SBBQ(I8(-1), acc1)
	SBBQ(Imm(3), acc2)
	CMOVQCS(t0, acc0)
	CMOVQCS(t1, acc1)
	CMOVQCS(t2, acc2)

	Comment("Add in the \"s\" part of the key")
	ADDQ(avx512RSStore.Offset(16), acc0)
	ADCQ(avx512RSStore.Offset(24), acc1)
}

/*
chacha20Poly1305OpenAVX512 is the decrypting direction, and it is structurally simpler than the sealing one.

Seal must hash ciphertext it has not produced yet, which forces a software pipeline: a group's Poly1305 work can only hide under the *next* group's rounds, so the first group carries no hashing and the last group's hashing has nothing to hide under. Open's MAC reads the input, which is already in memory and independent of the keystream, so every group hashes its own sixteen blocks under its own rounds. There is no prologue, no epilogue and no lag, and every group gets full overlap.

The kernel decrypts before the tag is known to be correct, which is the posture the AVX2 kernel beside it already ships; the Go caller zeroes the output buffer when this returns false.
*/
func chacha20Poly1305OpenAVX512() {
	Implement("chacha20Poly1305OpenAVX512")
	Attributes(0)
	Doc("chacha20Poly1305OpenAVX512 opens with a fused AVX-512 ChaCha20 and scalar Poly1305.",
		"Any length works, including zero.",
		"Returns whether the tag authenticated. The caller must zero dst when it did not.")

	initA, initB, initC, dRow, dRowKey := avx512SetupState()
	inc4 := avx512Inc4_DATA()

	/*
		openBatch emits n groups with their rounds interleaved, each hashing its own sixteen blocks of input. Unlike Seal there is no lag to manage: the MAC reads the input, which already exists, so a batch needs no prologue hashing nothing and no epilogue with nothing to hide under. With n == 1 this is the original single-group schedule exactly.

		All n groups hash before any of them XORs, so decrypting in place stays safe.
	*/
	openBatch := func(n int) {
		work, init := avx512NewBatch(n, initA, initB, initC, dRow, inc4)
		rounds := avx512RoundClosuresBatch(work)
		avx512EmitHashing(rounds, n*avx512PolyBlocks, func(i int) Mem {
			return Mem{Base: inp}.Offset(i * 16)
		})
		for j := 0; j < n; j++ {
			avx512AddInit(work[j], init[j])
			blocks := avx512Transpose(work[j])
			for i := 0; i < avx512BlocksPerGroup; i++ {
				at := j*avx512GroupBytes + i*64
				VPXORD(Mem{Base: inp}.Offset(at), blocks[i], blocks[i])
				VMOVDQU32(blocks[i], Mem{Base: oup}.Offset(at))
			}
		}
		VPADDD(inc4, init[n-1].d, dRow)
		ADDQ(U32(n*avx512GroupBytes), inp)
		ADDQ(U32(n*avx512GroupBytes), oup)
		SUBQ(U32(n*avx512GroupBytes), inl)
	}

	/*
		Open runs the key group on its own, before any batch. Every Open batch hashes its own ciphertext under its own rounds, so the key has to exist before the first one starts, and decrypting in place rules out writing a batch first and hashing it later. Running the key group beside the first batch and moving that batch's hashing into the next one was tried: Skylake-D lost 55 to 66 ns per packet, because doubling one batch's Poly1305 work is more than its rounds can hide when the MAC is already 40 percent of the fused cost, and Zen 5 gained nothing.
	*/
	// As in Seal, the short path sits after RET so the main path's layout is unchanged.
	Comment("Payloads of up to 704 bytes take the short path")
	CMPQ(inl, U32(avx512ShortMax))
	JBE(LabelRef("openAVX512Short"))

	Comment("Poly1305 key from the counter-0 group, run alone")
	keyWork, keyInit := avx512NewGroup(initA, initB, initC, dRowKey)
	for _, emit := range avx512RoundClosures(keyWork) {
		emit()
	}
	avx512KeyAndAD(keyWork, keyInit)

	/*
		The loop stops while a whole batch is still left, so the final batch always has one or two whole groups for a partial group to ride along with: past the short path's 704 bytes there are always at least 256 bytes when the loop exits, and a partial group never runs alone.
	*/
	Comment("Batches of groups, each hashing its own ciphertext under its own rounds")
	Label("openAVX512BatchLoop")
	CMPQ(inl, U32((avx512Groups+1)*avx512GroupBytes))
	JB(LabelRef("openAVX512Final"))
	openBatch(avx512Groups)
	JMP(LabelRef("openAVX512BatchLoop"))

	Comment("Final batch: one or two whole groups, and a partial group riding along if there is one")
	Label("openAVX512Final")
	CMPQ(inl, U32(2*avx512GroupBytes))
	JB(LabelRef("openAVX512FinalOne"))
	JE(LabelRef("openAVX512FinalTwoExact"))
	SUBQ(U32(2*avx512GroupBytes), inl)
	avx512FinalBatch("open", false, 2, 0, initA, initB, initC, dRow, inc4)
	JMP(LabelRef("openAVX512Finalize"))
	Label("openAVX512FinalTwoExact")
	openBatch(2)
	JMP(LabelRef("openAVX512Finalize"))
	Label("openAVX512FinalOne")
	CMPQ(inl, U32(avx512GroupBytes))
	JE(LabelRef("openAVX512FinalOneExact"))
	SUBQ(U32(avx512GroupBytes), inl)
	avx512FinalBatch("open", false, 1, 0, initA, initB, initC, dRow, inc4)
	JMP(LabelRef("openAVX512Finalize"))
	Label("openAVX512FinalOneExact")
	openBatch(1)
	JMP(LabelRef("openAVX512Finalize"))

	finalize := func() {
		avx512Reduce()

		Comment("Constant time compare against the tag, which sits just past the ciphertext")
		XORQ(RAX, RAX)
		MOVQ(U32(1), RDX)
		XORQ(Mem{Base: inp}.Offset(0*8), acc0)
		XORQ(Mem{Base: inp}.Offset(1*8), acc1)
		ORQ(acc1, acc0)
		CMOVQEQ(RDX, RAX)

		Comment("Return true iff the tags are equal")
		VZEROUPPER()
		Store(AL, ReturnIndex(0))
		RET()
	}
	Label("openAVX512Finalize")
	finalize()

	Comment("Short path: up to 704 bytes in one pass of rounds")
	Label("openAVX512Short")
	avx512ShortPath("open", false, initA, initB, initC, dRowKey, inc4)
	finalize()
}

func avx512HashBufferAt(prefix string, buf Mem, count Register) {
	MOVQ(count, itr1)
	XORQ(itr2, itr2)

	Label(prefix + "HashLoop")
	TESTQ(itr1, itr1)
	JLE(LabelRef(prefix + "HashDone"))
	block := buf
	block.Index, block.Scale = itr2, 1
	polyAdd(block)
	polyMulBMI2()
	ADDQ(Imm(16), itr2)
	SUBQ(Imm(16), itr1)
	JMP(LabelRef(prefix + "HashLoop"))

	Label(prefix + "HashDone")
}

// avx512ShortMax is the longest payload the short path takes: the counter-0 group's blocks 1 to 3 plus two more groups, eleven blocks.
const avx512ShortMax = 11 * 64

/*
avx512BlockMask returns a byte mask for block j of the inl bytes that remain: the low clamp(inl-64j, 0, 64) bits set, so a partial block can be loaded, XORed and stored where it lies. Both ends of the clamp are explicit. A negative count read as an unsigned index would set every bit rather than none, and BZHIQ reads only the low eight bits of its index, so a count of 300 would act as 44.

Clobbers itr1, itr2 and t0, none of which hold anything across a Poly1305 block. avo marks K0 restricted and never allocates it, which matters here, because as a predicate operand K0 encodes "no mask" whatever its contents, so a store predicated on it would write the whole register.
*/
func avx512BlockMask(j int) OpmaskVirtual {
	MOVQ(inl, itr1)
	if j > 0 {
		XORQ(itr2, itr2)
		SUBQ(U32(uint64(j)*64), itr1)
		CMOVQLT(itr2, itr1)
	}
	MOVQ(U32(64), itr2)
	CMPQ(itr1, itr2)
	CMOVQGT(itr2, itr1)
	MOVQ(I32(-1), t0)
	BZHIQ(itr1, t0, t0)
	k := K()
	KMOVQ(t0, k)
	return k
}

/*
avx512ShortPath handles payloads of up to 704 bytes, including empty ones, in one pass of rounds. The counter-0 group already has to run for the Poly1305 key, and its blocks 1 to 3 are exactly the keystream for the payload's first 192 bytes, so up to 192 bytes that one group does everything; up to 448 a second group, on counters 4 to 7, runs interleaved with it, and up to 704 a third, on counters 8 to 11. The general path would run the key group and then whole and partial groups after it, one chain at a time, which is what made short payloads slower than x/crypto.

Partial blocks are loaded and stored under byte masks, which also suppress faults past the end of the caller's buffers. Poly1305 reads the ciphertext from a buffer with everything past inl zeroed, which is the padding its final block needs. The hash has no rounds left to hide under; at these lengths it is a handful of blocks. Open hashes before it writes anything, so decrypting in place stays safe.

Leaves the pointer the caller finalises from (oup for Seal, inp for Open) just past the payload.
*/
func avx512ShortPath(prefix string, sealing bool, initA, initB, initC, dRowKey VecVirtual, inc4 Mem) {
	for extra := 0; extra <= 2; extra++ {
		if extra > 0 {
			Label(fmt.Sprint(prefix, "Short", extra))
		}
		if extra < 2 {
			CMPQ(inl, U32(uint64(3+4*extra)*64))
			JA(LabelRef(fmt.Sprint(prefix, "Short", extra+1)))
		}
		g0w, g0i := avx512NewGroup(initA, initB, initC, dRowKey)
		chains := []avx512Group{g0w}
		inits := []avx512Group{g0i}
		d := dRowKey
		for e := 0; e < extra; e++ {
			nd := ZMM()
			VPADDD(inc4, d, nd)
			d = nd
			w, ini := avx512NewGroup(initA, initB, initC, d)
			chains, inits = append(chains, w), append(inits, ini)
		}
		for _, emit := range avx512RoundClosuresBatch(chains) {
			emit()
		}
		var ks []VecVirtual
		for i := range chains {
			avx512AddInit(chains[i], inits[i])
			b := avx512Transpose(chains[i])
			ks = append(ks, b[:]...)
		}
		avx512StoreKeyAndAD(ks[0])
		nblocks := len(ks) - 1

		if sealing {
			for j := 0; j < nblocks; j++ {
				k := avx512BlockMask(j)
				src, ct := ZMM(), ZMM()
				VMOVDQU8_Z(Mem{Base: inp}.Offset(j*64), k, src)
				VPXORD(src, ks[j+1], ct)
				VMOVDQU8(ct, k, Mem{Base: oup}.Offset(j*64))
				VMOVDQU8_Z(ct, k, ct)
				VMOVDQU32(ct, avx512ShortStore.Offset(j*64))
			}
			avx512HashBufferAt(prefix+fmt.Sprint("Short", nblocks), avx512ShortStore, inl)
			ADDQ(inl, oup)
		} else {
			srcs := make([]VecVirtual, nblocks)
			for j := 0; j < nblocks; j++ {
				k := avx512BlockMask(j)
				srcs[j] = ZMM()
				VMOVDQU8_Z(Mem{Base: inp}.Offset(j*64), k, srcs[j])
				VMOVDQU32(srcs[j], avx512ShortStore.Offset(j*64))
			}
			avx512HashBufferAt(prefix+fmt.Sprint("Short", nblocks), avx512ShortStore, inl)
			for j := 0; j < nblocks; j++ {
				k := avx512BlockMask(j)
				VPXORD(srcs[j], ks[j+1], srcs[j])
				VMOVDQU8(srcs[j], k, Mem{Base: oup}.Offset(j*64))
			}
			ADDQ(inl, inp)
		}
		if extra < 2 {
			JMP(LabelRef(prefix + "ShortDone"))
		}
	}
	Label(prefix + "ShortDone")
}
