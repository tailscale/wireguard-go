package tun

import (
	"math/bits"
	"simd/archsimd"
)

const minAMD64SIMD = 256

// checksumAVX2Extend is an AVX2 AMD64 implementation of checksum using the
// [simd/archsimd] package and uses uint32 computation to simulate
// add-with-carry.
func checksumAVX2Extend(b []byte, initial uint16) uint16 {
	if len(b) < minAMD64SIMD {
		return checksumGeneric64(b, initial)
	}

	var acc1, acc2, acc3, acc4 archsimd.Uint32x8
	var load archsimd.Uint8x16

	for ; len(b) > load.Len()*4; b = b[load.Len()*4:] {
		load = archsimd.LoadUint8x16(b)
		acc1 = acc1.Add(load.ReshapeToUint16s().ExtendToUint32())
		load = archsimd.LoadUint8x16(b[load.Len():])
		acc2 = acc2.Add(load.ReshapeToUint16s().ExtendToUint32())
		load = archsimd.LoadUint8x16(b[load.Len()*2:])
		acc3 = acc3.Add(load.ReshapeToUint16s().ExtendToUint32())
		load = archsimd.LoadUint8x16(b[load.Len()*3:])
		acc4 = acc4.Add(load.ReshapeToUint16s().ExtendToUint32())
	}

	for len(b) > 0 {
		smallLoad, n := archsimd.LoadUint8x16Part(b)
		load16 := smallLoad.ReshapeToUint16s()
		acc1 = acc1.Add(load16.ExtendToUint32())
		b = b[n:]
	}

	acc1 = acc1.Add(acc2)
	acc2 = acc3.Add(acc4)
	acc1 = acc1.Add(acc2)

	accumAs64 := acc1.ReshapeToUint64s()
	accumParts := make([]uint64, accumAs64.Len())
	accumAs64.Store(accumParts)

	archsimd.ClearAVXUpperBits()

	var final, carry uint64
	final = uint64(bits.ReverseBytes16(initial))
	for _, v := range accumParts {
		final, carry = bits.Add64(final, v, carry)
	}

	return bits.ReverseBytes16(ipChecksumFold64(final, carry))
}

// checksumAVX2ExtendSplit is an AVX2 AMD64 implementation of checksum using the
// [simd/archsimd] package and uses uint32 computation to simulate
// add-with-carry, loading 32 bytes at a time and splitting the result across
// two registers.
func checksumAVX2ExtendSplit(b []byte, initial uint16) uint16 {
	if len(b) < minAMD64SIMD {
		return checksumGeneric64(b, initial)
	}

	var acc1, acc2, acc3, acc4 archsimd.Uint32x8

	for load := archsimd.BroadcastUint8x32(0); len(b) > load.Len()*2; b = b[load.Len()*2:] {
		var zero archsimd.Uint16x16

		load = archsimd.LoadUint8x32(b)
		load16 := load.ReshapeToUint16s()
		acc1 = acc1.Add(load16.InterleaveHiGrouped(zero).ReshapeToUint32s())
		acc2 = acc2.Add(load16.InterleaveLoGrouped(zero).ReshapeToUint32s())

		load = archsimd.LoadUint8x32(b[load.Len():])
		load16 = load.ReshapeToUint16s()
		acc3 = acc3.Add(load16.InterleaveHiGrouped(zero).ReshapeToUint32s())
		acc4 = acc4.Add(load16.InterleaveLoGrouped(zero).ReshapeToUint32s())
	}

	for len(b) > 0 {
		smallLoad, n := archsimd.LoadUint8x16Part(b)
		load16 := smallLoad.ReshapeToUint16s()
		acc1 = acc1.Add(load16.ExtendToUint32())
		b = b[n:]
	}

	acc1 = acc1.Add(acc2)
	acc2 = acc3.Add(acc4)
	acc1 = acc1.Add(acc2)

	accumAs64 := acc1.ReshapeToUint64s()
	accumParts := make([]uint64, accumAs64.Len())
	accumAs64.Store(accumParts)

	archsimd.ClearAVXUpperBits()

	var final, carry uint64
	final = uint64(bits.ReverseBytes16(initial))
	for _, v := range accumParts {
		final, carry = bits.Add64(final, v, carry)
	}

	return bits.ReverseBytes16(ipChecksumFold64(final, carry))
}

// checksumAVX2Saturate is an AVX2 AMD64 implementation of checksum using the
// [simd/archsimd] package and uses normal addition alongside saturated addition
// to simulate add-with-carry.
func checksumAVX2Saturate(b []byte, initial uint16) uint16 {
	if len(b) < minAMD64SIMD {
		return checksumGeneric64(b, initial)
	}

	var acc1, acc2, acc3, acc4 archsimd.Uint16x16
	var carry1, carry2, carry3, carry4 archsimd.Uint16x16
	for load := archsimd.BroadcastUint8x32(0); len(b) > load.Len()*4; b = b[load.Len()*4:] {
		load = archsimd.LoadUint8x32(b)
		saturated := load.ReshapeToUint16s().AddSaturated(acc1)
		acc1 = load.ReshapeToUint16s().Add(acc1)
		carry1 = carry1.Sub(saturated.NotEqual(acc1).ToInt16x16().ToBits())

		load = archsimd.LoadUint8x32(b[load.Len():])
		saturated = load.ReshapeToUint16s().AddSaturated(acc2)
		acc2 = load.ReshapeToUint16s().Add(acc2)
		carry2 = carry2.Sub(saturated.NotEqual(acc2).ToInt16x16().ToBits())

		load = archsimd.LoadUint8x32(b[load.Len()*2:])
		saturated = load.ReshapeToUint16s().AddSaturated(acc3)
		acc3 = load.ReshapeToUint16s().Add(acc3)
		carry3 = carry3.Sub(saturated.NotEqual(acc3).ToInt16x16().ToBits())

		load = archsimd.LoadUint8x32(b[load.Len()*3:])
		saturated = load.ReshapeToUint16s().AddSaturated(acc4)
		acc4 = load.ReshapeToUint16s().Add(acc4)
		carry4 = carry4.Sub(saturated.NotEqual(acc4).ToInt16x16().ToBits())
	}

	for len(b) > 0 {
		smallLoad, n := archsimd.LoadUint8x32Part(b)
		saturated := smallLoad.ReshapeToUint16s().AddSaturated(acc1)
		acc1 = smallLoad.ReshapeToUint16s().Add(acc1)
		carry1 = carry1.Sub(saturated.NotEqual(acc1).ToInt16x16().ToBits())
		b = b[n:]
	}

	carry1 = carry1.Add(carry2)
	carry2 = carry3.Add(carry4)
	carry1 = carry1.Add(carry2)

	saturated := acc1.AddSaturated(acc2)
	acc1 = acc1.Add(acc2)
	carry1 = carry1.Sub(saturated.NotEqual(acc1).ToInt16x16().ToBits())

	saturated = acc3.AddSaturated(acc4)
	acc2 = acc3.Add(acc4)
	carry1 = carry1.Sub(saturated.NotEqual(acc2).ToInt16x16().ToBits())

	saturated = acc1.AddSaturated(acc2)
	acc1 = acc1.Add(acc2)
	carry1 = carry1.Sub(saturated.NotEqual(acc1).ToInt16x16().ToBits())

	saturated = acc1.AddSaturated(carry1)
	acc1 = acc1.Add(carry1)
	acc1 = acc1.Sub(saturated.NotEqual(acc1).ToInt16x16().ToBits())

	accumAs64 := acc1.ReshapeToUint64s()
	accumParts := make([]uint64, accumAs64.Len())
	accumAs64.Store(accumParts)

	archsimd.ClearAVXUpperBits()

	var final, carry uint64
	final = uint64(bits.ReverseBytes16(initial))
	for _, v := range accumParts {
		final, carry = bits.Add64(final, v, carry)
	}

	return bits.ReverseBytes16(ipChecksumFold64(final, carry))
}

// checksumAVX512Intrinsics is an AVX512 AMD64 implementation of checksum using
// the platform simd package.
func checksumAVX512Intrinsics(b []byte, initial uint16) uint16 {
	if len(b) < minAMD64SIMD {
		return checksumGeneric64(b, initial)
	}

	var load archsimd.Uint8x32
	var acc archsimd.Uint32x16

	for len(b) > load.Len() {
		load = archsimd.LoadUint8x32(b)
		load16 := load.ReshapeToUint16s()
		acc = acc.Add(load16.ExtendToUint32())
		b = b[load.Len():]
	}
	if len(b) > 0 {
		load, _ = archsimd.LoadUint8x32Part(b)
		load16 := load.ReshapeToUint16s()
		acc = acc.Add(load16.ExtendToUint32())
		b = b[len(b):]
	}

	accumAs64 := acc.ReshapeToUint64s()
	accumParts := make([]uint64, accumAs64.Len())
	accumAs64.Store(accumParts)

	archsimd.ClearAVXUpperBits()

	var final, carry uint64
	final = uint64(bits.ReverseBytes16(initial))
	for _, v := range accumParts {
		final, carry = bits.Add64(final, v, carry)
	}

	return bits.ReverseBytes16(ipChecksumFold64(final, carry))
}
