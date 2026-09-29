package tun

import (
	"math/bits"
	"simd"
	"strconv"

	"golang.org/x/sys/cpu"
)

const minGenericSIMD = 64

// checksumSIMDExtend is a [simd] implementation of checksum and uses uint32
// computation to simulate add-with-carry.
func checksumSIMDExtend(b []byte, initial uint16) uint16 {
	if len(b) < minGenericSIMD {
		if strconv.IntSize < 64 {
			return checksumGeneric32(b, initial)
		}
		return checksumGeneric64(b, initial)
	}

	var maskLoader simd.Int16s
	maskSeed := make([]int16, maskLoader.Len())
	for i := range maskSeed {
		if i%2 == 0 {
			maskSeed[i] = -1
		}
	}
	maskLoader = simd.LoadInt16s(maskSeed)
	topMask := maskLoader.ToMask()
	bottomMask := maskLoader.Not().ToMask()

	var accum1a, accum1b, accum2a, accum2b, accum3a, accum3b, accum4a, accum4b simd.Uint32s
	minMultiStream := 32 * accum1a.Len()
	if len(b) > minMultiStream {
		var cur8 simd.Uint8s
		for len(b) > cur8.Len()*4 {
			var cur16 simd.Uint16s
			var cur32a, cur32b simd.Uint32s

			cur8 = simd.LoadUint8s(b)
			b = b[cur8.Len():]
			cur16 = cur8.ReshapeToUint16s()
			if cpu.IsBigEndian {
				cur32a = cur16.Masked(bottomMask).ReshapeToUint32s()
				cur32b = cur16.Masked(topMask).ReshapeToUint32s().ShiftAllRight(16)
			} else {
				cur32a = cur16.Masked(topMask).ReshapeToUint32s()
				cur32b = cur16.Masked(bottomMask).ReshapeToUint32s().ShiftAllRight(16)
			}
			accum1a = accum1a.Add(cur32a)
			accum1b = accum1b.Add(cur32b)

			cur8 = simd.LoadUint8s(b)
			b = b[cur8.Len():]
			cur16 = cur8.ReshapeToUint16s()
			if cpu.IsBigEndian {
				cur32a = cur16.Masked(bottomMask).ReshapeToUint32s()
				cur32b = cur16.Masked(topMask).ReshapeToUint32s().ShiftAllRight(16)
			} else {
				cur32a = cur16.Masked(topMask).ReshapeToUint32s()
				cur32b = cur16.Masked(bottomMask).ReshapeToUint32s().ShiftAllRight(16)
			}
			accum2a = accum2a.Add(cur32a)
			accum2b = accum2b.Add(cur32b)

			cur8 = simd.LoadUint8s(b)
			b = b[cur8.Len():]
			cur16 = cur8.ReshapeToUint16s()
			if cpu.IsBigEndian {
				cur32a = cur16.Masked(bottomMask).ReshapeToUint32s()
				cur32b = cur16.Masked(topMask).ReshapeToUint32s().ShiftAllRight(16)
			} else {
				cur32a = cur16.Masked(topMask).ReshapeToUint32s()
				cur32b = cur16.Masked(bottomMask).ReshapeToUint32s().ShiftAllRight(16)
			}
			accum3a = accum3a.Add(cur32a)
			accum3b = accum3b.Add(cur32b)

			cur8 = simd.LoadUint8s(b)
			b = b[cur8.Len():]
			cur16 = cur8.ReshapeToUint16s()
			if cpu.IsBigEndian {
				cur32a = cur16.Masked(bottomMask).ReshapeToUint32s()
				cur32b = cur16.Masked(topMask).ReshapeToUint32s().ShiftAllRight(16)
			} else {
				cur32a = cur16.Masked(topMask).ReshapeToUint32s()
				cur32b = cur16.Masked(bottomMask).ReshapeToUint32s().ShiftAllRight(16)
			}
			accum4a = accum4a.Add(cur32a)
			accum4b = accum4b.Add(cur32b)
		}

		// Combine 1 and 2 into 1, 3 and 4 into 2
		accum1a = accum1a.Add(accum2a)
		accum1b = accum1b.Add(accum2b)
		accum2a = accum3a.Add(accum4a)
		accum2b = accum3b.Add(accum4b)

		// Combine 1 and 2 into 1
		accum1a = accum1a.Add(accum2a)
		accum1b = accum1b.Add(accum2b)
	}
	for len(b) > 0 {
		cur8, n := simd.LoadUint8sPart(b)
		cur16 := cur8.ReshapeToUint16s()

		var cur32a, cur32b simd.Uint32s
		if cpu.IsBigEndian {
			cur32a = cur16.Masked(bottomMask).ReshapeToUint32s()
			cur32b = cur16.Masked(topMask).ReshapeToUint32s().ShiftAllRight(16)
		} else {
			cur32a = cur16.Masked(topMask).ReshapeToUint32s()
			cur32b = cur16.Masked(bottomMask).ReshapeToUint32s().ShiftAllRight(16)
		}

		accum1a = accum1a.Add(cur32a)
		accum1b = accum1b.Add(cur32b)

		b = b[n:]
	}

	accumAs64 := accum1a.Add(accum1b).ReshapeToUint64s()
	accumParts := make([]uint64, accumAs64.Len())
	accumAs64.Store(accumParts)

	var final, carry uint64
	if cpu.IsBigEndian {
		final = uint64(initial)
	} else {
		final = uint64(bits.ReverseBytes16(initial))
	}
	for _, v := range accumParts {
		final, carry = bits.Add64(final, v, carry)
	}

	folded := ipChecksumFold64(final, carry)
	if !cpu.IsBigEndian {
		folded = bits.ReverseBytes16(folded)
	}
	return folded
}

// checksumSIMDSaturate is a [simd] implementation of checksum and uses normal
// addition alongside saturated addition to simulate add-with-carry.
func checksumSIMDSaturate(b []byte, initial uint16) uint16 {
	if len(b) < minGenericSIMD {
		if strconv.IntSize < 64 {
			return checksumGeneric32(b, initial)
		}
		return checksumGeneric64(b, initial)
	}

	ones := simd.BroadcastUint16s(1)

	var accum1, accum2, accum3, accum4 simd.Uint16s
	var carry1, carry2, carry3, carry4 simd.Uint16s
	minMultiStream := 16 * accum1.Len()
	if len(b) > minMultiStream {
		var cur8 simd.Uint8s
		var saturated simd.Uint16s
		var carryDetect simd.Mask16s
		for len(b) > cur8.Len()*4 {
			var cur16 simd.Uint16s

			cur8 = simd.LoadUint8s(b[:cur8.Len()])
			b = b[cur8.Len():]
			cur16 = cur8.ReshapeToUint16s()
			saturated = accum1.AddSaturated(cur16)
			accum1 = accum1.Add(cur16)
			carryDetect = accum1.NotEqual(saturated)
			carry1 = carry1.Add(ones.Masked(carryDetect))

			cur8 = simd.LoadUint8s(b[:cur8.Len()])
			b = b[cur8.Len():]
			cur16 = cur8.ReshapeToUint16s()
			saturated = accum2.AddSaturated(cur16)
			accum2 = accum2.Add(cur16)
			carryDetect = accum2.NotEqual(saturated)
			carry2 = carry2.Add(ones.Masked(carryDetect))

			cur8 = simd.LoadUint8s(b[:cur8.Len()])
			b = b[cur8.Len():]
			cur16 = cur8.ReshapeToUint16s()
			saturated = accum3.AddSaturated(cur16)
			accum3 = accum3.Add(cur16)
			carryDetect = accum3.NotEqual(saturated)
			carry3 = carry3.Add(ones.Masked(carryDetect))

			cur8 = simd.LoadUint8s(b[:cur8.Len()])
			b = b[cur8.Len():]
			cur16 = cur8.ReshapeToUint16s()
			saturated = accum4.AddSaturated(cur16)
			accum4 = accum4.Add(cur16)
			carryDetect = accum4.NotEqual(saturated)
			carry4 = carry4.Add(ones.Masked(carryDetect))
		}

		// Combine 1 and 2 into 1, 3 and 4 into 2
		carry1 = carry1.Add(carry2)
		saturated = accum1.AddSaturated(accum2)
		accum1 = accum1.Add(accum2)
		carryDetect = accum1.NotEqual(saturated)
		carry1 = carry1.Add(ones.Masked(carryDetect))

		carry2 = carry3.Add(carry4)
		saturated = accum3.AddSaturated(accum4)
		accum2 = accum3.Add(accum4)
		carryDetect = accum2.NotEqual(saturated)
		carry2 = carry2.Add(ones.Masked(carryDetect))

		// Combine 1 and 2 into 1
		carry1 = carry1.Add(carry2)
		saturated = accum1.AddSaturated(accum2)
		accum1 = accum1.Add(accum2)
		carryDetect = accum1.NotEqual(saturated)
		carry1 = carry1.Add(ones.Masked(carryDetect))
	}

	for len(b) > 0 {
		cur8, n := simd.LoadUint8sPart(b)
		cur16 := cur8.ReshapeToUint16s()

		saturated := accum1.AddSaturated(cur16)
		accum1 = accum1.Add(cur16)

		carryDetect := accum1.NotEqual(saturated)
		carry1 = carry1.Add(ones.Masked(carryDetect))

		b = b[n:]
	}

	// Fold
	saturated := accum1.AddSaturated(carry1)
	accum1 = accum1.Add(carry1)

	carryDetect := accum1.NotEqual(saturated)
	accum1 = accum1.Add(ones.Masked(carryDetect))

	// Extract
	accumAs64 := accum1.ReshapeToUint64s()
	accumParts := make([]uint64, accumAs64.Len())
	accumAs64.Store(accumParts)

	// Combine
	var final, carry uint64
	if cpu.IsBigEndian {
		final = uint64(initial)
	} else {
		final = uint64(bits.ReverseBytes16(initial))
	}
	for _, v := range accumParts {
		final, carry = bits.Add64(final, v, carry)
	}

	folded := ipChecksumFold64(final, carry)
	if !cpu.IsBigEndian {
		folded = bits.ReverseBytes16(folded)
	}
	return folded
}
