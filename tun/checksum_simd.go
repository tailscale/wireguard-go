package tun

import (
	"math/bits"
	"simd"

	"golang.org/x/sys/cpu"
)

// checksumGenericSIMD is a reference implementation of checksum using the
// platform-independent simd package.
func checksumGenericSIMD(b []byte, initial uint16) uint16 {
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

	var accum1, accum2 simd.Uint32s
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

		accum1 = accum1.Add(cur32a)
		accum2 = accum2.Add(cur32b)

		b = b[n:]
	}

	accumAs64 := accum1.Add(accum2).ReshapeToUint64s()
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

// checksumGenericSIMDAlternate is a reference implementation of checksum using
// the platform-independent simd package using saturating addition.
func checksumGenericSIMDAlternate(b []byte, initial uint16) uint16 {
	ones := simd.BroadcastUint16s(1)

	const streams = 1
	var carries [streams]simd.Uint16s
	var accum [streams]simd.Uint16s
	/*
		if len(b) > streams*2*accum[0].Len() {
			for len(b) > streams*2*accum[0].Len() {
				var cur16 [streams]simd.Uint16s
				for i := range streams {
					var cur8 simd.Uint8s
					cur8 = simd.LoadUint8s(b[cur8.Len()*i : cur8.Len()*(i+1)])
					cur16[i] = cur8.ReshapeToUint16s()
				}

				for i := range streams {
					saturated := accum[i].AddSaturated(cur16[i])
					accum[i] = accum[i].Add(cur16[i])

					carryDetect := accum[i].NotEqual(saturated)
					carries[i] = carries[i].Add(ones.Masked(carryDetect))
				}

				b = b[streams*2*accum[0].Len():]
			}

				for i := range streams / 2 {
					saturated := accum[i].AddSaturated(accum[i+4])
					accum[i] = accum[i].Add(accum[i+4])
					carryDetect := accum[i].NotEqual(saturated)
					carries[i] = carries[i].Add(carries[i+4].Add(ones.Masked(carryDetect)))
				}
				for i := range streams / 4 {
					saturated := accum[i].AddSaturated(accum[i+2])
					accum[i] = accum[i].Add(accum[i+2])
					carryDetect := accum[i].NotEqual(saturated)
					carries[i] = carries[i].Add(carries[i+2].Add(ones.Masked(carryDetect)))
				}
			saturated := accum[0].AddSaturated(accum[1])
			accum[0] = accum[0].Add(accum[1])
			carryDetect := accum[0].NotEqual(saturated)
			carries[0] = carries[0].Add(carries[1].Add(ones.Masked(carryDetect)))
		}
	*/

	for len(b) > 0 {
		cur8, n := simd.LoadUint8sPart(b)
		cur16 := cur8.ReshapeToUint16s()

		saturated := accum[0].AddSaturated(cur16)
		accum[0] = accum[0].Add(cur16)

		carryDetect := accum[0].NotEqual(saturated)
		carries[0] = carries[0].Add(ones.Masked(carryDetect))

		b = b[n:]
	}

	// Folding twice will always be enough.
	saturatedFold := accum[0].AddSaturated(carries[0])
	accum[0] = accum[0].Add(carries[0])

	carryDetect := accum[0].NotEqual(saturatedFold)
	accum[0] = accum[0].Add(ones.Masked(carryDetect))

	// Extract
	accumAs64 := accum[0].ReshapeToUint64s()
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
