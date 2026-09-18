//go:build !amd64

package tun

import "simd"

var archChecksumFuncs = []archChecksumDetails{
	{
		name:      "generic32",
		available: true,
		f:         checksumGeneric32,
	},
	{
		name:      "generic32Alternate",
		available: true,
		f:         checksumGeneric32Alternate,
	},
	{
		name:      "generic64",
		available: true,
		f:         checksumGeneric64,
	},
	{
		name:      "generic64Alternate",
		available: true,
		f:         checksumGeneric64Alternate,
	},
	{
		name:      "genericSIMD",
		available: !simd.Emulated() && simd.VectorBitSize() >= 64,
		f:         checksumGenericSIMD,
	},
}
