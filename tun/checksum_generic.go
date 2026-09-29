// This file contains IP checksum algorithms that are not specific to any
// architecture and don't use hardware acceleration.

//go:build !amd64

package tun

import (
	"simd"
	"strconv"
)

func Checksum(data []byte, initial uint16) uint16 {
	if !simd.Emulated() {
		return checksumGenericSIMD(data, initial)
	}

	if strconv.IntSize < 64 {
		return checksumGeneric32(data, initial)
	}
	return checksumGeneric64(data, initial)
}
