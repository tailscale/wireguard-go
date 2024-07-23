package tun

import "golang.org/x/sys/cpu"

// Checksum computes an IP checksum starting with the provided initial value.
// The length of data should be at least 128 bytes for best performance. Smaller
// buffers will still compute a correct result.
var Checksum = checksumAMD64

func init() {
	if cpu.X86.HasAVX && cpu.X86.HasAVX2 && cpu.X86.HasBMI2 {
		Checksum = checksumAVX2
		return
	}
	if cpu.X86.HasSSE2 {
		Checksum = checksumSSE2
		return
	}
}
