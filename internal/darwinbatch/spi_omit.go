//go:build darwin && ts_omit_darwin_spi

// Stubs for the ts_omit_darwin_spi build, which has no reference to sendmsg_x or recvmsg_x.

package darwinbatch

import "syscall"

// Placeholders, since this build must not contain the real names.
const (
	SendName = "batched-send"
	RecvName = "batched-recv"
)

const spiAvailable = false

func sendmsgX(fd uintptr, msgs *msghdrX, cnt int, flags int) (int, syscall.Errno) {
	return 0, syscall.ENOSYS
}

func recvmsgX(fd uintptr, msgs *msghdrX, cnt int, flags int) (int, syscall.Errno) {
	return 0, syscall.ENOSYS
}
