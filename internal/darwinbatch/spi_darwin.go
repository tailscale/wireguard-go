//go:build darwin && !ts_omit_darwin_spi

// The only file that names sendmsg_x and recvmsg_x; spi_omit.go replaces it under ts_omit_darwin_spi. Like x/sys/unix, it calls the libc wrappers through an assembly trampoline rather than cgo, since Apple does not keep syscall numbers stable.
//
// Both functions are exported by libSystem in the public macOS SDK but declared only in xnu's socket_private.h.

package darwinbatch

import (
	"syscall"
	_ "unsafe" // for go:linkname
)

// syscall.syscall6 is the runtime's libc call path on darwin, reached by linkname as x/sys/unix does.
func syscall_syscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

//go:linkname syscall_syscall6 syscall.syscall6

//go:cgo_import_dynamic libc_sendmsg_x sendmsg_x "/usr/lib/libSystem.B.dylib"

var libc_sendmsg_x_trampoline_addr uintptr

//go:cgo_import_dynamic libc_recvmsg_x recvmsg_x "/usr/lib/libSystem.B.dylib"

var libc_recvmsg_x_trampoline_addr uintptr

// SendName and RecvName label errors. They are defined per build so an omit build does not contain the real names.
const (
	SendName = "sendmsg_x"
	RecvName = "recvmsg_x"
)

// spiAvailable is false in the omit build.
const spiAvailable = true

// sendmsgX is ssize_t sendmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags).
func sendmsgX(fd uintptr, msgs *msghdrX, cnt int, flags int) (int, syscall.Errno) {
	r, _, e := syscall_syscall6(libc_sendmsg_x_trampoline_addr, fd,
		uintptr(ptr(msgs)), uintptr(cnt), uintptr(flags), 0, 0)
	return int(r), e
}

// recvmsgX is ssize_t recvmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags).
func recvmsgX(fd uintptr, msgs *msghdrX, cnt int, flags int) (int, syscall.Errno) {
	r, _, e := syscall_syscall6(libc_recvmsg_x_trampoline_addr, fd,
		uintptr(ptr(msgs)), uintptr(cnt), uintptr(flags), 0, 0)
	return int(r), e
}
