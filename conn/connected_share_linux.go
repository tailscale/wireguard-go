//go:build linux

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// sharePort sets SO_REUSEPORT, which Linux limits to sockets of the same effective user ID.
//
// Do not add SO_REUSEADDR: UDP sockets that all set it can share a port with no user check, so any local process could bind the port and take a peer's traffic.
func sharePort(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return serr
}
