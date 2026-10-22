//go:build unix && !linux && !aix && !solaris && !illumos

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// sharePort sets SO_REUSEADDR so connected sockets can bind specific addresses beside the wildcard socket, and the wildcard socket can be rebound while they hold the port.
//
// SO_REUSEPORT is not used: on a wildcard socket it lets any local user bind the port and take a peer's traffic. SO_REUSEADDR allows neither a second bind of the same address and port nor another user's bind of a specific address.
func sharePort(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return serr
}
