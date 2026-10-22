//go:build darwin

package conn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const dontFragmentSupported = true

// setDontFragment sets IP_DONTFRAG or IPV6_DONTFRAG; see [WithDontFragment].
func setDontFragment(network string, c syscall.RawConn) error {
	level, opt := unix.IPPROTO_IP, unix.IP_DONTFRAG
	if network == "udp6" {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG
	}
	var serr error
	if err := c.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), level, opt, 1) }); err != nil {
		return err
	}
	return serr
}
