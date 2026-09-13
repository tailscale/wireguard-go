//go:build android || windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"syscall"
)

// firstConn returns the first socket of a group, or an error if the group is
// empty. It exists for the platform hooks that reach a socket outside Send.
func firstConn(socks []*stdNetSocket) (*net.UDPConn, error) {
	if len(socks) == 0 {
		return nil, syscall.EINVAL
	}
	return socks[0].conn, nil
}
