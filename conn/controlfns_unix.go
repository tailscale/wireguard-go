//go:build !windows && !linux && !js

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 */

package conn

import "syscall"

func init() {
	controlFns = append(controlFns,
		// Set SO_RCVBUF/SO_SNDBUF - this could be common with the _unix code except
		// for the unfortunate type specificity of syscall.Handle.
		func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, socketBufferSize)
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, socketBufferSize)
			})
		},
	)
}
