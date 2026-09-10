/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

func (s *StdNetBind) PeekLookAtSocketFd4() (fd int, err error) {
	conn, err := firstConn(s.v4) // Single-queue on Android, see StdNetBind.Open.
	if err != nil {
		return -1, err
	}
	sysconn, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}

func (s *StdNetBind) PeekLookAtSocketFd6() (fd int, err error) {
	conn, err := firstConn(s.v6) // Single-queue on Android, see StdNetBind.Open.
	if err != nil {
		return -1, err
	}
	sysconn, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	err = sysconn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return
}
