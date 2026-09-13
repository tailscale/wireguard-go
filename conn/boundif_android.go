/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

func (s *StdNetBind) PeekLookAtSocketFd4() (fd int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, err := firstConn(s.v4)
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
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, err := firstConn(s.v6)
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
