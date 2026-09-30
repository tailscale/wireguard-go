//go:build !darwin

package conn

import "syscall"

const dontFragmentSupported = false

func setDontFragment(string, syscall.RawConn) error { return nil }
