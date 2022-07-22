/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2022 WireGuard LLC. All Rights Reserved.
 */

// Package conn implements WireGuard's network connections.
package conn

import (
	"testing"
)

func TestPrettyName(t *testing.T) {
	var (
		recvFunc ReceiveFunc = func(buffs [][]byte, sizes []int, eps []Endpoint) (n int, err error) { return }
	)

	const want = "TestPrettyName"

	t.Run("ReceiveFunc.PrettyName", func(t *testing.T) {
		if got := recvFunc.PrettyName(); got != want {
			t.Errorf("PrettyName() = %v, want %v", got, want)
		}
	})
}
