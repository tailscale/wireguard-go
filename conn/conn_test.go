/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"testing"

	"github.com/tailscale/wireguard-go/buffer"
)

func TestPrettyName(t *testing.T) {
	var (
		recvFunc ReceiveFunc = func(stacks []buffer.Stack, eps []Endpoint) (n int, err error) { return }
	)

	const want = "TestPrettyName"

	t.Run("ReceiveFunc.PrettyName", func(t *testing.T) {
		if got := recvFunc.PrettyName(); got != want {
			t.Errorf("PrettyName() = %v, want %v", got, want)
		}
	})
}
