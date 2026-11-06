// SPDX-License-Identifier: MIT

//go:build ts_lowmem_release

package tun

func releaseGROPacketReferences(packets [][]byte) {
	clear(packets)
}
