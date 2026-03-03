//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package iobuf

const (
	MaxSegmentSize   = 2048 - 32
	MaxPooledBuffers = 0 // Disable and allow for infinite memory growth
)
