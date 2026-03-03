//go:build !android && !ios && !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package iobuf

const (
	MaxSegmentSize   = (1 << 16) - 1
	MaxPooledBuffers = 0 // Disable and allow for infinite memory growth
)
