//go:build ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package iobuf

var (
	MaxPooledBuffers = 1024 // Var to allow further reduction. Recreate [DefaultRawPool] if changed.
)

const MaxSegmentSize = 1700
