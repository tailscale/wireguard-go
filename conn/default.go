//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

func NewDefaultBind(opts ...Option) Bind { return NewStdNetBind(opts...) }
