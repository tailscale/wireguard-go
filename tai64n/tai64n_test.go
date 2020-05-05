/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package tai64n

import (
	"testing"
	"time"
)

/* Testing the essential property of the timestamp
 * as used by WireGuard.
 */
func TestMonotonic(t *testing.T) {
	startTime := time.Now()
	nanosToNext := whitenerMask - uint32(startTime.Nanosecond())&whitenerMask
	sameTime := startTime.Add(time.Duration(nanosToNext) * time.Nanosecond)
	nextTime := startTime.Add(time.Duration(nanosToNext)*time.Nanosecond + 1)

	start, same, next := stamp(startTime), stamp(sameTime), stamp(nextTime)
	if same.After(start) {
		t.Error("Whitening insufficient")
	}
	if !next.After(start) {
		t.Error("Not monotonically increasing on whitened nano-second scale")
	}
}
