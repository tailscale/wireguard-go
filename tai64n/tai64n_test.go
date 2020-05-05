/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package tai64n

import (
	"testing"
	"time"
)

// Test that timestamps are monotonic as required by Wireguard and that
// nanosecond-level information is whitened to prevent side channel attacks.
func TestMonotonic(t *testing.T) {
	ts := []Timestamp{
		stamp(time.Unix(0, 123123456)),
		stamp(time.Unix(0, 123123654)), // within the same microsecond
		stamp(time.Unix(0, 133456123)), // in ~10 milliseconds
		stamp(time.Unix(0, 143321654)), // in ~20 milliseconds
	}

	// Timestamps in Wireguard must grow monotonically with passage of time.
	for i := 0; i < len(ts)-1; i++ {
		if ts[i].After(ts[i+1]) {
			t.Error("Timestamps not monotonic")
		}
	}

	// Whitening should reduce timestamp granularity
	// to more than 10 but fewer than 20 milliseconds.
	if ts[1].After(ts[0]) || ts[2].After(ts[0]) {
		t.Error("Whitening insufficient")
	}
	if !ts[3].After(ts[0]) {
		t.Error("Not monotonically increasing on whitened nano-second scale")
	}
}
