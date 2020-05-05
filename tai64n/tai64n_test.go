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
	// Whitening should reduce timestamp granularity
	// to more than 10 but fewer than 20 milliseconds.
	tests := []struct {
		name      string
		t1, t2    time.Time
		wantAfter bool
	}{
		{"same_microsecond", time.Unix(0, 123123456), time.Unix(0, 123123654), false},
		{"10_milliseconds", time.Unix(0, 123123456), time.Unix(0, 133456123), false},
		{"20_milliseconds", time.Unix(0, 123123456), time.Unix(0, 143321654), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts1, ts2 := stamp(tt.t1), stamp(tt.t2)
			got := ts2.After(ts1)
			if got != tt.wantAfter {
				t.Errorf("after = %v; want %v", got, tt.wantAfter)
			}
		})
	}
}
