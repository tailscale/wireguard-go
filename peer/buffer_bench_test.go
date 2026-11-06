// SPDX-License-Identifier: MIT

package peer

import (
	"fmt"
	"testing"
)

// Measure descriptor preflight only, not crypto or payload throughput. Address
// order must not select a more expensive algorithm for otherwise valid batches.
func BenchmarkPacketBounds(b *testing.B) {
	for _, send := range []bool{true, false} {
		direction := "Receive"
		if send {
			direction = "Send"
		}
		for _, reversed := range []bool{false, true} {
			order := "ordered"
			if reversed {
				order = "reversed"
			}
			for _, batch := range []int{16, 64, 256} {
				b.Run(fmt.Sprintf("%s/%s/batch=%d", direction, order, batch), func(b *testing.B) {
					packets := benchPackets(batch, 1280)
					if reversed {
						for i, j := 0, len(packets)-1; i < j; i, j = i+1, j-1 {
							packets[i], packets[j] = packets[j], packets[i]
						}
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if err := validatePackets(packets, 1420, send); err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
					reportPackets(b, batch)
				})
			}
		}
	}
}
