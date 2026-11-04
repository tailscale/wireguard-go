// SPDX-License-Identifier: MIT

package peerindex_test

import (
	"fmt"
	"testing"

	"github.com/tailscale/wireguard-go/peerindex"
)

func BenchmarkTableLookup(b *testing.B) {
	for _, size := range []int{1, 1024, 65536} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			var table peerindex.Table[int]
			indexes := make([]uint32, size)
			for i := range indexes {
				var err error
				indexes[i], err = table.Allocate(i)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				i := 0
				for pb.Next() {
					if owner, ok := table.Lookup(indexes[i]); !ok || owner != i {
						b.Error("misroute")
						return
					}
					i++
					if i == len(indexes) {
						i = 0
					}
				}
			})
		})
	}
}
