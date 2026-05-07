// SPDX-License-Identifier: BSD-3-Clause

//go:build arm

package poly1305

import (
	"crypto/rand"
	"fmt"
	"testing"

	xpoly1305 "golang.org/x/crypto/poly1305"
)

// Bench Poly1305 alone at multiple sizes to surface where NEON dispatch
// might amortize transfer costs.
func BenchmarkSum(b *testing.B) {
	for _, size := range []int{1436, 4096, 16384} {
		size := size
		var key [32]byte
		rand.Read(key[:])
		msg := make([]byte, size)
		rand.Read(msg)
		b.Run(fmt.Sprintf("%d/xcrypto", size), func(b *testing.B) {
			var tag [16]byte
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				xpoly1305.Sum(&tag, msg, &key)
			}
		})
		b.Run(fmt.Sprintf("%d/asm", size), func(b *testing.B) {
			var tag [16]byte
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				Sum(&tag, msg, &key)
			}
		})
	}
}
