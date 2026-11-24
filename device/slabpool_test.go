// Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
// SPDX-License-Identifier: MIT

package device

import (
	"testing"
	"time"
)

// With every big slab in flight, get hands out a small slab at once instead of waiting, and big ones again once one is back.
func TestSlabPoolFallsBackWhenExhausted(t *testing.T) {
	const size, limit = 1 << 20, 2
	p := newSlabPool(size, limit)
	var held []*packetBuf
	for range limit {
		b := p.get()
		if len(b.slab) != size {
			t.Fatalf("slab of %d bytes before the pool is exhausted, want %d", len(b.slab), size)
		}
		held = append(held, b)
	}
	got := make(chan *packetBuf)
	go func() { got <- p.get() }()
	var small *packetBuf
	select {
	case small = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("get waited for a slab with every one in flight")
	}
	if len(small.slab) != p.smallSize() {
		t.Fatalf("fallback slab of %d bytes, want %d", len(small.slab), p.smallSize())
	}
	small.decRef()
	held[0].decRef()
	if b := p.get(); len(b.slab) != size {
		t.Fatalf("slab of %d bytes after a big one came back, want %d", len(b.slab), size)
	}
}
