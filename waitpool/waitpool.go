/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

// Package waitpool provides a sync.Pool wrapper that caps the number of
// concurrently checked-out elements, blocking Get when the cap is reached.
package waitpool

import (
	"sync"
)

// WaitPool is a sync.Pool with an optional concurrency cap. When max > 0,
// Get blocks once max elements are checked out until a corresponding Put
// returns one. When max == 0 there is no cap and Get never blocks.
type WaitPool struct {
	pool  sync.Pool
	cond  sync.Cond
	lock  sync.Mutex
	count int // Get calls not yet Put back
	max   int
}

// New returns a WaitPool with the given concurrency cap and constructor.
// A max of 0 (or negative) disables the cap.
func New(max int, newFn func() any) *WaitPool {
	if max < 0 {
		max = 0
	}
	p := &WaitPool{pool: sync.Pool{New: newFn}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

// HasAccounting reports whether the pool enforces a concurrency cap.
func (p *WaitPool) HasAccounting() bool {
	return p != nil && p.max != 0
}

// Get returns an element from the pool, blocking if the concurrency cap is reached.
func (p *WaitPool) Get() any {
	if p.max != 0 {
		p.lock.Lock()
		for p.count >= p.max {
			p.cond.Wait()
		}
		p.count++
		p.lock.Unlock()
	}
	return p.pool.Get()
}

// Put returns an element to the pool and unblocks one waiting Get if any.
func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.count--
	p.cond.Signal()
}
