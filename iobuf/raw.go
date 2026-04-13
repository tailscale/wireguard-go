/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package iobuf

import (
	"unsafe"

	"github.com/tailscale/wireguard-go/waitpool"
)

var _ Recycler = (*RawPool)(nil)

// Raw is the fundamental byte array.
type Raw [MaxBufferSize]byte

// RawPool wraps [waitpool.WaitPool] of [Raw] buffers
// to configure their return via [RawPool.Recycle].
type RawPool struct {
	*waitpool.WaitPool
}

func (p *RawPool) Get() *Raw {
	return p.WaitPool.Get().(*Raw)
}

// Recycle returns the backing array of v to the pool.
func (p *RawPool) Recycle(goPtr unsafe.Pointer, _ uintptr) {
	arr := (*Raw)(goPtr)
	p.Put(arr)
}

func NewRawPool(size int) *RawPool {
	return &RawPool{waitpool.New(size, func() any {
		return new(Raw)
	})}
}

// DefaultRawPool is used for package-level [Init] and [EnsureAllocated].
var DefaultRawPool = NewRawPool(MaxPooledBuffers)

// HasAccounting reports whether the default raw-buffer pool enforces a
// concurrency cap. Callers use it to decide whether allocation can block,
// and therefore whether queue finalizers are needed to drain blocked
// producers when an autodraining queue is GC'd.
func HasAccounting() bool {
	return DefaultRawPool.HasAccounting()
}

// EnsureAllocated fills zero-valued Views from the [DefaultRawPool].
func EnsureAllocated(bufs []View) {
	for i := range bufs {
		if bufs[i].Bytes == nil {
			Init(&bufs[i])
		}
	}
}

// Init initializes a [View] in-place with a fresh backing from the pool.
// Sets Bytes to the full backing array.
func Init(b *View) {
	arr := DefaultRawPool.Get()
	b.Recycler = DefaultRawPool
	b.BackingGo = unsafe.Pointer(arr)
	b.Bytes = arr[:]
}
