/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package iobuf

import (
	"errors"
	"sync/atomic"
	"unsafe"

	"github.com/tailscale/wireguard-go/waitpool"
)

var _ Recycler = (*Shared)(nil)

// Shared is a backing array that can be shared by multiple Views.
// It implements [Recycler], and will return itself to the [Pool] when all
// Views referring to it are released. It counts self as reference, and must be
// released as well.
type Shared struct {
	Bytes         Raw
	BytesRecycler Recycler
	Refs          atomic.Int32
}

// Refer sets b to refer to a slice of the backing array.
func (s *Shared) Refer(b *View, start, end int) {
	b.Recycler = s
	b.BackingGo = unsafe.Pointer(s)
	s.Refs.Add(1)
	b.Bytes = s.Bytes[start:end:end]
}

// Recycle is called by a View's Release when the View is no longer in use.
func (s *Shared) Recycle(goPtr unsafe.Pointer, _ uintptr) {
	if s.BytesRecycler != nil && s.Refs.Add(-1) == 0 {
		s.BytesRecycler.Recycle(goPtr, 0) // return to pool
	}
}

// Release this instance for reuse. Should be called exactly once, and will
// keep its Views alive until they are released as well.
func (s *Shared) Release() {
	s.Recycle(unsafe.Pointer(s), 0)
}

var (
	ErrStrideOutOfRange    = errors.New("buffer: stride must be > 0 and <= readLen")
	ErrReadLenOverflow     = errors.New("buffer: readLen exceeds buffer capacity")
	ErrInsufficientBuffers = errors.New("buffer: insufficient buffers")
)

// SplitCoalesced fills vs with non-overlapping slices of the backing array,
// where stride is the desired slice length, and readLen is the total length of data to split.
// The last slice may be shorter than stride if readLen is not a multiple of stride.
func (s *Shared) SplitCoalesced(vs []View, stride, readLen int) (n int, err error) {
	if readLen > len(s.Bytes) {
		return 0, ErrReadLenOverflow
	}
	if stride <= 0 || stride > readLen {
		return 0, ErrStrideOutOfRange
	}
	numToSplit := (readLen + stride - 1) / stride
	if numToSplit > len(vs) {
		return 0, ErrInsufficientBuffers
	}
	start, end := 0, stride
	for i := range numToSplit {
		s.Refer(&vs[i], start, end)
		start = end
		end += stride
		if end > readLen {
			end = readLen
		}
	}
	return numToSplit, nil
}

// SharedBufPool is used for package-level [Get] and [EnsureAllocated].
var SharedBufPool = NewSharedBufferPool(MaxPooledBuffers)

// SharedBufferPool is a capped pool of backing arrays.
type SharedBufferPool struct {
	*waitpool.WaitPool
}

func NewSharedBufferPool(limit int) *SharedBufferPool {
	pool := &SharedBufferPool{}
	pool.WaitPool = waitpool.New(limit, func() any {
		p := new(Shared)
		p.BytesRecycler = pool
		return p
	})
	return pool
}

func (p *SharedBufferPool) Get() *Shared {
	arr := p.WaitPool.Get().(*Shared)
	arr.Refs.Store(1) // *Shared must be Released as well.
	return arr
}

// Recycle returns the buffer to the pool.
func (p *SharedBufferPool) Recycle(goPtr unsafe.Pointer, _ uintptr) {
	arr := (*Shared)(goPtr)
	p.Put(arr)
}
