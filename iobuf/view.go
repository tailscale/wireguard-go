/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

// Package iobuf provides pooled packet buffers for the I/O pipeline.
// Each [View] carries one packet and a recycle function that returns
// its backing storage to the originating pool on [Release].
package iobuf

import "unsafe"

// Recycler returns the backing of a [View] to its source for reuse.
// Implementations read whichever of [View.BackingGo] or [View.BackingExt]
// matches their allocation strategy.
type Recycler interface {
	Recycle(unsafe.Pointer, uintptr)
}

// RecycleFunc is a function adapter for [Recycler].
type RecycleFunc func(unsafe.Pointer, uintptr)

func (f RecycleFunc) Recycle(goPtr unsafe.Pointer, extPtr uintptr) { f(goPtr, extPtr) }

// View is the packet envelope. Meant to be a value type,
// allocated once per goroutine and reused across read cycles.
//
// Exactly one of BackingGo / BackingExt is set for a managed View
// (Recycler != nil). Both are zero for unmanaged Views.
type View struct {
	Recycler Recycler

	// BackingGo holds a Go-allocated backing object. Zero otherwise.
	BackingGo unsafe.Pointer

	// BackingExt holds an opaque address into off-heap memory (e.g. a
	// WinRio ring slot, an AF_XDP region). Zero otherwise.
	BackingExt uintptr

	// Bytes holds the bounded packet data. Cut from the backing,
	// it may be re-sliced by the caller. Do not append() on this slice.
	// Nil for uninitialized Views.
	Bytes []byte
}

// Release returns the backing data to its source and zeros the View.
func (b *View) Release() {
	if b.Recycler != nil {
		b.Recycler.Recycle(b.BackingGo, b.BackingExt)
	}
	*b = View{}
}

// Claim transfers ownership: returns a copy of the View and zeros the source.
func (b *View) Claim() View {
	c := *b
	*b = View{}
	return c
}

// ReleaseAll releases each View in the slice.
func ReleaseAll(bufs []View) {
	for i := range bufs {
		bufs[i].Release()
	}
}
