/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package iobuf

import (
	"testing"
	"unsafe"

	"github.com/tailscale/wireguard-go/waitpool"
)

func TestViewRelease(t *testing.T) {
	var released bool
	v := View{
		Recycler:   RecycleFunc(func(unsafe.Pointer, uintptr) { released = true }),
		BackingExt: 1,
		Bytes:      make([]byte, 1),
	}
	v.Release()
	if !released {
		t.Fatal("Recycler was not called on Release")
	}
	if v.Recycler != nil || v.BackingGo != nil || v.BackingExt != 0 || v.Bytes != nil {
		t.Fatal("View not zeroed after Release")
	}
	// Double release is safe.
	v.Release()
	// Unmanaged Release is a no-op.
	u := View{Bytes: make([]byte, 1)}
	u.Release() // must not panic
	if u.Bytes != nil {
		t.Fatal("unmanaged View not zeroed after Release")
	}
}

func TestViewClaim(t *testing.T) {
	var released bool
	orig := View{
		Recycler:   RecycleFunc(func(unsafe.Pointer, uintptr) { released = true }),
		BackingExt: 1,
		Bytes:      make([]byte, 1),
	}
	claimed := orig.Claim()
	// Source must be zeroed.
	if orig.Recycler != nil || orig.BackingGo != nil || orig.BackingExt != 0 || orig.Bytes != nil {
		t.Fatal("source not zeroed after Claim")
	}
	// Original Release is a no-op
	orig.Release()
	if released {
		t.Fatal("Recycler called when releasing moved copy")
	}
	// Claimed copy must carry ownership.
	if claimed.Recycler == nil || claimed.BackingExt != 1 {
		t.Fatal("claimed copy missing ownership fields")
	}
	claimed.Release()
	if !released {
		t.Fatal("Recycler not called when releasing claimed copy")
	}
}

func TestReleaseAll(t *testing.T) {
	var count int
	r := RecycleFunc(func(unsafe.Pointer, uintptr) { count++ })
	bufs := []View{
		{Recycler: r, BackingExt: 1, Bytes: make([]byte, 1)},
		{},
		{Recycler: r, BackingExt: 2, Bytes: make([]byte, 1)},
	}
	ReleaseAll(bufs)
	if count != 2 {
		t.Fatalf("expected 2 recycle calls, got %d", count)
	}
	for i, b := range bufs {
		if b.Recycler != nil || b.Bytes != nil {
			t.Fatalf("bufs[%d] not zeroed", i)
		}
	}
}

func TestRawPoolRoundTrip(t *testing.T) {
	pool := &RawPool{waitpool.New(0, func() any {
		return new(Raw)
	})}
	arr := pool.Get()
	arr[0] = 0xAB
	v := View{
		Recycler:  pool,
		BackingGo: unsafe.Pointer(arr),
		Bytes:     arr[:],
	}
	v.Release()
	got := pool.Get()
	if got[0] != 0xAB {
		t.Fatal("pool did not return the same backing array")
	}
}

func TestDefaultPoolHelpers(t *testing.T) {
	saved := DefaultRawPool
	DefaultRawPool = NewRawPool(0)
	defer func() { DefaultRawPool = saved }()

	bufs := make([]View, 3)
	Init(&bufs[1])
	bufs[1].Bytes[0] = 0xAB
	EnsureAllocated(bufs) // Init 0 and 2
	for i, v := range bufs {
		if v.Recycler != DefaultRawPool || v.Bytes == nil || v.BackingGo == nil {
			t.Fatalf("bufs[%d] not initialized", i)
		}
	}
	if bufs[1].Bytes[0] != 0xAB {
		t.Fatal("EnsureAllocated replaced an already-initialised View")
	}
	bufs[0].Release()
	if bufs[0].Recycler != nil || bufs[0].BackingGo != nil || bufs[0].Bytes != nil {
		t.Fatal("View not zeroed after Release")
	}
}
