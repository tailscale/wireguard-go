/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync/atomic"
	"testing"
)

func TestPacketBufRefCount(t *testing.T) {
	var cleanups atomic.Int32
	buf := newPacketBuf(0, func(buf *packetBuf) {
		cleanups.Add(1)
	})
	if buf.refCount.Load() != 0 {
		t.Fatalf("buf.refCount initialized nonzero: %d", buf.refCount.Load())
	}
	buf.incRef()
	buf.incRef()
	if buf.refCount.Load() != 2 {
		t.Fatalf("buf.refCount = %d, want 2", buf.refCount.Load())
	}
	buf.decRef()
	if got := cleanups.Load(); got != 0 {
		t.Fatalf("cleanup count after first decRef = %d, want 0", got)
	}
	buf.decRef()
	if cleanups.Load() != 1 {
		t.Fatalf("cleanup count = %d, want 1", cleanups.Load())
	}
	if got := buf.refCount.Load(); got != 0 {
		t.Fatalf("final ref count = %d, want 0", got)
	}
}

func TestPacketBufRefCountUnderflow(t *testing.T) {
	var cleanups atomic.Int32
	buf := newPacketBuf(0, func(*packetBuf) {
		cleanups.Add(1)
	})

	defer func() {
		if recover() == nil {
			t.Fatal("decRef did not panic on underflow")
		}
		if got := cleanups.Load(); got != 0 {
			t.Fatalf("cleanup count = %d, want 0", got)
		}
	}()

	buf.decRef()
}

func TestGetPacketBufOwnsReference(t *testing.T) {
	device := new(Device)
	device.pool.packetBufs = NewWaitPool(0, func() any {
		return newPacketBuf(0, func(buf *packetBuf) {
			device.pool.packetBufs.Put(buf)
		})
	})

	buf := device.getPacketBuf()
	if got := buf.refCount.Load(); got != 1 {
		t.Fatalf("buf.refCount = %d, want 1", got)
	}
	buf.decRef()
}
