/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package iobuf

import (
	"bytes"
	"testing"
)

func TestSharedReferRecycle(t *testing.T) {
	pool := NewSharedBufferPool(0)
	s := pool.Get()
	if got := s.Refs.Load(); got != 1 {
		t.Fatalf("Get: Refs = %d, want 1 (pool pre-increment)", got)
	}
	var v1, v2 View
	s.Refer(&v1, 0, 4)
	s.Refer(&v2, 4, 8)
	if got := s.Refs.Load(); got != 3 {
		t.Fatalf("after two Refer: Refs = %d, want 3", got)
	}
	v1.Release()
	if got := s.Refs.Load(); got != 2 {
		t.Fatalf("after v1.Release: Refs = %d, want 2", got)
	}
	v2.Release()
	if got := s.Refs.Load(); got != 1 {
		t.Fatalf("after v2.Release: Refs = %d, want 1", got)
	}
	// Only the matching Shared.Release returns to the pool.
	s.Bytes[0] = 0xAB
	s.Release()
	got := pool.Get()
	if got != s {
		t.Fatal("pool did not return the same *Shared after full Release")
	}
	if got.Bytes[0] != 0xAB {
		t.Fatal("pool did not preserve backing array contents")
	}
	if r := got.Refs.Load(); r != 1 {
		t.Fatalf("pool.Get Refs = %d, want 1", r)
	}
}

func TestSharedNilRecyclerRelease(t *testing.T) {
	// An unmanaged Shared (nil BytesRecycler) is GC-managed; draining its refs
	// to zero must not panic — Recycle no-ops instead of returning to a pool.
	s := &Shared{}
	s.Refs.Store(1)
	var v View
	s.Refer(&v, 0, 4)
	v.Release()
	s.Release() // drives Refs to 0; must not deref the nil recycler
	if got := s.Refs.Load(); got != 0 {
		t.Fatalf("after full release: Refs = %d, want 0", got)
	}
}

func BenchmarkSplitCoalesced(b *testing.B) {
	s := &Shared{}
	for i := range s.Bytes {
		s.Bytes[i] = byte(i)
	}
	vs := make([]View, 64)
	for b.Loop() {
		_, err := s.SplitCoalesced(vs, 1, 64)
		if err != nil {
			b.Fatal(err)
		}
	}

}

func TestSplitCoalesced(t *testing.T) {
	const numViews = 10
	tests := []struct {
		name    string
		stride  int
		readLen int
		wantN   int
		wantErr error
	}{
		{
			name:    "non-divisible stride",
			stride:  3,
			readLen: 16,
			wantN:   6,
		},
		{
			name:    "exact stride",
			stride:  2,
			readLen: 16,
			wantN:   8,
		},
		{
			name:    "single segment",
			stride:  16,
			readLen: 16,
			wantN:   1,
		},
		{
			name:    "stride zero",
			stride:  0,
			readLen: 16,
			wantErr: ErrStrideOutOfRange,
		},
		{
			name:    "stride negative",
			stride:  -1,
			readLen: 16,
			wantErr: ErrStrideOutOfRange,
		},
		{
			name:    "stride exceeds readLen",
			stride:  17,
			readLen: 16,
			wantErr: ErrStrideOutOfRange,
		},
		{
			name:    "insufficient buffers",
			stride:  1,
			readLen: 16,
			wantErr: ErrInsufficientBuffers,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Shared{}
			for i := 0; i < tc.readLen && i < len(s.Bytes); i++ {
				s.Bytes[i] = byte(i)
			}
			vs := make([]View, numViews)

			n, err := s.SplitCoalesced(vs, tc.stride, tc.readLen)
			if err != tc.wantErr {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
			if n != tc.wantN {
				t.Fatalf("expected %d segments, got %d", tc.wantN, n)
			}

			srcOff := 0
			for i, v := range vs[:n] {
				got := v.Bytes
				wantLen := tc.stride
				if i == n-1 {
					wantLen = tc.readLen - (n-1)*tc.stride
				}
				if len(got) != wantLen {
					t.Fatalf("segment %d: expected len %d, got %d", i, wantLen, len(got))
				}
				want := s.Bytes[srcOff : srcOff+wantLen]
				if !bytes.Equal(got, want) {
					t.Fatalf("segment %d: data mismatch: got %v, want %v", i, got, want)
				}
				srcOff += wantLen
			}
		})
	}
}
