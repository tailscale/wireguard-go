// SPDX-License-Identifier: MIT

package peerindex_test

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/tailscale/wireguard-go/peerindex"
)

// indexEntropy supplies index candidates, then repeats fallback. It accepts
// only four-byte reads so allocation changes cannot silently alter the test.
type indexEntropy struct {
	values   []uint32
	fallback uint32
	calls    int
}

func (r *indexEntropy) Read(p []byte) (int, error) {
	if len(p) != 4 {
		panic("unexpected index entropy request")
	}
	v := r.fallback
	if r.calls < len(r.values) {
		v = r.values[r.calls]
	}
	r.calls++
	binary.LittleEndian.PutUint32(p, v)
	return len(p), nil
}

func TestTableReleaseReusedIndex(t *testing.T) {
	previous := rand.Reader
	t.Cleanup(func() { rand.Reader = previous })
	rand.Reader = &indexEntropy{fallback: 7}
	var table peerindex.Table[int]
	index, err := table.Allocate(1)
	if err != nil {
		t.Fatal(err)
	}
	table.Release(index, 1)
	reused, err := table.Allocate(2)
	if err != nil || reused != index {
		t.Fatalf("Allocate(2) = %d, %v; want %d, nil", reused, err, index)
	}
	table.Release(index, 1)
	if owner, ok := table.Lookup(index); !ok || owner != 2 {
		t.Fatal("stale release deleted reused index")
	}
	if table.Len() != 1 {
		t.Fatal("stale release changed count")
	}
	table.Release(index, 2)
	if table.Len() != 0 {
		t.Fatal("leak")
	}
}

func TestTableCollisionsAndExhaustion(t *testing.T) {
	previous := rand.Reader
	defer func() { rand.Reader = previous }()
	r := &indexEntropy{values: []uint32{0, 7, 7, 0, 9}}
	rand.Reader = r
	var table peerindex.Table[int]
	for owner, want := range []uint32{7, 9} {
		got, err := table.Allocate(owner + 1)
		if err != nil || got != want {
			t.Fatalf("Allocate(%d) = %d, %v; want %d", owner+1, got, err, want)
		}
	}
	if r.calls != 5 || table.Len() != 2 {
		t.Fatalf("draws=%d entries=%d; want 5, 2", r.calls, table.Len())
	}
	for _, candidate := range []uint32{0, 7} {
		r = &indexEntropy{fallback: candidate}
		rand.Reader = r
		got, err := table.Allocate(3)
		if got != 0 || !errors.Is(err, peerindex.ErrFull) || r.calls != 128 {
			t.Fatalf("candidate %d: got=%d err=%v draws=%d", candidate, got, err, r.calls)
		}
		if table.Len() != 2 {
			t.Fatal("failed allocation changed namespace")
		}
		for i, owner := range map[uint32]int{7: 1, 9: 2} {
			if got, ok := table.Lookup(i); !ok || got != owner {
				t.Fatalf("failed allocation replaced index %d: %d, %t", i, got, ok)
			}
		}
	}
}
