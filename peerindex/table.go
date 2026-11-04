// SPDX-License-Identifier: MIT

// Package peerindex allocates receiver indexes and maps them to their owners.
package peerindex

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/go4org/hashtriemap"
)

// ErrFull reports that [Table.Allocate] exhausted its bounded random allocation
// attempts.
var ErrFull = errors.New("peerindex: collision budget exhausted")

// Table maps nonzero receiver indexes to owners. Its zero value is ready to use.
// Methods may be called concurrently. A Table must not be copied after first use.
// The usual instantiation is Table[*peer.Peer], which implements peer.IndexAllocator.
// The type parameter lets peer's internal tests use Table without an import cycle.
type Table[T comparable] struct {
	mu      sync.Mutex // Serializes writes and protects count.
	count   int
	entries hashtriemap.HashTrieMap[uint32, T]
}

// Allocate reserves a random nonzero index for owner and returns it.
// It returns zero and [ErrFull] if its allocation attempts are exhausted.
func (t *Table[T]) Allocate(owner T) (uint32, error) {
	for range 128 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		index := binary.LittleEndian.Uint32(b[:])
		if index == 0 {
			continue
		}
		t.mu.Lock()
		if _, ok := t.entries.Load(index); !ok {
			t.entries.Store(index, owner)
			t.count++
			t.mu.Unlock()
			return index, nil
		}
		t.mu.Unlock()
	}
	return 0, ErrFull
}

// Release removes index only if its current owner equals owner.
func (t *Table[T]) Release(index uint32, owner T) {
	if index == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if current, ok := t.entries.Load(index); ok && current == owner {
		t.entries.Delete(index)
		t.count--
	}
}

// Lookup returns the owner of index and whether the index is allocated.
// If absent, it returns the zero value of T and false.
func (t *Table[T]) Lookup(index uint32) (T, bool) {
	return t.entries.Load(index)
}

// Len returns the number of allocated indexes.
func (t *Table[T]) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}
