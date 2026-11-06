// SPDX-License-Identifier: MIT

// Package peerindex maps WireGuard receiver indices to owners.
// A Table[*peer.Peer] implements peer.IndexAllocator and can be shared across
// identities and socket shards.
package peerindex

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
)

// ErrFull indicates that allocation exhausted its collision budget.
var ErrFull = errors.New("peerindex: collision budget exhausted")

// Table maps cryptographically random, nonzero indices to owners. The zero
// value is ready to use. Methods are safe for concurrent use. A Table must not
// be copied after first use.
//
// Lookup grants neither protocol ownership nor authentication. Routes may be
// removed after lookup. Callers must synchronize dispatch with owner teardown.
// Table does not register static keys. Applications must reject duplicate
// (local identity, remote key) registrations or retire the old peer.
type Table[T comparable] struct {
	mu      sync.RWMutex
	entries map[uint32]T
}

// Allocate registers owner at a random, nonzero index not currently in use.
// On error it returns zero and retains no allocation. It tries at most 128
// candidates before returning ErrFull.
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
		if _, ok := t.entries[index]; !ok {
			if t.entries == nil {
				t.entries = make(map[uint32]T)
			}
			t.entries[index] = owner
			t.mu.Unlock()
			return index, nil
		}
		t.mu.Unlock()
	}
	return 0, ErrFull
}

// Release removes index only if it belongs to owner. Zero and unknown indices
// are ignored. Release each allocation exactly once. A stale release cannot be
// distinguished from a new allocation of the same index to the same owner.
func (t *Table[T]) Release(index uint32, owner T) {
	if index == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if current, ok := t.entries[index]; ok && current == owner {
		delete(t.entries, index)
	}
}

// Lookup returns the owner of index and whether it is registered.
// The mapping may be released before Lookup returns.
func (t *Table[T]) Lookup(index uint32) (T, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	owner, ok := t.entries[index]
	return owner, ok
}

// Len returns the number of registered indices.
func (t *Table[T]) Len() int { t.mu.RLock(); defer t.mu.RUnlock(); return len(t.entries) }
