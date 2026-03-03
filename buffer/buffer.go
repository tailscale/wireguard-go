/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 *
 * Package buffer implements a reusable buffer abstraction.
 *
 * Wireguard-go's data processing is constrained by both the hosts API,
 * and the transformations performed during encapsulation:
 *
 *  1. Encryption requires tail- and headroom for extra headers and padding.
 *     Available via winrio, and pread(2).
 *  2. Systems are moving towards coalesced reads for both TCP and UDP.
 *     The read data has no gaps for individual slices.
 *  3. crypto.AEAD interface requires a contiguous dst []byte for Sealing.
 *     So we can't use scatter-gather to inject the gaps.
 *
 * Until one of these three conditions is changed, the encryption strategy
 * is to copy on read into buffers with the required gaps.
 * The buffers are right-sized for the packet to avoid memory inflation.
 * To recycle said allocations, each buffer carries a recycle function
 * that routes it back to its originating pool.
 *
 * Decryption shrinks each fragment instead of growing, so buffers can pass
 * through the pipeline without copying till the egress coalescion.
 * Depending on the chosen head of the coalescion, there may or may be no room
 * and reallocation is a necessary fallback until we start passing
 * buffers in batches.
 */
package buffer

const (
	MaxMessageSize = (1 << 16) - 1 // largest possible UDP datagram
)

// Source produces new Buffers.
type Source interface {
	Get(size int) *Buffer
}

// Buffer is a reusable slice of bytes of fixed length.
// The returned Data slice must not be retained past Release.
type Buffer struct {
	data    []byte
	recycle func(*Buffer)
}

// New creates a standalone Buffer. Intended for use in tests.
func New(b []byte) *Buffer {
	return &Buffer{data: b}
}

func (b *Buffer) Data() []byte {
	return b.data
}

func (b *Buffer) Len() int {
	return len(b.data)
}

func (b *Buffer) Release() {
	if b.recycle != nil {
		memclr(b.data)
		b.recycle(b)
	}
}

func ReleaseAll(bs []*Buffer) {
	for i := range bs {
		if bs[i] != nil {
			bs[i].Release()
			bs[i] = nil
		}
	}
}

type Arena struct {
	*Buffer
	watermark int
}

func (a *Arena) Get(size int) []byte {
	if a.watermark+size > len(a.Buffer.Data()) {
		panic("arena overflow") // or return a heap-allocated fallback
	}
	b := a.Buffer.Data()[a.watermark : a.watermark+size]
	a.watermark += size
	return b
}

func (a *Arena) Flush() {
	memclr(a.Buffer.Data()[:a.watermark])
	a.watermark = 0
}

func memclr(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
