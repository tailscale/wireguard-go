package buffer

import "iter"

// Stack wraps a single Buffer representing one network message or a
// segment thereof.
//
// Fields:
//   - base: absolute byte offset of this segment's start within buf.Data().
//   - size: number of valid bytes from base (full segment including headers).
//   - offset: relative skip from base applied when reading payload via Data().
//   - gsoSize: segment stride for GSO-coalesced messages (0 = single segment).
//
// After decryption, offset is advanced past the transport header so that
// Data() yields only the inner IP packet. Frame() always returns the full
// segment from base, which the TUN write path needs.
//
// Stacks are single-owner values: ownership transfers by assignment
// and the source is zeroed. Release frees the underlying Buffer (or
// decrements its reference count when the buffer is shared across
// per-segment sub-stacks).
type Stack struct {
	buf     *Buffer
	base    uint16
	size    uint16
	offset  uint16
	gsoSize uint16
}

// NewStack creates a Stack from buf with the given valid byte count.
// base starts at 0; offset starts at 0; gsoSize starts at 0 (single segment).
func NewStack(buf *Buffer, size int) Stack {
	return Stack{buf: buf, size: uint16(size)}
}

// NewSegmentStack creates a single-segment Stack pointing into buf at the
// given absolute base position with the given size. Used when splitting a
// GSO stack into per-segment sub-stacks.
func NewSegmentStack(buf *Buffer, base, size int) Stack {
	return Stack{buf: buf, base: uint16(base), size: uint16(size)}
}

func (s *Stack) SetGSO(size int)   { s.gsoSize = uint16(size) }
func (s *Stack) SetOffset(off int) { s.offset = uint16(off) }
func (s *Stack) SetSize(size int)  { s.size = uint16(size) }
func (s *Stack) Buffer() *Buffer   { return s.buf }
func (s *Stack) Base() int         { return int(s.base) }
func (s *Stack) Offset() int       { return int(s.offset) }
func (s *Stack) Size() int         { return int(s.size) }
func (s *Stack) GSOSize() int      { return int(s.gsoSize) }

// Data returns the active payload region: buf.Data()[base+offset : base+size].
// For a freshly received segment (offset=0), this is the full wire packet.
// After decryption sets offset=MessageTransportOffsetContent, this is the
// decrypted IP packet.
// Returns nil when the stack is zero (e.g. after decryption failure).
func (s *Stack) Data() []byte {
	if s.buf == nil {
		return nil
	}
	return s.buf.Data()[s.base+s.offset : s.base+s.size]
}

// Frame returns the full segment from base: buf.Data()[base : base+size].
// This includes any headers before offset, which the TUN write path needs
// (it applies its own offset parameter to skip them).
func (s *Stack) Frame() []byte {
	if s.buf == nil {
		return nil
	}
	return s.buf.Data()[s.base : s.base+s.size]
}

// Release frees the underlying Buffer (decrements its reference count).
// Safe to call on a zero Stack.
func (s *Stack) Release() {
	if s.buf != nil {
		s.buf.Release()
		s.buf = nil
	}
}

// Segments returns an iterator over the individual packet segments.
// Each yielded []byte is a sub-slice of the underlying Buffer.
//
// When gsoSize == 0 (single segment), yields Data().
// When gsoSize > 0 (coalesced), yields segments of gsoSize bytes
// (last may be shorter), each with offset applied from its natural
// start position.
func (s *Stack) Segments() iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		if s.buf == nil {
			return
		}
		data := s.buf.Data()
		base := int(s.base)
		off := int(s.offset)
		size := int(s.size)
		if s.gsoSize == 0 {
			yield(data[base+off : base+size])
			return
		}
		gs := int(s.gsoSize)
		pos := 0
		for pos < size {
			end := pos + gs
			if end > size {
				end = size
			}
			if pos+off >= end {
				// Last segment too short for offset — skip.
				break
			}
			if !yield(data[base+pos+off : base+end]) {
				return
			}
			pos = end
		}
	}
}

// SegmentFrames returns an iterator like Segments but ignores the offset,
// yielding each segment's full frame from its natural start position.
// This is used by the consumer to access both the transport header
// (counter, receiver) and the decrypted payload within each segment.
func (s *Stack) SegmentFrames() iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		if s.buf == nil {
			return
		}
		data := s.buf.Data()
		base := int(s.base)
		size := int(s.size)
		if s.gsoSize == 0 {
			yield(data[base : base+size])
			return
		}
		gs := int(s.gsoSize)
		pos := 0
		for pos < size {
			end := pos + gs
			if end > size {
				end = size
			}
			if !yield(data[base+pos : base+end]) {
				return
			}
			pos = end
		}
	}
}

// NumSegments returns the number of segments without iterating.
func (s *Stack) NumSegments() int {
	if s.gsoSize == 0 {
		return 1
	}
	return (int(s.size) + int(s.gsoSize) - 1) / int(s.gsoSize)
}

// ReleaseStacks releases all non-zero stacks and zeroes the entries.
func ReleaseStacks(stacks []Stack) {
	for i := range stacks {
		stacks[i].Release()
	}
}
