/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

// Packet describes Buffer[Offset:Offset+Size] in caller-owned storage.
// len(Buffer), not cap(Buffer), must cover every writable byte. Send needs
// TransportHeaderSize bytes before Offset and padding plus a 16-byte tag after
// Offset+Size. It rewrites successful descriptors to the wire range. Control
// methods use Offset as the wire start, ignore input Size, and return the size
// written. Receive returns a separate plaintext descriptor including padding.
//
// Calls require exclusive access to their buffers and do not retain them.
// Admission and preparation tokens hold copies, so input storage may be reused
// after admission. Different packets' writable regions must be disjoint.
// Overlap is not checked. Disjoint regions may share a slab in any vector order.
type Packet struct {
	Buffer       []byte
	Offset, Size int
}

func (p Packet) valid() bool {
	return p.Offset >= 0 && p.Size >= 0 && p.Offset <= len(p.Buffer) && p.Size <= len(p.Buffer)-p.Offset
}

// Bytes returns the packet range, aliasing Buffer. The range must be valid.
func (p Packet) Bytes() []byte { return p.Buffer[p.Offset : p.Offset+p.Size] }
func output(p Packet, size int) (Packet, error) {
	if p.Offset < 0 || p.Offset > len(p.Buffer) || size > len(p.Buffer)-p.Offset {
		return Packet{}, ErrShortBuffer
	}
	p.Size = size
	return p, nil
}

// paddingSize matches device.calculatePaddingSize, including packets > MTU.
func paddingSize(size, mtu int) int {
	last := size
	if mtu > 0 && last > mtu {
		last %= mtu
	}
	// Modulo avoids an overflowing size+15.
	padding := (-last) & (PaddingMultiple - 1)
	if mtu > 0 && padding > mtu-last {
		padding = mtu - last
	}
	return padding
}
func sendRange(p Packet, mtu int) (Packet, error) {
	if !p.valid() || p.Offset < TransportHeaderSize {
		return Packet{}, ErrInvalidBuffer
	}
	tail := paddingSize(p.Size, mtu) + 16
	if tail > len(p.Buffer)-p.Offset-p.Size {
		return Packet{}, ErrShortBuffer
	}
	return Packet{p.Buffer, p.Offset - TransportHeaderSize, p.Size + TransportHeaderSize + tail}, nil
}

// validatePackets checks descriptor bounds before any packet is written.
// It does not check overlap. The caller must provide disjoint writable regions.
func validatePackets(packets []Packet, mtu int, send bool) error {
	for _, p := range packets {
		if send {
			if _, err := sendRange(p, mtu); err != nil {
				return err
			}
		} else if !p.valid() {
			return ErrInvalidBuffer
		}
	}
	return nil
}
