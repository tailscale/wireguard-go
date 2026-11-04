/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

// Packet identifies a byte range in caller-owned storage. Offset and Size must
// be nonnegative, and Offset+Size must not exceed len(Buffer).
//
// Packet operations use the buffer in place. The caller must provide exclusive
// access to each operation's working range, including send headroom and padding.
// Working ranges of packets in a batch must not overlap.
type Packet struct {
	// Buffer is the storage containing the packet and any available headroom and tailroom.
	Buffer []byte
	// Offset is the start of the packet, and Size is its length in bytes.
	Offset, Size int
}

func (p Packet) valid() bool {
	return p.Offset >= 0 && p.Size >= 0 && p.Offset <= len(p.Buffer) && p.Size <= len(p.Buffer)-p.Offset
}

// Bytes returns the packet's range as a slice sharing Buffer.
// It panics if the range is invalid.
func (p Packet) Bytes() []byte { return p.Buffer[p.Offset : p.Offset+p.Size] }

func output(p Packet, size int) (Packet, error) {
	if p.Offset < 0 || p.Offset > len(p.Buffer) || size > len(p.Buffer)-p.Offset {
		return Packet{}, ErrShortBuffer
	}
	p.Size = size
	return p, nil
}

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
