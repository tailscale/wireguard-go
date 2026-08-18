/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"os"
)

type Event int

const (
	EventUp = 1 << iota
	EventDown
	EventMTUUpdate
)

// ReadPacket describes a packet read by [tun.Device.Read].
type ReadPacket struct {
	// Offset is the starting byte offset.
	Offset int
	// Size is the size of the packet.
	Size int
}

// ReadPacketSpacing is the number of bytes reserved before the first packet,
// between adjacent packets, and after the final packet filled by [Device.Read].
const ReadPacketSpacing = 64

type Device interface {
	// File returns the file descriptor of the device.
	File() *os.File

	// Read reads one or more packets from the [Device] into slab. On return, it
	// populates packets and returns the number of entries to evaluate. Those
	// entries are valid even when err is non-nil. Callers must provide at least
	// [Device.BatchSize] entries.
	//
	// Read reserves [ReadPacketSpacing] bytes before the first packet, between
	// adjacent packets, and after the final packet. The contents of the reserved
	// space are unspecified; the [Device] may use them while Read is executing.
	// Callers must provide a slab of at least 2*[ReadPacketSpacing] bytes.
	//
	// Read returns [ErrTooManySegments] if packets or slab cannot accommodate
	// all packets produced by the read.
	Read(slab []byte, packets []ReadPacket) (n int, err error)

	// Write one or more packets to the device (without any additional headers).
	// On a successful write it returns the number of packets written. A nonzero
	// offset can be used to instruct the Device on where to begin writing from
	// each packet contained within the bufs slice.
	Write(bufs [][]byte, offset int) (int, error)

	// MTU returns the MTU of the Device.
	MTU() (int, error)

	// Name returns the current name of the Device.
	Name() (string, error)

	// Events returns a channel of type Event, which is fed Device events.
	Events() <-chan Event

	// Close stops the Device and closes the Event channel.
	Close() error

	// BatchSize returns the preferred/max number of packets that can be read or
	// written in a single read/write call. BatchSize must not change over the
	// lifetime of a Device.
	BatchSize() int
}

// GRODevice is a Device extended with methods for disabling GRO. Certain OS
// versions may have offload bugs. Where these bugs negatively impact throughput
// or break connectivity entirely we can use these methods to disable the
// related offload.
//
// Linux has the following known, GRO bugs.
//
// torvalds/linux@e269d79c7d35aa3808b1f3c1737d63dab504ddc8 broke virtio_net
// TCP & UDP GRO causing GRO writes to return EINVAL. The bug was then
// resolved later in
// torvalds/linux@89add40066f9ed9abe5f7f886fe5789ff7e0c50e. The offending
// commit was pulled into various LTS releases.
//
// UDP GRO writes end up blackholing/dropping packets destined for a
// vxlan/geneve interface on kernel versions prior to 6.8.5.
type GRODevice interface {
	Device
	// DisableUDPGRO disables UDP GRO if it is enabled.
	DisableUDPGRO()
	// DisableTCPGRO disables TCP GRO if it is enabled.
	DisableTCPGRO()
}
