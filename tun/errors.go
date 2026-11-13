package tun

import (
	"errors"
)

var (
	// ErrTooManySegments is returned by Reader.Read() when segmentation
	// overflows the length of supplied buffers. This error should not cause
	// reads to cease.
	ErrTooManySegments = errors.New("too many segments")

	// ErrInvalidGSOPacket is returned by Reader.Read() when the kernel
	// delivers a GSO packet that cannot be segmented. That packet is dropped;
	// this error should not cause reads to cease.
	ErrInvalidGSOPacket = errors.New("invalid GSO packet")
)
