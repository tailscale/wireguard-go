package tun

import (
	"errors"
)

var (
	// ErrTooManySegments is returned by Device.Read() when segmentation
	// overflows the length of supplied buffers. This error should not cause
	// reads to cease.
	ErrTooManySegments = errors.New("too many segments")

	// ErrInvalidGSOSize is returned when the GSO segment size is not positive.
	ErrInvalidGSOSize = errors.New("gso size must be > 0")
)
