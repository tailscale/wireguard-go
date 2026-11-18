package tun

import (
	"errors"
)

var (
	// ErrTooManySegments is returned by Reader.Read() when segmentation
	// overflows the length of supplied buffers. This error should not cause
	// reads to cease.
	ErrTooManySegments = errors.New("too many segments")

	// ErrExists is returned by [CreateTUN] when the named interface already
	// exists. It is wrapped together with the platform errno, and is not
	// returned under [NonExclusive], where an existing interface is adopted.
	ErrExists = errors.New("TUN interface already exists")
)
