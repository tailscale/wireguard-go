//go:build darwin

/*
Package darwinbatch wraps darwin's batched socket calls, sendmsg_x and recvmsg_x, which move a batch of datagrams per syscall on a UDP socket or a utun. Datagrams are sent from and received into the caller's buffers.

The calls are reached through libSystem's wrappers without cgo, as x/sys/unix does, and only spi_darwin.go names them. Building with -tags ts_omit_darwin_spi produces a binary with no reference to either call, for app review; [Supported] then reports false and callers use one datagram per syscall.
*/
package darwinbatch

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// msghdrX mirrors xnu's struct msghdr_x, 56 bytes on amd64 and arm64 as TestMsghdrXLayout pins. The blank fields are alignment padding.
type msghdrX struct {
	name       *byte
	namelen    uint32
	_          uint32
	iov        *unix.Iovec
	iovlen     int32
	_          uint32
	control    *byte
	controllen uint32
	flags      int32
	datalen    uint64
}

func ptr(m *msghdrX) unsafe.Pointer { return unsafe.Pointer(m) }

// State holds the message and iovec arrays for one batch on one fd. It is not safe for concurrent use.
//
// The iovecs point at the caller's buffers unpinned: these are libSystem calls, not cgo calls, so the cgo pointer rules do not apply.
type State struct {
	msgs []msghdrX
	iovs []unix.Iovec
	lens []int // capacity staged by StageRecv, restored before each Recv
}

// New returns a State for batches of up to n datagrams.
func New(n int) *State {
	s := &State{msgs: make([]msghdrX, n), iovs: make([]unix.Iovec, n), lens: make([]int, n)}
	for i := range s.msgs {
		s.msgs[i].iov = &s.iovs[i]
		s.msgs[i].iovlen = 1
	}
	return s
}

// Cap is the largest batch the State holds.
func (s *State) Cap() int { return len(s.msgs) }

// Supported reports whether the calls are compiled in and a loopback self-test passed on the running kernel. struct msghdr_x is in no public header, so the self-test turns a layout change into a fallback rather than corrupt I/O.
func Supported() bool {
	selfTestOnce.Do(func() {
		if !spiAvailable {
			selfTestErr = errOmitted
			return
		}
		selfTestErr = selfTest()
	})
	return selfTestErr == nil
}

// SelfTestErr is why [Supported] reports false, or nil if it reports true.
func SelfTestErr() error {
	Supported()
	return selfTestErr
}

// Stage points datagram i of the next Send at pkt.
func (s *State) Stage(i int, pkt []byte) {
	s.iovs[i].Base = nil
	if len(pkt) > 0 {
		s.iovs[i].Base = &pkt[0]
	}
	s.iovs[i].SetLen(len(pkt))
	s.msgs[i].datalen = uint64(len(pkt))
}

// StageRecv points slot i of the next Recv at dst, so the kernel writes the datagram straight into it.
func (s *State) StageRecv(i int, dst []byte) {
	s.lens[i] = len(dst)
	s.iovs[i].Base = nil
	if len(dst) > 0 {
		s.iovs[i].Base = &dst[0]
	}
}

// Send sends the first cnt staged datagrams with one sendmsg_x and returns how many were accepted. It returns syscall.EAGAIN as is.
func (s *State) Send(fd uintptr, cnt int) (int, error) {
	cnt = min(cnt, len(s.msgs))
	if cnt <= 0 {
		return 0, nil
	}
	r, e := sendmsgX(fd, &s.msgs[0], cnt, 0)
	if e != 0 {
		return 0, e
	}
	return r, nil
}

// Recv receives up to want datagrams into the staged slots with one recvmsg_x and returns how many arrived. It returns syscall.EAGAIN as is.
func (s *State) Recv(fd uintptr, want int) (int, error) {
	want = min(want, len(s.msgs))
	if want <= 0 {
		return 0, nil
	}
	for i := range want {
		// recvmsg_x reads each msghdr_x back in, so restore the lengths and flags. macOS 12 sets MSG_TRUNC on a truncated datagram and then fails with EINVAL until it is cleared.
		s.iovs[i].SetLen(s.lens[i])
		s.msgs[i].datalen = uint64(s.lens[i])
		s.msgs[i].flags = 0
	}
	r, e := recvmsgX(fd, &s.msgs[0], want, 0)
	if e != 0 {
		return 0, e
	}
	return r, nil
}

// RecvLen is the size of the datagram Recv placed in slot i, never more than the slot holds.
func (s *State) RecvLen(i int) int {
	return min(int(s.msgs[i].datalen), s.lens[i])
}

// Reset drops the references to the caller's buffers, so a reused State does not keep them alive.
func (s *State) Reset() {
	for i := range s.msgs {
		s.iovs[i].Base = nil
		s.lens[i] = 0
	}
}
