//go:build darwin

/*
Package darwinbatch wraps darwin's batched socket calls, sendmsg_x and recvmsg_x, which move a batch of datagrams per syscall on a UDP socket or a utun. Datagrams are sent from and received into the caller's buffers.

The calls are reached through libSystem's wrappers without cgo, as x/sys/unix does, and only spi_darwin.go names them. Building with -tags ts_omit_darwin_spi produces a binary with no reference to either call, for app review; [Supported] then reports false and callers use one datagram per syscall.
*/
package darwinbatch

import (
	"net/netip"
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

	names []unix.RawSockaddrAny   // each datagram's source, once RecvNames is called
	dsts  []unix.RawSockaddrInet6 // each datagram's destination, once StageTo is called
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

// RecvNames makes Recv record each datagram's source address, for [State.Name].
func (s *State) RecvNames() {
	s.names = make([]unix.RawSockaddrAny, len(s.msgs))
	for i := range s.msgs {
		s.msgs[i].name = (*byte)(unsafe.Pointer(&s.names[i]))
	}
}

// Name is the source address of the datagram Recv placed in slot i, or nil if RecvNames was not called or the kernel gave none.
func (s *State) Name(i int) *unix.RawSockaddrAny {
	if s.names == nil || s.msgs[i].namelen == 0 {
		return nil
	}
	return &s.names[i]
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

// Stage points datagram i of the next Send at pkt, for a connected socket or a utun.
func (s *State) Stage(i int, pkt []byte) {
	if s.dsts != nil {
		s.msgs[i].name, s.msgs[i].namelen = nil, 0
	}
	s.iovs[i].Base = nil
	if len(pkt) > 0 {
		s.iovs[i].Base = &pkt[0]
	}
	s.iovs[i].SetLen(len(pkt))
	s.msgs[i].datalen = uint64(len(pkt))
}

// StageTo points datagram i of the next Send at pkt, addressed to dst, for an unconnected socket. See [UnconnectedSelfTestErr].
func (s *State) StageTo(i int, pkt []byte, dst netip.AddrPort) {
	s.Stage(i, pkt)
	if s.dsts == nil {
		s.dsts = make([]unix.RawSockaddrInet6, len(s.msgs))
	}
	s.msgs[i].name = (*byte)(unsafe.Pointer(&s.dsts[i]))
	s.msgs[i].namelen = putSockaddr(&s.dsts[i], dst)
}

// putSockaddr writes ap into sa as a sockaddr_in or sockaddr_in6 and returns its length.
func putSockaddr(sa *unix.RawSockaddrInet6, ap netip.AddrPort) uint32 {
	port := ap.Port()<<8 | ap.Port()>>8
	if ap.Addr().Is4() {
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		*sa4 = unix.RawSockaddrInet4{Len: unix.SizeofSockaddrInet4, Family: unix.AF_INET, Port: port, Addr: ap.Addr().As4()}
		return unix.SizeofSockaddrInet4
	}
	*sa = unix.RawSockaddrInet6{Len: unix.SizeofSockaddrInet6, Family: unix.AF_INET6, Port: port, Addr: ap.Addr().As16()}
	return unix.SizeofSockaddrInet6
}

// AddrPort is the source of the datagram Recv placed in slot i, or the zero AddrPort if there is none; see [State.RecvNames].
func (s *State) AddrPort(i int) netip.AddrPort {
	sa := s.Name(i)
	if sa == nil {
		return netip.AddrPort{}
	}
	switch sa.Addr.Family {
	case unix.AF_INET:
		sa4 := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		return netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), sa4.Port<<8|sa4.Port>>8)
	case unix.AF_INET6:
		sa6 := (*unix.RawSockaddrInet6)(unsafe.Pointer(sa))
		return netip.AddrPortFrom(netip.AddrFrom16(sa6.Addr).Unmap(), sa6.Port<<8|sa6.Port>>8)
	}
	return netip.AddrPort{}
}

// StageRecv points slot i of the next Recv at dst.
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
		if s.names != nil {
			s.msgs[i].namelen = uint32(unsafe.Sizeof(s.names[i]))
		}
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
