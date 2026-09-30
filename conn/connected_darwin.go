//go:build darwin

package conn

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/tailscale/wireguard-go/internal/darwinbatch"
)

// coalesceDelay is longer on darwin, where reads come back shallow without the pause. Much longer shows up in round-trip time.
const coalesceDelay = 500 * time.Microsecond

// Darwin batches with sendmsg_x and recvmsg_x. Without them (ts_omit_darwin_spi) connected sockets do one datagram per syscall.

func newBatchSender(c *net.UDPConn, _ netip.AddrPort) batchSender {
	if !darwinbatch.Supported() {
		return nil
	}
	return &sendmsgXSender{c: c, st: darwinbatch.New(IdealBatchSize)}
}

func newBatchReader(c *net.UDPConn, dst netip.AddrPort) batchReader {
	if !darwinbatch.Supported() {
		return newPacketConnReader(c, dst.Addr().Is6())
	}
	st := darwinbatch.New(IdealBatchSize)
	st.RecvNames()
	return &recvmsgXReader{c: c, st: st, dst: dst}
}

// sendmsgXSender sends with sendmsg_x. mu guards st, which is shared by every goroutine sending to this address.
type sendmsgXSender struct {
	c  *net.UDPConn
	mu sync.Mutex
	st *darwinbatch.State
}

func (s *sendmsgXSender) sendBatch(bufs [][]byte, offset int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rc, err := s.c.SyscallConn()
	if err != nil {
		return err
	}
	for len(bufs) > 0 {
		n := min(len(bufs), s.st.Cap())
		for i := range n {
			s.st.Stage(i, bufs[i][offset:])
		}
		var sent int
		var serr error
		werr := rc.Write(func(fd uintptr) bool {
			for {
				sent, serr = s.st.Send(fd, n)
				if serr != syscall.EINTR {
					break
				}
			}
			return serr != syscall.EAGAIN // full: wait for writability
		})
		s.st.Reset()
		if werr != nil {
			return werr
		}
		if serr != nil {
			return os.NewSyscallError(darwinbatch.SendName, serr)
		}
		if sent <= 0 {
			return nil // drop the rest rather than spin
		}
		bufs = bufs[sent:]
	}
	return nil
}

// recvmsgXReader reads with recvmsg_x into the caller's buffers. It leaves Addr nil for datagrams from dst, saving an allocation per datagram.
type recvmsgXReader struct {
	c   *net.UDPConn
	st  *darwinbatch.State
	dst netip.AddrPort
}

func (r *recvmsgXReader) ReadBatch(msgs []ipv6.Message, _ int) (int, error) {
	want := min(len(msgs), r.st.Cap())
	for i := range want {
		r.st.StageRecv(i, msgs[i].Buffers[0])
	}
	defer r.st.Reset()
	rc, err := r.c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var serr error
	if err := rc.Read(func(fd uintptr) bool {
		for {
			n, serr = r.st.Recv(fd, want)
			if serr != syscall.EINTR {
				break
			}
		}
		return serr != syscall.EAGAIN // empty: wait for readability
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, os.NewSyscallError(darwinbatch.RecvName, serr)
	}
	for i := range n {
		msgs[i].N = r.st.RecvLen(i)
		msgs[i].Addr = r.source(r.st.Name(i))
	}
	return n, nil
}

// source is sa as a net.Addr, or nil when it is the connected address or absent.
func (r *recvmsgXReader) source(sa *unix.RawSockaddrAny) net.Addr {
	var ap netip.AddrPort
	var scope uint32
	switch {
	case sa == nil:
		return nil
	case sa.Addr.Family == unix.AF_INET:
		p := (*unix.RawSockaddrInet4)(unsafe.Pointer(sa))
		ap = netip.AddrPortFrom(netip.AddrFrom4(p.Addr), port(&p.Port))
	case sa.Addr.Family == unix.AF_INET6:
		p := (*unix.RawSockaddrInet6)(unsafe.Pointer(sa))
		ap = netip.AddrPortFrom(netip.AddrFrom16(p.Addr), port(&p.Port))
		scope = p.Scope_id
	default:
		return nil
	}
	if ap.Addr() == r.dst.Addr().WithZone("") && ap.Port() == r.dst.Port() {
		return nil
	}
	a := &net.UDPAddr{IP: ap.Addr().AsSlice(), Port: int(ap.Port())}
	if scope != 0 {
		a.Zone = strconv.Itoa(int(scope))
		if ifi, err := net.InterfaceByIndex(int(scope)); err == nil {
			a.Zone = ifi.Name
		}
	}
	return a
}

// port reads a sockaddr port, which is in network byte order.
func port(p *uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(p))
	return uint16(b[0])<<8 | uint16(b[1])
}

// There is no UDP GRO on darwin.
func enableGRO(syscall.RawConn) {}

func hasGRO(*net.UDPConn) bool { return false }

const connectedRecvBufSize = connectedBufSize

func forceRecvBuf(uintptr) {}
