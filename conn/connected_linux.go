//go:build linux

package conn

import (
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// coalesceDelay is short on Linux, where recvmmsg already returns deep batches.
const coalesceDelay = 200 * time.Microsecond

// connectedRecvBufSize is large because with UDP GRO each queued datagram can be a 64 KiB coalesced run. It is a limit, not an allocation.
const connectedRecvBufSize = 4 << 20

// forceRecvBuf sets the receive buffer past net.core.rmem_max if the process is allowed to.
func forceRecvBuf(fd uintptr) {
	_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, connectedRecvBufSize)
}

// mmsgSender sends with sendmmsg, grouping datagrams for UDP GSO with coalesceMessages where supported.
type mmsgSender struct {
	// mu guards msgs, which is shared by every goroutine sending to this address.
	mu   sync.Mutex
	v4   *ipv4.PacketConn
	v6   *ipv6.PacketConn
	ep   StdNetEndpoint
	msgs []ipv6.Message
	gso  bool
}

func newBatchSender(c *net.UDPConn, dst netip.AddrPort) batchSender {
	s := &mmsgSender{ep: StdNetEndpoint{AddrPort: dst}, msgs: make([]ipv6.Message, IdealBatchSize)}
	for i := range s.msgs {
		s.msgs[i].Buffers = make(net.Buffers, 1)
		s.msgs[i].OOB = make([]byte, 0, controlSize)
	}
	s.gso, _ = supportsUDPOffload(c)
	if dst.Addr().Is6() {
		s.v6 = ipv6.NewPacketConn(c)
	} else {
		s.v4 = ipv4.NewPacketConn(c)
	}
	return s
}

// enableGRO turns on UDP GRO. hasGRO reports whether it took, since older kernels refuse it.
func enableGRO(c syscall.RawConn) {
	c.Control(func(fd uintptr) { _ = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, socketOptionUDPGRO, 1) })
}

func hasGRO(c *net.UDPConn) bool {
	_, rx := supportsUDPOffload(c)
	return rx
}

func newBatchReader(c *net.UDPConn, dst netip.AddrPort) batchReader {
	return newPacketConnReader(c, dst.Addr().Is6())
}

func (s *mmsgSender) sendBatch(bufs [][]byte, offset int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(bufs) > 0 {
		chunk := bufs[:min(len(bufs), len(s.msgs))]
		for i := range s.msgs {
			s.msgs[i].Buffers = s.msgs[i].Buffers[:1]
			s.msgs[i].OOB = s.msgs[i].OOB[:0]
		}
		var n int
		if s.gso {
			n = coalesceMessages(nil, &s.ep, chunk, offset, s.msgs, setGSOSize)
		} else {
			for i, b := range chunk {
				s.msgs[i].Buffers[0] = b[offset:]
			}
			n = len(chunk)
		}
		// coalesceMessages stores a typed nil *net.UDPAddr, which x/net would dereference.
		for i := range s.msgs[:n] {
			s.msgs[i].Addr = nil
		}
		var sent int
		var err error
		if s.v6 != nil {
			sent, err = s.v6.WriteBatch(s.msgs[:n], 0)
		} else {
			sent, err = s.v4.WriteBatch(s.msgs[:n], 0)
		}
		if err != nil && s.gso && errShouldDisableUDPGSO(err) {
			s.gso = false // retry this chunk without GSO
			continue
		}
		if err != nil {
			return err
		}
		if sent <= 0 {
			return nil // drop the rest rather than spin
		}
		consumed := sent
		if s.gso {
			consumed = 0
			for i := range s.msgs[:sent] {
				consumed += len(s.msgs[i].Buffers)
			}
		}
		bufs = bufs[consumed:]
	}
	return nil
}
