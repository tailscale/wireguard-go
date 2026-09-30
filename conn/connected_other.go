//go:build unix && !aix && !solaris && !illumos && !linux && !darwin

package conn

import (
	"net"
	"net/netip"
	"syscall"
	"time"
)

// coalesceDelay matches Linux. It has no effect until reads here return more than one datagram.
const coalesceDelay = 200 * time.Microsecond

// newBatchSender returns nil: there is no batched send here.
func newBatchSender(*net.UDPConn, netip.AddrPort) batchSender { return nil }

func newBatchReader(c *net.UDPConn, dst netip.AddrPort) batchReader {
	return newPacketConnReader(c, dst.Addr().Is6())
}

// There is no UDP GRO here.
func enableGRO(syscall.RawConn) {}

func hasGRO(*net.UDPConn) bool { return false }

const connectedRecvBufSize = connectedBufSize

func forceRecvBuf(uintptr) {}
