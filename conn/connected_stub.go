//go:build !unix || aix || solaris || illumos

package conn

import (
	"errors"
	"net/netip"
	"syscall"
)

// ConnectedSockets is unavailable on this platform. [NewConnectedSockets] returns nil, and methods on a nil set do nothing.
type ConnectedSockets struct{}

const connectedSupported = false

func NewConnectedSockets(ConnectedConfig) *ConnectedSockets { return nil }

// ConnectedDeliveryCheck reports that this platform has no ConnectedSockets.
func ConnectedDeliveryCheck() error { return errConnectedUnsupported }

var errConnectedUnsupported = errors.New("connected sockets are not implemented on this platform")

func ReusePortControl(string, string, syscall.RawConn) error { return nil }

func (*ConnectedSockets) Send(netip.AddrPort, [][]byte, int) (bool, error) { return false, nil }

func (*ConnectedSockets) SendFrom(netip.AddrPort, netip.Addr, [][]byte, int) (bool, error) {
	return false, nil
}

func (*ConnectedSockets) Dial(netip.AddrPort, netip.Addr, int) bool { return false }

func (*ConnectedSockets) Rebind(int)   {}
func (*ConnectedSockets) Close() error { return nil }
