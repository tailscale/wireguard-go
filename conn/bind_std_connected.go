package conn

import (
	"net/netip"
	"syscall"
)

// connectedControl gives StdNetBind's connected sockets the same fwmark as its own sockets.
func (s *StdNetBind) connectedControl(network, address string, c syscall.RawConn) error {
	mark := s.mark.Load()
	if mark == 0 {
		return nil
	}
	var serr error
	if err := c.Control(func(fd uintptr) { serr = applyMark(fd, mark) }); err != nil {
		return err
	}
	return serr
}

// receiveConnected is the extra ReceiveFunc that delivers what cs's sockets received.
func (s *StdNetBind) receiveConnected(cs *ConnectedSockets) ReceiveFunc {
	var pkts []ConnectedPacket
	return func(slab []byte, packets []ReceivedPacket) (int, error) {
		if len(pkts) < len(packets) {
			pkts = make([]ConnectedPacket, len(packets))
		}
		n, err := cs.ReadBatch(slab, pkts[:len(packets)])
		// One endpoint per run of datagrams from the same address, freshly allocated because the device may keep it.
		var (
			ep    *StdNetEndpoint
			local netip.Addr
		)
		for i, p := range pkts[:n] {
			if ep == nil || ep.AddrPort != p.Source || local != p.Local {
				// Use the socket's local address as the sticky source so replies stay on this pair.
				ep, local = &StdNetEndpoint{AddrPort: p.Source}, p.Local
				if local.IsValid() {
					setSrc(ep, local, 0)
				}
			}
			packets[i] = ReceivedPacket{Offset: p.Offset, Size: p.Size, Endpoint: ep}
		}
		return n, err
	}
}
