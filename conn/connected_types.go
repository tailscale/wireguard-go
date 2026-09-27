package conn

import (
	"net/netip"
	"syscall"
)

// ConnectedConfig configures [NewConnectedSockets].
type ConnectedConfig struct {
	// Port is the local port every socket binds to: that of the caller's own socket, which must allow sharing. Zero means the set takes nothing until [ConnectedSockets.Rebind] gives it a port.
	Port int

	// Control, if non-nil, is applied to every socket before it connects. Pass whatever the caller's socket uses to pick its route, such as a fwmark or interface binding.
	Control func(network, address string, c syscall.RawConn) error

	// MaxSockets bounds the number of sockets. Zero means [DefaultMaxConnectedSockets].
	MaxSockets int

	// MaxDatagram is the largest datagram the caller expects, so sockets start with slots that hold it. Zero suits ordinary MTUs; set it for a jumbo tunnel to avoid losing the first large read.
	MaxDatagram int

	// OpenAfter is how many bytes an address pair must carry, sent and received together, before it gets its own socket. Zero means [DefaultOpenAfter], and 1 opens on the first datagram.
	OpenAfter int
}

/*
DefaultOpenAfter is the default for ConnectedConfig.OpenAfter: 1 MiB.

A connected socket only pays under load, and costs a file descriptor, a goroutine and its receive buffers, so a pair that carries only handshakes, keepalives and small exchanges is better left on the caller's socket. Counts start again at every idle check, so a pair must carry this much within one 30 to 60 second interval: about 8 ms of a 1 Gbit/s flow, or 80 ms at 100 Mbit/s.

Closing is deliberately a different test. A socket closes only after a whole interval with no traffic at all in either direction, so once open it stays open through any lull short of the peer going quiet, and a rate that hovers near this threshold cannot open and close it over and over.
*/
const DefaultOpenAfter = 1 << 20

/*
DefaultMaxConnectedSockets is the default socket limit.

It is set by memory rather than by anything else, because falling back to the caller's socket is much slower per packet for the addresses that do, so a limit below the working set costs throughput out of proportion to the number of addresses left over. A socket costs about 0.26 MiB, or about 1.15 MiB once it carries jumbo datagrams and from the start on Linux with GRO, whose coalesced reads need 64 KiB slots, so the limit is between about 67 and 295 MiB. The OpenAfter threshold keeps sockets to the peers carrying real traffic, so few exist at once in practice. An embedder with a tight memory budget, such as an iOS network extension, should set a lower one.
*/
const DefaultMaxConnectedSockets = 256

// ConnectedPacket describes one datagram returned by [ConnectedSockets.ReadBatch].
type ConnectedPacket struct {
	Offset int            // start of the datagram in the slab
	Size   int            // length of the datagram
	Source netip.AddrPort // the remote address the datagram came from
	Local  netip.Addr     // the local address it was sent to, which is its socket's
}
