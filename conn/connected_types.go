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

	// Reader is required. When a socket opens, the set calls Reader with its [ConnectedReadFunc], which the caller calls from its own goroutine (avoiding a copy and a handoff) until it returns [net.ErrClosed]. slabSize and batchSize are what one full batch needs.
	// Reader returns false if the caller can no longer read, and the socket is closed unused.
	Reader func(read ConnectedReadFunc, slabSize, batchSize int) bool
}

// ConnectedReadFunc reads datagrams from one connected socket into slab, describing them in packets, and returns how many it read, at least one; it blocks until one arrives. Only one goroutine may call it at a time. See ConnectedConfig.Reader.
type ConnectedReadFunc func(slab []byte, packets []ConnectedPacket) (int, error)

// DefaultOpenAfter is the default ConnectedConfig.OpenAfter. A connected socket only pays under load, so pairs carrying only handshakes and keepalives stay on the caller's socket.
// Counts reset at each idle check, but a socket closes only after a whole idle interval, so a rate near the threshold cannot flap.
const DefaultOpenAfter = 1 << 20

// DefaultMaxConnectedSockets is the default socket limit. Each socket costs a file descriptor, kernel buffers and a few tens of KiB of read state (a few hundred with GRO).
// Embedders with a tight memory budget, such as an iOS network extension, should set a lower one.
const DefaultMaxConnectedSockets = 256

// ConnectedPacket describes one datagram a [ConnectedReadFunc] read.
type ConnectedPacket struct {
	Offset int            // start of the datagram in the slab
	Size   int            // length of the datagram
	Source netip.AddrPort // the remote address the datagram came from
	Local  netip.Addr     // the local address it was sent to, which is its socket's
}
