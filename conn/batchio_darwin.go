//go:build darwin

package conn

import (
	"errors"
	"net"
	"sync"
	"syscall"

	"github.com/tailscale/wireguard-go/internal/darwinbatch"
	"golang.org/x/net/ipv6"
)

// UnconnectedBatch reads and sends up to [IdealBatchSize] datagrams per syscall on an unconnected UDP socket, using recvmsg_x and sendmsg_x. Its methods match x/net's batch methods, with one buffer and no control data per message.
//
// ReadBatch calls are serialised. WriteBatch is safe for concurrent use.
type UnconnectedBatch struct {
	rc syscall.RawConn

	readMu sync.Mutex
	rx     *darwinbatch.State
	addrs  []net.UDPAddr // reused per read slot so reads do not allocate
	ips    [][16]byte

	tx sync.Pool // of *darwinbatch.State
}

// BatchIOSupported returns why [NewUnconnectedBatch] would fail on this host (a ts_omit_darwin_spi build or a failed kernel self-test), or nil.
func BatchIOSupported() error { return darwinbatch.UnconnectedSelfTestErr() }

// NewUnconnectedBatch returns an UnconnectedBatch for c, or the error from [BatchIOSupported].
func NewUnconnectedBatch(c *net.UDPConn) (*UnconnectedBatch, error) {
	if err := BatchIOSupported(); err != nil {
		return nil, err
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	b := &UnconnectedBatch{rc: rc, rx: darwinbatch.New(IdealBatchSize), addrs: make([]net.UDPAddr, IdealBatchSize), ips: make([][16]byte, IdealBatchSize)}
	b.rx.RecvNames()
	b.tx.New = func() any { return darwinbatch.New(IdealBatchSize) }
	return b, nil
}

// ReadBatch blocks until at least one datagram arrives. The Addr values it sets are reused by the next call.
func (b *UnconnectedBatch) ReadBatch(msgs []ipv6.Message, _ int) (int, error) {
	b.readMu.Lock()
	defer b.readMu.Unlock()
	want := min(len(msgs), b.rx.Cap())
	for i := range want {
		b.rx.StageRecv(i, msgs[i].Buffers[0])
	}
	defer b.rx.Reset()
	var n int
	var rerr error
	if err := b.rc.Read(func(fd uintptr) bool {
		n, rerr = b.rx.Recv(fd, want)
		return rerr != syscall.EAGAIN
	}); err != nil {
		return 0, err
	}
	if rerr != nil {
		return 0, &net.OpError{Op: "read", Net: "udp", Err: rerr}
	}
	for i := range n {
		ap := b.rx.AddrPort(i)
		ip := ap.Addr().As16()
		b.ips[i] = ip
		a := &b.addrs[i]
		a.IP, a.Port, a.Zone = b.ips[i][:], int(ap.Port()), ""
		if ap.Addr().Is4() {
			a.IP = b.ips[i][12:16]
		}
		msgs[i].N = b.rx.RecvLen(i)
		msgs[i].NN = 0
		msgs[i].Addr = a
	}
	return n, nil
}

var errBatchAddr = errors.New("UnconnectedBatch: message has no *net.UDPAddr destination")

// WriteBatch returns how many messages the kernel accepted.
func (b *UnconnectedBatch) WriteBatch(msgs []ipv6.Message, _ int) (int, error) {
	st := b.tx.Get().(*darwinbatch.State)
	defer func() { st.Reset(); b.tx.Put(st) }()
	cnt := min(len(msgs), st.Cap())
	for i := range cnt {
		ua, ok := msgs[i].Addr.(*net.UDPAddr)
		if !ok {
			return 0, errBatchAddr
		}
		st.StageTo(i, msgs[i].Buffers[0], ua.AddrPort())
	}
	var n int
	var serr error
	if err := b.rc.Write(func(fd uintptr) bool {
		n, serr = st.Send(fd, cnt)
		return serr != syscall.EAGAIN
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, &net.OpError{Op: "write", Net: "udp", Err: serr}
	}
	return n, nil
}
