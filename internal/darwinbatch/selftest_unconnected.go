//go:build darwin

package darwinbatch

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

var (
	unconnectedOnce sync.Once
	unconnectedErr  error
)

// UnconnectedSelfTestErr is nil if a loopback test shows that sendmsg_x honours per-datagram destinations ([State.StageTo]) and recvmsg_x reports sources. [Supported] covers only connected sockets and the utun.
func UnconnectedSelfTestErr() error {
	unconnectedOnce.Do(func() {
		if !Supported() {
			unconnectedErr = SelfTestErr()
			return
		}
		unconnectedErr = unconnectedSelfTest()
	})
	return unconnectedErr
}

// unconnectedSelfTest sends four datagrams to two receivers alternately with one sendmsg_x, and checks that each receives its two with the right source.
func unconnectedSelfTest() error {
	listen := func() (*net.UDPConn, error) { return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}) }
	tx, err := listen()
	if err != nil {
		return fmt.Errorf("unconnected self-test: %w", err)
	}
	defer tx.Close()
	var rxs [2]*net.UDPConn
	for i := range rxs {
		if rxs[i], err = listen(); err != nil {
			return fmt.Errorf("unconnected self-test: %w", err)
		}
		defer rxs[i].Close()
	}
	src := tx.LocalAddr().(*net.UDPAddr).AddrPort()

	payloads := [4]string{"wg-selftest-0", "wg-selftest-1", "wg-selftest-2", "wg-selftest-3"}
	st := New(len(payloads))
	for i, p := range payloads {
		st.StageTo(i, []byte(p), rxs[i%2].LocalAddr().(*net.UDPAddr).AddrPort())
	}
	if sent, err := do(tx, true, func(fd uintptr) (int, error) { return st.Send(fd, len(payloads)) }); err != nil || sent != len(payloads) {
		return fmt.Errorf("unconnected self-test: %s sent %d of %d: %v", SendName, sent, len(payloads), err)
	}
	for r, rx := range rxs {
		rs := New(2)
		rs.RecvNames()
		var bufs [2][64]byte
		for i := range bufs {
			rs.StageRecv(i, bufs[i][:])
		}
		rx.SetReadDeadline(time.Now().Add(2 * time.Second))
		for got := 0; got < 2; {
			n, err := do(rx, false, func(fd uintptr) (int, error) { return rs.Recv(fd, 2-got) })
			if err != nil {
				return fmt.Errorf("unconnected self-test: %s: %w", RecvName, err)
			}
			for i := range n {
				want := payloads[r+2*(got+i)]
				if b := string(bufs[i][:rs.RecvLen(i)]); b != want {
					return fmt.Errorf("unconnected self-test: receiver %d got %q, want %q", r, b, want)
				}
				if a := rs.AddrPort(i); a != netip.AddrPortFrom(src.Addr(), src.Port()) {
					return fmt.Errorf("unconnected self-test: source %v, want %v", a, src)
				}
			}
			got += n
		}
	}
	return nil
}
