//go:build darwin

package darwinbatch

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

var (
	selfTestOnce sync.Once
	selfTestErr  error

	errOmitted = errors.New("built with ts_omit_darwin_spi")
)

// selfTest sends four datagrams over loopback with one sendmsg_x on a connected socket, reads them back with recvmsg_x, and checks the count and contents.
func selfTest() error {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return fmt.Errorf("self-test: %w", err)
	}
	defer rx.Close()
	tx, err := net.DialUDP("udp4", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return fmt.Errorf("self-test: %w", err)
	}
	defer tx.Close()

	payloads := [4]string{"wg-selftest-0", "wg-selftest-1", "wg-selftest-2", "wg-selftest-3"}
	st := New(len(payloads))
	for i, p := range payloads {
		st.Stage(i, []byte(p))
	}
	sent, err := do(tx, true, func(fd uintptr) (int, error) { return st.Send(fd, len(payloads)) })
	if err != nil || sent != len(payloads) {
		return fmt.Errorf("self-test: %s sent %d of %d: %v", SendName, sent, len(payloads), err)
	}

	rs := New(len(payloads))
	var bufs [4][64]byte
	for i := range bufs {
		rs.StageRecv(i, bufs[i][:])
	}
	rx.SetReadDeadline(time.Now().Add(2 * time.Second))
	for got := 0; got < len(payloads); {
		n, err := do(rx, false, func(fd uintptr) (int, error) { return rs.Recv(fd, len(payloads)-got) })
		if err != nil {
			return fmt.Errorf("self-test: %s: %w", RecvName, err)
		}
		for i := range n {
			if b := string(bufs[i][:rs.RecvLen(i)]); b != payloads[got+i] {
				return fmt.Errorf("self-test: got %q, want %q", b, payloads[got+i])
			}
		}
		got += n
	}
	return nil
}

// do runs call on c's fd, waiting on the runtime poller while it returns EAGAIN.
func do(c *net.UDPConn, write bool, call func(fd uintptr) (int, error)) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var cerr error
	f := func(fd uintptr) bool {
		n, cerr = call(fd)
		return cerr != syscall.EAGAIN
	}
	if write {
		err = rc.Write(f)
	} else {
		err = rc.Read(f)
	}
	if err != nil {
		return 0, err
	}
	return n, cerr
}
