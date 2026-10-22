//go:build darwin

package conn

import (
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func dontFragmentOf(t *testing.T, network string, c syscall.RawConn) int {
	t.Helper()
	level, opt := unix.IPPROTO_IP, unix.IP_DONTFRAG
	if network == "udp6" {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG
	}
	var v int
	var gerr error
	if err := c.Control(func(fd uintptr) { v, gerr = unix.GetsockoptInt(int(fd), level, opt) }); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

func rawConn(t *testing.T, c *net.UDPConn) syscall.RawConn {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	return rc
}

func TestStdNetBindDontFragment(t *testing.T) {
	for _, on := range []bool{false, true} {
		var opts []Option
		if on {
			opts = append(opts, WithDontFragment(true))
		}
		b := NewStdNetBind(opts...).(*StdNetBind)
		if _, _, err := b.Open(0); err != nil {
			t.Fatal(err)
		}
		want := 0
		if on {
			want = 1
		}
		for _, sock := range b.v4 {
			if got := dontFragmentOf(t, "udp4", rawConn(t, sock.conn)); got != want {
				t.Errorf("WithDontFragment(%v): udp4 IP_DONTFRAG = %d, want %d", on, got, want)
			}
		}
		for _, sock := range b.v6 {
			if got := dontFragmentOf(t, "udp6", rawConn(t, sock.conn)); got != want {
				t.Errorf("WithDontFragment(%v): udp6 IPV6_DONTFRAG = %d, want %d", on, got, want)
			}
		}
		if len(b.v4) == 0 || len(b.v6) == 0 {
			t.Fatalf("Open made %d udp4 and %d udp6 sockets, want at least one of each", len(b.v4), len(b.v6))
		}

		// Connected sockets, dialled with connectedControl, get the same setting.
		d := net.Dialer{Control: b.connectedControl}
		nc, err := d.Dial("udp4", "127.0.0.1:9")
		if err != nil {
			b.Close()
			t.Fatal(err)
		}
		if got := dontFragmentOf(t, "udp4", rawConn(t, nc.(*net.UDPConn))); got != want {
			t.Errorf("WithDontFragment(%v): connected udp4 IP_DONTFRAG = %d, want %d", on, got, want)
		}
		nc.Close()
		b.Close()
	}
}
