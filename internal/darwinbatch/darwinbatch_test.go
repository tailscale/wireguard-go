//go:build darwin

package darwinbatch

import (
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestMsghdrXLayout pins struct msghdr_x's offsets and size to xnu's. Without cgo nothing checks them against the header, and a wrong offset would not fail loudly.
func TestMsghdrXLayout(t *testing.T) {
	var m msghdrX
	if got, want := unsafe.Sizeof(m), uintptr(56); got != want {
		t.Fatalf("sizeof(msghdrX) = %d, want %d", got, want)
	}
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"msg_name", unsafe.Offsetof(m.name), 0},
		{"msg_namelen", unsafe.Offsetof(m.namelen), 8},
		{"msg_iov", unsafe.Offsetof(m.iov), 16},
		{"msg_iovlen", unsafe.Offsetof(m.iovlen), 24},
		{"msg_control", unsafe.Offsetof(m.control), 32},
		{"msg_controllen", unsafe.Offsetof(m.controllen), 40},
		{"msg_flags", unsafe.Offsetof(m.flags), 44},
		{"msg_datalen", unsafe.Offsetof(m.datalen), 48},
	} {
		if c.got != c.want {
			t.Errorf("offsetof(%s) = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// A normal build must report Supported, or batching silently falls back; an omit build must not.
func TestSupported(t *testing.T) {
	if !spiAvailable {
		if Supported() {
			t.Fatal("omit build reports Supported() == true, so callers will try the absent SPI")
		}
		t.Skip("built with ts_omit_darwin_spi; Supported() correctly reports false")
	}
	if !Supported() {
		t.Fatal("Supported() is false, but this test binary is running on darwin with the SPI present")
	}
}

// fionread is darwin's FIONREAD, _IOR('f', 127, int), which x/sys/unix does not define for darwin.
const fionread = 0x4004667f

// TestSendRecvRoundTrip sends and receives a batch over loopback, which also checks that the kernel agrees on where msg_datalen is.
func TestSendRecvRoundTrip(t *testing.T) {
	if !spiAvailable {
		t.Skip("built with ts_omit_darwin_spi; there is no SPI to round-trip")
	}
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	const n = 6
	const plen = 300
	snd := New(n)
	for i := 0; i < n; i++ {
		p := make([]byte, plen)
		for j := range p {
			p[j] = byte(i + 1)
		}
		snd.Stage(i, p)
	}
	var sent int
	rc, err := cli.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Control(func(fd uintptr) {
		sent, err = snd.Send(fd, n)
	}); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if sent != n {
		t.Fatalf("Send accepted %d of %d", sent, n)
	}

	rcv := New(n)
	bufs := make([][]byte, n)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
		rcv.StageRecv(i, bufs[i])
	}
	var got int
	src, err := srv.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	// Wait until all n datagrams are queued so one Recv returns them all. FIONREAD counts the bytes of every queued datagram.
	for until := time.Now().Add(2 * time.Second); time.Now().Before(until); time.Sleep(time.Millisecond) {
		var queued int
		src.Control(func(fd uintptr) { queued, _ = unix.IoctlGetInt(int(fd), fionread) })
		if queued >= n*plen {
			break
		}
	}
	// Retry on EAGAIN, as the runtime poller would.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if cerr := src.Control(func(fd uintptr) {
			got, err = rcv.Recv(fd, n)
		}); cerr != nil {
			t.Fatal(cerr)
		}
		if err == nil && got > 0 {
			break
		}
		if err != nil && err != syscall.EAGAIN {
			t.Fatalf("Recv: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("Recv never returned a datagram (last err %v, got %d)", err, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got != n {
		t.Fatalf("Recv returned %d of %d", got, n)
	}
	for i := 0; i < got; i++ {
		m := bufs[i][:rcv.RecvLen(i)]
		if len(m) != plen {
			t.Errorf("message %d is %d bytes, want %d", i, len(m), plen)
			continue
		}
		want := byte(i + 1)
		for j, b := range m {
			if b != want {
				t.Errorf("message %d byte %d is %d, want %d", i, j, b, want)
				break
			}
		}
	}
}

// Recv restores each slot's staged length and clears its flags before the call.
func TestRecvRestoresStagedSlot(t *testing.T) {
	s := New(1)
	s.StageRecv(0, make([]byte, 2048))
	s.msgs[0].datalen = 17 // as a previous Recv of a 17-byte datagram leaves it
	s.iovs[0].SetLen(17)
	s.msgs[0].flags = 0x10 // MSG_TRUNC, as macOS 12 leaves it
	s.Recv(^uintptr(0), 1) // fails on the bad fd, after the restore
	if s.msgs[0].datalen != 2048 || s.iovs[0].Len != 2048 || s.msgs[0].flags != 0 {
		t.Fatalf("after Recv: datalen %d, iov len %d, flags %#x; want 2048, 2048, 0", s.msgs[0].datalen, s.iovs[0].Len, s.msgs[0].flags)
	}
}

// A slot that received an oversized datagram still works afterwards. Only macOS 12 sets MSG_TRUNC, so only there does this catch a missing clear.
func TestSlotSurvivesAnOversizedDatagram(t *testing.T) {
	if !Supported() {
		t.Skip("no batched receive on this build or kernel")
	}
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	cli, err := net.DialUDP("udp4", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	const slot = 128
	st := New(4)
	st.StageRecv(0, make([]byte, slot))
	defer st.Reset()

	recv := func(what string) int {
		t.Helper()
		rc, err := srv.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var n int
		var serr error
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if cerr := rc.Control(func(fd uintptr) { n, serr = st.Recv(fd, 1) }); cerr != nil {
				t.Fatalf("%s: control: %v", what, cerr)
			}
			if serr == nil && n > 0 {
				return n
			}
			if serr != nil && serr != syscall.EAGAIN {
				t.Fatalf("%s: Recv: %v (a stale msg_flags from a truncated read is rejected as EINVAL on macOS 12 and wedges the slot for good)", what, serr)
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("%s: nothing received before the deadline (last err %v)", what, serr)
		return 0
	}

	// Larger than the slot, so the kernel truncates it.
	if _, err := cli.Write(make([]byte, slot*4)); err != nil {
		t.Fatal(err)
	}
	recv("truncating read")

	// Then an ordinary datagram on the same slot.
	if _, err := cli.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	if got := recv("read after truncation"); got != 1 {
		t.Errorf("after a truncated read the slot returned %d messages, want 1", got)
	}
}
