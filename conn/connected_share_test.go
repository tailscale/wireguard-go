//go:build unix && !aix && !solaris && !illumos

package conn

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// tryBind binds a UDP socket to addr:port and returns the kernel's answer.
func tryBind(addr string, port int, reusePort bool) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if reusePort {
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}
	sa := &unix.SockaddrInet4{Port: port}
	copy(sa.Addr[:], net.ParseIP(addr).To4())
	return unix.Bind(fd, sa)
}

// withConnected returns a shared port with a connected socket open on it.
func withConnected(t *testing.T) int {
	t.Helper()
	_, peerAP := listenPeer(t, "udp4")
	_, port := listenShared(t, "udp4")
	s := newSet(t, ConnectedConfig{Port: port})
	if handled, err := s.Send(peerAP, [][]byte{[]byte("x")}, 0); !handled || err != nil {
		t.Fatalf("Send = %v, %v", handled, err)
	}
	return port
}

// Connected sockets do not make the caller's port joinable with SO_REUSEPORT.
func TestSharedSocketStaysExclusive(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux admits a process of the same user to a SO_REUSEPORT group by design; TestOtherUserCannotShareThePort covers other users")
	}
	port := withConnected(t)
	if err := tryBind("0.0.0.0", port, true); !errors.Is(err, unix.EADDRINUSE) {
		t.Fatalf("a wildcard SO_REUSEPORT bind of the shared port: %v, want EADDRINUSE", err)
	}
}

// Another user cannot bind the shared port to steal a peer's traffic.
// Needs root, to rerun the test binary as nobody.
func TestOtherUserCannotShareThePort(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to run a helper as another user")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no nobody user")
	}
	uid, _ := strconv.Atoi(nobody.Uid)
	gid, _ := strconv.Atoi(nobody.Gid)
	port := withConnected(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestOtherUserHelper$")
	cmd.Env = append(os.Environ(), "WG_TEST_HELPER_PORT="+strconv.Itoa(port))
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		t.Fatalf("another user could bind the shared port:\n%s", out)
	case err != nil:
		t.Skipf("cannot run the helper as nobody (is the test binary readable by it?): %v", err)
	}
}

func TestOtherUserHelper(t *testing.T) {
	port, err := strconv.Atoi(os.Getenv("WG_TEST_HELPER_PORT"))
	if err != nil {
		t.Skip("only run as a helper")
	}
	for _, addr := range []string{"0.0.0.0", "127.0.0.1"} {
		for _, rp := range []bool{false, true} {
			if err := tryBind(addr, port, rp); err == nil {
				t.Errorf("bind %s:%d (SO_REUSEPORT %v) was allowed", addr, port, rp)
			}
		}
	}
}
