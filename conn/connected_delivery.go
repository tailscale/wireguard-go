//go:build unix && !aix && !solaris && !illumos

package conn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

var (
	deliveryOnce sync.Once
	deliveryErr  error
)

// ConnectedDeliveryCheck returns nil if the kernel delivers a peer's datagrams to a connected socket rather than to the unconnected socket sharing its port. It tests once on loopback and caches the result; while it fails, [ConnectedSockets] opens no sockets and every send uses the caller's socket.
//
// Linux only prefers the connected socket since 5.4 (backported to 4.19.75).
func ConnectedDeliveryCheck() error {
	deliveryOnce.Do(func() { deliveryErr = deliveryTest() })
	return deliveryErr
}

func deliveryTest() error {
	lc := net.ListenConfig{Control: ReusePortControl}
	ctx := context.Background()
	shared, err := lc.ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("connected delivery check: %w", err)
	}
	defer shared.Close()
	port := shared.LocalAddr().(*net.UDPAddr).Port
	loop := net.IPv4(127, 0, 0, 1)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loop})
	if err != nil {
		return fmt.Errorf("connected delivery check: %w", err)
	}
	defer peer.Close()
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loop})
	if err != nil {
		return fmt.Errorf("connected delivery check: %w", err)
	}
	defer other.Close()
	// Bound to a specific address and connected, as ConnectedSockets does.
	d := net.Dialer{LocalAddr: &net.UDPAddr{IP: loop, Port: port}, Control: func(_, _ string, c syscall.RawConn) error { return sharePort(c) }}
	cc, err := d.DialContext(ctx, "udp4", peer.LocalAddr().String())
	if err != nil {
		return fmt.Errorf("connected delivery check: %w", err)
	}
	defer cc.Close()

	to := &net.UDPAddr{IP: loop, Port: port}
	deadline := time.Now().Add(2 * time.Second)
	cc.SetReadDeadline(deadline)
	shared.SetReadDeadline(deadline)
	buf := make([]byte, 16)
	if _, err := peer.WriteToUDP([]byte("peer"), to); err != nil {
		return fmt.Errorf("connected delivery check: %w", err)
	}
	if n, err := cc.Read(buf); err != nil || string(buf[:n]) != "peer" {
		return fmt.Errorf("connected delivery check: the connected socket did not receive its peer's datagram (%q, %v)", buf[:n], err)
	}
	if _, err := other.WriteToUDP([]byte("other"), to); err != nil {
		return fmt.Errorf("connected delivery check: %w", err)
	}
	n, _, err := shared.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("connected delivery check: the shared socket did not receive another sender's datagram: %w", err)
	}
	if string(buf[:n]) != "other" {
		return errors.New("connected delivery check: the kernel delivered a datagram to the wrong socket")
	}
	return nil
}
