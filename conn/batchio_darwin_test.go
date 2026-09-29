//go:build darwin

package conn

import (
	"net/netip"
	"testing"
	"time"
)

// With WithBatchedIO, a batch round-trips intact and with the right source over IPv4 and IPv6.
func TestStdNetBindBatchedIO(t *testing.T) {
	if err := BatchIOSupported(); err != nil {
		t.Skip("batched calls unavailable:", err)
	}
	for _, loop := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()} {
		a := NewStdNetBind(WithBatchedIO(true)).(*StdNetBind)
		b := NewStdNetBind(WithBatchedIO(true)).(*StdNetBind)
		if a.BatchSize() != IdealBatchSize {
			t.Fatalf("BatchSize() = %d with WithBatchedIO, want %d", a.BatchSize(), IdealBatchSize)
		}
		_, aport, err := a.Open(0)
		if err != nil {
			t.Fatal(err)
		}
		fns, bport, err := b.Open(0)
		if err != nil {
			a.Close()
			t.Fatal(err)
		}
		if a.batch4 == nil || a.batch6 == nil || b.batch4 == nil || b.batch6 == nil {
			t.Fatalf("batched I/O not in use: a %v/%v b %v/%v", a.batch4 != nil, a.batch6 != nil, b.batch4 != nil, b.batch6 != nil)
		}
		fn := fns[0]
		if loop.Is6() {
			fn = fns[1]
		}
		const count = 16
		bufs := make([][]byte, count)
		for i := range bufs {
			bufs[i] = []byte{byte(i), 'w', 'g'}
		}
		if err := a.Send(bufs, &StdNetEndpoint{AddrPort: netip.AddrPortFrom(loop, bport)}, 0); err != nil {
			t.Fatalf("%v: Send: %v", loop, err)
		}
		slab := make([]byte, IdealBatchSize*maxDatagramSize)
		packets := make([]ReceivedPacket, IdealBatchSize)
		got, most := 0, 0
		deadline := time.Now().Add(3 * time.Second)
		for got < count && time.Now().Before(deadline) {
			n, err := fn(slab, packets)
			if err != nil {
				t.Fatalf("%v: receive: %v", loop, err)
			}
			most = max(most, n)
			for _, p := range packets[:n] {
				d := slab[p.Offset : p.Offset+p.Size]
				if len(d) != 3 || d[0] != byte(got) {
					t.Fatalf("%v: datagram %d = %v", loop, got, d)
				}
				src := p.Endpoint.(*StdNetEndpoint).AddrPort
				if src != netip.AddrPortFrom(loop, aport) {
					t.Fatalf("%v: source %v, want %v", loop, src, netip.AddrPortFrom(loop, aport))
				}
				got++
			}
		}
		if got != count {
			t.Fatalf("%v: received %d of %d", loop, got, count)
		}
		if most < 2 {
			t.Errorf("%v: every read returned one datagram; the batched path was not used", loop)
		}
		a.Close()
		b.Close()
	}
}
