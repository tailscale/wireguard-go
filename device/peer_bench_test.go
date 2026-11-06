// SPDX-License-Identifier: MIT

package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	core "github.com/tailscale/wireguard-go/peer"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

// BenchmarkPeerDevicePipeline measures channel/TUN pipelines, including copies,
// workers, timers, routing, and allocations. Bind and TUN batch sizes are one.
// batch is the application's submission and drain window. Each packet is drained,
// checked for length and sequence, and counted once. DeviceToPeer omits a
// receive-side TUN copy. These are complete pipelines, not isolated crypto costs.
// Long runs can include device maintenance traffic.
func BenchmarkPeerDevicePipeline(b *testing.B) {
	for _, size := range []int{64, 1420} {
		for _, batch := range []int{1, 16, 64} {
			for _, direction := range []string{"PeerToDevice", "DeviceToPeer", "DeviceToDevice"} {
				b.Run(fmt.Sprintf("%s/bytes=%d/window=%d", direction, size, batch), func(b *testing.B) {
					// One untimed watchdog bounds stalls without per-packet allocations.
					watchdog := time.AfterFunc(60*time.Second, func() { panic("pipeline benchmark stalled") })
					defer watchdog.Stop()
					b.ReportAllocs()
					b.SetBytes(int64(size * batch))
					if direction == "DeviceToDevice" {
						benchmarkDevicePair(b, size, batch)
						return
					}
					h := newInteropPair(b, core.PresharedKey{}, core.PresharedKey{})
					// Establish with device as initiator without the synctest-only test helpers.
					if err := h.dp.SendHandshakeInitiation(false); err != nil {
						b.Fatal(err)
					}
					response, err := h.handle(<-h.bind.tx)
					if err != nil {
						b.Fatal(err)
					}
					h.inject(response.Bytes())
					if r := h.open(<-h.bind.tx); r.Disposition != core.Keepalive {
						b.Fatalf("confirmation %+v", r)
					}
					vectors := make([]core.Packet, batch)
					results := make([]core.ReceiveResult, batch)
					ips := make([][]byte, batch)
					slab := make([]byte, batch*1536)
					for i := range ips {
						ips[i] = interopIP(false, direction == "PeerToDevice", size, 0)
						vectors[i] = core.Packet{Buffer: slab[i*1536 : (i+1)*1536 : (i+1)*1536], Offset: 40, Size: size}
					}
					seq := uint64(0)
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						for j, ip := range ips {
							binary.LittleEndian.PutUint64(ip[len(ip)-8:], seq+uint64(j))
							if direction == "PeerToDevice" {
								vectors[j].Offset = 40
								vectors[j].Size = size
								copy(vectors[j].Bytes(), ip)
							} else {
								h.tun.Outbound <- ip
							}
						}
						if direction == "PeerToDevice" {
							if n, err := h.p.Send(time.Now(), vectors); n.N != batch || err != nil {
								b.Fatalf("send %d %v", n.N, err)
							}
							for _, p := range vectors {
								h.inject(p.Bytes())
							}
							for j := 0; j < batch; j++ {
								got := <-h.delivered
								if len(got) != size || binary.LittleEndian.Uint64(got[len(got)-8:]) != seq+uint64(j) {
									b.Fatal("loss, ordering or length")
								}
							}
						} else {
							for j := range vectors {
								wire := <-h.bind.tx
								vectors[j] = core.Packet{Buffer: wire, Size: len(wire)}
							}
							if n, err := h.p.Receive(time.Now(), vectors, results); n.N != batch || err != nil {
								b.Fatalf("receive %d %v", n.N, err)
							}
							for j, r := range results {
								if r.Disposition != core.Data || r.Err != nil || r.Packet.Size != size || binary.LittleEndian.Uint64(r.Packet.Bytes()[size-8:]) != seq+uint64(j) {
									b.Fatal("loss, replay or length")
								}
							}
						}
						seq += uint64(batch)
					}
					b.StopTimer()
					reportPipeline(b, batch)
				})
			}
		}
	}
}
func reportPipeline(b *testing.B, batch int) {
	b.ReportMetric(float64(b.N)*float64(batch)/b.Elapsed().Seconds(), "packets/s")
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(batch), "ns/packet")
	b.ReportMetric(0, "lost-packets") // exact fixed-N sequence-checked drain above
}
func benchmarkDevicePair(b *testing.B, size, batch int) {
	pair := benchmarkChannelPair(b)
	// Matching Bind/TUN channel adapters, one queue, one packet per bind operation.
	// Existing latency/throughput benchmarks use a different completion denominator.
	warm := interopIP(false, true, size, 0)
	copy(warm[12:16], pair[0].ip.AsSlice())
	copy(warm[16:20], pair[1].ip.AsSlice())
	pair[0].tun.Outbound <- warm
	if got := <-pair[1].tun.Inbound; !bytes.Equal(got, warm) {
		b.Fatal("warmup delivery")
	}
	packets := make([][]byte, batch)
	for i := range packets {
		packets[i] = bytes.Clone(warm)
	}
	// Decouple a bounded window of TUN writes from draining. TUN itself is
	// unbuffered. A collector of equal depth is used in the mixed receive path too.
	delivered := make(chan []byte, 256)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case p := <-pair[1].tun.Inbound:
				select {
				case delivered <- p:
				case <-done:
					return
				}
			}
		}
	}()
	seq := uint64(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j, p := range packets {
			binary.LittleEndian.PutUint64(p[size-8:], seq+uint64(j))
			pair[0].tun.Outbound <- p
		}
		for j := 0; j < batch; j++ {
			got := <-delivered
			if len(got) != size || binary.LittleEndian.Uint64(got[size-8:]) != seq+uint64(j) {
				b.Fatal("loss, ordering or length")
			}
		}
		seq += uint64(batch)
	}
	b.StopTimer()
	reportPipeline(b, batch)
}

// Use the identical single-family, depth-256, copying Bind as mixed pipelines,
// rather than comparing against bindtest's depth-8192/two-family configuration.
func benchmarkChannelPair(b *testing.B) (pair testPair) {
	cfg, endpoint := genConfigs(b)
	binds := [2]*interopBind{newInteropBind(), newInteropBind()}
	binds[0].tx = binds[1].rx
	binds[1].tx = binds[0].rx
	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		p.dev = NewDevice(p.tun.TUN(), binds[i], NewLogger(LogLevelError, ""))
		b.Cleanup(p.dev.Close)
		if err := p.dev.IpcSet(cfg[i]); err != nil {
			b.Fatal(err)
		}
		if err := p.dev.Up(); err != nil {
			b.Fatal(err)
		}
		if err := p.dev.IpcSet(fmt.Sprintf(endpoint[i], 1)); err != nil {
			b.Fatal(err)
		}
	}
	return pair
}
