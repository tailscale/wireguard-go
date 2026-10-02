// SPDX-License-Identifier: MIT

package tun

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var lowmemTCP *tcpGROTable
var lowmemUDP *udpGROTable
var lowmemIOV groToWrite

func BenchmarkLowMemoryGROInit(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		lowmemTCP = newTCPGROTable()
		lowmemUDP = newUDPGROTable()
		lowmemIOV = newGROToWrite()
	}
}

// Exercise growth to a full batch and reuse after reset. Packet bytes and
// write ordering must remain identical for non-coalescible TCP/UDP traffic.
func TestGROFullBatchGrowth(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		for _, distinct := range []bool{false, true} {
			t.Run(proto+map[bool]string{false: "/one-flow", true: "/many-flows"}[distinct], func(t *testing.T) {
				tcp, udp, wi := newTCPGROTable(), newUDPGROTable(), newGROToWrite()
				for round := 0; round < 4; round++ {
					packets := make([][]byte, conn.IdealBatchSize)
					want := make([][]byte, len(packets))
					for i := range packets {
						dst := ip4PortB
						if distinct {
							dst = netip.AddrPortFrom(dst.Addr(), uint16(i+1))
						}
						if proto == "tcp" {
							// Gaps prevent coalescing even when all packets share a flow.
							packets[i] = tcp4Packet(ip4PortA, dst, header.TCPFlagAck, 100, uint32(1+i*1000))
						} else {
							// Increasing datagram lengths cannot coalesce into an earlier,
							// smaller UDP segment size.
							packets[i] = udp4Packet(ip4PortA, dst, 100+i)
						}
						want[i] = bytes.Clone(packets[i][offset:])
					}
					if err := handleGRO(packets, offset, tcp, udp, 0, &wi); err != nil {
						t.Fatal(err)
					}
					if len(wi.iovs) != len(want) {
						t.Fatalf("got %d writes, want %d", len(wi.iovs), len(want))
					}
					for i, vectors := range wi.iovs {
						if got := bytes.Join(vectors[1:], nil); !bytes.Equal(got, want[i]) {
							t.Fatalf("packet %d changed", i)
						}
					}
					tcp.reset()
					udp.reset()
					wi.reset()
				}
			})
		}
	}
}
