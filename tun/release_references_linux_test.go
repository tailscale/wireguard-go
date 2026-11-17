// SPDX-License-Identifier: MIT

//go:build ts_lowmem_release

package tun

import (
	"bytes"
	"github.com/tailscale/wireguard-go/conn"
	"testing"
)

func TestGROResetReleasesPacketReferences(t *testing.T) {
	tcp, udp, wi := newTCPGROTable(), newUDPGROTable(), newGROToWrite()
	for _, count := range []int{conn.IdealBatchSize, 1, conn.IdealBatchSize, 3} {
		packets := make([][]byte, count)
		for i := range packets {
			packets[i] = udp4Packet(ip4PortA, ip4PortB, 100)
		}
		if err := handleGRO(packets, offset, tcp, udp, 0, &wi); err != nil {
			t.Fatal(err)
		}
		if len(wi.iovs) != 1 || len(wi.iovs[0]) != count+1 {
			t.Fatalf("coalescing failed: writes=%d vectors=%d count=%d", len(wi.iovs), len(wi.iovs[0]), count)
		}
		wantHeader := &wi.iovs[0][0][0]
		tcp.reset()
		udp.reset()
		wi.reset()
		if &wi.iovs[:1][0][0][0] != wantHeader {
			t.Fatal("lost reusable virtio header")
		}
		for _, v := range wi.iovs[:cap(wi.iovs)] {
			if !bytes.Equal(v[0], make([]byte, virtioNetHdrLen)) {
				t.Fatal("virtio header not zeroed")
			}
			for _, p := range v[1:cap(v)] {
				if p != nil {
					t.Fatal("completed packet retained after reset")
				}
			}
		}
	}
}
