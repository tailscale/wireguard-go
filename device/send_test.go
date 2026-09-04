/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
)

func TestCopyPacketBufIfFits(t *testing.T) {
	const (
		packetSize            = 1
		singlePktRequiredSize = packetSize + outboundPlaintextTailroom
		twoPktRequiredSize    = 2*packetSize + outboundPlaintextTailroom
	)
	packets := []tun.ReadPacket{
		{
			Offset: 0,
			Size:   packetSize,
		},
	}

	tests := []struct {
		name    string
		dst     *packetBuf
		srcSize int
		packets []tun.ReadPacket
		want    bool
	}{
		{
			name:    "nil dst",
			dst:     nil,
			srcSize: singlePktRequiredSize,
			packets: packets,
			want:    false,
		},
		{
			name:    "empty packets",
			dst:     newPacketBuf(singlePktRequiredSize, func(*packetBuf) {}),
			srcSize: singlePktRequiredSize,
			packets: nil,
			want:    false,
		},
		{
			name:    "exact fit",
			dst:     newPacketBuf(singlePktRequiredSize, func(*packetBuf) {}),
			srcSize: singlePktRequiredSize,
			packets: packets,
			want:    true,
		},
		{
			name:    "src too short",
			dst:     newPacketBuf(singlePktRequiredSize, func(*packetBuf) {}),
			srcSize: singlePktRequiredSize - 1,
			packets: packets,
			want:    false,
		},
		{
			name:    "dst too short",
			dst:     newPacketBuf(singlePktRequiredSize-1, func(*packetBuf) {}),
			srcSize: singlePktRequiredSize,
			packets: packets,
			want:    false,
		},
		{
			name:    "multiple packets",
			dst:     newPacketBuf(twoPktRequiredSize, func(*packetBuf) {}),
			srcSize: twoPktRequiredSize,
			packets: []tun.ReadPacket{
				{
					Offset: 0,
					Size:   1,
				},
				{
					Offset: 1,
					Size:   1,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := newPacketBuf(tt.srcSize, func(*packetBuf) {})
			for i := range src.slab {
				src.slab[i] = byte(i)
			}

			got := copyPacketBufIfFits(tt.dst, src, tt.packets)
			if got != tt.want {
				t.Fatalf("copyPacketBufIfFits() = %v, want %v", got, tt.want)
			}
			if got && !bytes.Equal(
				tt.dst.slab[:len(tt.dst.slab)-outboundPlaintextTailroom],
				src.slab[:len(src.slab)-outboundPlaintextTailroom],
			) {
				t.Fatal("destination does not contain copied source data")
			}
		})
	}
}

func BenchmarkCopyPacketBufIfFits(b *testing.B) {
	const packetSize = smallPacketBufSize -
		tun.ReadPacketSpacing -
		outboundPlaintextTailroom

	src := newPacketBuf(batchingSlabSize, func(*packetBuf) {})
	dst := newPacketBuf(smallPacketBufSize, func(*packetBuf) {})
	packets := []tun.ReadPacket{{
		Offset: tun.ReadPacketSpacing,
		Size:   packetSize,
	}}

	b.SetBytes(tun.ReadPacketSpacing + packetSize)
	b.ReportAllocs()
	for b.Loop() {
		copyPacketBufIfFits(dst, src, packets)
	}
}
