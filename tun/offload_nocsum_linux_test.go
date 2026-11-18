/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// A GSO packet aggregated by NIC hardware GRO and forwarded into the TUN
// device is CHECKSUM_UNNECESSARY rather than CHECKSUM_PARTIAL, so the kernel
// sends it without VIRTIO_NET_HDR_F_NEEDS_CSUM and with csum_start and
// csum_offset left at zero.
func Test_handleVirtioReadNoCsumOffsets(t *testing.T) {
	ip4PortPriv := netip.MustParseAddrPort("10.0.0.1:1")
	hwGRO := func(gsoType uint8) virtioNetHdr {
		return virtioNetHdr{
			flags:   unix.VIRTIO_NET_HDR_F_DATA_VALID,
			gsoType: gsoType,
			gsoSize: 100,
		}
	}
	tests := []struct {
		name     string
		hdr      virtioNetHdr
		pktIn    []byte
		wantLens []int
		isV6     bool
		proto    uint8
	}{
		{"tcp4", hwGRO(unix.VIRTIO_NET_HDR_GSO_TCPV4), tcp4Packet(ip4PortPriv, ip4PortB, header.TCPFlagAck|header.TCPFlagPsh, 250, 1), []int{140, 140, 90}, false, unix.IPPROTO_TCP},
		{"tcp6", hwGRO(unix.VIRTIO_NET_HDR_GSO_TCPV6), tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck|header.TCPFlagPsh, 250, 1), []int{160, 160, 110}, true, unix.IPPROTO_TCP},
		{"udp4", hwGRO(unix.VIRTIO_NET_HDR_GSO_UDP_L4), udp4Packet(ip4PortPriv, ip4PortB, 250), []int{128, 128, 78}, false, unix.IPPROTO_UDP},
		{"udp6", hwGRO(unix.VIRTIO_NET_HDR_GSO_UDP_L4), udp6Packet(ip6PortA, ip6PortB, 250), []int{148, 148, 98}, true, unix.IPPROTO_UDP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := make([]byte, 2*(1<<16-1))
			packets := make([]ReadPacket, conn.IdealBatchSize)
			tt.hdr.encode(tt.pktIn)
			n, err := handleVirtioRead(tt.pktIn, out, packets)
			if err != nil {
				t.Fatalf("got err: %v", err)
			}
			if n != len(tt.wantLens) {
				t.Fatalf("got %d packets, wanted %d", n, len(tt.wantLens))
			}
			wantSeq := uint32(1)
			for i, wantLen := range tt.wantLens {
				if packets[i].Size != wantLen {
					t.Fatalf("packet[%d] size: got %d, want %d", i, packets[i].Size, wantLen)
				}
				pkt := out[packets[i].Offset : packets[i].Offset+packets[i].Size]
				iphLen := 20
				if tt.isV6 {
					iphLen = 40
				} else if !header.IPv4(pkt).IsChecksumValid() {
					t.Fatalf("packet[%d]: invalid IPv4 checksum", i)
				}
				if !checksumValid(pkt, uint8(iphLen), tt.proto, tt.isV6) {
					t.Fatalf("packet[%d]: invalid transport checksum", i)
				}
				if tt.proto == unix.IPPROTO_TCP {
					if seq := header.TCP(pkt[iphLen:]).SequenceNumber(); seq != wantSeq {
						t.Fatalf("packet[%d]: seq %d, want %d", i, seq, wantSeq)
					}
					wantSeq += uint32(wantLen - iphLen - 20)
				}
			}
		})
	}
}

// A hardware-GRO packet whose offsets cannot be repaired, such as IPv6 with an
// extension header, is dropped without closing the device.
func Test_handleVirtioReadNoCsumOffsetsUnsupported(t *testing.T) {
	pkt := tcp6Packet(ip6PortA, ip6PortB, header.TCPFlagAck|header.TCPFlagPsh, 250, 1)
	pkt[virtioNetHdrLen+6] = unix.IPPROTO_HOPOPTS
	hdr := virtioNetHdr{
		flags:   unix.VIRTIO_NET_HDR_F_DATA_VALID,
		gsoType: unix.VIRTIO_NET_HDR_GSO_TCPV6,
		gsoSize: 100,
	}
	hdr.encode(pkt)
	out := make([]byte, 2*(1<<16-1))
	packets := make([]ReadPacket, conn.IdealBatchSize)
	n, err := handleVirtioRead(pkt, out, packets)
	if err != nil || n != 0 {
		t.Fatalf("got n=%d err=%v, want n=0 err=nil", n, err)
	}
}
