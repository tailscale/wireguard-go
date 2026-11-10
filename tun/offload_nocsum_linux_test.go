/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
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

// A packet that cannot be segmented must surface as ErrInvalidGSOPacket, which
// callers drop instead of treating as a fatal read error.
func Test_handleVirtioReadInvalidGSOPacket(t *testing.T) {
	tests := []struct {
		name  string
		hdr   virtioNetHdr
		pktIn []byte
	}{
		{
			"tcp gso type, udp payload",
			virtioNetHdr{gsoType: unix.VIRTIO_NET_HDR_GSO_TCPV4, gsoSize: 100},
			udp4Packet(ip4PortA, ip4PortB, 250),
		},
		{
			"udp gso type, tcp payload",
			virtioNetHdr{gsoType: unix.VIRTIO_NET_HDR_GSO_UDP_L4, gsoSize: 100},
			tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 250, 1),
		},
		{
			"ipv4 ihl below minimum",
			virtioNetHdr{gsoType: unix.VIRTIO_NET_HDR_GSO_TCPV4, gsoSize: 100},
			func() []byte {
				b := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 250, 1)
				b[offset] = 0x44
				return b
			}(),
		},
		{
			"unsupported gso type",
			virtioNetHdr{gsoType: 0x7f, gsoSize: 100},
			tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 250, 1),
		},
		{
			"tcp header length invalid",
			virtioNetHdr{flags: unix.VIRTIO_NET_HDR_F_NEEDS_CSUM, gsoType: unix.VIRTIO_NET_HDR_GSO_TCPV4, gsoSize: 100, csumStart: 20, csumOffset: 16},
			func() []byte {
				b := tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 250, 1)
				b[offset+20+12] = 0x10
				return b
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := make([]byte, 2*(1<<16-1))
			packets := make([]ReadPacket, conn.IdealBatchSize)
			tt.hdr.encode(tt.pktIn)
			_, err := handleVirtioRead(tt.pktIn, out, packets)
			if !errors.Is(err, ErrInvalidGSOPacket) {
				t.Fatalf("got err %v, want ErrInvalidGSOPacket", err)
			}
		})
	}
}
