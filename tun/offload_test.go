package tun

import (
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Fuzz_GSOSplit(f *testing.F) {
	const segmentSize = 100

	tcpFields := &header.TCPFields{
		SrcPort:    1,
		DstPort:    1,
		SeqNum:     1,
		AckNum:     1,
		DataOffset: 20,
		Flags:      header.TCPFlagAck | header.TCPFlagPsh,
		WindowSize: 3000,
	}
	udpFields := &header.UDPFields{
		SrcPort: 1,
		DstPort: 1,
		Length:  8 + segmentSize,
	}

	gsoTCPv4 := make([]byte, 20+20+segmentSize)
	header.IPv4(gsoTCPv4).Encode(&header.IPv4Fields{
		SrcAddr:     tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.1").AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.2").AsSlice()),
		Protocol:    ipProtoTCP,
		TTL:         64,
		TotalLength: uint16(len(gsoTCPv4)),
	})
	header.TCP(gsoTCPv4[20:]).Encode(tcpFields)

	gsoUDPv4 := make([]byte, 20+8+segmentSize)
	header.IPv4(gsoUDPv4).Encode(&header.IPv4Fields{
		SrcAddr:     tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.1").AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(netip.MustParseAddr("192.0.2.2").AsSlice()),
		Protocol:    ipProtoUDP,
		TTL:         64,
		TotalLength: uint16(len(gsoUDPv4)),
	})
	header.UDP(gsoTCPv4[20:]).Encode(udpFields)

	gsoTCPv6 := make([]byte, 40+20+segmentSize)
	header.IPv6(gsoTCPv6).Encode(&header.IPv6Fields{
		SrcAddr:           tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::1").AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::2").AsSlice()),
		TransportProtocol: ipProtoTCP,
		HopLimit:          64,
		PayloadLength:     uint16(20 + segmentSize),
	})
	header.TCP(gsoTCPv6[40:]).Encode(tcpFields)

	gsoUDPv6 := make([]byte, 40+8+segmentSize)
	header.IPv6(gsoUDPv6).Encode(&header.IPv6Fields{
		SrcAddr:           tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::1").AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::2").AsSlice()),
		TransportProtocol: ipProtoUDP,
		HopLimit:          64,
		PayloadLength:     uint16(8 + segmentSize),
	})
	header.UDP(gsoUDPv6[20:]).Encode(udpFields)

	out := make([][]byte, conn.IdealBatchSize)
	for i := range out {
		out[i] = make([]byte, 65535)
	}
	sizes := make([]int, conn.IdealBatchSize)

	f.Add(gsoTCPv4, int(GSOTCPv4), uint16(40), uint16(20), uint16(16), uint16(100), false)
	f.Add(gsoUDPv4, int(GSOUDPL4), uint16(28), uint16(20), uint16(6), uint16(100), false)
	f.Add(gsoTCPv6, int(GSOTCPv6), uint16(60), uint16(40), uint16(16), uint16(100), false)
	f.Add(gsoUDPv6, int(GSOUDPL4), uint16(48), uint16(40), uint16(6), uint16(100), false)

	f.Fuzz(func(t *testing.T, pkt []byte, gsoType int, hdrLen, csumStart, csumOffset, gsoSize uint16, needsCsum bool) {
		options := GSOOptions{
			GSOType:    GSOType(gsoType),
			HdrLen:     hdrLen,
			CsumStart:  csumStart,
			CsumOffset: csumOffset,
			GSOSize:    gsoSize,
			NeedsCsum:  needsCsum,
		}
		n, _ := GSOSplit(pkt, options, out, sizes, 0)
		if n > len(sizes) {
			t.Errorf("n (%d) > len(sizes): %d", n, len(sizes))
		}
	})
}
