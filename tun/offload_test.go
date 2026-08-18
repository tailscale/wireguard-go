package tun

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/tailscale/wireguard-go/conn"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestGSOSplitOverlappingInputs verifies that GSOSplit produces correct segments
// when in overlaps slab, without overwriting unread input.
func TestGSOSplitOverlappingInput(t *testing.T) {
	const (
		spacing    = ReadPacketSpacing
		hdrLen     = 28 // 20-byte IPv4 header + 8-byte UDP header
		payloadLen = 250
		gsoSize    = 100
		slabLen    = 1024
	)

	newInput := func() []byte {
		in := make([]byte, hdrLen+payloadLen)
		in[0] = 4 << 4 // IPv4
		for i := range in[hdrLen:] {
			in[hdrLen+i] = byte(i)
		}
		return in
	}

	options := GSOOptions{
		GSOType:    GSOUDPL4,
		HdrLen:     hdrLen,
		CsumStart:  20,
		CsumOffset: 6,
		GSOSize:    gsoSize,
	}

	// Generate reference output using disjoint input and output.
	wantSlab := make([]byte, slabLen)
	wantPackets := make([]ReadPacket, 3)
	wantN, err := GSOSplit(
		newInput(),
		options,
		wantSlab,
		wantPackets,
		spacing,
	)
	if err != nil {
		t.Fatalf("GSOSplit with disjoint input: %v", err)
	}

	// Place the input at the documented overlapping location.
	gotSlab := make([]byte, slabLen)
	in := newInput()
	overlappingIn := gotSlab[spacing : spacing+len(in)]
	copy(overlappingIn, in)

	gotPackets := make([]ReadPacket, 3)
	gotN, err := GSOSplit(
		overlappingIn,
		options,
		gotSlab,
		gotPackets,
		spacing,
	)
	if err != nil {
		t.Fatalf("GSOSplit with overlapping input: %v", err)
	}

	if gotN != wantN {
		t.Fatalf("got %d packets, want %d", gotN, wantN)
	}

	for i := range gotN {
		if gotPackets[i] != wantPackets[i] {
			t.Errorf(
				"packets[%d] = %+v, want %+v",
				i,
				gotPackets[i],
				wantPackets[i],
			)
			continue
		}

		got := gotPackets[i]
		want := wantPackets[i]

		gotBytes := gotSlab[got.Offset : got.Offset+got.Size]
		wantBytes := wantSlab[want.Offset : want.Offset+want.Size]
		if !slices.Equal(gotBytes, wantBytes) {
			t.Errorf("packet %d differs with overlapping input", i)
		}
	}
}

// TestGSOSplitPartialCapacity verifies that GSOSplit handles inputs that exceed
// the capacity of the output slab, packet descriptors, or both.
func TestGSOSplitPartialCapacity(t *testing.T) {
	const (
		spacing       = 10
		hdrLen        = 28 // 20-byte IPv4 header + 8-byte UDP header
		gsoSize       = 100
		fullPacketLen = hdrLen + gsoSize

		threeFullFit = 4*spacing + 3*fullPacketLen
		shortTailFit = 4*spacing + 2*fullPacketLen + hdrLen + 50
	)

	tests := []struct {
		name       string
		payloadLen int
		slabLen    int
		packetCap  int
		wantSizes  []int
		wantErr    bool
	}{
		{
			name:       "exact fit of full segments",
			payloadLen: 300,
			slabLen:    threeFullFit,
			packetCap:  3,
			wantSizes:  []int{128, 128, 128},
		},
		{
			name:       "exact fit with short tail",
			payloadLen: 250,
			slabLen:    shortTailFit,
			packetCap:  3,
			wantSizes:  []int{128, 128, 78},
		},
		{
			name:       "one byte short of short tail",
			payloadLen: 250,
			slabLen:    shortTailFit - 1,
			packetCap:  3,
			wantSizes:  []int{128, 128},
			wantErr:    true,
		},
		{
			name:       "packet descriptor exhaustion",
			payloadLen: 250,
			slabLen:    shortTailFit,
			packetCap:  2,
			wantSizes:  []int{128, 128},
			wantErr:    true,
		},
		{
			name:       "no segment fits",
			payloadLen: 250,
			slabLen:    2*spacing + fullPacketLen - 1,
			packetCap:  3,
			wantErr:    true,
		},
	}

	options := GSOOptions{
		GSOType:    GSOUDPL4,
		HdrLen:     hdrLen,
		CsumStart:  20,
		CsumOffset: 6,
		GSOSize:    gsoSize,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := make([]byte, hdrLen+tt.payloadLen)
			in[0] = 4 << 4 // IPv4

			for i := range in[hdrLen:] {
				in[hdrLen+i] = byte(i)
			}

			slab := make([]byte, tt.slabLen)
			packets := make([]ReadPacket, tt.packetCap)

			n, err := GSOSplit(in, options, slab, packets, spacing)
			if n != len(tt.wantSizes) {
				t.Fatalf("n = %d, want %d", n, len(tt.wantSizes))
			}
			if tt.wantErr {
				if !errors.Is(err, ErrTooManySegments) {
					t.Fatalf("error = %v, want ErrTooManySegments", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for i, wantSize := range tt.wantSizes {
				got := packets[i]

				if got.Size != wantSize {
					t.Errorf(
						"packets[%d].Size = %d, want %d",
						i,
						got.Size,
						wantSize,
					)
				}

				wantOffset := spacing + i*(fullPacketLen+spacing)
				if got.Offset != wantOffset {
					t.Errorf(
						"packets[%d].Offset = %d, want %d",
						i,
						got.Offset,
						wantOffset,
					)
				}

				payloadStart := i * gsoSize
				payloadEnd := min(payloadStart+gsoSize, tt.payloadLen)

				gotPayload := slab[got.Offset+hdrLen : got.Offset+got.Size]
				wantPayload := in[hdrLen+payloadStart : hdrLen+payloadEnd]
				if !slices.Equal(gotPayload, wantPayload) {
					t.Errorf("packets[%d] has incorrect payload", i)
				}
			}
		})
	}
}

// TestGSOSplitMinimumGSOSize documents the minimum GSO size at which a
// maximum-sized IPv4 packet can be completely split into [conn.IdealBatchSize]
// packet descriptors. GSO size 512 produces 128 segments; 511 produces 129.
func TestGSOSplitMinimumGSOSize(t *testing.T) {
	// Any changes to [conn.IdealBatchSize] should consider impacts on
	// segmentation splitting limits.
	if conn.IdealBatchSize != 128 {
		t.Fatalf("conn.IdealBatchSize = %d, want 128", conn.IdealBatchSize)
	}

	const (
		maxPacketSize = 1<<16 - 1
		slabSize      = 2 * (1<<16 - 1)
		minGSOSize    = 512
	)

	tests := []struct {
		name       string
		gsoType    GSOType
		hdrLen     uint16
		csumOffset uint16
	}{
		{
			name:       "UDP",
			gsoType:    GSOUDPL4,
			hdrLen:     28,
			csumOffset: 6,
		},
		{
			name:       "TCP",
			gsoType:    GSOTCPv4,
			hdrLen:     40,
			csumOffset: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := make([]byte, maxPacketSize)
			in[0] = 4 << 4 // IPv4

			for _, gsoSize := range []int{minGSOSize, minGSOSize - 1} {
				t.Run(fmt.Sprint(gsoSize), func(t *testing.T) {
					payloadLen := len(in) - int(tt.hdrLen)
					wantSegments :=
						(payloadLen + gsoSize - 1) / gsoSize

					slab := make([]byte, slabSize)
					packets := make([]ReadPacket, conn.IdealBatchSize)

					n, err := GSOSplit(
						in,
						GSOOptions{
							GSOType:    tt.gsoType,
							HdrLen:     tt.hdrLen,
							CsumStart:  20,
							CsumOffset: tt.csumOffset,
							GSOSize:    uint16(gsoSize),
						},
						slab,
						packets,
						ReadPacketSpacing,
					)

					wantN := min(
						wantSegments,
						conn.IdealBatchSize,
					)
					if n != wantN {
						t.Fatalf("n = %d, want %d", n, wantN)
					}

					wantErr := wantSegments > conn.IdealBatchSize
					if got := errors.Is(err, ErrTooManySegments); got != wantErr {
						t.Fatalf(
							"ErrTooManySegments = %v, want %v; err = %v",
							got,
							wantErr,
							err,
						)
					}
				})
			}
		})
	}
}

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
	header.UDP(gsoUDPv4[20:]).Encode(udpFields)

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
	header.UDP(gsoUDPv6[40:]).Encode(udpFields)

	out := make([]byte, 2*(1<<16-1))
	packets := make([]ReadPacket, conn.IdealBatchSize)

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
		n, _ := GSOSplit(pkt, options, out, packets, ReadPacketSpacing)
		if n > len(packets) {
			t.Errorf("n (%d) > len(packets): %d", n, len(packets))
		}
	})
}
