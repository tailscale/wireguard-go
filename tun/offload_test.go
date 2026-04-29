package tun

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/iobuf"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_spreadSegments(t *testing.T) {
	const (
		offset         = 20
		tailroom       = 30
		spillsByFrames = 4
	)

	tests := []struct {
		name           string
		gsoSize        int
		payloadLen     int
		availableViews int
		wantN          int
		wantTotal      int // 0 means "same as wantN" (no truncation)
		wantFrameLen   int // headroom + gsoSize + tailroom
		wantBuffers    int
		wantErr        error
	}{
		{
			name:           "single segment",
			gsoSize:        400,
			payloadLen:     400,
			availableViews: 2,
			wantN:          1,
			wantFrameLen:   450,
			wantBuffers:    1,
		},
		{
			name:           "fills one buffer short last",
			gsoSize:        400,
			payloadLen:     (iobuf.MaxBufferSize/450-1)*400 + 150,
			availableViews: iobuf.MaxBufferSize / 450,
			wantN:          iobuf.MaxBufferSize / 450,
			wantFrameLen:   450,
			wantBuffers:    1,
		},
		{
			name:           "fills one buffer full last",
			gsoSize:        400,
			payloadLen:     iobuf.MaxBufferSize / 450 * 400,
			availableViews: iobuf.MaxBufferSize / 450,
			wantN:          iobuf.MaxBufferSize / 450,
			wantFrameLen:   450,
			wantBuffers:    1,
		},
		{
			name:           "spills short last",
			gsoSize:        400,
			payloadLen:     (iobuf.MaxBufferSize/450+spillsByFrames-1)*400 + 150, // last segment short
			availableViews: iobuf.MaxBufferSize/450 + spillsByFrames,
			wantN:          iobuf.MaxBufferSize/450 + spillsByFrames,
			wantFrameLen:   450,
			wantBuffers:    2,
		},
		{
			name:           "spills full last",
			gsoSize:        400,
			payloadLen:     (iobuf.MaxBufferSize/450 + spillsByFrames) * 400, // last segment full
			availableViews: iobuf.MaxBufferSize/450 + spillsByFrames,
			wantN:          iobuf.MaxBufferSize/450 + spillsByFrames,
			wantFrameLen:   450,
			wantBuffers:    2,
		},
		{
			name:           "non-positive gso size",
			gsoSize:        0,
			payloadLen:     100,
			availableViews: 1,
			wantErr:        ErrInvalidGSOSize,
		},
		{
			// More segments than output views: deliver the first availableViews
			// (all full gsoSize), drop the rest. spreadSegments itself does not
			// error on truncation — GSOSplit surfaces ErrTooManySegments.
			name:           "truncates to output views",
			gsoSize:        400,
			payloadLen:     3 * 400,
			availableViews: 2,
			wantN:          2,
			wantTotal:      3,
			wantFrameLen:   450,
			wantBuffers:    1,
		},
		{
			// Truncation that still needs a spill buffer for the delivered prefix.
			name:           "truncates across spill",
			gsoSize:        400,
			payloadLen:     (iobuf.MaxBufferSize/450 + spillsByFrames + 2) * 400,
			availableViews: iobuf.MaxBufferSize/450 + spillsByFrames,
			wantN:          iobuf.MaxBufferSize/450 + spillsByFrames,
			wantTotal:      iobuf.MaxBufferSize/450 + spillsByFrames + 2,
			wantFrameLen:   450,
			wantBuffers:    2,
		},
		{
			// A single frame does not fit in one buffer: hard error, nothing
			// delivered.
			name:           "frame larger than buffer",
			gsoSize:        iobuf.MaxBufferSize,
			payloadLen:     iobuf.MaxBufferSize,
			availableViews: 1,
			wantErr:        ErrTooManySegments,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sourced int
			alloc := func() *iobuf.Shared {
				sourced++
				s := &iobuf.Shared{}
				s.Refs.Store(1) // mirror the pool's initial ref
				return s
			}
			src := alloc()

			// Each payload byte is set to its 1-based segment marker, bounded by
			// the backing array (oversized payloads only exercise error paths).
			if tt.gsoSize > 0 {
				fillLen := min(tt.payloadLen, len(src.Bytes)-offset)
				for j := range fillLen {
					src.Bytes[offset+j] = byte(j/tt.gsoSize + 1)
				}
			}

			out := make([]iobuf.View, tt.availableViews)
			n, total, err := spreadSegments(src, out, offset, tt.payloadLen, tt.gsoSize, tailroom, alloc)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("spreadSegments: %v", err)
			}
			if n != tt.wantN {
				t.Fatalf("n = %d, want %d", n, tt.wantN)
			}
			wantTotal := tt.wantTotal
			if wantTotal == 0 {
				wantTotal = tt.wantN
			}
			if total != wantTotal {
				t.Fatalf("total = %d, want %d", total, wantTotal)
			}

			// The short tail only applies to the true last segment (total-1);
			// under truncation every delivered segment is full gsoSize.
			lastSeg := tt.payloadLen - (total-1)*tt.gsoSize
			backings := map[unsafe.Pointer]struct{}{}
			for i := range n {
				segLen := tt.gsoSize
				if i == total-1 {
					segLen = lastSeg
				}
				// View must expose the packet [headroom+payload] with tailroom in cap.
				if len(out[i].Bytes) != offset+segLen {
					t.Fatalf("segment %d: view len %d, want %d", i, len(out[i].Bytes), offset+segLen)
				}
				if cap(out[i].Bytes) != tt.wantFrameLen {
					t.Fatalf("segment %d: view cap %d, want frame len %d", i, cap(out[i].Bytes), tt.wantFrameLen)
				}
				// The payload at headroom must equal this segment's marker.
				want := bytes.Repeat([]byte{byte(i + 1)}, segLen)
				if !bytes.Equal(out[i].Bytes[offset:offset+segLen], want) {
					t.Fatalf("segment %d payload mismatch", i)
				}
				backings[out[i].BackingGo] = struct{}{}
			}
			if len(backings) != tt.wantBuffers {
				t.Fatalf("distinct backings = %d, want %d", len(backings), tt.wantBuffers)
			}
			if sourced != tt.wantBuffers {
				t.Fatalf("buffers sourced from pool = %d, want %d", sourced, tt.wantBuffers)
			}
			iobuf.ReleaseAll(out[:n])
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

	out := make([]iobuf.View, conn.IdealBatchSize)

	f.Add(gsoTCPv4, int(GSOTCPv4), uint16(40), uint16(20), uint16(16), uint16(100), false)
	f.Add(gsoUDPv4, int(GSOUDPL4), uint16(28), uint16(20), uint16(6), uint16(100), false)
	f.Add(gsoTCPv6, int(GSOTCPv6), uint16(60), uint16(40), uint16(16), uint16(100), false)
	f.Add(gsoUDPv6, int(GSOUDPL4), uint16(48), uint16(40), uint16(6), uint16(100), false)

	const outOffset = 24
	const tailroom = 31

	f.Fuzz(func(t *testing.T, pkt []byte, gsoType int, hdrLen, csumStart, csumOffset, gsoSize uint16, needsCsum bool) {
		options := GSOOptions{
			GSOType:    GSOType(gsoType),
			HdrLen:     hdrLen,
			CsumStart:  csumStart,
			CsumOffset: csumOffset,
			GSOSize:    gsoSize,
			NeedsCsum:  needsCsum,
		}
		alloc := func() *iobuf.Shared {
			s := &iobuf.Shared{}
			s.Refs.Store(1)
			return s
		}
		shared := alloc()
		if outOffset+len(pkt) > len(shared.Bytes) {
			return
		}
		copy(shared.Bytes[outOffset:], pkt)
		payloadStart := outOffset + int(hdrLen)
		payloadLen := len(pkt) - int(hdrLen)
		if payloadLen < 0 {
			payloadLen = 0
		}
		n, _ := GSOSplit(shared, options, payloadStart, payloadLen, out, outOffset, tailroom, alloc)
		if n > len(out) {
			t.Errorf("n (%d) > len(out): %d", n, len(out))
		}
	})
}
