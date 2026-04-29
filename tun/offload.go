package tun

import (
	"encoding/binary"
	"fmt"

	"github.com/tailscale/wireguard-go/iobuf"
)

// GSOType represents the type of segmentation offload.
type GSOType int

const (
	GSONone GSOType = iota
	GSOTCPv4
	GSOTCPv6
	GSOUDPL4
)

func (g GSOType) String() string {
	switch g {
	case GSONone:
		return "GSONone"
	case GSOTCPv4:
		return "GSOTCPv4"
	case GSOTCPv6:
		return "GSOTCPv6"
	case GSOUDPL4:
		return "GSOUDPL4"
	default:
		return "unknown"
	}
}

// GSOOptions is loosely modeled after struct virtio_net_hdr from the VIRTIO
// specification. It is a common representation of GSO metadata that can be
// applied to support packet GSO across tun.Device implementations.
type GSOOptions struct {
	// GSOType represents the type of segmentation offload.
	GSOType GSOType
	// HdrLen is the sum of the layer 3 and 4 header lengths. This field may be
	// zero when GSOType == GSONone.
	HdrLen uint16
	// CsumStart is the head byte index of the packet data to be checksummed,
	// i.e. the start of the TCP or UDP header.
	CsumStart uint16
	// CsumOffset is the offset from CsumStart where the 2-byte checksum value
	// should be placed.
	CsumOffset uint16
	// GSOSize is the size of each segment exclusive of HdrLen. The tail segment
	// may be smaller than this value.
	GSOSize uint16
	// NeedsCsum may be set where GSOType == GSONone. When set, the checksum
	// at CsumStart + CsumOffset must be a partial checksum, i.e. the
	// pseudo-header sum.
	NeedsCsum bool
}

const (
	ipv4SrcAddrOffset = 12
	ipv6SrcAddrOffset = 8
)

const tcpFlagsOffset = 13

const (
	tcpFlagFIN uint8 = 0x01
	tcpFlagPSH uint8 = 0x08
	tcpFlagACK uint8 = 0x10
)

const (
	// defined here in order to avoid importation of any platform-specific pkgs
	ipProtoTCP = 6
	ipProtoUDP = 17
)

// MaxL3L4HeaderLen is the conservative upper bound on the combined IP + transport
// header length GSOSplit may copy per segment: IPv6 (40) + max TCP (60).
const MaxL3L4HeaderLen = 100

// spreadSegments spreads the coalesced payload at
// src.Bytes[offset : offset+payloadLen] into uniform [offset | gsoSize |
// tailroom] frames, one per segment, emitting a View per frame into out.
//
// Frames that overflow src source extra Shared buffers from alloc. The initial
// pool ref on each extra is dropped here, leaving it owned by its views.
//
// Frames that do not fit into out views are dropped and n < total is returned
// with ErrTooManySegments.
func spreadSegments(src *iobuf.Shared, out []iobuf.View, offset, payloadLen, gsoSize, tailroom int, alloc func() *iobuf.Shared) (n, total int, err error) {
	if gsoSize <= 0 {
		return 0, 0, ErrInvalidGSOSize
	}
	frame := offset + gsoSize + tailroom
	perBuf := len(src.Bytes) / frame
	if perBuf < 1 {
		return 0, 0, ErrTooManySegments
	}
	total = (payloadLen + gsoSize - 1) / gsoSize
	n = min(total, len(out))
	nbuf := (n + perBuf - 1) / perBuf

	bufs := make([]*iobuf.Shared, nbuf)
	bufs[0] = src
	for k := 1; k < nbuf; k++ {
		bufs[k] = alloc()
	}

	for i := n - 1; i >= 0; i-- {
		segLen := gsoSize
		if i == total-1 {
			segLen = payloadLen - (total-1)*gsoSize
		}
		b := bufs[i/perBuf]
		frameStart := (i % perBuf) * frame
		copy(b.Bytes[frameStart+offset:frameStart+offset+segLen], src.Bytes[offset+i*gsoSize:offset+i*gsoSize+segLen])
		b.Refer(&out[i], frameStart, frameStart+frame)
		out[i].Bytes = out[i].Bytes[:offset+segLen]
	}

	for _, b := range bufs[1:] {
		b.Release()
	}
	return n, total, nil
}

// GSOSplit splits the coalesced packet living at
// shared.Bytes[outOffset : outOffset+HdrLen+payloadLen] into one or more
// per-segment views in outBufs.
//
// Layout invariants on entry:
//
//	shared.Bytes[outOffset : outOffset+HdrLen]            holds the L3+L4 header.
//	shared.Bytes[outOffset+HdrLen : outOffset+HdrLen+payloadLen] holds [p1, p2, ..., pN].
//	payloadStart == outOffset + HdrLen.
//
// Each emitted view's Bytes[outOffset:] is the per-segment packet (header +
// payload), and the View retains tailroom bytes of cap past Bytes for in-place
// growth during encryption. Views may span more than one backing buffer when the
// spread overflows shared (see spreadSegments).
//
// GSONone (or payloadLen < GSOSize) emits a single view without spreading;
// otherwise payloads are spread into frames and per-segment L3+L4 headers are
// back-filled from a stack-saved template.
//
// Returns the number of views populated.
func GSOSplit(shared *iobuf.Shared, options GSOOptions, payloadStart, payloadLen int, outBufs []iobuf.View, outOffset, tailroom int, alloc func() *iobuf.Shared) (int, error) {
	hdrLen := int(options.HdrLen)
	if payloadStart != outOffset+hdrLen && options.GSOType != GSONone {
		return 0, fmt.Errorf("payloadStart (%d) != outOffset+HdrLen (%d)", payloadStart, outOffset+hdrLen)
	}
	if payloadLen < 0 {
		return 0, fmt.Errorf("negative payloadLen (%d)", payloadLen)
	}
	if outOffset+hdrLen+payloadLen > len(shared.Bytes) {
		return 0, fmt.Errorf("packet end %d exceeds shared cap %d", outOffset+hdrLen+payloadLen, len(shared.Bytes))
	}
	in := shared.Bytes[outOffset : outOffset+hdrLen+payloadLen]

	cSumAt := int(options.CsumStart) + int(options.CsumOffset)
	if cSumAt+1 >= len(in) {
		return 0, fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", cSumAt+1, len(in))
	}
	if cSumAt+1 >= hdrLen && options.GSOType != GSONone {
		return 0, fmt.Errorf("checksum location (%d) does not fit in per-segment header (%d)", cSumAt+1, hdrLen)
	}

	if options.GSOType == GSONone || payloadLen < int(options.GSOSize) {
		end := outOffset + len(in)
		capEnd := end + tailroom
		if capEnd > len(shared.Bytes) {
			return 0, fmt.Errorf("single-segment frame end %d exceeds shared cap %d", capEnd, len(shared.Bytes))
		}
		if options.NeedsCsum {
			initial := binary.BigEndian.Uint16(in[cSumAt:])
			in[cSumAt], in[cSumAt+1] = 0, 0
			binary.BigEndian.PutUint16(in[cSumAt:], ^Checksum(in[options.CsumStart:], initial))
		}
		shared.Refer(&outBufs[0], 0, capEnd)
		outBufs[0].Bytes = outBufs[0].Bytes[:end]
		return 1, nil
	}

	if options.HdrLen < options.CsumStart {
		return 0, fmt.Errorf("GSO HdrLen (%d) < GSO CsumStart (%d)", options.HdrLen, options.CsumStart)
	}

	ipVersion := in[0] >> 4
	switch ipVersion {
	case 4:
		if options.GSOType != GSOTCPv4 && options.GSOType != GSOUDPL4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %s", ipVersion, options.GSOType)
		}
		if int(options.CsumStart) < 20 {
			return 0, fmt.Errorf("GSO CsumStart (%d) < minimum ipv4 header size (%d)", options.CsumStart, 20)
		}
	case 6:
		if options.GSOType != GSOTCPv6 && options.GSOType != GSOUDPL4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %s", ipVersion, options.GSOType)
		}
		if int(options.CsumStart) < 40 {
			return 0, fmt.Errorf("GSO CsumStart (%d) < minimum ipv6 header size (%d)", options.CsumStart, 40)
		}
	default:
		return 0, fmt.Errorf("invalid ip header version: %d", ipVersion)
	}

	if hdrLen > MaxL3L4HeaderLen {
		return 0, fmt.Errorf("GSO HdrLen (%d) exceeds MaxL3L4HeaderLen (%d)", hdrLen, MaxL3L4HeaderLen)
	}

	// Save unmodified L3+L4 header. All read-only fields (TCP seq, src/dst
	// addresses, IPv4 id base) MUST be sourced from hdrTemplate, not from
	// shared.Bytes — segment 0's header is mutated in place by its own fixup.
	var hdrTemplate [MaxL3L4HeaderLen]byte
	copy(hdrTemplate[:hdrLen], in[:hdrLen])

	iphLen := int(options.CsumStart)
	srcAddrOffset := ipv6SrcAddrOffset
	addrLen := 16
	if ipVersion == 4 {
		srcAddrOffset = ipv4SrcAddrOffset
		addrLen = 4
	}
	transportCsumAt := int(options.CsumStart + options.CsumOffset)
	var firstTCPSeqNum uint32
	var protocol uint8
	if options.GSOType == GSOTCPv4 || options.GSOType == GSOTCPv6 {
		protocol = ipProtoTCP
		if hdrLen < int(options.CsumStart)+20 {
			return 0, fmt.Errorf("GSO HdrLen (%d) < GSO CsumStart (%d) + minimum TCP header size (%d)",
				hdrLen, options.CsumStart, 20)
		}
		firstTCPSeqNum = binary.BigEndian.Uint32(hdrTemplate[options.CsumStart+4:])
	} else {
		protocol = ipProtoUDP
		if hdrLen < int(options.CsumStart)+8 {
			return 0, fmt.Errorf("GSO HdrLen (%d) < GSO CsumStart (%d) + minimum UDP header size (%d)",
				hdrLen, options.CsumStart, 8)
		}
	}

	gsoSize := int(options.GSOSize)
	n, total, err := spreadSegments(shared, outBufs, payloadStart, payloadLen, gsoSize, tailroom, alloc)
	if err != nil {
		return 0, err
	}

	for i := range n {
		out := outBufs[i].Bytes[outOffset:]
		totalLen := len(out)
		segLen := totalLen - hdrLen

		if i > 0 {
			copy(out[:hdrLen], hdrTemplate[:hdrLen])
		}
		if ipVersion == 4 {
			// For IPv4 we are responsible for incrementing the ID field,
			// updating the total len field, and recalculating the header
			// checksum.
			if i > 0 {
				id := binary.BigEndian.Uint16(out[4:])
				id += uint16(i)
				binary.BigEndian.PutUint16(out[4:], id)
			}
			out[10], out[11] = 0, 0 // clear ipv4 header checksum
			binary.BigEndian.PutUint16(out[2:], uint16(totalLen))
			ipv4CSum := ^Checksum(out[:iphLen], 0)
			binary.BigEndian.PutUint16(out[10:], ipv4CSum)
		} else {
			// For IPv6 we are responsible for updating the payload length field.
			binary.BigEndian.PutUint16(out[4:], uint16(totalLen-iphLen))
		}

		if protocol == ipProtoTCP {
			// set TCP seq and adjust TCP flags
			tcpSeq := firstTCPSeqNum + uint32(gsoSize)*uint32(i)
			binary.BigEndian.PutUint32(out[options.CsumStart+4:], tcpSeq)
			if i != total-1 {
				// FIN and PSH should only be set on the true last segment. Under
				// truncation (n < total) the last delivered segment is mid-stream,
				// so this clears them on every delivered segment.
				clearFlags := tcpFlagFIN | tcpFlagPSH
				out[options.CsumStart+tcpFlagsOffset] &^= clearFlags
			}
		} else {
			// set UDP header len
			binary.BigEndian.PutUint16(out[options.CsumStart+4:], uint16(segLen)+(options.HdrLen-options.CsumStart))
		}

		out[transportCsumAt], out[transportCsumAt+1] = 0, 0 // clear tcp/udp checksum
		transportHeaderLen := int(options.HdrLen - options.CsumStart)
		lenForPseudo := uint16(transportHeaderLen + segLen)
		transportCSum := PseudoHeaderChecksum(protocol,
			hdrTemplate[srcAddrOffset:srcAddrOffset+addrLen],
			hdrTemplate[srcAddrOffset+addrLen:srcAddrOffset+addrLen*2],
			lenForPseudo)
		transportCSum = ^Checksum(out[options.CsumStart:totalLen], transportCSum)
		binary.BigEndian.PutUint16(out[options.CsumStart+options.CsumOffset:], transportCSum)
	}
	if n < total {
		return n, ErrTooManySegments
	}
	return n, nil
}
