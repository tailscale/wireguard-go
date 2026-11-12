/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSplitNeedsMatchesGSOSplit checks that splitNeeds reports exactly the
// capacity GSOSplit needs: the frame splits whole into that much, and one
// packet entry or one byte less leaves it short. The batched drain relies on
// this to never split a frame it cannot place whole.
func TestSplitNeedsMatchesGSOSplit(t *testing.T) {
	src := netip.MustParseAddrPort("192.0.2.1:1")
	dst := netip.MustParseAddrPort("192.0.2.2:2")
	tests := []struct {
		name       string
		payloadLen int
		gsoSize    uint16
		wantSegs   int
	}{
		{"single, no gso", 1200, 0, 1},
		{"payload below gso size", 50, 100, 1},
		{"exact multiple", 300, 100, 3},
		{"short tail", 250, 100, 3},
		{"more than 64 segments", 64000, 500, 128},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := func() ([]byte, GSOOptions) {
				pkt := udp4Packet(src, dst, tt.payloadLen)[offset:]
				opts := GSOOptions{GSOType: GSONone, HdrLen: 28, CsumStart: 20, CsumOffset: 6}
				if tt.gsoSize > 0 {
					opts.GSOType = GSOUDPL4
					opts.GSOSize = tt.gsoSize
				}
				return pkt, opts
			}
			pkt, opts := frame()
			segs, need := splitNeeds(pkt, opts, ReadPacketSpacing)
			if segs != tt.wantSegs {
				t.Fatalf("segments = %d, want %d", segs, tt.wantSegs)
			}

			n, err := GSOSplit(pkt, opts, make([]byte, need), make([]ReadPacket, segs), ReadPacketSpacing)
			if err != nil || n != segs {
				t.Fatalf("exact fit: n=%d err=%v, want %d, nil", n, err, segs)
			}

			pkt, opts = frame()
			if _, err := GSOSplit(pkt, opts, make([]byte, need-1), make([]ReadPacket, segs), ReadPacketSpacing); !errors.Is(err, ErrTooManySegments) {
				t.Fatalf("one byte short: err=%v, want ErrTooManySegments", err)
			}
			if segs > 1 {
				pkt, opts = frame()
				if _, err := GSOSplit(pkt, opts, make([]byte, need), make([]ReadPacket, segs-1), ReadPacketSpacing); !errors.Is(err, ErrTooManySegments) {
					t.Fatalf("one entry short: err=%v, want ErrTooManySegments", err)
				}
			}
		})
	}
}

// fakeTUNQueue returns a queue whose fd is one end of a non-blocking
// SOCK_SEQPACKET socketpair, which keeps packet boundaries the way a tun does,
// and a function that writes one frame to the other end.
func fakeTUNQueue(t *testing.T, vnetHdr bool) (*tunQueue, func([]byte)) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fds[0]), "fake-tun")
	t.Cleanup(func() { file.Close(); unix.Close(fds[1]) })
	tun := &NativeTun{errors: make(chan error, 1), vnetHdr: vnetHdr}
	if err := appendQueue(tun, file); err != nil {
		t.Fatal(err)
	}
	write := func(frame []byte) {
		t.Helper()
		if _, err := unix.Write(fds[1], frame); err != nil {
			t.Fatal(err)
		}
	}
	return tun.queues[0], write
}

// payload returns an IPv4/UDP packet whose payload bytes are all b, so a test
// can tell packets apart and check none was split or shifted.
func payload(b byte, n int) []byte {
	pkt := udp4Packet(netip.MustParseAddrPort("192.0.2.1:1"), netip.MustParseAddrPort("192.0.2.2:2"), n)[offset:]
	for i := 28; i < len(pkt); i++ {
		pkt[i] = b
	}
	return pkt
}

func withVirtioNone(pkt []byte) []byte {
	frame := make([]byte, virtioNetHdrLen+len(pkt))
	hdr := virtioNetHdr{gsoType: unix.VIRTIO_NET_HDR_GSO_NONE}
	hdr.encode(frame)
	copy(frame[virtioNetHdrLen:], pkt)
	return frame
}

func checkPackets(t *testing.T, slab []byte, got []ReadPacket, want ...[]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d packets, want %d", len(got), len(want))
	}
	end := 0
	for i, p := range got {
		if p.Offset-end < ReadPacketSpacing {
			t.Fatalf("packet %d at %d leaves %d bytes of spacing, want >= %d", i, p.Offset, p.Offset-end, ReadPacketSpacing)
		}
		if !bytes.Equal(slab[p.Offset:p.Offset+p.Size], want[i]) {
			t.Fatalf("packet %d does not match what was written", i)
		}
		end = p.Offset + p.Size
	}
	if len(slab)-end < ReadPacketSpacing {
		t.Fatalf("last packet leaves %d trailing bytes, want >= %d", len(slab)-end, ReadPacketSpacing)
	}
}

// TestBatchedReadDrainsQueuedPackets checks that one Read returns every packet
// already queued, in order, laid out per the Reader contract, and that a frame
// that does not fit is delivered first by the next Read rather than dropped.
func TestBatchedReadDrainsQueuedPackets(t *testing.T) {
	for _, vnet := range []bool{false, true} {
		t.Run(fmt.Sprintf("vnetHdr=%v", vnet), func(t *testing.T) {
			q, write := fakeTUNQueue(t, vnet)
			q.tun.EnableBatchedReads()
			var pkts [][]byte
			for i := range 5 {
				p := payload(byte('a'+i), 100)
				pkts = append(pkts, p)
				if vnet {
					write(withVirtioNone(p))
				} else {
					write(p)
				}
			}

			// Room for exactly three packets: the fourth stays pending.
			slab := make([]byte, ReadPacketSpacing+3*(len(pkts[0])+ReadPacketSpacing))
			packets := make([]ReadPacket, 8)
			n, err := q.Read(slab, packets)
			if err != nil {
				t.Fatal(err)
			}
			checkPackets(t, slab, packets[:n], pkts[:3]...)

			slab = make([]byte, 4096)
			n, err = q.Read(slab, packets)
			if err != nil {
				t.Fatal(err)
			}
			checkPackets(t, slab, packets[:n], pkts[3:]...)
		})
	}
}

// TestBatchedReadOffByDefault checks that until EnableBatchedReads a Read returns one
// packet even when more are queued.
func TestBatchedReadOffByDefault(t *testing.T) {
	q, write := fakeTUNQueue(t, false)
	a, b := payload('a', 100), payload('b', 100)
	write(a)
	write(b)
	slab := make([]byte, 4096)
	packets := make([]ReadPacket, 8)
	n, err := q.Read(slab, packets)
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v, want 1 packet", n, err)
	}
	checkPackets(t, slab, packets[:n], a)
}
