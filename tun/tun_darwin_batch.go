//go:build darwin

package tun

import (
	"encoding/binary"
	"io"
	"os"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/internal/darwinbatch"
)

// darwinBatch is the utun batch size, 1 when the batched calls are unavailable.
var darwinBatch = func() int {
	if darwinbatch.Supported() {
		return conn.IdealBatchSize
	}
	return 1
}()

const (
	utunOptMaxPendingPackets = 16 // UTUN_OPT_MAX_PENDING_PACKETS
	sysprotoControl          = 2  // SYSPROTO_CONTROL

	// darwinMaxPending is the utun's pending-packet queue depth when batching. The kernel default of 1 leaves a batched read only one packet to return. A few batches is enough; deeper was slower.
	darwinMaxPending = 512
)

// setMaxPending raises the utun's pending-packet queue for batched reads. On failure the kernel default stays.
func setMaxPending(f *os.File) {
	if darwinBatch <= 1 {
		return
	}
	if rc, err := f.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), sysprotoControl, utunOptMaxPendingPackets, darwinMaxPending)
		})
	}
}

// darwinWriteBatchMax is the largest packet, with its 4-byte header, written with sendmsg_x; a batch with a larger one uses write(2). A batched utun write of more than one page collapses on Intel, and using the page size rather than 4096 keeps batching on Apple Silicon's 16 KB pages.
var darwinWriteBatchMax = os.Getpagesize()

// writeBatchTooBig is the fallback decision, separate so it can be tested without a utun.
func writeBatchTooBig(need, max int) bool {
	return max > 0 && need > max
}

// writeStates pools batched-write state, since writes are concurrent (one goroutine per peer).
var writeStates = sync.Pool{New: func() any { return darwinbatch.New(conn.IdealBatchSize) }}

/*
readBatch fills slab with as many packets as one recvmsg_x returns. Packets go on a fixed stride of MTU plus ReadPacketSpacing, with the utun's 4-byte header in the spacing before each.

The MTU is cached, so a read racing an MTU change can use slots that are too small. A packet that fills its slot but is shorter than its IP header claims is dropped, and the cache cleared.
*/
func (tun *NativeTun) readBatch(slab []byte, packets []ReadPacket) (int, error) {
	mtu := int(tun.mtuCache.Load())
	if mtu <= 0 {
		m, err := tun.MTU()
		if err != nil {
			return 0, err
		}
		if m <= 0 {
			return 0, io.ErrShortBuffer
		}
		mtu = m
		tun.mtuCache.Store(int32(mtu))
	}
	stride := mtu + ReadPacketSpacing
	want := min((len(slab)-ReadPacketSpacing)/stride, len(packets), darwinBatch)
	if want < 1 {
		return 0, io.ErrShortBuffer
	}
	if tun.batch == nil {
		tun.batch = darwinbatch.New(darwinBatch)
	}
	for i := range want {
		off := ReadPacketSpacing + i*stride
		tun.batch.StageRecv(i, slab[off-4:off+mtu])
	}
	defer tun.batch.Reset()

	rc, err := tun.tunFile.SyscallConn()
	if err != nil {
		return 0, err
	}
	var got int
	var serr error
	if err := rc.Read(func(fd uintptr) bool {
		for {
			got, serr = tun.batch.Recv(fd, want)
			if serr != syscall.EINTR {
				break
			}
		}
		return serr != syscall.EAGAIN
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, os.NewSyscallError(darwinbatch.RecvName, serr)
	}
	out := 0
	for i := range got {
		n := tun.batch.RecvLen(i) - 4 // less the address family header
		if n <= 0 {
			continue
		}
		off := ReadPacketSpacing + i*stride
		if n >= mtu && ipLen(slab[off:off+n]) > n {
			tun.mtuCache.Store(0)
			continue
		}
		packets[out] = ReadPacket{Offset: off, Size: n}
		out++
	}
	return out, nil
}

// writeBatch writes bufs with sendmsg_x straight from the caller's buffers, putting each packet's 4-byte header before offset. Like writeUnbatched it stops at the first packet that is neither IPv4 nor IPv6.
func (tun *NativeTun) writeBatch(bufs [][]byte, offset int) (int, error) {
	need := 0
	for _, b := range bufs {
		need = max(need, len(b)-offset+4)
	}
	if writeBatchTooBig(need, darwinWriteBatchMax) {
		return tun.writeUnbatched(bufs, offset)
	}
	st := writeStates.Get().(*darwinbatch.State)
	defer func() {
		st.Reset()
		writeStates.Put(st)
	}()
	rc, err := tun.tunFile.SyscallConn()
	if err != nil {
		return 0, err
	}

	written := 0
	for written < len(bufs) {
		staged := 0
		var bad error
		for _, buf := range bufs[written:min(len(bufs), written+st.Cap())] {
			b := buf[offset-4:]
			switch b[4] >> 4 {
			case 4:
				b[0], b[1], b[2], b[3] = 0, 0, 0, unix.AF_INET
			case 6:
				b[0], b[1], b[2], b[3] = 0, 0, 0, unix.AF_INET6
			default:
				bad = unix.EAFNOSUPPORT
			}
			if bad != nil {
				break
			}
			st.Stage(staged, b)
			staged++
		}
		if staged == 0 {
			return written, bad
		}
		var sent int
		var serr error
		if err := rc.Write(func(fd uintptr) bool {
			for {
				sent, serr = st.Send(fd, staged)
				if serr != syscall.EINTR {
					break
				}
			}
			return serr != syscall.EAGAIN
		}); err != nil {
			return written, err
		}
		if serr != nil {
			return written, os.NewSyscallError(darwinbatch.SendName, serr)
		}
		if sent <= 0 {
			return written, io.ErrShortWrite
		}
		written += sent // the next pass resumes after a short send, or returns the packet that stopped staging
	}
	return written, nil
}

// ipLen is the length an IPv4 or IPv6 header claims, or 0 if it cannot tell.
func ipLen(pkt []byte) int {
	switch {
	case len(pkt) >= ipv4.HeaderLen && pkt[0]>>4 == 4:
		return int(binary.BigEndian.Uint16(pkt[2:4]))
	case len(pkt) >= ipv6.HeaderLen && pkt[0]>>4 == 6:
		return ipv6.HeaderLen + int(binary.BigEndian.Uint16(pkt[4:6]))
	}
	return 0
}
