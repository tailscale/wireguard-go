/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (c) Tailscale Inc & contributors
 */

package tun

/* Implementation of the TUN device interface for linux
 */

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/mdlayher/netlink"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/rwcancel"
	"golang.org/x/sys/unix"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

type NativeTun struct {
	queues []*tunQueue // queues[0] always exists and is used by Read and Write

	index         int32      // if index
	errors        chan error // async error handling
	events        chan Event // device related events
	netlinkSock   int
	netlinkCancel *rwcancel.RWCancel

	hackListenerClosed      sync.Mutex
	statusListenersShutdown chan struct{}
	batchSize               int
	vnetHdr                 bool

	closeOnce sync.Once

	nameOnce  sync.Once // guards calling initNameCache, which sets following fields
	nameCache string    // name of interface
	nameErr   error

	gro atomic.Int32 // groDisablementFlags for cross-queue access
}

// tunQueue is a single kernel queue of a tun device, and is the [Queue]
// handed out by [NativeTun.Queues].
// An individual tunQueue is not concurrency-safe, but distinct queues can
// be read or written concurrently.
type tunQueue struct {
	tun     *NativeTun
	file    *os.File
	rawConn syscall.RawConn

	writeOpMu   sync.Mutex // writeOpMu guards the following fields
	toWrite     groToWrite
	tcpGROTable *tcpGROTable
	udpGROTable *udpGROTable
}

// appendQueue wraps file as a new queue of tun. It must be called before tun is
// published to other goroutines, and only appends on success.
func appendQueue(tun *NativeTun, file *os.File) error {
	q := &tunQueue{
		tun:         tun,
		file:        file,
		tcpGROTable: newTCPGROTable(),
		udpGROTable: newUDPGROTable(),
		toWrite:     newGROToWrite(),
	}
	var err error
	q.rawConn, err = file.SyscallConn()
	if err != nil {
		return err
	}
	tun.queues = append(tun.queues, q)
	return nil
}

func (q *tunQueue) File() *os.File { return q.file }

// Queues implements [MultiQueueDevice].
func (tun *NativeTun) Queues() []Queue {
	qs := make([]Queue, 0, len(tun.queues))
	for _, q := range tun.queues {
		qs = append(qs, q)
	}
	return qs
}

type groDisablementFlags int

const (
	tcpGRODisabled groDisablementFlags = 1 << iota
	udpGRODisabled
)

func (g *groDisablementFlags) canTCPGRO() bool {
	return (*g)&tcpGRODisabled == 0
}

func (g *groDisablementFlags) canUDPGRO() bool {
	return (*g)&udpGRODisabled == 0
}

func (tun *NativeTun) File() *os.File {
	return tun.queues[0].file
}

func (tun *NativeTun) routineHackListener() {
	defer tun.hackListenerClosed.Unlock()
	/* This is needed for the detection to work across network namespaces
	 * If you are reading this and know a better method, please get in touch.
	 */
	last := 0
	const (
		up   = 1
		down = 2
	)
	for {
		sysconn, err := tun.File().SyscallConn()
		if err != nil {
			return
		}
		err2 := sysconn.Control(func(fd uintptr) {
			_, err = unix.Write(int(fd), nil)
		})
		if err2 != nil {
			return
		}
		switch err {
		case unix.EINVAL:
			if last != up {
				// If the tunnel is up, it reports that write() is
				// allowed but we provided invalid data.
				tun.events <- EventUp
				last = up
			}
		case unix.EIO:
			if last != down {
				// If the tunnel is down, it reports that no I/O
				// is possible, without checking our provided data.
				tun.events <- EventDown
				last = down
			}
		default:
			return
		}
		select {
		case <-time.After(time.Second):
			// nothing
		case <-tun.statusListenersShutdown:
			return
		}
	}
}

func createNetlinkSocket() (int, error) {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	saddr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR,
	}
	err = unix.Bind(sock, saddr)
	if err != nil {
		return -1, err
	}
	return sock, nil
}

func (tun *NativeTun) routineNetlinkListener() {
	defer func() {
		unix.Close(tun.netlinkSock)
		tun.hackListenerClosed.Lock()
		close(tun.events)
		tun.netlinkCancel.Close()
	}()

	for msg := make([]byte, 1<<16); ; {
		var err error
		var msgn int
		for {
			msgn, _, _, _, err = unix.Recvmsg(tun.netlinkSock, msg[:], nil, 0)
			if err == nil || !rwcancel.RetryAfterError(err) {
				break
			}
			if !tun.netlinkCancel.ReadyRead() {
				tun.errors <- fmt.Errorf("netlink socket closed: %w", err)
				return
			}
		}
		if err != nil {
			tun.errors <- fmt.Errorf("failed to receive netlink message: %w", err)
			return
		}

		select {
		case <-tun.statusListenersShutdown:
			return
		default:
		}

		wasEverUp := false
		for remain := msg[:msgn]; len(remain) >= unix.SizeofNlMsghdr; {

			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))

			if int(hdr.Len) > len(remain) {
				break
			}

			switch hdr.Type {
			case unix.NLMSG_DONE:
				remain = []byte{}

			case unix.RTM_NEWLINK:
				info := *(*unix.IfInfomsg)(unsafe.Pointer(&remain[unix.SizeofNlMsghdr]))
				remain = remain[hdr.Len:]

				if info.Index != tun.index {
					// not our interface
					continue
				}

				if info.Flags&unix.IFF_RUNNING != 0 {
					tun.events <- EventUp
					wasEverUp = true
				}

				if info.Flags&unix.IFF_RUNNING == 0 {
					// Don't emit EventDown before we've ever emitted EventUp.
					// This avoids a startup race with HackListener, which
					// might detect Up before we have finished reporting Down.
					if wasEverUp {
						tun.events <- EventDown
					}
				}

				tun.events <- EventMTUUpdate

			default:
				remain = remain[hdr.Len:]
			}
		}
	}
}

func getIFIndex(name string) (int32, error) {
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFINDEX),
		uintptr(unsafe.Pointer(&ifr[0])),
	)

	if errno != 0 {
		return 0, errno
	}

	return *(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])), nil
}

func (tun *NativeTun) setMTU(n int) error {
	name, err := tun.Name()
	if err != nil {
		return err
	}

	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}

	defer unix.Close(fd)

	req, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("unix.NewIfreq(%q): %w", name, err)
	}
	req.SetUint32(uint32(n))
	err = unix.IoctlIfreq(fd, unix.SIOCSIFMTU, req)
	if err != nil {
		return fmt.Errorf("failed to set MTU of TUN device %q: %w", name, err)
	}
	return nil
}

func (tun *NativeTun) MTU() (int, error) {
	name, err := tun.Name()
	if err != nil {
		return 0, err
	}

	// open datagram socket
	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC,
		0,
	)
	if err != nil {
		return 0, err
	}

	defer unix.Close(fd)

	// do ioctl call

	var ifr [ifReqSize]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCGIFMTU),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU of TUN device: %w", errno)
	}

	return int(*(*int32)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))), nil
}

func (tun *NativeTun) Name() (string, error) {
	tun.nameOnce.Do(tun.initNameCache)
	return tun.nameCache, tun.nameErr
}

func (tun *NativeTun) initNameCache() {
	tun.nameCache, tun.nameErr = tun.nameSlow()
}

func (tun *NativeTun) nameSlow() (string, error) {
	return tunNameOf(tun.File())
}

func tunNameOf(file *os.File) (string, error) {
	sysconn, err := file.SyscallConn()
	if err != nil {
		return "", fmt.Errorf("failed to get name of TUN device: %w", err)
	}
	var ifr [ifReqSize]byte
	var errno syscall.Errno
	err = sysconn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(unix.TUNGETIFF),
			uintptr(unsafe.Pointer(&ifr[0])),
		)
	})
	if err != nil {
		return "", fmt.Errorf("failed to get name of TUN device: %w", err)
	}
	if errno != 0 {
		return "", fmt.Errorf("failed to get name of TUN device: %w", errno)
	}
	return unix.ByteSliceToString(ifr[:]), nil
}

func (tun *NativeTun) Write(bufs [][]byte, offset int) (int, error) {
	return tun.queues[0].write(bufs, offset)
}

// WriteTo implements [MultiQueueDevice].
func (tun *NativeTun) WriteTo(flow int, bufs [][]byte, offset int) (int, error) {
	return tun.queues[uint(flow)%uint(len(tun.queues))].write(bufs, offset)
}

func (q *tunQueue) write(bufs [][]byte, offset int) (int, error) {
	q.writeOpMu.Lock()
	defer func() {
		q.tcpGROTable.reset()
		q.udpGROTable.reset()
		q.toWrite.reset()
		q.writeOpMu.Unlock()
	}()
	var (
		errs  error
		total int
	)
	if !q.tun.vnetHdr {
		for i := range bufs {
			n, err := q.file.Write(bufs[i][offset:])
			if errors.Is(err, syscall.EBADFD) {
				return total, os.ErrClosed
			}
			if err != nil {
				errs = errors.Join(errs, err)
			} else {
				total += n
			}
		}
		return total, errs
	}
	err := handleGRO(
		bufs,
		offset,
		q.tcpGROTable,
		q.udpGROTable,
		groDisablementFlags(q.tun.gro.Load()),
		&q.toWrite,
	)
	if err != nil {
		return 0, err
	}
	for _, nb := range q.toWrite.iovs {
		var werr error
		var n int
		err := q.rawConn.Write(func(fd uintptr) bool {
			for {
				n, werr = unix.Writev(int(fd), nb)
				if errors.Is(werr, syscall.EINTR) {
					continue // quick retry on interrupt, EINTR is never returned with partial writes
				}
				return !errors.Is(werr, syscall.EAGAIN) // poller retry on "would block"
			}
		})
		// err is a poller error (e.g. fd closed before the syscall)
		// werr is the Writev syscall error itself.
		if err != nil {
			return total, err
		}
		if errors.Is(werr, syscall.EBADFD) {
			return total, os.ErrClosed
		}
		if werr != nil {
			errs = errors.Join(errs, werr)
		} else {
			total += n
		}
	}
	return total, errs
}

// handleVirtioRead splits in into slab, leaving [ReadPacketSpacing] bytes at
// the front of the first packet, between every adjacent packet, and at the end
// of the last packet. It mutates packets to reflect the size and offset of each
// packet in slab, and returns the number of packets read.
func handleVirtioRead(in []byte, slab []byte, packets []ReadPacket) (int, error) {
	var hdr virtioNetHdr
	err := hdr.decode(in)
	if err != nil {
		return 0, err
	}
	in = in[virtioNetHdrLen:]

	options, err := hdr.toGSOOptions()
	if err != nil {
		return 0, err
	}

	// Don't trust HdrLen from the kernel as it can be equal to the length
	// of the entire first packet when the kernel is handling it as part of a
	// FORWARD path. Instead, parse the transport header length and add it onto
	// CsumStart, which is synonymous for IP header length.
	if options.GSOType == GSOUDPL4 {
		options.HdrLen = options.CsumStart + 8
	} else if options.GSOType != GSONone {
		if len(in) <= int(options.CsumStart+12) {
			return 0, errors.New("packet is too short")
		}

		tcpHLen := uint16(in[options.CsumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			// A TCP header must be between 20 and 60 bytes in length.
			return 0, fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		options.HdrLen = options.CsumStart + tcpHLen
	}

	return GSOSplit(in, options, slab, packets, ReadPacketSpacing)
}

// assert that [ReadPacketSpacing] is >= [virtioNetHdrLen], as [NativeTun.Read]
// assumes so, and uses headroom for [virtioNetHdr].
const _ = uint(ReadPacketSpacing - virtioNetHdrLen)

func (tun *NativeTun) Read(slab []byte, packets []ReadPacket) (int, error) {
	return tun.queues[0].Read(slab, packets)
}

func (q *tunQueue) Read(slab []byte, packets []ReadPacket) (int, error) {
	select {
	case err := <-q.tun.errors:
		return 0, err
	default:
		start := ReadPacketSpacing
		if q.tun.vnetHdr {
			start -= virtioNetHdrLen
		}
		readInto := slab[start : len(slab)-ReadPacketSpacing]
		n, err := q.file.Read(readInto)
		if errors.Is(err, syscall.EBADFD) {
			err = os.ErrClosed
		}
		if err != nil {
			return 0, err
		}
		if q.tun.vnetHdr {
			return handleVirtioRead(readInto[:n], slab, packets)
		} else {
			packets[0].Size = n
			packets[0].Offset = ReadPacketSpacing
			return 1, nil
		}
	}
}

func (tun *NativeTun) Events() <-chan Event {
	return tun.events
}

func (tun *NativeTun) Close() error {
	var err1, err2 error
	tun.closeOnce.Do(func() {
		if tun.statusListenersShutdown != nil {
			close(tun.statusListenersShutdown)
			if tun.netlinkCancel != nil {
				err1 = tun.netlinkCancel.Cancel()
			}
		} else if tun.events != nil {
			close(tun.events)
		}
		for _, q := range tun.queues {
			if cerr := q.file.Close(); cerr != nil && err2 == nil {
				err2 = cerr
			}
		}
	})
	if err1 != nil {
		return err1
	}
	return err2
}

func (tun *NativeTun) BatchSize() int {
	return tun.batchSize
}

// DisableUDPGRO disables UDP GRO if it is enabled. See the GRODevice interface
// for cases where it should be called.
func (tun *NativeTun) DisableUDPGRO() {
	tun.gro.Or(int32(udpGRODisabled))
}

// DisableTCPGRO disables TCP GRO if it is enabled. See the GRODevice interface
// for cases where it should be called.
func (tun *NativeTun) DisableTCPGRO() {
	tun.gro.Or(int32(tcpGRODisabled))
}

const (
	// TODO: support TSO with ECN bits
	tunTCPOffloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
	tunUDPOffloads = unix.TUN_F_USO4 | unix.TUN_F_USO6
)

func (tun *NativeTun) initFromFlags(name string) error {
	sc, err := tun.File().SyscallConn()
	if err != nil {
		return err
	}
	if e := sc.Control(func(fd uintptr) {
		var (
			ifr *unix.Ifreq
		)
		ifr, err = unix.NewIfreq(name)
		if err != nil {
			return
		}
		err = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, ifr)
		if err != nil {
			return
		}
		got := ifr.Uint16()
		if got&unix.IFF_VNET_HDR != 0 {
			// tunTCPOffloads were added in Linux v2.6. We require their support
			// if IFF_VNET_HDR is set.
			err = unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads)
			if err != nil {
				return
			}
			tun.vnetHdr = true
			tun.batchSize = conn.IdealBatchSize
			// tunUDPOffloads were added in Linux v6.2. We do not return an
			// error if they are unsupported at runtime.
			if unix.IoctlSetInt(int(fd), unix.TUNSETOFFLOAD, tunTCPOffloads|tunUDPOffloads) != nil {
				tun.DisableUDPGRO()
			}
		} else {
			tun.batchSize = 1
		}
	}); e != nil {
		return e
	}
	return err
}

// openTUNFile opens /dev/net/tun and attaches it to name.
func openTUNFile(name string, flags uint16) (*os.File, error) {
	file, _, err := openTUNQueue(name, flags)
	return file, err
}

// adoptTUNFiles attaches to an existing TUN interface and preserves its queue mode.
// It uses one queue for a single-queue interface, regardless of queues.
// Multiqueue attachment checks do not prevent concurrent attachments.
func adoptTUNFiles(name string, queues int) (_ []*os.File, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("adoptTUNFiles: %w", err)
		}
	}()
	if name == "" || len(name) >= unix.IFNAMSIZ || strings.IndexByte(name, 0) >= 0 {
		return nil, fmt.Errorf("invalid TUN name %q", name)
	}
	if queues < 1 {
		return nil, fmt.Errorf("invalid queue count %d", queues)
	}
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	link, err := queryTUNLink(conn, name)
	if err != nil {
		return nil, err
	}
	if link.flags&tunRequiredFlags != tunRequiredFlags {
		return nil, fmt.Errorf("TUN %q has incompatible flags %#x", name, link.flags)
	}
	if err := link.checkQueues(0); err != nil {
		return nil, err
	}

	first, _, err := openTUNQueue(name, link.flags)
	if err != nil {
		return nil, err
	}
	files := []*os.File{first}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	check := func() error {
		current, err := queryTUNLink(conn, name)
		if err != nil {
			return err
		}
		if current.index != link.index || current.flags != link.flags {
			return fmt.Errorf("TUN %q changed during adoption", name)
		}
		return current.checkQueues(uint32(len(files)))
	}
	// TUNSETIFF can create an interface if the queried one has disappeared.
	if err := check(); err != nil {
		return nil, err
	}
	if link.flags&unix.IFF_MULTI_QUEUE != 0 {
		files = addTUNQueues(files, name, link.flags, queues)
		if err := check(); err != nil {
			return nil, err
		}
	}
	// The caller owns the files on success.
	owned := files
	files = nil
	return owned, nil
}

const (
	tunRequiredFlags  = uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	tunQueueFlagsMask = tunRequiredFlags | unix.IFF_TAP | unix.IFF_VNET_HDR | unix.IFF_MULTI_QUEUE
)

func createTUNFiles(name string, queues int) ([]*os.File, error) {
	if queues < 1 {
		return nil, fmt.Errorf("createTUNFiles: invalid queue count %d", queues)
	}
	flags := tunRequiredFlags | unix.IFF_VNET_HDR
	if queues > 1 {
		flags |= unix.IFF_MULTI_QUEUE
	}
	first, resolved, err := openTUNQueue(name, flags|unix.IFF_TUN_EXCL)
	if err != nil {
		return nil, err
	}
	return addTUNQueues([]*os.File{first}, resolved, flags, queues), nil
}

func addTUNQueues(files []*os.File, name string, flags uint16, queues int) []*os.File {
	for len(files) < queues {
		f, _, err := openTUNQueue(name, flags)
		if err != nil {
			break // Use the queues already opened.
		}
		files = append(files, f)
	}
	return files
}

func openTUNQueue(name string, flags uint16) (_ *os.File, _ string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("openTUNQueue(%q): %w", name, err)
		}
	}()
	if strings.IndexByte(name, 0) >= 0 {
		return nil, "", fmt.Errorf("invalid TUN name")
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, "", err
	}
	fd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", cloneDevicePath, err)
	}
	defer func() {
		if err != nil {
			unix.Close(fd)
		}
	}()
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return nil, "", err
	}
	if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil {
		return nil, "", err
	}
	got := ifr.Uint16()
	if got&tunRequiredFlags != tunRequiredFlags || got&tunQueueFlagsMask != flags&tunQueueFlagsMask {
		return nil, "", fmt.Errorf("incompatible TUN flags %#x, requested %#x", got, flags)
	}
	if got&unix.IFF_VNET_HDR != 0 {
		if err := checkTUNVnetHeader(fd); err != nil {
			return nil, "", err
		}
	}
	return os.NewFile(uintptr(fd), cloneDevicePath), ifr.Name(), nil
}

func checkTUNVnetHeader(fd int) error {
	size, err := unix.IoctlGetInt(fd, unix.TUNGETVNETHDRSZ)
	if err != nil {
		return err
	}
	if size != virtioNetHdrLen {
		return fmt.Errorf("incompatible virtio net header size %d, want %d", size, virtioNetHdrLen)
	}
	little, err := tunVnetByteOrderFlag(fd, unix.TUNGETVNETLE)
	if err != nil {
		return err
	}
	big, err := tunVnetByteOrderFlag(fd, unix.TUNGETVNETBE)
	if err != nil {
		return err
	}
	nativeLittle := binary.NativeEndian.Uint16([]byte{1, 0}) == 1
	headerLittle := little || !big && nativeLittle
	if headerLittle != nativeLittle {
		return fmt.Errorf("virtio net header uses non-native byte order")
	}
	return nil
}

func tunVnetByteOrderFlag(fd int, request uint) (bool, error) {
	v, err := unix.IoctlGetInt(fd, request)
	// Kernels without byte-order overrides use native byte order.
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTTY) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if v != 0 && v != 1 {
		return false, fmt.Errorf("invalid virtio net byte-order flag %d from ioctl %#x", v, request)
	}
	return v != 0, nil
}

type tunLink struct {
	index                  uint32
	flags                  uint16
	queues, disabledQueues uint32
}

func (link tunLink) checkQueues(owned uint32) error {
	if link.flags&unix.IFF_MULTI_QUEUE != 0 && (link.queues != owned || link.disabledQueues != 0) {
		return fmt.Errorf("unexpected TUN attachments (active=%d, disabled=%d, owned=%d): %w", link.queues, link.disabledQueues, owned, unix.EBUSY)
	}
	return nil
}

func queryTUNLink(conn *netlink.Conn, name string) (tunLink, error) {
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.IFLA_IFNAME, Data: append([]byte(name), 0)}})
	if err != nil {
		return tunLink{}, err
	}
	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_GETLINK, Flags: netlink.Request},
		Data:   append(make([]byte, unix.SizeofIfInfomsg), attrs...),
	})
	if err != nil {
		return tunLink{}, err
	}
	if len(msgs) != 1 || msgs[0].Header.Type != unix.RTM_NEWLINK || msgs[0].Header.Flags&netlink.Multi != 0 {
		return tunLink{}, fmt.Errorf("unexpected RTM_GETLINK response")
	}
	return parseTUNLink(msgs[0].Data, name)
}

func parseTUNLink(data []byte, name string) (tunLink, error) {
	var link tunLink
	if len(data) < unix.SizeofIfInfomsg {
		return link, fmt.Errorf("short link message")
	}
	link.index = binary.NativeEndian.Uint32(data[4:])
	attrs, err := tunAttrs(data[unix.SizeofIfInfomsg:], unix.IFLA_IFNAME, unix.IFLA_LINKINFO)
	if err != nil {
		return link, err
	}
	if int32(link.index) <= 0 || !bytes.Equal(attrs[unix.IFLA_IFNAME], append([]byte(name), 0)) {
		return link, fmt.Errorf("unexpected link identity")
	}
	info, err := tunAttrs(attrs[unix.IFLA_LINKINFO], unix.IFLA_INFO_KIND, unix.IFLA_INFO_DATA)
	if err != nil {
		return link, err
	}
	if !bytes.Equal(info[unix.IFLA_INFO_KIND], []byte("tun\x00")) {
		return link, fmt.Errorf("interface is not a TUN")
	}
	attrs, err = tunAttrs(info[unix.IFLA_INFO_DATA], unix.IFLA_TUN_TYPE, unix.IFLA_TUN_MULTI_QUEUE, unix.IFLA_TUN_PI, unix.IFLA_TUN_VNET_HDR, unix.IFLA_TUN_NUM_QUEUES, unix.IFLA_TUN_NUM_DISABLED_QUEUES)
	if err != nil {
		return link, err
	}
	if typ := attrs[unix.IFLA_TUN_TYPE]; len(typ) != 1 || typ[0] != unix.IFF_TUN {
		return link, fmt.Errorf("interface is not a TUN")
	}
	link.flags = unix.IFF_TUN
	for _, field := range []struct {
		attr     uint16
		flag     uint16
		inverted bool
	}{
		{unix.IFLA_TUN_MULTI_QUEUE, unix.IFF_MULTI_QUEUE, false},
		{unix.IFLA_TUN_PI, unix.IFF_NO_PI, true},
		{unix.IFLA_TUN_VNET_HDR, unix.IFF_VNET_HDR, false},
	} {
		v := attrs[field.attr]
		if len(v) != 1 || v[0] > 1 {
			return link, fmt.Errorf("missing or invalid TUN flag %d", field.attr)
		}
		if (v[0] != 0) != field.inverted {
			link.flags |= field.flag
		}
	}
	for _, field := range []struct {
		attr  uint16
		value *uint32
	}{
		{unix.IFLA_TUN_NUM_QUEUES, &link.queues},
		{unix.IFLA_TUN_NUM_DISABLED_QUEUES, &link.disabledQueues},
	} {
		v, present := attrs[field.attr]
		if !present && link.flags&unix.IFF_MULTI_QUEUE == 0 {
			continue
		}
		if len(v) != 4 {
			return link, fmt.Errorf("missing or invalid TUN queue count %d", field.attr)
		}
		*field.value = binary.NativeEndian.Uint32(v)
	}
	return link, nil
}

// tunAttrs returns the requested attributes, rejecting duplicate occurrences.
func tunAttrs(data []byte, fields ...uint16) (map[uint16][]byte, error) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return nil, err
	}
	attrs := make(map[uint16][]byte)
	for ad.Next() {
		typ := ad.Type()
		if !slices.Contains(fields, typ) {
			continue
		}
		if _, present := attrs[typ]; present {
			return nil, fmt.Errorf("duplicate netlink attribute %d", typ)
		}
		attrs[typ] = ad.Bytes()
	}
	return attrs, ad.Err()
}

// CreateTUN creates a Device with the provided name and MTU.
// Existing names fail with EBUSY unless [WithAdoptExisting] is set.
func CreateTUN(name string, mtu int, opts ...Option) (Device, error) {
	config := defaultConfig()
	for _, opt := range opts {
		opt.apply(&config)
	}
	if config.queues < 1 {
		return nil, fmt.Errorf("CreateTUN(%q): %d tun queues requested, must be at least 1", name, config.queues)
	}
	files, err := createTUNFiles(name, config.queues)
	if errors.Is(err, unix.EBUSY) && config.adoptExisting && runtime.GOOS != "android" {
		files, err = adoptTUNFiles(name, config.queues)
		if err != nil && !errors.Is(err, unix.EBUSY) {
			err = fmt.Errorf("%w: %w", unix.EBUSY, err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("CreateTUN(%q): %w", name, err)
	}
	return CreateTUNFromFiles(files, mtu)
}

// CreateTUNFromFile creates a Device from an os.File with the provided MTU.
func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	return CreateTUNFromFiles([]*os.File{file}, mtu)
}

// CreateTUNFromFiles creates a Device with the provided MTU from one file per
// kernel queue. It satisfies [MultiQueueDevice] when there is more than one.
// Files must be distinct and ownership transfers.
func CreateTUNFromFiles(files []*os.File, mtu int) (Device, error) {
	if len(files) == 0 {
		return nil, errors.New("CreateTUNFromFiles requires at least one file")
	}
	tun := &NativeTun{
		events:                  make(chan Event, 5),
		errors:                  make(chan error, 5),
		statusListenersShutdown: make(chan struct{}),
	}
	// Append every queue before spawning routineHackListener et al.
	for _, file := range files {
		if err := appendQueue(tun, file); err != nil {
			for _, f := range files {
				f.Close()
			}
			return nil, err
		}
	}

	name, err := tun.Name()
	if err != nil {
		tun.Close()
		return nil, err
	}
	// Verify that all fds are attached to the same interface.
	for i, file := range files[1:] {
		got, err := tunNameOf(file)
		if err != nil {
			tun.Close()
			return nil, fmt.Errorf("tun queue %d: %w", i+1, err)
		}
		if got != name {
			tun.Close()
			return nil, fmt.Errorf("tun queue %d is attached to %q, want %q", i+1, got, name)
		}
	}

	// Offload is negotiated once for the whole device, on queue 0.
	if err := tun.initFromFlags(name); err != nil {
		tun.Close()
		return nil, err
	}

	// start event listener
	tun.index, err = getIFIndex(name)
	if err != nil {
		tun.Close()
		return nil, err
	}

	tun.netlinkSock, err = createNetlinkSocket()
	if err != nil {
		tun.Close()
		return nil, err
	}
	tun.netlinkCancel, err = rwcancel.NewRWCancel(tun.netlinkSock)
	if err != nil {
		// No goroutine owns netlinkSock yet, and tun.Close won't reach it.
		unix.Close(tun.netlinkSock)
		tun.Close()
		return nil, err
	}

	tun.hackListenerClosed.Lock()
	go tun.routineNetlinkListener()
	go tun.routineHackListener() // cross namespace

	err = tun.setMTU(mtu)
	if err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

// CreateUnmonitoredTUNFromFD creates a Device from the provided file
// descriptor.
func CreateUnmonitoredTUNFromFD(fd int) (Device, string, error) {
	return CreateUnmonitoredTUNFromFDs([]int{fd})
}

// CreateUnmonitoredTUNFromFDs creates a Device from one descriptor per kernel
// queue. It satisfies [MultiQueueDevice] when there is more than one.
func CreateUnmonitoredTUNFromFDs(fds []int) (Device, string, error) {
	if len(fds) == 0 {
		return nil, "", errors.New("CreateUnmonitoredTUNFromFDs requires at least one fd")
	}
	// Error if passed duplicate FDs.
	var dupes []int
	set := map[int]struct{}{}
	for _, v := range fds {
		if _, dup := set[v]; dup {
			dupes = append(dupes, v)
			continue
		}
		set[v] = struct{}{}
	}
	if len(dupes) != 0 {
		for fd := range set {
			unix.Close(fd)
		}
		return nil, "", fmt.Errorf("passed duplicate file descriptors: %v", dupes)
	}
	tun := &NativeTun{
		events: make(chan Event, 5),
		errors: make(chan error, 5),
	}
	for i, fd := range fds {
		// See openTUNFile: this must precede os.NewFile.
		if err := unix.SetNonblock(fd, true); err != nil {
			tun.Close()
			for _, rest := range fds[i:] {
				unix.Close(rest)
			}
			return nil, "", err
		}
		file := os.NewFile(uintptr(fd), "/dev/tun")
		if err := appendQueue(tun, file); err != nil {
			file.Close() // not saved, so tun.Close won't reach it
			tun.Close()
			for _, rest := range fds[i+1:] {
				unix.Close(rest)
			}
			return nil, "", err
		}
	}

	name, err := tun.Name()
	if err != nil {
		tun.Close()
		return nil, "", err
	}
	for i, q := range tun.queues[1:] {
		got, err := tunNameOf(q.file)
		if err != nil {
			tun.Close()
			return nil, "", fmt.Errorf("tun queue %d: %w", i+1, err)
		}
		if got != name {
			tun.Close()
			return nil, "", fmt.Errorf("tun queue %d is attached to %q, want %q", i+1, got, name)
		}
	}

	// Offload is negotiated once for the whole device, on queue 0.
	if err := tun.initFromFlags(name); err != nil {
		tun.Close()
		return nil, "", err
	}
	return tun, name, nil
}
