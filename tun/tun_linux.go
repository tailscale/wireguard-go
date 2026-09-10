/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

/* Implementation of the TUN device interface for linux
 */

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/rwcancel"
	"golang.org/x/sys/unix"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

// tunQueue is a single kernel queue of a tun device. Distinct queues can
// be accessed concurrently without sharing a lock.
type tunQueue struct {
	file    *os.File
	rawConn syscall.RawConn

	writeOpMu   sync.Mutex // writeOpMu guards the following fields
	toWrite     groToWrite
	tcpGROTable *tcpGROTable
	udpGROTable *udpGROTable
}

func newTunQueue(file *os.File) (*tunQueue, error) {
	q := &tunQueue{
		file:        file,
		tcpGROTable: newTCPGROTable(),
		udpGROTable: newUDPGROTable(),
		toWrite:     newGROToWrite(),
	}
	var err error
	q.rawConn, err = file.SyscallConn()
	if err != nil {
		return nil, err
	}
	return q, nil
}

type NativeTun struct {
	tunFile *os.File    // aliases queues[0].file for ioctl
	queues  []*tunQueue // queues[0] always exists and is used by Read and Write

	index                   int32      // if index
	errors                  chan error // async error handling
	events                  chan Event // device related events
	netlinkSock             int
	netlinkCancel           *rwcancel.RWCancel
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

// ReadFuncs implements [MultiQueueDevice].
func (tun *NativeTun) ReadFuncs() []ReadFunc {
	fns := make([]ReadFunc, 0, len(tun.queues))
	for _, q := range tun.queues {
		fns = append(fns, func(slab []byte, packets []ReadPacket) (int, error) {
			return tun.read(q, slab, packets)
		})
	}
	return fns
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
	return tun.tunFile
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
		sysconn, err := tun.tunFile.SyscallConn()
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
	sysconn, err := tun.tunFile.SyscallConn()
	if err != nil {
		return "", err
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
	return tun.write(tun.queues[0], bufs, offset)
}

// WriteQueue implements [MultiQueueDevice].
func (tun *NativeTun) WriteQueue(qi int, bufs [][]byte, offset int) (int, error) {
	return tun.write(tun.queues[qi%len(tun.queues)], bufs, offset)
}

func (tun *NativeTun) write(q *tunQueue, bufs [][]byte, offset int) (int, error) {
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
	if !tun.vnetHdr {
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
	err := handleGRO(bufs, offset, q.tcpGROTable, q.udpGROTable, groDisablementFlags(tun.gro.Load()), &q.toWrite)
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
	return tun.read(tun.queues[0], slab, packets)
}

func (tun *NativeTun) read(q *tunQueue, slab []byte, packets []ReadPacket) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		start := ReadPacketSpacing
		if tun.vnetHdr {
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
		if tun.vnetHdr {
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
	sc, err := tun.tunFile.SyscallConn()
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
				tun.gro.Or(int32(udpGRODisabled))
			}
		} else {
			tun.batchSize = 1
		}
	}); e != nil {
		return e
	}
	return err
}

// openTUNQueue opens /dev/net/tun and attaches it to name. Passing
// multiqueue adds IFF_MULTI_QUEUE, which every attach to a multiqueue device
// must set, including the first.
func openTUNQueue(name string, multiqueue bool) (*os.File, error) {
	nfd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CreateTUN(%q) failed; %s does not exist", name, cloneDevicePath)
		}
		return nil, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}
	// IFF_VNET_HDR enables the "tun status hack" via routineHackListener()
	// where a null write will return EINVAL indicating the TUN is up.
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if multiqueue {
		flags |= unix.IFF_MULTI_QUEUE
	}
	ifr.SetUint16(flags)
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}

	// Note that the above -- open,ioctl,nonblock -- must happen prior to handing it to netpoll as below this line.
	return os.NewFile(uintptr(nfd), cloneDevicePath), nil
}

// CreateTUN creates a Device with the provided name and MTU. Passing
// [WithQueues] creates a multiqueue device satisfying [MultiQueueDevice].
// Asking for more queues than the kernel's MAX_TAP_QUEUES fails rather than
// silently clamping, see device.MaxTAPQueues.
func CreateTUN(name string, mtu int, opts ...Option) (Device, error) {
	config := defaultConfig()
	for _, opt := range opts {
		opt.apply(&config)
	}
	queues := config.queues
	fd, err := openTUNQueue(name, queues > 1) // All members must declare multiqueue
	if err != nil {
		return nil, err
	}
	dev, err := CreateTUNFromFile(fd, mtu)
	if err != nil || queues == 1 {
		return dev, err
	}
	tun := dev.(*NativeTun)
	// The interface name the kernel created may differ from what was requested.
	resolved, err := tun.Name()
	if err != nil {
		tun.Close()
		return nil, err
	}
	for i := 1; i < queues; i++ {
		fd, err := openTUNQueue(resolved, true)
		if err != nil {
			tun.Close()
			return nil, fmt.Errorf("attaching tun queue %d: %w", i, err)
		}
		// Offload is already negotiated for the whole device
		// and these queues need no further setup.
		q, err := newTunQueue(fd)
		if err != nil {
			fd.Close()
			tun.Close()
			return nil, err
		}
		tun.queues = append(tun.queues, q)
	}
	return tun, nil
}

// CreateTUNFromFile creates a Device from an os.File with the provided MTU.
func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	q0, err := newTunQueue(file)
	if err != nil {
		return nil, err
	}
	tun := &NativeTun{
		tunFile:                 file,
		queues:                  []*tunQueue{q0},
		events:                  make(chan Event, 5),
		errors:                  make(chan error, 5),
		statusListenersShutdown: make(chan struct{}),
	}

	name, err := tun.Name()
	if err != nil {
		return nil, err
	}

	err = tun.initFromFlags(name)
	if err != nil {
		return nil, err
	}

	// start event listener
	tun.index, err = getIFIndex(name)
	if err != nil {
		return nil, err
	}

	tun.netlinkSock, err = createNetlinkSocket()
	if err != nil {
		return nil, err
	}
	tun.netlinkCancel, err = rwcancel.NewRWCancel(tun.netlinkSock)
	if err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}

	tun.hackListenerClosed.Lock()
	go tun.routineNetlinkListener()
	go tun.routineHackListener() // cross namespace

	err = tun.setMTU(mtu)
	if err != nil {
		unix.Close(tun.netlinkSock)
		return nil, err
	}

	return tun, nil
}

// CreateUnmonitoredTUNFromFD creates a Device from the provided file
// descriptor.
func CreateUnmonitoredTUNFromFD(fd int) (Device, string, error) {
	err := unix.SetNonblock(fd, true)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), "/dev/tun")
	q0, err := newTunQueue(file)
	if err != nil {
		return nil, "", err
	}
	tun := &NativeTun{
		tunFile: file,
		queues:  []*tunQueue{q0},
		events:  make(chan Event, 5),
		errors:  make(chan error, 5),
	}
	name, err := tun.Name()
	if err != nil {
		return nil, "", err
	}
	err = tun.initFromFlags(name)
	if err != nil {
		return nil, "", err
	}
	return tun, name, err
}
