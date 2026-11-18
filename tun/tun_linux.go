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
	"runtime"
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

type NativeTun struct {
	queues []*tunQueue // queues[0] always exists and is used by Read and Write

	errors chan error // async error handling
	events chan Event // device related events

	statusListenersShutdown chan struct{}

	// nlMu guards the fields below.
	nlMu     sync.Mutex
	nl       *netlinkConn // current; routineNetlinkListener closes replaced ones
	nlClosed bool         // routineNetlinkListener is exiting or has exited

	batchSize int
	vnetHdr   bool

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

// initialLinkState returns EventUp or EventDown to report as the interface's
// initial state, since netlink only reports changes. It tries to use the "tun
// status hack": a zero-length write to the tun fd fails with EIO if the
// interface is down, and with EINVAL otherwise. That only worked on Linux 4.5
// through 5.0. Linux commit 4477138fa0ae ("tun: properly test for IFF_UP", in
// v5.1 and backported to 5.0.6, 4.19.33, 4.14.110, and 4.9.167) moved
// tun_get_user's IFF_UP check after its header length validation, so a
// zero-length write now always fails with EINVAL, and this reports EventUp even
// for a down interface. That is kept as is because users such as wireguard-go's
// main rely on the initial EventUp to bring the device up. It returns 0 on
// error.
func (tun *NativeTun) initialLinkState() Event {
	var werr error
	if err := tun.queues[0].rawConn.Control(func(fd uintptr) {
		_, werr = unix.Write(int(fd), nil)
	}); err != nil {
		return 0
	}
	switch werr {
	case unix.EINVAL:
		return EventUp
	case unix.EIO:
		return EventDown
	}
	return 0
}

// netlinkConn is a netlink route socket subscribed to link and address
// changes in the network namespace the tun interface is (or was) in.
type netlinkConn struct {
	sock   int
	cancel *rwcancel.RWCancel // for sock

	// index is the interface's index in sock's namespace, or 0 once the
	// interface has been seen to leave it (by deletion or by moving), after
	// which the index may refer to some other interface. It is only accessed
	// by routineNetlinkListener after the conn is published in tun.nl.
	index int32

	// ioctlSock is a datagram socket in the same namespace as sock, for
	// interface ioctls, or -1 if sock is in the creator's namespace.
	ioctlSock int
}

// close releases c's resources. c.cancel may be nil.
func (c *netlinkConn) close() {
	unix.Close(c.sock)
	if c.cancel != nil {
		c.cancel.Close()
	}
	if c.ioctlSock >= 0 {
		unix.Close(c.ioctlSock)
	}
}

// errRetryFollow is returned by tryFollowLocked when the interface is
// mid-move, and following it should be retried shortly.
var errRetryFollow = errors.New("tun interface is moving between network namespaces")

// tryFollowLocked tries once to replace tun.nl with a netlinkConn in the
// interface's current network namespace, and if successful, wakes
// routineNetlinkListener to switch to it. It returns errRetryFollow if the
// interface appears to be mid-move. tun.nlMu must be held.
func (tun *NativeTun) tryFollowLocked() error {
	nsFD, err := tun.netnsFD()
	if err != nil {
		return err
	}
	c, err := newNetlinkConnIn(nsFD, tun.File())
	unix.Close(nsFD)
	if errors.Is(err, unix.ENODEV) {
		// A moving interface is in its new namespace briefly before it can
		// be looked up by name there.
		return errRetryFollow
	}
	if err != nil {
		return err
	}
	// The interface may have moved again before the new socket was bound,
	// in which case the socket won't see that move.
	if same, err := tun.inNetnsOf(c.sock); err != nil || !same {
		c.close()
		if err != nil {
			return err
		}
		return errRetryFollow
	}
	old := tun.nl
	tun.nl = c
	return old.cancel.Cancel() // wake routineNetlinkListener, which closes old
}

// testHookDelLink, if non-nil, is called by routineNetlinkListener after it
// handles RTM_DELLINK for the interface.
var testHookDelLink func()

// followAfterDelLink is called by routineNetlinkListener after seeing the
// interface leave cur's network namespace (e.g. by "ip link set <name> netns
// <ns>"), to keep tracking it in its new namespace. Without that, netlink
// would no longer report its link changes, and MTU would fail or report some
// other interface's MTU.
//
// Following requires Linux 5.2 or later (for TUNGETDEVNETNS), and
// CAP_SYS_ADMIN and CAP_NET_ADMIN over the new namespace. If it fails, link
// changes go unreported until the interface moves again. Name continues to
// report the original name.
//
// The kernel sends RTM_DELLINK partway through a move, before the interface
// joins its new namespace, and a move can take a while on a loaded system.
// So this retries with backoff for up to followTimeout, without holding
// tun.nlMu while waiting. If the interface is still (or again, after moving
// away and back) in cur's namespace after a second, cur is replaced anyway to
// pick up its possibly new index.
func (tun *NativeTun) followAfterDelLink(cur *netlinkConn) {
	const (
		followTimeout = 10 * time.Second
		sameNetnsWait = time.Second
		maxDelay      = 250 * time.Millisecond
	)
	start := time.Now()
	for delay := time.Millisecond; ; delay = min(2*delay, maxDelay) {
		tun.nlMu.Lock()
		if tun.nlClosed || tun.nl != cur {
			tun.nlMu.Unlock()
			return
		}
		same, err := tun.inNetnsOf(cur.sock)
		if err != nil {
			// Most likely, the interface was deleted.
			tun.nlMu.Unlock()
			return
		}
		if !same || time.Since(start) >= sameNetnsWait {
			err = tun.tryFollowLocked()
		}
		followed := tun.nl != cur
		tun.nlMu.Unlock()
		if followed || (err != nil && err != errRetryFollow) {
			return
		}
		if time.Since(start) >= followTimeout {
			return
		}
		t := time.NewTimer(delay)
		select {
		case <-t.C:
		case <-tun.statusListenersShutdown:
			t.Stop()
			return
		}
	}
}

// tunGetDevNetns is the TUNGETDEVNETNS ioctl, _IO('T', 227), which returns a
// new file descriptor for the network namespace of a tun fd's interface. It
// is missing from x/sys/unix.
const tunGetDevNetns = 0x54e3

// netnsFD returns a new file descriptor for the interface's current network
// namespace.
func (tun *NativeTun) netnsFD() (int, error) {
	var nsFD int
	var ioctlErr error
	if err := tun.queues[0].rawConn.Control(func(fd uintptr) {
		nsFD, ioctlErr = unix.IoctlRetInt(int(fd), tunGetDevNetns)
	}); err != nil {
		return -1, err
	}
	if ioctlErr != nil {
		return -1, fmt.Errorf("TUNGETDEVNETNS: %w", ioctlErr)
	}
	return nsFD, nil
}

// inNetnsOf reports whether the interface is in the same network namespace
// as socket sock.
func (tun *NativeTun) inNetnsOf(sock int) (bool, error) {
	devNS, err := tun.netnsFD()
	if err != nil {
		return false, err
	}
	defer unix.Close(devNS)
	sockNS, err := unix.IoctlRetInt(sock, unix.SIOCGSKNS)
	if err != nil {
		return false, fmt.Errorf("SIOCGSKNS: %w", err)
	}
	defer unix.Close(sockNS)
	var a, b unix.Stat_t
	if err := unix.Fstat(devNS, &a); err != nil {
		return false, err
	}
	if err := unix.Fstat(sockNS, &b); err != nil {
		return false, err
	}
	return a.Dev == b.Dev && a.Ino == b.Ino, nil
}

// inNetns calls fn on an OS thread that has temporarily joined network
// namespace nsFD. Sockets created by fn are in that namespace.
//
// The thread's original namespace is restored afterwards. Relying on the
// runtime to terminate a still-locked thread when its goroutine exits is not
// enough: if the goroutine happens to run on the main thread, the runtime
// can't terminate it, and parks it instead. That would leave the main thread
// (and so /proc/self/ns/net) in the other namespace, and keep that namespace
// alive, for the life of the process.
func inNetns(nsFD int, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		orig, err := unix.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			runtime.UnlockOSThread()
			errc <- err
			return
		}
		defer unix.Close(orig)
		if err := unix.Setns(nsFD, unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			errc <- fmt.Errorf("setns: %w", err)
			return
		}
		fnErr := fn()
		if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
			// Leave the thread locked, so that the runtime doesn't reuse
			// it for other goroutines in the wrong namespace.
			errc <- errors.Join(fnErr, fmt.Errorf("restoring netns: %w", err))
			return
		}
		runtime.UnlockOSThread()
		errc <- fnErr
	}()
	return <-errc
}

// newNetlinkConnIn returns a netlinkConn in network namespace nsFD for the
// interface of tun fd file. It queues a request for the interface's current
// state on the new socket, so that routineNetlinkListener reports it.
func newNetlinkConnIn(nsFD int, file *os.File) (*netlinkConn, error) {
	c := &netlinkConn{sock: -1, ioctlSock: -1}
	err := inNetns(nsFD, func() (err error) {
		if c.sock, err = createNetlinkSocket(); err != nil {
			return err
		}
		c.ioctlSock, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		return err
	})
	if err != nil {
		if c.sock >= 0 {
			c.close()
		}
		return nil, err
	}
	if c.cancel, err = rwcancel.NewRWCancel(c.sock); err != nil {
		c.close()
		return nil, err
	}
	name, err := tunNameOf(file)
	if err != nil {
		c.close()
		return nil, err
	}
	if c.index, err = getIFIndexOn(c.ioctlSock, name); err != nil {
		c.close()
		return nil, err
	}
	req := struct {
		hdr unix.NlMsghdr
		ifi unix.IfInfomsg
	}{
		hdr: unix.NlMsghdr{
			Len:   unix.SizeofNlMsghdr + unix.SizeofIfInfomsg,
			Type:  unix.RTM_GETLINK,
			Flags: unix.NLM_F_REQUEST,
		},
		ifi: unix.IfInfomsg{Family: unix.AF_UNSPEC, Index: c.index},
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&req)), unsafe.Sizeof(req))
	if err := unix.Sendto(c.sock, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		c.close()
		return nil, fmt.Errorf("RTM_GETLINK: %w", err)
	}
	return c, nil
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
	var cur *netlinkConn
	defer func() {
		tun.nlMu.Lock()
		tun.nlClosed = true
		if tun.nl != nil && tun.nl != cur {
			tun.nl.close() // swapped in, but never picked up
		}
		if cur != nil {
			cur.close()
		}
		tun.nl = nil
		close(tun.events)
		tun.nlMu.Unlock()
	}()

	// wasEverUp is whether we have ever emitted EventUp from netlink.
	wasEverUp := false
	msg := make([]byte, 1<<16)
	for {
		tun.nlMu.Lock()
		if tun.nl != cur {
			if cur != nil {
				cur.close()
			}
			cur = tun.nl
		}
		tun.nlMu.Unlock()

		var err error
		var msgn int
		for {
			msgn, _, _, _, err = unix.Recvmsg(cur.sock, msg[:], nil, 0)
			if err == nil || !rwcancel.RetryAfterError(err) {
				break
			}
			if !cur.cancel.ReadyRead() {
				break
			}
		}
		if err != nil && rwcancel.RetryAfterError(err) {
			// Canceled, either by Close or by tryFollowLocked.
			tun.nlMu.Lock()
			swapped := !tun.nlClosed && tun.nl != cur
			tun.nlMu.Unlock()
			if swapped {
				continue
			}
			tun.errors <- fmt.Errorf("netlink socket closed: %w", err)
			return
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

		for remain := msg[:msgn]; len(remain) >= unix.SizeofNlMsghdr; {

			hdr := *(*unix.NlMsghdr)(unsafe.Pointer(&remain[0]))

			if hdr.Len < unix.SizeofNlMsghdr || int(hdr.Len) > len(remain) {
				break
			}
			msgLen := hdr.Len
			isLink := hdr.Type == unix.RTM_NEWLINK || hdr.Type == unix.RTM_DELLINK
			if isLink && msgLen < unix.SizeofNlMsghdr+unix.SizeofIfInfomsg {
				break
			}

			switch hdr.Type {
			case unix.NLMSG_DONE:
				remain = []byte{}

			case unix.RTM_NEWLINK:
				info := *(*unix.IfInfomsg)(unsafe.Pointer(&remain[unix.SizeofNlMsghdr]))
				remain = remain[msgLen:]

				if info.Index != cur.index {
					// not our interface
					continue
				}

				if info.Flags&unix.IFF_RUNNING != 0 {
					tun.events <- EventUp
					wasEverUp = true
				}

				if info.Flags&unix.IFF_RUNNING == 0 {
					// Don't emit EventDown before we've ever emitted EventUp.
					// This avoids a race with the startup link state probe,
					// which might detect Up before we have finished reporting
					// Down.
					if wasEverUp {
						tun.events <- EventDown
					}
				}

				tun.events <- EventMTUUpdate

			case unix.RTM_DELLINK:
				info := *(*unix.IfInfomsg)(unsafe.Pointer(&remain[unix.SizeofNlMsghdr]))
				remain = remain[msgLen:]

				if info.Index != cur.index {
					continue
				}
				// The interface was deleted or moved to another namespace.
				// Either way, its index here may now be reused by another
				// interface, so stop matching it.
				cur.index = 0
				tun.followAfterDelLink(cur)
				if testHookDelLink != nil {
					testHookDelLink()
				}

			default:
				remain = remain[msgLen:]
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
	return getIFIndexOn(fd, name)
}

// getIFIndexOn returns the index of interface name in the network namespace
// of datagram socket fd.
func getIFIndexOn(fd int, name string) (int32, error) {
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
	tun.nlMu.Lock()
	if c := tun.nl; c != nil && c.ioctlSock >= 0 {
		// The interface was followed into another network namespace, and
		// may have been renamed there, so look up its current name.
		defer tun.nlMu.Unlock()
		name, err := tunNameOf(tun.File())
		if err != nil {
			return 0, err
		}
		return getMTUOn(c.ioctlSock, name)
	}
	tun.nlMu.Unlock()

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
	return getMTUOn(fd, name)
}

// getMTUOn returns the MTU of interface name in the network namespace of
// datagram socket fd.
func getMTUOn(fd int, name string) (int, error) {
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

	// Hardware GRO can deliver a segmented packet with zero offsets.
	// Repair CsumStart from the IP header length, and CsumOffset from the GSO type.
	if options.GSOType != GSONone && options.CsumStart == 0 {
		if err := setGSOOffsetsFromHeaders(in, &options); err != nil {
			return 0, err
		}
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

// setGSOOffsetsFromHeaders sets options.CsumStart and options.CsumOffset from
// the IP header of in. It fails when the IP header is malformed, or when the
// transport protocol does not match options.GSOType (this includes IPv6
// extension headers, which are not walked).
func setGSOOffsetsFromHeaders(in []byte, options *GSOOptions) error {
	if len(in) < 1 {
		return errors.New("packet is too short")
	}
	var iphLen int
	var proto uint8
	switch ipVersion := in[0] >> 4; ipVersion {
	case 4:
		if len(in) < 20 {
			return fmt.Errorf("length of packet (%d) < minimum ipv4 header size (%d)", len(in), 20)
		}
		iphLen = int(in[0]&0x0f) * 4
		if iphLen < 20 || iphLen > len(in) {
			return fmt.Errorf("ipv4 header len is invalid: %d", iphLen)
		}
		proto = in[9]
	case 6:
		if len(in) < 40 {
			return fmt.Errorf("length of packet (%d) < minimum ipv6 header size (%d)", len(in), 40)
		}
		iphLen = 40
		proto = in[6]
	default:
		return fmt.Errorf("invalid ip header version: %d", ipVersion)
	}
	var wantProto uint8
	var csumOffset uint16
	switch options.GSOType {
	case GSOTCPv4, GSOTCPv6:
		wantProto, csumOffset = ipProtoTCP, 16
	case GSOUDPL4:
		wantProto, csumOffset = ipProtoUDP, 6
	default:
		return fmt.Errorf("unsupported GSO type: %s", options.GSOType)
	}
	if proto != wantProto {
		return fmt.Errorf("transport protocol %d does not match GSO type %s", proto, options.GSOType)
	}
	options.CsumStart = uint16(iphLen)
	options.CsumOffset = csumOffset
	return nil
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
			tun.nlMu.Lock()
			if tun.nl != nil && !tun.nlClosed {
				err1 = tun.nl.cancel.Cancel()
			}
			tun.nlClosed = true
			tun.nlMu.Unlock()
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

// CreateTUN creates a Device with the provided name and MTU.
func CreateTUN(name string, mtu int, opts ...Option) (Device, error) {
	config := defaultConfig()
	for _, opt := range opts {
		opt.apply(&config)
	}
	if config.queues < 1 {
		return nil, fmt.Errorf("%d tun queues requested, must be at least 1", config.queues)
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if config.queues > 1 {
		// all members must declare multiqueue
		flags |= unix.IFF_MULTI_QUEUE
	}
	// Set IFF_TUN_EXCL to fail with EBUSY if name already exists.
	first, err := openTUNFile(name, flags|unix.IFF_TUN_EXCL)
	if err != nil {
		return nil, err
	}
	files := []*os.File{first}
	if config.queues > 1 {
		// Resolve name wildcards (%d) to not spawn new groups.
		if resolved, err := tunNameOf(first); err == nil {
			for range config.queues - 1 {
				f, err := openTUNFile(resolved, flags)
				if err != nil {
					break // return a short group
				}
				files = append(files, f)
			}
		}
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
	// Append every queue before spawning routineNetlinkListener.
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
	index, err := getIFIndex(name)
	if err != nil {
		tun.Close()
		return nil, err
	}

	sock, err := createNetlinkSocket()
	if err != nil {
		tun.Close()
		return nil, err
	}
	cancel, err := rwcancel.NewRWCancel(sock)
	if err != nil {
		// No goroutine owns sock yet, and tun.Close won't reach it.
		unix.Close(sock)
		tun.Close()
		return nil, err
	}
	tun.nl = &netlinkConn{sock: sock, cancel: cancel, index: index, ioctlSock: -1}

	// Report the initial link state. The netlink socket is already bound, so
	// no changes after this are lost, and nothing else can have filled the
	// events buffer yet.
	if ev := tun.initialLinkState(); ev != 0 {
		tun.events <- ev
	}
	go tun.routineNetlinkListener()

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
