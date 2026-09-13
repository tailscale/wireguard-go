/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func requireNetAdmin(tb testing.TB) {
	// These tests create real IFF_MULTI_QUEUE tun interfaces, which needs
	// CAP_NET_ADMIN.
	tb.Helper()
	c := cap.GetProc()
	hasNetAdmin, err := c.GetFlag(cap.Effective, cap.NET_ADMIN)
	if err != nil {
		tb.Fatalf("failed to check capability: %v", err)
	}
	if !hasNetAdmin {
		tb.Skip("needs root to create a tun interface")
	}
	if _, err := os.Stat(cloneDevicePath); err != nil {
		tb.Skipf("%s is unavailable: %v", cloneDevicePath, err)
	}
}

func createMultiQueueTUN(tb testing.TB, queues int) *NativeTun {
	tb.Helper()
	name := fmt.Sprintf("wgtest%d", os.Getpid()%10000)
	dev, err := CreateTUN(name, 1420, WithExtraQueues(queues-1))
	if err != nil {
		tb.Fatalf("CreateTUN(%q, %d queues): %v", name, queues, err)
	}
	tun := dev.(*NativeTun)
	tb.Cleanup(func() { tun.Close() })
	return tun
}

func tunFlags(tb testing.TB, tun *NativeTun) uint16 {
	tb.Helper()
	var ifr [ifReqSize]byte
	var errno unix.Errno
	sc, err := tun.File().SyscallConn()
	if err != nil {
		tb.Fatalf("SyscallConn: %v", err)
	}
	err = sc.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd,
			uintptr(unix.TUNGETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	})
	if err != nil {
		tb.Fatalf("TUNGETIFF: %v", err)
	}
	if errno != 0 {
		tb.Fatalf("TUNGETIFF: %v", errno)
	}
	return *(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))
}

func TestMultiQueueCreate(t *testing.T) {
	requireNetAdmin(t)
	const queues = 4
	tun := createMultiQueueTUN(t, queues)

	qs := QueuesOf(tun)
	if len(qs) != queues {
		t.Fatalf("QueuesOf returned %d queues, want %d", len(qs), queues)
	}
	// Every queue must be its own descriptor, or the fan-out is a no-op.
	fds := make(map[uintptr]bool, queues)
	for i, q := range tun.queues {
		fd := q.file.Fd()
		if fds[fd] {
			t.Errorf("queue %d reuses fd %d", i, fd)
		}
		fds[fd] = true
	}
	if flags := tunFlags(t, tun); flags&unix.IFF_MULTI_QUEUE == 0 {
		t.Errorf("IFF_MULTI_QUEUE not set, flags = %#x", flags)
	}
}

func TestSingleQueueHasNoMultiQueueFlag(t *testing.T) {
	requireNetAdmin(t)
	tun := createMultiQueueTUN(t, 1)

	if qs := QueuesOf(tun); len(qs) != 1 {
		t.Fatalf("QueuesOf returned %d queues, want 1", len(qs))
	}
	if flags := tunFlags(t, tun); flags&unix.IFF_MULTI_QUEUE != 0 {
		t.Errorf("IFF_MULTI_QUEUE set on a single-queue device, flags = %#x", flags)
	}
}

func TestTooManyQueues(t *testing.T) {
	requireNetAdmin(t)
	name := fmt.Sprintf("wgtest%d", os.Getpid()%10000)
	// The kernel returns E2BIG past MAX_TAP_QUEUES, RLIMIT_NOFILE may produce
	// EMFILE first.
	const queues = 1000
	dev, err := CreateTUN(name, 1420, WithExtraQueues(queues-1))
	if err == nil {
		dev.Close()
		t.Fatalf("CreateTUN with %d queues succeeded, want an error", queues)
	}
	if !strings.Contains(err.Error(), "attaching extra tun queue") {
		t.Errorf("error = %q, want it to mention the failing queue", err)
	}
}

func TestCloseReleasesEveryFD(t *testing.T) {
	requireNetAdmin(t)
	const queues = 4
	tun := createMultiQueueTUN(t, queues)

	fds := make([]uintptr, 0, queues)
	for _, q := range tun.queues {
		fds = append(fds, q.file.Fd())
	}
	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i, fd := range fds {
		if _, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
			t.Errorf("queue %d fd %d still open after Close", i, fd)
		}
	}
}
