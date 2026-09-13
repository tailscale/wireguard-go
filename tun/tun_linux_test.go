/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

const testMTU = 1420

func requireNetAdmin(tb testing.TB) {
	// These tests create real IFF_MULTI_QUEUE tun interfaces, which needs
	// CAP_NET_ADMIN.
	tb.Helper()
	if _, err := os.Stat(cloneDevicePath); err != nil {
		tb.Skipf("%s is unavailable: %v", cloneDevicePath, err)
	}
	file, err := openTUNFile(testTUNName(tb), unix.IFF_TUN|unix.IFF_NO_PI|unix.IFF_MULTI_QUEUE)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			tb.Skip("needs CAP_NET_ADMIN to create a tun interface")
		}
		tb.Fatalf("failed to create a probe tun interface: %v", err)
	}
	file.Close()
}

var testTUNSeq atomic.Uint32

func testTUNName(tb testing.TB) string {
	tb.Helper()
	return fmt.Sprintf("wgt%dx%d", os.Getpid()%10000, testTUNSeq.Add(1))
}

func openQueueFiles(tb testing.TB, queues int) []*os.File {
	tb.Helper()
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if queues > 1 {
		flags |= unix.IFF_MULTI_QUEUE
	}
	first, err := openTUNFile(testTUNName(tb), flags)
	if err != nil {
		tb.Fatalf("openTUNFile: %v", err)
	}
	files := []*os.File{first}
	closeAll := func() {
		for _, f := range files {
			f.Close()
		}
	}
	name, err := tunNameOf(first)
	if err != nil {
		closeAll()
		tb.Fatalf("tunNameOf: %v", err)
	}
	for i := 1; i < queues; i++ {
		f, err := openTUNFile(name, flags)
		if err != nil {
			closeAll()
			tb.Fatalf("openTUNFile queue %d: %v", i, err)
		}
		files = append(files, f)
	}
	tb.Cleanup(closeAll)
	return files
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

func TestTUNLifecycle(t *testing.T) {
	requireNetAdmin(t)
	constructors := []struct {
		name   string
		create func(tb testing.TB, queues int) (Device, []*os.File)
	}{{
		name: "CreateTUN",
		create: func(tb testing.TB, queues int) (Device, []*os.File) {
			tb.Helper()
			name := testTUNName(tb)
			dev, err := CreateTUN(name, testMTU, WithExtraQueues(queues-1))
			if err != nil {
				tb.Fatalf("CreateTUN(%q, %d queues): %v", name, queues, err)
			}
			return dev, nil
		},
	}, {
		name: "CreateTUN/wildcardName",
		create: func(tb testing.TB, queues int) (Device, []*os.File) {
			tb.Helper()
			name := testTUNName(tb) + "%d"
			dev, err := CreateTUN(name, testMTU, WithExtraQueues(queues-1))
			if err != nil {
				tb.Fatalf("CreateTUN(%q, %d queues): %v", name, queues, err)
			}
			return dev, nil
		},
	}, {
		name: "CreateTUNFromFiles",
		create: func(tb testing.TB, queues int) (Device, []*os.File) {
			tb.Helper()
			files := openQueueFiles(tb, queues)
			if len(files) == 1 {
				// Cover the single-file wrapper as well.
				dev, err := CreateTUNFromFile(files[0], testMTU)
				if err != nil {
					tb.Fatalf("CreateTUNFromFile: %v", err)
				}
				return dev, files
			}
			dev, err := CreateTUNFromFiles(files, testMTU)
			if err != nil {
				tb.Fatalf("CreateTUNFromFiles(%d files): %v", len(files), err)
			}
			return dev, files
		},
	}}

	for _, ctor := range constructors {
		for _, queues := range []int{1, 4} {
			t.Run(fmt.Sprintf("%s/%dqueues", ctor.name, queues), func(t *testing.T) {
				dev, want := ctor.create(t, queues)
				t.Cleanup(func() { dev.Close() })

				qs := QueuesOf(dev)
				if len(qs) != queues {
					t.Fatalf("QueuesOf returned %d queues, want %d", len(qs), queues)
				}

				name, err := dev.Name()
				if err != nil {
					t.Fatalf("Name: %v", err)
				}

				fds := make([]uintptr, 0, queues)
				seen := make(map[uintptr]bool, queues)
				for i, q := range qs {
					f := q.File()
					if f == nil {
						t.Fatalf("queue %d has no file", i)
					}
					// Every queue has to be on the same interface.
					if got, err := tunNameOf(f); err != nil {
						t.Errorf("queue %d name: %v", i, err)
					} else if got != name {
						t.Errorf("queue %d is on interface %q, want %q", i, got, name)
					}
					// Each queue must wrap the file it was given, in order.
					if want != nil && f != want[i] {
						t.Errorf("queue %d wraps %v, want %v", i, f, want[i])
					}
					// And each must be its own descriptor.
					fd := f.Fd()
					if seen[fd] {
						t.Errorf("queue %d reuses fd %d", i, fd)
					}
					seen[fd] = true
					fds = append(fds, fd)
				}

				// Every member of a multiqueue group has to declare
				// IFF_MULTI_QUEUE, and a single-queue device must not.
				flags := tunFlags(t, dev.(*NativeTun))
				if got, want := flags&unix.IFF_MULTI_QUEUE != 0, queues > 1; got != want {
					t.Errorf("IFF_MULTI_QUEUE set = %v, want %v (flags = %#x)", got, want, flags)
				}

				if err := dev.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				for i, fd := range fds {
					if _, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
						t.Errorf("queue %d fd %d still open after Close", i, fd)
					}
				}
				// Close is idempotent: device.Device.Close and the embedder
				// both call it.
				if err := dev.Close(); err != nil {
					t.Errorf("second Close: %v", err)
				}
			})
		}
	}
}

func TestTooManyQueues(t *testing.T) {
	requireNetAdmin(t)
	name := testTUNName(t)
	const queues = 1000
	dev, err := CreateTUN(name, testMTU, WithExtraQueues(queues-1))
	if err == nil {
		dev.Close()
		t.Fatalf("CreateTUN with %d queues succeeded, want an error", queues)
	}
	if !strings.Contains(err.Error(), "attaching extra tun queue") {
		t.Errorf("error = %q, want it to mention the failing queue", err)
	}
}

func TestCreateTUNFromFilesErrorClosesFiles(t *testing.T) {
	requireNetAdmin(t)
	files := openQueueFiles(t, 4)
	dev, err := CreateTUNFromFiles(files, 1)
	if err == nil {
		dev.Close()
		t.Fatal("CreateTUNFromFiles with MTU 1 succeeded, want an error")
	}
	for i, f := range files {
		if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("queue %d not closed by a failed CreateTUNFromFiles: err = %v", i, err)
		}
	}
}

func TestCreateTUNFromFilesNonTUNClosesFile(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("Open %s: %v", os.DevNull, err)
	}
	defer f.Close()

	if dev, err := CreateTUNFromFiles([]*os.File{f}, testMTU); err == nil {
		dev.Close()
		t.Fatal("CreateTUNFromFiles on a non-TUN file succeeded, want an error")
	}
	if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("file not closed by a failed CreateTUNFromFiles: err = %v", err)
	}
}

func TestCreateTUNFromFilesRejectsDuplicateFDs(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("Open %s: %v", os.DevNull, err)
	}
	defer f.Close()
	dev, err := CreateTUNFromFiles([]*os.File{f, f}, testMTU)
	if err == nil {
		dev.Close()
		t.Fatal("CreateTUNFromFiles with a repeated fd succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "same file descriptor") {
		t.Errorf("err = %v, want it to mention the repeated file descriptor", err)
	}
	if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("file not closed by a failed CreateTUNFromFiles: err = %v", err)
	}
}

func TestCreateTUNFromFilesRejectsEmpty(t *testing.T) {
	dev, err := CreateTUNFromFiles(nil, testMTU)
	if err == nil {
		dev.Close()
		t.Fatal("CreateTUNFromFiles(nil) succeeded, want an error")
	}
	if err.Error() == "" {
		t.Error("CreateTUNFromFiles(nil) returned an error with an empty message")
	}
}
