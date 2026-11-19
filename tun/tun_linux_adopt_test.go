// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: MIT

//go:build linux && !android

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestCreateTUNAdoptsUnused(t *testing.T) {
	for _, existing := range []int{1, 4} {
		for _, requested := range []int{1, 4} {
			t.Run(fmt.Sprintf("%dto%d", existing, requested), func(t *testing.T) {
				old, name := persistentTestTUN(t, existing)
				before, err := net.InterfaceByName(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := old.Close(); err != nil {
					t.Fatal(err)
				}
				dev, err := CreateTUN(name, 1280, WithQueues(requested))
				if dev != nil {
					dev.Close()
					t.Fatal("default creation adopted an existing interface")
				}
				if !errors.Is(err, unix.EBUSY) {
					t.Fatalf("default creation = %v, want EBUSY", err)
				}
				dev, err = CreateTUN(name, 1280, WithQueues(requested), WithAdoptExisting())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dev.Close() })
				wantQueues := requested
				if existing == 1 {
					wantQueues = 1
				}
				if got := len(QueuesOf(dev)); got != wantQueues {
					t.Errorf("queues = %d, want %d", got, wantQueues)
				}
				after, err := net.InterfaceByName(name)
				if err != nil {
					t.Fatal(err)
				}
				if before.Index != after.Index {
					t.Error("interface was recreated")
				}
				if got := tunFlags(t, dev.(*NativeTun))&unix.IFF_MULTI_QUEUE != 0; got != (existing > 1) {
					t.Errorf("multiqueue mode = %v, want %v", got, existing > 1)
				}
			})
		}
	}
}

func TestCreateTUNDoesNotAdoptBusy(t *testing.T) {
	for _, mode := range []string{"single", "singleNoCarrier", "multi", "disabledOnly"} {
		t.Run(mode, func(t *testing.T) {
			queues := 4
			if mode == "single" || mode == "singleNoCarrier" {
				queues = 1
			}
			old, name := persistentTestTUN(t, queues)
			if mode == "singleNoCarrier" {
				ioctlRecoveryFile(t, old.File(), func(fd int) error {
					return unix.IoctlSetPointerInt(fd, unix.TUNSETCARRIER, 0)
				})
			}
			before, err := net.InterfaceByName(name)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "disabledOnly" {
				for _, q := range QueuesOf(old) {
					ioctlRecoveryFile(t, q.File(), func(fd int) error {
						ifr, err := unix.NewIfreq(name)
						if err != nil {
							return err
						}
						ifr.SetUint16(unix.IFF_DETACH_QUEUE)
						return unix.IoctlIfreq(fd, unix.TUNSETQUEUE, ifr)
					})
				}
			}
			dev, err := CreateTUN(name, 1280, WithQueues(queues), WithAdoptExisting())
			if dev != nil {
				dev.Close()
				t.Fatal("adopted busy interface")
			}
			if !errors.Is(err, unix.EBUSY) {
				t.Fatalf("error = %v, want EBUSY", err)
			}
			if queues > 1 {
				want := "active=4, disabled=0"
				if mode == "disabledOnly" {
					want = "active=0, disabled=4"
				}
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error missing queue counts %q: %v", want, err)
				}
			}
			after, err := net.InterfaceByName(name)
			if err != nil {
				t.Fatal(err)
			}
			if after.Index != before.Index {
				t.Error("busy interface replaced")
			}
		})
	}
}

var recoveryTestSeq atomic.Uint32

func TestCreateTUNQueueConfiguration(t *testing.T) {
	for _, queues := range []int{1, 4} {
		for _, naming := range []string{"literal", "wildcard", "empty"} {
			t.Run(fmt.Sprintf("%d/%s", queues, naming), func(t *testing.T) {
				name := recoveryTestName()
				if naming == "wildcard" {
					name += "%d"
				}
				if naming == "empty" {
					name = ""
				}
				dev, err := CreateTUN(name, 1280, WithQueues(queues), WithAdoptExisting())
				if err != nil {
					if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrNotExist) {
						t.Skipf("needs /dev/net/tun and CAP_NET_ADMIN: %v", err)
					}
					t.Fatal(err)
				}
				t.Cleanup(func() { dev.Close() })
				actual, err := dev.Name()
				if err != nil {
					t.Fatal(err)
				}
				if actual == "" || strings.Contains(actual, "%") {
					t.Fatalf("unresolved name %q", actual)
				}
				if naming == "literal" && actual != name {
					t.Errorf("name = %q, want %q", actual, name)
				}
				if got := len(QueuesOf(dev)); got != queues {
					t.Errorf("queues = %d, want %d", got, queues)
				}
				wantFlags := tunRequiredFlags | unix.IFF_VNET_HDR
				if queues > 1 {
					wantFlags |= unix.IFF_MULTI_QUEUE
				}
				for _, q := range QueuesOf(dev) {
					ioctlRecoveryFile(t, q.File(), func(fd int) error {
						ifr, err := unix.NewIfreq("")
						if err != nil {
							return err
						}
						if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil {
							return err
						}
						if ifr.Name() != actual {
							t.Errorf("queue name = %q, want %q", ifr.Name(), actual)
						}
						if got := ifr.Uint16() & tunQueueFlagsMask; got != wantFlags {
							t.Errorf("flags = %#x, want %#x", got, wantFlags)
						}
						flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
						if err != nil {
							return err
						}
						if flags&unix.FD_CLOEXEC == 0 {
							t.Error("queue is not close-on-exec")
						}
						flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
						if err != nil {
							return err
						}
						if flags&unix.O_NONBLOCK == 0 {
							t.Error("queue is blocking")
						}
						return nil
					})
				}
				files, err := createTUNFiles(actual, queues)
				for _, f := range files {
					f.Close()
				}
				if !errors.Is(err, unix.EBUSY) {
					t.Fatalf("exclusive creation = %v, want EBUSY", err)
				}
			})
		}
	}
}

func TestCreateTUNFilesInvalidQueues(t *testing.T) {
	for _, queues := range []int{0, -1} {
		if files, err := createTUNFiles(recoveryTestName(), queues); err == nil {
			for _, f := range files {
				f.Close()
			}
			t.Errorf("accepted queue count %d", queues)
		}
	}
}

func recoveryTestName() string {
	return fmt.Sprintf("wga%dx%d", os.Getpid()%10000, recoveryTestSeq.Add(1))
}

func ioctlRecoveryFile(t *testing.T, file *os.File, f func(int) error) {
	t.Helper()
	conn, err := file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var ioctlErr error
	if err := conn.Control(func(fd uintptr) { ioctlErr = f(int(fd)) }); err != nil {
		t.Fatal(err)
	}
	if ioctlErr != nil {
		t.Fatal(ioctlErr)
	}
}

func persistentTestTUN(t *testing.T, queues int) (Device, string) {
	t.Helper()
	name := recoveryTestName()
	files, err := createTUNFiles(name, queues)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, os.ErrNotExist) {
			t.Skipf("needs /dev/net/tun and CAP_NET_ADMIN: %v", err)
		}
		t.Fatal(err)
	}
	var fds []int
	defer func() {
		for _, f := range files {
			f.Close()
		}
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	for _, f := range files {
		ioctlRecoveryFile(t, f, func(fd int) error {
			dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
			if err == nil {
				fds = append(fds, dup)
			}
			return err
		})
	}
	owned := fds
	fds = nil
	dev, _, err := CreateUnmonitoredTUNFromFDs(owned)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dev.Close() })
	ioctlRecoveryFile(t, dev.File(), func(fd int) error { return unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1) })
	t.Cleanup(func() {
		dev.Close()
		if _, err := net.InterfaceByName(name); err != nil {
			return
		}
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer unix.Close(fd)
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			t.Error(err)
			return
		}
		flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
		if queues > 1 {
			flags |= unix.IFF_MULTI_QUEUE
		}
		ifr.SetUint16(flags)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			t.Error(err)
			return
		}
		if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 0); err != nil {
			t.Error(err)
		}
	})
	return dev, name
}

func TestAdoptTUNVnetHeader(t *testing.T) {
	for _, queues := range []int{1, 4} {
		for _, mode := range []string{"largeHeader", "foreignByteOrder", "nativeByteOrder"} {
			t.Run(fmt.Sprintf("%d/%s", queues, mode), func(t *testing.T) {
				old, name := persistentTestTUN(t, queues)
				before, err := net.InterfaceByName(name)
				if err != nil {
					t.Fatal(err)
				}
				request, value := uint(unix.TUNSETVNETHDRSZ), 12
				if mode != "largeHeader" {
					little := binary.NativeEndian.Uint16([]byte{1, 0}) == 1
					if mode == "foreignByteOrder" {
						little = !little
					}
					request, value = unix.TUNSETVNETBE, 1
					if little {
						request = unix.TUNSETVNETLE
					}
				}
				var configErr error
				ioctlRecoveryFile(t, old.File(), func(fd int) error {
					configErr = unix.IoctlSetPointerInt(fd, request, value)
					return nil
				})
				if configErr != nil {
					if errors.Is(configErr, unix.EINVAL) || errors.Is(configErr, unix.ENOTTY) {
						t.Skipf("kernel does not support this virtio header setting: %v", configErr)
					}
					t.Fatal(configErr)
				}
				if err := old.Close(); err != nil {
					t.Fatal(err)
				}
				dev, err := CreateTUN(name, 1280, WithQueues(queues), WithAdoptExisting())
				if mode == "nativeByteOrder" {
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { dev.Close() })
				} else {
					if dev != nil {
						dev.Close()
						t.Fatal("adopted incompatible virtio header")
					}
					want := "header size 12"
					if mode == "foreignByteOrder" {
						want = "non-native byte order"
					}
					if err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("error = %v, want %q", err, want)
					}
					if !errors.Is(err, unix.EBUSY) {
						t.Errorf("adoption error does not wrap EBUSY: %v", err)
					}
				}
				after, err := net.InterfaceByName(name)
				if err != nil {
					t.Fatal(err)
				}
				if after.Index != before.Index {
					t.Error("interface was recreated")
				}
			})
		}
	}
}

func TestAdoptTUNWithoutVnetHeader(t *testing.T) {
	for _, queues := range []int{1, 4} {
		t.Run(strconv.Itoa(queues), func(t *testing.T) {
			old, name := persistentTestTUN(t, queues)
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			flags := tunRequiredFlags
			if queues > 1 {
				flags |= unix.IFF_MULTI_QUEUE
			}
			f, _, err := openTUNQueue(name, flags)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			dev, err := CreateTUN(name, 1280, WithQueues(queues), WithAdoptExisting())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { dev.Close() })
			if dev.BatchSize() != 1 {
				t.Errorf("batch size = %d, want 1", dev.BatchSize())
			}
		})
	}
}

func TestAdoptTUNInitializationFailure(t *testing.T) {
	for _, queues := range []int{1, 4} {
		t.Run(strconv.Itoa(queues), func(t *testing.T) {
			old, name := persistentTestTUN(t, queues)
			before, err := net.InterfaceByName(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			dev, err := CreateTUN(name, 1, WithQueues(queues), WithAdoptExisting()) // Invalid MTU makes initialization fail.
			if dev != nil {
				dev.Close()
				t.Fatal("adoption with invalid MTU succeeded")
			}
			if err == nil {
				t.Fatal("adoption returned no error")
			}
			after, err := net.InterfaceByName(name)
			if err != nil {
				t.Fatal(err)
			}
			if after.Index != before.Index {
				t.Error("interface was recreated on failure")
			}
			// Initialization failure must release the acquired queues.
			dev, err = CreateTUN(name, 1280, WithQueues(queues), WithAdoptExisting())
			if err != nil {
				t.Fatalf("adoption after failure: %v", err)
			}
			t.Cleanup(func() { dev.Close() })
		})
	}
}

func tunTestU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func tunTestAttrs(attrs ...netlink.Attribute) []byte {
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		panic(err)
	}
	return b
}

func tunTestLink(name, kind string, fields map[uint16][]byte) []byte {
	var attrs []netlink.Attribute
	for typ, data := range fields {
		attrs = append(attrs, netlink.Attribute{Type: typ, Data: data})
	}
	data := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(data[4:], 7)
	return append(data, tunTestAttrs(
		netlink.Attribute{Type: unix.IFLA_IFNAME, Data: append([]byte(name), 0)},
		netlink.Attribute{Type: unix.IFLA_LINKINFO | netlink.Nested, Data: tunTestAttrs(
			netlink.Attribute{Type: unix.IFLA_INFO_KIND, Data: append([]byte(kind), 0)},
			netlink.Attribute{Type: unix.IFLA_INFO_DATA | netlink.Nested, Data: tunTestAttrs(attrs...)},
		)},
	)...)
}

func baseTUNTestFields() map[uint16][]byte {
	return map[uint16][]byte{
		unix.IFLA_TUN_TYPE:        {unix.IFF_TUN},
		unix.IFLA_TUN_MULTI_QUEUE: {0},
		unix.IFLA_TUN_PI:          {0},
		unix.IFLA_TUN_VNET_HDR:    {1},
	}
}

func TestParseTUNLink(t *testing.T) {
	baseFlags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	for _, tt := range []struct {
		name    string
		change  func(map[uint16][]byte)
		want    tunLink
		wantErr bool
	}{
		{name: "single", want: tunLink{index: 7, flags: baseFlags}},
		{name: "noVnetHdr", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_VNET_HDR] = []byte{0} }, want: tunLink{index: 7, flags: baseFlags &^ unix.IFF_VNET_HDR}},
		{name: "multi", change: func(a map[uint16][]byte) {
			a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{1}
			a[unix.IFLA_TUN_NUM_QUEUES] = tunTestU32(0)
			a[unix.IFLA_TUN_NUM_DISABLED_QUEUES] = tunTestU32(0)
		}, want: tunLink{index: 7, flags: baseFlags | unix.IFF_MULTI_QUEUE}},
		{name: "holders", change: func(a map[uint16][]byte) {
			a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{1}
			a[unix.IFLA_TUN_NUM_QUEUES] = tunTestU32(2)
			a[unix.IFLA_TUN_NUM_DISABLED_QUEUES] = tunTestU32(3)
		}, want: tunLink{index: 7, flags: baseFlags | unix.IFF_MULTI_QUEUE, queues: 2, disabledQueues: 3}},
		{name: "missingCounts", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{1} }, wantErr: true},
		{name: "missingDisabledCount", change: func(a map[uint16][]byte) {
			a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{1}
			a[unix.IFLA_TUN_NUM_QUEUES] = tunTestU32(0)
		}, wantErr: true},
		{name: "missingActiveCount", change: func(a map[uint16][]byte) {
			a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{1}
			a[unix.IFLA_TUN_NUM_DISABLED_QUEUES] = tunTestU32(0)
		}, wantErr: true},
		{name: "missingMode", change: func(a map[uint16][]byte) { delete(a, unix.IFLA_TUN_MULTI_QUEUE) }, wantErr: true},
		{name: "invalidMode", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_MULTI_QUEUE] = []byte{2} }, wantErr: true},
		{name: "tap", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_TYPE] = []byte{unix.IFF_TAP} }, wantErr: true},
		{name: "missingType", change: func(a map[uint16][]byte) { delete(a, unix.IFLA_TUN_TYPE) }, wantErr: true},
		{name: "shortCount", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_NUM_QUEUES] = []byte{0} }, wantErr: true},
		{name: "invalidPI", change: func(a map[uint16][]byte) { a[unix.IFLA_TUN_PI] = []byte{2} }, wantErr: true},
		{name: "missingPI", change: func(a map[uint16][]byte) { delete(a, unix.IFLA_TUN_PI) }, wantErr: true},
		{name: "missingVnetHdr", change: func(a map[uint16][]byte) { delete(a, unix.IFLA_TUN_VNET_HDR) }, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			attrs := baseTUNTestFields()
			if tt.change != nil {
				tt.change(attrs)
			}
			got, err := parseTUNLink(tunTestLink("test0", "tun", attrs), "test0")
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
	for _, data := range [][]byte{
		{0},
		make([]byte, unix.SizeofIfInfomsg),
		tunTestLink("test0", "dummy", nil),
		tunTestLink("other0", "tun", nil),
	} {
		if _, err := parseTUNLink(data, "test0"); err == nil {
			t.Errorf("accepted invalid link %x", data)
		}
	}
}

func TestTUNLinkRepeatedPadding(t *testing.T) {
	msg := tunTestLink("test0", "tun", baseTUNTestFields())
	msg = append(msg, tunTestAttrs(
		netlink.Attribute{Type: unix.IFLA_PAD},
		netlink.Attribute{Type: unix.IFLA_PAD},
	)...)
	if _, err := parseTUNLink(msg, "test0"); err != nil {
		t.Fatal(err)
	}
	msg = append(msg, tunTestAttrs(netlink.Attribute{Type: unix.IFLA_IFNAME, Data: []byte("test0\x00")})...)
	if _, err := parseTUNLink(msg, "test0"); err == nil {
		t.Fatal("accepted duplicate interface name")
	}
}

func TestTUNAttrs(t *testing.T) {
	data := tunTestAttrs(netlink.Attribute{Type: unix.IFLA_TUN_NUM_QUEUES, Data: tunTestU32(0)}, netlink.Attribute{Type: unix.IFLA_TUN_NUM_QUEUES, Data: tunTestU32(1)})
	if _, err := tunAttrs(data, unix.IFLA_TUN_NUM_QUEUES); err == nil {
		t.Fatal("accepted duplicate attachment count")
	}
	// Unrequested attributes may repeat.
	if _, err := tunAttrs(data, unix.IFLA_TUN_TYPE); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{{1}, {3, 0, 1, 0}, {8, 0, 1, 0}} {
		if _, err := tunAttrs(data, unix.IFLA_TUN_TYPE); err == nil {
			t.Errorf("accepted malformed attributes %x", data)
		}
	}
}

func TestTUNLinkQueueOwnership(t *testing.T) {
	for _, tt := range []struct {
		active, disabled, owned uint32
		wantErr                 bool
	}{
		{0, 0, 0, false}, {1, 0, 1, false}, {4, 0, 4, false},
		{1, 0, 0, true}, {0, 1, 0, true}, {2, 0, 1, true}, {1, 1, 1, true},
	} {
		link := tunLink{flags: unix.IFF_MULTI_QUEUE, queues: tt.active, disabledQueues: tt.disabled}
		err := link.checkQueues(tt.owned)
		if errors.Is(err, unix.EBUSY) != tt.wantErr {
			t.Errorf("%+v owned=%d: %v", link, tt.owned, err)
		}
	}
}

func FuzzParseTUNLink(f *testing.F) {
	f.Add(tunTestLink("test0", "tun", baseTUNTestFields()))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = parseTUNLink(data, "test0") })
}

func TestAdoptTUNRefusesNonTUN(t *testing.T) {
	dev, err := CreateTUN("lo", 1280, WithAdoptExisting())
	if dev != nil {
		dev.Close()
		t.Fatal("adopted loopback interface")
	}
	if err == nil {
		t.Fatal("accepted loopback interface")
	}
}

func TestAdoptTUNMissing(t *testing.T) {
	if _, err := adoptTUNFiles(recoveryTestName(), 1); !errors.Is(err, unix.ENODEV) {
		t.Fatalf("got %v, want ENODEV", err)
	}
}

func TestAdoptTUNFilesErrorPrefix(t *testing.T) {
	for _, name := range []string{"", "name-too-long-for-tun", "bad\x00name", recoveryTestName(), "lo"} {
		_, err := adoptTUNFiles(name, 1)
		if err == nil {
			t.Fatalf("adoptTUNFiles(%q) unexpectedly succeeded", name)
		}
		if msg := err.Error(); !strings.HasPrefix(msg, "adoptTUNFiles: ") || strings.Count(msg, "adoptTUNFiles: ") != 1 {
			t.Errorf("error must have exactly one adoptTUN prefix: %v", err)
		}
	}
}
