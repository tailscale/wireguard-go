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
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCreateTUNConfiguration(t *testing.T) {
	requireNetAdmin(t)
	for _, tt := range []struct {
		name      string
		existing  int
		requested int
		busy      bool
		detached  bool
		noHeader  bool
		want      int
		wantErr   error
	}{
		{name: "newSingle", requested: 1, want: 1},
		{name: "newMulti", requested: 4, want: 4},
		{name: "adoptSingle", existing: 1, requested: 1, want: 1},
		{name: "singleFallback", existing: 1, requested: 4, want: 1},
		{name: "adoptMulti", existing: 4, requested: 4, want: 4},
		{name: "resizeMulti", existing: 4, requested: 2, want: 2},
		{name: "multiCannotBecomeSingle", existing: 4, requested: 1, wantErr: unix.EINVAL},
		{name: "busySingle", existing: 1, requested: 1, busy: true, wantErr: unix.EBUSY},
		{name: "busySingleFallback", existing: 1, requested: 4, busy: true, wantErr: unix.EBUSY},
		{name: "busyMulti", existing: 4, requested: 4, busy: true, wantErr: unix.EBUSY},
		// Sysfs counts active queues only. Detached fds remain undetectable.
		{name: "detachedMulti", existing: 4, requested: 4, busy: true, detached: true, want: 4},
		{name: "enableSingleHeader", existing: 1, requested: 4, noHeader: true, want: 1},
		{name: "enableMultiHeader", existing: 4, requested: 4, noHeader: true, want: 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			name, index := testTUNName(t), 0
			if tt.existing != 0 {
				old, existingName := persistentTestTUN(t, tt.existing)
				name = existingName
				iface, err := net.InterfaceByName(name)
				if err != nil {
					t.Fatal(err)
				}
				index = iface.Index
				if tt.detached {
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
				if !tt.busy {
					old.Close()
				}
				if tt.noHeader {
					flags := tunRequiredFlags
					if tt.existing > 1 {
						flags |= unix.IFF_MULTI_QUEUE
					}
					f, err := openTUNFile(name, flags)
					if err != nil {
						t.Fatal(err)
					}
					f.Close()
				}
			}
			var logs []string
			dev, err := CreateTUN(name, 1280, WithQueues(tt.requested), WithLogf(func(format string, args ...any) {
				logs = append(logs, fmt.Sprintf(format, args...))
			}))
			if !errors.Is(err, tt.wantErr) {
				if dev != nil {
					dev.Close()
				}
				t.Fatalf("CreateTUN = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if dev != nil {
					dev.Close()
					t.Fatal("non-nil device on failure")
				}
				if tt.name == "busyMulti" {
					if len(logs) != 1 || !strings.Contains(logs[0], "cannot acquire all active queues") || !strings.Contains(logs[0], "rx=8 tx=8, owned=4") {
						t.Errorf("unclear acquisition error: %v", logs)
					}
					// Failed acquisition must release only our queues.
					if err := checkTUNQueues(filepath.Join("/sys/class/net", name, "queues"), tt.existing); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				t.Cleanup(func() { dev.Close() })
				if got := len(QueuesOf(dev)); got != tt.want {
					t.Errorf("queues = %d, want %d", got, tt.want)
				}
				if dev.BatchSize() <= 1 {
					t.Error("virtio headers not enabled")
				}
				if tt.want < tt.requested && (len(logs) != 1 || !strings.Contains(logs[0], "using single queue")) {
					t.Errorf("missing fallback log: %v", logs)
				}
			}
			if index != 0 {
				iface, err := net.InterfaceByName(name)
				if err != nil || iface.Index != index {
					t.Fatalf("interface replaced: interface=%v error=%v", iface, err)
				}
			}
		})
	}
}

func TestCheckTUNQueues(t *testing.T) {
	for _, tt := range []struct {
		name    string
		rx, tx  int
		owned   int
		missing bool
		wantErr bool
	}{
		{name: "one", rx: 1, tx: 1, owned: 1},
		{name: "four", rx: 4, tx: 4, owned: 4},
		{name: "otherHolders", rx: 5, tx: 5, owned: 4, wantErr: true},
		{name: "tooFew", rx: 1, tx: 1, owned: 4, wantErr: true},
		{name: "rxMismatch", rx: 5, tx: 4, owned: 4, wantErr: true},
		{name: "txMismatch", rx: 4, tx: 5, owned: 4, wantErr: true},
		{name: "empty", owned: 1, wantErr: true},
		{name: "unavailable", missing: true, owned: 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := t.TempDir()
			for prefix, n := range map[string]int{"rx": tt.rx, "tx": tt.tx} {
				for i := range n {
					if err := os.Mkdir(filepath.Join(path, fmt.Sprintf("%s-%d", prefix, i)), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			// Only queue directories contribute to the count.
			if err := os.WriteFile(filepath.Join(path, "rx-99"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if tt.missing {
				path = filepath.Join(path, "missing")
			}
			err := checkTUNQueues(path, tt.owned)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkTUNQueues = %v, want error=%v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateTUNFailureCleanup(t *testing.T) {
	requireNetAdmin(t)
	for _, queues := range []int{1, 4} {
		for _, failure := range []string{"largeHeader", "foreignByteOrder", "initialization"} {
			t.Run(fmt.Sprintf("%d/%s", queues, failure), func(t *testing.T) {
				old, name := persistentTestTUN(t, queues)
				request, value := uint(unix.TUNSETVNETHDRSZ), 12
				if failure == "foreignByteOrder" {
					request, value = unix.TUNSETVNETLE, 1
					if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 {
						request = unix.TUNSETVNETBE
					}
				}
				set := func(value int) {
					ioctlRecoveryFile(t, old.File(), func(fd int) error {
						err := unix.IoctlSetPointerInt(fd, request, value)
						if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTTY) {
							t.Skipf("unsupported header setting: %v", err)
						}
						return err
					})
				}
				if failure != "initialization" {
					set(value)
				}
				old.Close()
				mtu := 1280
				if failure == "initialization" {
					mtu = 1
				}
				dev, err := CreateTUN(name, mtu, WithQueues(queues))
				if dev != nil {
					dev.Close()
				}
				if err == nil || dev != nil {
					t.Fatalf("CreateTUN = %v, %v, want failure", dev, err)
				}
				// Restore the header through a raw fd, bypassing format validation.
				fd, err := unix.Open(cloneDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				file := os.NewFile(uintptr(fd), cloneDevicePath)
				defer file.Close()
				ifr, _ := unix.NewIfreq(name)
				flags := tunDefaultFlags
				if queues > 1 {
					flags |= unix.IFF_MULTI_QUEUE
				}
				ifr.SetUint16(flags)
				if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
					t.Fatalf("failed acquisition leaked queues: %v", err)
				}
				if failure != "initialization" {
					value = 0
					if failure == "largeHeader" {
						value = virtioNetHdrLen
					}
					if err := unix.IoctlSetPointerInt(fd, request, value); err != nil {
						t.Fatal(err)
					}
				}
				file.Close()
				// A complete retry also detects leaked multiqueue fds.
				dev, err = CreateTUN(name, 1280, WithQueues(queues))
				if err != nil {
					t.Fatalf("retry after failure: %v", err)
				}
				dev.Close()
			})
		}
	}
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
	name := testTUNName(t)
	dev, err := CreateTUN(name, 1280, WithQueues(queues))
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
