/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCreateTUNCollision creates an interface, then calls CreateTUN with the
// same name. The incumbent is either held open or left persistent with no
// queues attached, and is never created with IFF_VNET_HDR: only the attacher
// that finds no other queue gets to set the device flags.
func TestCreateTUNCollision(t *testing.T) {
	requireNetAdmin(t)
	const (
		sq = uint16(unix.IFF_TUN | unix.IFF_NO_PI)
		mq = sq | unix.IFF_MULTI_QUEUE
	)
	for _, tt := range []struct {
		name        string
		incumbent   uint16 // TUNSETIFF flags of the interface already there
		persist     bool   // close the incumbent queue, leaving the interface
		queues      int
		wantErr     error
		wantQueues  int
		wantVnetHdr bool
	}{
		{name: "activeSQ/req1", incumbent: sq, queues: 1, wantErr: unix.EBUSY},
		{name: "activeSQ/req4", incumbent: sq, queues: 4, wantErr: unix.EBUSY},
		{name: "activeMQ/req1", incumbent: mq, queues: 1, wantErr: unix.EINVAL},
		{name: "activeMQ/req4", incumbent: mq, queues: 4, wantQueues: 4},
		{name: "orphanSQ/req1", incumbent: sq, persist: true, queues: 1, wantQueues: 1, wantVnetHdr: true},
		{name: "orphanSQ/req4", incumbent: sq, persist: true, queues: 4, wantQueues: 1, wantVnetHdr: true},
		{name: "orphanMQ/req1", incumbent: mq, persist: true, queues: 1, wantErr: unix.EINVAL},
		{name: "orphanMQ/req4", incumbent: mq, persist: true, queues: 4, wantQueues: 4, wantVnetHdr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			name := testTUNName(t)
			flags := tt.incumbent
			f, err := openTUNFile(name, flags)
			if err != nil {
				t.Fatalf("openTUNFile(%q, %#x): %v", name, flags, err)
			}
			if !tt.persist {
				t.Cleanup(func() { f.Close() })
			} else {
				if err := unix.IoctlSetInt(int(f.Fd()), unix.TUNSETPERSIST, 1); err != nil {
					f.Close()
					t.Fatalf("TUNSETPERSIST: %v", err)
				}
				f.Close()
				t.Cleanup(func() {
					f, err := openTUNFile(name, flags)
					if err != nil {
						t.Errorf("reopen %q to clear persist: %v", name, err)
						return
					}
					if err := unix.IoctlSetInt(int(f.Fd()), unix.TUNSETPERSIST, 0); err != nil {
						t.Errorf("clear persist on %q: %v", name, err)
					}
					f.Close()
				})
			}

			dev, err := CreateTUN(name, testMTU, WithQueues(tt.queues))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					if err == nil {
						dev.Close()
					}
					t.Fatalf("CreateTUN(%q, %d queues) = %v, want %v", name, tt.queues, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateTUN(%q, %d queues): %v", name, tt.queues, err)
			}
			t.Cleanup(func() { dev.Close() })

			if got := len(QueuesOf(dev)); got != tt.wantQueues {
				t.Errorf("got %d queues, want %d", got, tt.wantQueues)
			}
			got := tunFlags(t, dev.(*NativeTun))
			if (got&unix.IFF_VNET_HDR != 0) != tt.wantVnetHdr {
				t.Errorf("flags %#x: IFF_VNET_HDR set = %v, want %v", got, got&unix.IFF_VNET_HDR != 0, tt.wantVnetHdr)
			}
		})
	}
}
