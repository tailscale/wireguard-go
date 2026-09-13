/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"os"
	"testing"
)

type fakeDevice struct{}

func (*fakeDevice) Read(slab []byte, packets []ReadPacket) (int, error) { return 0, nil }
func (*fakeDevice) Write(bufs [][]byte, offset int) (int, error)        { return 0, nil }
func (*fakeDevice) File() *os.File                                      { return nil }
func (*fakeDevice) MTU() (int, error)                                   { return 0, nil }
func (*fakeDevice) Name() (string, error)                               { return "fake", nil }
func (*fakeDevice) Events() <-chan Event                                { return nil }
func (*fakeDevice) Close() error                                        { return nil }
func (*fakeDevice) BatchSize() int                                      { return 1 }

type fakeMultiQueueDevice struct {
	fakeDevice
	queues []Queue
}

func (d *fakeMultiQueueDevice) Queues() []Queue { return d.queues }

func TestQueuesOf(t *testing.T) {
	t.Run("plain device", func(t *testing.T) {
		dev := &fakeDevice{}
		qs := QueuesOf(dev)
		if len(qs) != 1 {
			t.Fatalf("len(QueuesOf(dev)) = %d, want 1", len(qs))
		}
		if qs[0] != Queue(dev) {
			t.Errorf("QueuesOf(dev)[0] = %v, want dev itself", qs[0])
		}
	})

	t.Run("multiqueue device", func(t *testing.T) {
		want := []Queue{&fakeDevice{}, &fakeDevice{}, &fakeDevice{}, &fakeDevice{}}
		dev := &fakeMultiQueueDevice{queues: want}
		qs := QueuesOf(dev)
		if len(qs) != len(want) {
			t.Fatalf("len(QueuesOf(dev)) = %d, want %d", len(qs), len(want))
		}
		for i := range want {
			if qs[i] != want[i] {
				t.Errorf("QueuesOf(dev)[%d] = %v, want %v", i, qs[i], want[i])
			}
		}
	})

	for _, tc := range []struct {
		name   string
		queues []Queue
	}{
		{"nil queues", nil},
		{"empty queues", []Queue{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := &fakeMultiQueueDevice{queues: tc.queues}
			qs := QueuesOf(dev)
			if len(qs) != 1 {
				t.Fatalf("len(QueuesOf(dev)) = %d, want 1", len(qs))
			}
			if qs[0] != Queue(dev) {
				t.Errorf("QueuesOf(dev)[0] = %v, want dev itself", qs[0])
			}
		})
	}
}
