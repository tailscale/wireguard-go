/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 * Copyright (c) Tailscale Inc & contributors
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

func (d *fakeMultiQueueDevice) WriteTo(_ int, _ [][]byte, _ int) (int, error) {
	return 0, nil
}

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

func TestTUNConfig(t *testing.T) {
	if c := defaultConfig(); c.queues != 1 || c.logf != nil {
		t.Fatalf("default tun config: %+v", c)
	}
}

func TestWithLogf(t *testing.T) {
	c := defaultConfig()
	calls := 0
	WithLogf(func(format string, args ...any) {
		calls++
		if format != "queue %d" || len(args) != 1 || args[0] != 4 {
			t.Errorf("format=%q args=%v", format, args)
		}
	}).apply(&c)
	if c.logf == nil {
		t.Fatal("logger was not configured")
	}
	if calls != 0 {
		t.Fatal("configuring the logger called it")
	}
	c.logf("queue %d", 4)
	if calls != 1 {
		t.Errorf("logger calls = %d, want 1", calls)
	}
	WithLogf(nil).apply(&c)
	if c.logf != nil {
		t.Error("nil logger did not disable logging")
	}
}

func TestTUNOptions(t *testing.T) {
	c := defaultConfig()
	WithQueues(4).apply(&c)
	if c.queues != 4 {
		t.Fatalf("configured tun config: %+v", c)
	}
}
