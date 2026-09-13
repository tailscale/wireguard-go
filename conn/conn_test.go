/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"slices"
	"testing"
)

func TestPrettyName(t *testing.T) {
	var (
		recvFunc ReceiveFunc = func(slab []byte, packets []ReceivedPacket) (n int, err error) { return }
	)

	const want = "TestPrettyName"

	t.Run("ReceiveFunc.PrettyName", func(t *testing.T) {
		if got := recvFunc.PrettyName(); got != want {
			t.Errorf("PrettyName() = %v, want %v", got, want)
		}
	})
}

type stubBind struct{}

func (stubBind) Open(uint16) ([]ReceiveFunc, uint16, error) { return nil, 0, nil }
func (stubBind) Close() error                               { return nil }
func (stubBind) SetMark(uint32) error                       { return nil }
func (stubBind) Send([][]byte, Endpoint, int) error         { return nil }
func (stubBind) ParseEndpoint(string) (Endpoint, error)     { return nil, nil }
func (stubBind) BatchSize() int                             { return 1 }

// namedStubBind labels its receive funcs, satisfying [NamedBind].
type namedStubBind struct {
	stubBind
	names []string
}

func (b namedStubBind) ReceiveNames() []string { return b.names }

func mkTestReceiveFunc() ReceiveFunc {
	return func(slab []byte, packets []ReceivedPacket) (n int, err error) { return }
}

func TestNamesOf(t *testing.T) {
	fns := []ReceiveFunc{mkTestReceiveFunc(), mkTestReceiveFunc()}

	// Guard the premise of the fallback: reflection cannot tell these apart.
	if a, b := fns[0].PrettyName(), fns[1].PrettyName(); a != b {
		t.Fatalf("PrettyName should collide, got %q and %q", a, b)
	}

	tests := []struct {
		name string
		bind Bind
		want []string
	}{
		{
			name: "named",
			bind: namedStubBind{names: []string{"v4", "v6"}},
			want: []string{"v4", "v6"},
		},
		{
			name: "named wrong length",
			bind: namedStubBind{names: []string{"v4"}},
			want: []string{"0/mkTestReceiveFunc", "1/mkTestReceiveFunc"},
		},
		{
			name: "named nil",
			bind: namedStubBind{},
			want: []string{"0/mkTestReceiveFunc", "1/mkTestReceiveFunc"},
		},
		{
			name: "unnamed",
			bind: stubBind{},
			want: []string{"0/mkTestReceiveFunc", "1/mkTestReceiveFunc"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NamesOf(tt.bind, fns)
			if !slices.Equal(got, tt.want) {
				t.Errorf("NamesOf() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("no fns", func(t *testing.T) {
		if got := NamesOf(stubBind{}, nil); len(got) != 0 {
			t.Errorf("NamesOf() = %q, want empty", got)
		}
	})
}

type sendStubBind struct {
	stubBind
	sendCalled bool
}

func (b *sendStubBind) Send(_ [][]byte, _ Endpoint, _ int) error {
	b.sendCalled = true
	return nil
}

// multiSocketStubBind records the last [MultiSocketBind.SendTo].
type multiSocketStubBind struct {
	sendStubBind
	sendToCalled bool
	sendToFlow   int
}

func (b *multiSocketStubBind) SendTo(flow int, _ [][]byte, _ Endpoint, _ int) error {
	b.sendToCalled, b.sendToFlow = true, flow
	return nil
}

func TestSendToOf(t *testing.T) {
	t.Run("plain bind", func(t *testing.T) {
		bind := &sendStubBind{}
		// The flow is dropped, but the rest of the call must arrive intact.
		if err := SendToOf(bind)(3, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
		if !bind.sendCalled {
			t.Fatal("Send was not called")
		}
	})

	t.Run("multisocket bind", func(t *testing.T) {
		bind := &multiSocketStubBind{}
		if err := SendToOf(bind)(3, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
		if !bind.sendToCalled {
			t.Fatal("SendTo was not called")
		}
		if bind.sendToFlow != 3 {
			t.Errorf("SendTo flow = %d, want 3", bind.sendToFlow)
		}
		if bind.sendCalled {
			t.Error("SendToOf routed to Send, want SendTo")
		}
	})
}
