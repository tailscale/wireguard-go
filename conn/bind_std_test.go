package conn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/ipv6"
)

func TestStdNetBindReceiveFuncAfterClose(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	bind.Close()
	slab := make([]byte, 1)
	packets := make([]ReceivedPacket, 1)
	for _, fn := range fns {
		// The ReceiveFuncs must not access conn-related fields on StdNetBind
		// unguarded. Close() nils the conn-related fields resulting in a panic
		// if they violate the mutex.
		fn(slab, packets)
	}
}

func TestSocketName(t *testing.T) {
	tests := []struct {
		family   string
		i, total int
		want     string
	}{
		{"v4", 0, 1, "v4"},
		{"v6", 0, 1, "v6"},
		{"v4", 0, 4, "v4:0"},
		{"v4", 3, 4, "v4:3"},
		{"v6", 3, 4, "v6:3"},
	}
	for _, tt := range tests {
		if got := socketName(tt.family, tt.i, tt.total); got != tt.want {
			t.Errorf("socketName(%q, %d, %d) = %q, want %q",
				tt.family, tt.i, tt.total, got, tt.want)
		}
	}
}

func TestStdNetBindNames(t *testing.T) {
	want := func(bind *StdNetBind) []string {
		var names []string
		for i := range bind.v4 {
			names = append(names, socketName("v4", i, len(bind.v4)))
		}
		for i := range bind.v6 {
			names = append(names, socketName("v6", i, len(bind.v6)))
		}
		return names
	}

	for _, sockets := range []int{1, 4} {
		t.Run(fmt.Sprintf("sockets=%d", sockets), func(t *testing.T) {
			bind := NewStdNetBind(WithSockets(sockets)).(*StdNetBind)
			fns, _, err := bind.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			defer bind.Close()

			names := bind.ReceiveNames()
			if len(names) != len(fns) {
				t.Fatalf("len(Names()) = %d, len(fns) = %d", len(names), len(fns))
			}
			if got := want(bind); !slices.Equal(names, got) {
				t.Errorf("ReceiveNames() = %q, want %q", names, got)
			}
			wantMulti := sockets > 1 && reusePortFn != nil
			if gotMulti := len(bind.v4) > 1; gotMulti != wantMulti {
				t.Errorf("len(v4) = %d, want %d sockets", len(bind.v4), sockets)
			}
			if wantMulti && !slices.Contains(names, "v4:3") {
				t.Errorf("ReceiveNames() = %q, want it to contain v4:3", names)
			}
			if len(slices.Compact(slices.Clone(names))) != len(names) {
				t.Errorf("ReceiveNames() = %q, want all distinct", names)
			}
			if got := NamesOf(bind, fns); !slices.Equal(got, names) {
				t.Errorf("ReceiveNamesOf() = %q, want %q", got, names)
			}
		})
	}
}

func TestStdNetBindNamesAfterClose(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	bind.Close()
	if names := bind.ReceiveNames(); len(names) != 0 {
		t.Errorf("ReceiveNames() after Close = %q, want empty", names)
	}
	for i, name := range NamesOf(bind, fns) {
		if want := strconv.Itoa(i) + "/"; !strings.HasPrefix(name, want) {
			t.Errorf("ReceiveNamesOf()[%d] = %q, want prefix %q", i, name, want)
		}
	}
}

// openMultiSocketBind returns a bind with n v4 sockets, skipping the test if
// this platform cannot supply them.
func openMultiSocketBind(t *testing.T, n int) *StdNetBind {
	t.Helper()
	if reusePortFn == nil {
		t.Skip("no SO_REUSEPORT on this platform")
	}
	bind := NewStdNetBind(WithSockets(n)).(*StdNetBind)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bind.Close() })
	if len(bind.v4) != n {
		t.Fatalf("len(v4) = %d, want %d", len(bind.v4), n)
	}
	return bind
}

func TestStdNetBindOpenRefusesExistingGroup(t *testing.T) {
	held := openMultiSocketBind(t, 2)
	defer held.Close()
	port := held.v4[0].conn.LocalAddr().(*net.UDPAddr).Port

	bind := NewStdNetBind(WithSockets(2))
	if _, _, err := bind.Open(uint16(port)); !errors.Is(err, errEADDRINUSE) {
		bind.Close()
		t.Fatalf("Open() on a held port = %v, want EADDRINUSE", err)
	}
}

func mockSetGSOSize(control *[]byte, gsoSize uint16) {
	*control = (*control)[:cap(*control)]
	binary.LittleEndian.PutUint16(*control, gsoSize)
}

func Test_coalesceMessages(t *testing.T) {
	cases := []struct {
		name  string
		buffs [][]byte
		// Each wantLens slice corresponds to the Buffers of a single coalesced message,
		// and each int is the expected length of the corresponding Buffer[i].
		wantLens [][]int
		wantGSO  []int
	}{
		{
			name: "one message no coalesce",
			buffs: [][]byte{
				make([]byte, 1, 1),
			},
			wantLens: [][]int{{1}},
			wantGSO:  []int{0},
		},
		{
			name: "two messages equal len coalesce",
			buffs: [][]byte{
				make([]byte, 1, 2),
				make([]byte, 1, 1),
			},
			wantLens: [][]int{{1, 1}},
			wantGSO:  []int{1},
		},
		{
			name: "two messages unequal len coalesce",
			buffs: [][]byte{
				make([]byte, 2, 3),
				make([]byte, 1, 1),
			},
			wantLens: [][]int{{2, 1}},
			wantGSO:  []int{2},
		},
		{
			name: "three messages second unequal len coalesce",
			buffs: [][]byte{
				make([]byte, 2, 3),
				make([]byte, 1, 1),
				make([]byte, 2, 2),
			},
			wantLens: [][]int{{2, 1}, {2}},
			wantGSO:  []int{2, 0},
		},
		{
			name: "three messages limited cap coalesce",
			buffs: [][]byte{
				make([]byte, 2, 4),
				make([]byte, 2, 2),
				make([]byte, 2, 2),
			},
			wantLens: [][]int{{2, 2, 2}},
			wantGSO:  []int{2},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			addr := &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1").To4(),
				Port: 1,
			}
			msgs := make([]ipv6.Message, len(tt.buffs))
			for i := range msgs {
				msgs[i].Buffers = make([][]byte, 1)
				msgs[i].OOB = make([]byte, 0, 2)
			}
			got := coalesceMessages(addr, &StdNetEndpoint{AddrPort: addr.AddrPort()}, tt.buffs, 0, msgs, mockSetGSOSize)
			if got != len(tt.wantLens) {
				t.Fatalf("got len %d want: %d", got, len(tt.wantLens))
			}
			for i := 0; i < got; i++ {
				if msgs[i].Addr != addr {
					t.Errorf("msgs[%d].Addr != passed addr", i)
				}
				if len(msgs[i].Buffers) != len(tt.wantLens[i]) {
					t.Fatalf("len(msgs[%d].Buffers) %d != %d", i, len(msgs[i].Buffers), len(tt.wantLens[i]))
				}
				for j := range tt.wantLens[i] {
					gotLen := len(msgs[i].Buffers[j])
					if gotLen != tt.wantLens[i][j] {
						t.Errorf("len(msgs[%d].Buffers[%d]) %d != %d", i, j, gotLen, tt.wantLens[i][j])
					}
				}
				gotGSO, err := mockGetGSOSize(msgs[i].OOB)
				if err != nil {
					t.Fatalf("msgs[%d] getGSOSize err: %v", i, err)
				}
				if gotGSO != tt.wantGSO[i] {
					t.Errorf("msgs[%d] gsoSize %d != %d", i, gotGSO, tt.wantGSO[i])
				}
			}
		})
	}
}

func mockGetGSOSize(control []byte) (int, error) {
	if len(control) < 2 {
		return 0, nil
	}
	return int(binary.LittleEndian.Uint16(control)), nil
}

func Test_fillReceivedPackets(t *testing.T) {
	newMsg := func(n, gso int) ipv6.Message {
		msg := ipv6.Message{
			Buffers: [][]byte{make([]byte, maxDatagramSize)},
			N:       n,
			OOB:     make([]byte, 2),
			Addr:    &net.UDPAddr{},
		}
		binary.LittleEndian.PutUint16(msg.OOB, uint16(gso))
		if gso > 0 {
			msg.NN = 2
		}
		return msg
	}

	cases := []struct {
		name        string
		msgs        []ipv6.Message
		wantNumEval int
		wantPackets [][2]int // {offset, size}
		wantErr     bool
	}{
		{
			name: "first split",
			msgs: []ipv6.Message{
				newMsg(3, 1),
			},
			wantNumEval: 3,
			wantPackets: [][2]int{
				{0, 1},
				{1, 1},
				{2, 1},
			},
			wantErr: false,
		},
		{
			name: "first no split",
			msgs: []ipv6.Message{
				newMsg(1, 0),
			},
			wantNumEval: 1,
			wantPackets: [][2]int{
				{0, 1},
			},
			wantErr: false,
		},
		{
			name: "first no split last no split",
			msgs: []ipv6.Message{
				newMsg(1, 0),
				newMsg(1, 0),
			},
			wantNumEval: 2,
			wantPackets: [][2]int{
				{0, 1},
				{maxDatagramSize, 1},
			},
			wantErr: false,
		},
		{
			name: "first no split last split",
			msgs: []ipv6.Message{
				newMsg(1, 0),
				newMsg(3, 1),
			},
			wantNumEval: 4,
			wantPackets: [][2]int{
				{0, 1},
				{maxDatagramSize, 1},
				{maxDatagramSize + 1, 1},
				{maxDatagramSize + 2, 1},
			},
			wantErr: false,
		},
		{
			name: "first split last split",
			msgs: []ipv6.Message{
				newMsg(2, 1),
				newMsg(2, 1),
			},
			wantNumEval: 4,
			wantPackets: [][2]int{
				{0, 1},
				{1, 1},
				{maxDatagramSize, 1},
				{maxDatagramSize + 1, 1},
			},
			wantErr: false,
		},
		{
			name: "first no split last split overflow",
			msgs: []ipv6.Message{
				newMsg(1, 0),
				newMsg(4, 1),
			},
			wantNumEval: 4,
			wantPackets: [][2]int{
				{0, 1},
				{maxDatagramSize, 1},
				{maxDatagramSize + 1, 1},
				{maxDatagramSize + 2, 1},
			},
			wantErr: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			packets := make([]ReceivedPacket, len(tt.wantPackets))
			got, err := fillReceivedPackets(
				tt.msgs,
				1<<16-1,
				packets,
				true,
				mockGetGSOSize,
			)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err: %v", err)
			}
			if got != tt.wantNumEval {
				t.Fatalf("got to eval: %d want: %d", got, tt.wantNumEval)
			}
			if len(packets) != len(tt.wantPackets) {
				t.Fatalf("got %d packets, want %d", len(packets), len(tt.wantPackets))
			}
			for i, want := range tt.wantPackets {
				got := packets[i]
				if got.Offset != want[0] || got.Size != want[1] {
					t.Errorf(
						"packets[%d] = {Offset: %d, Size: %d}, want {Offset: %d, Size: %d}",
						i, got.Offset, got.Size, want[0], want[1],
					)
				}
			}
		})
	}
}
