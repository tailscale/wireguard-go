package conn

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/tailscale/wireguard-go/buffer"
	"golang.org/x/net/ipv6"
)

func TestStdNetBindReceiveFuncAfterClose(t *testing.T) {
	bind := NewStdNetBind().(*StdNetBind)
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	bind.Close()
	stacks := make([]buffer.Stack, IdealBatchSize)
	stacks[0] = buffer.NewStack(buffer.New(make([]byte, buffer.MaxMessageSize)), 0)
	eps := make([]Endpoint, IdealBatchSize)
	for _, fn := range fns {
		// The ReceiveFuncs must not access conn-related fields on StdNetBind
		// unguarded. Close() nils the conn-related fields resulting in a panic
		// if they violate the mutex.
		fn(stacks, eps)
	}
}

func mockSetGSOSize(control *[]byte, gsoSize uint16) {
	*control = (*control)[:cap(*control)]
	binary.LittleEndian.PutUint16(*control, gsoSize)
}

func Test_coalesceMessages(t *testing.T) {
	cases := []struct {
		name     string
		buffs    [][]byte
		wantLens []int
		wantGSO  []int
	}{
		{
			name: "one message no coalesce",
			buffs: [][]byte{
				make([]byte, 1, 1),
			},
			wantLens: []int{1},
			wantGSO:  []int{0},
		},
		{
			name: "two messages equal len coalesce",
			buffs: [][]byte{
				make([]byte, 1, 2),
				make([]byte, 1, 1),
			},
			wantLens: []int{2},
			wantGSO:  []int{1},
		},
		{
			name: "two messages unequal len coalesce",
			buffs: [][]byte{
				make([]byte, 2, 3),
				make([]byte, 1, 1),
			},
			wantLens: []int{3},
			wantGSO:  []int{2},
		},
		{
			name: "three messages second unequal len coalesce",
			buffs: [][]byte{
				make([]byte, 2, 3),
				make([]byte, 1, 1),
				make([]byte, 2, 2),
			},
			wantLens: []int{3, 2},
			wantGSO:  []int{2, 0},
		},
		{
			name: "three messages limited cap coalesce",
			buffs: [][]byte{
				make([]byte, 2, 4),
				make([]byte, 2, 2),
				make([]byte, 2, 2),
			},
			wantLens: []int{6},
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
				var gotLen int
				for _, b := range msgs[i].Buffers {
					gotLen += len(b)
				}
				if gotLen != tt.wantLens[i] {
					t.Errorf("len(msgs[%d].Buffers) %d != %d", i, gotLen, tt.wantLens[i])
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
