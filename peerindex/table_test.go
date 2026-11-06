// SPDX-License-Identifier: MIT

package peerindex_test

import (
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/peer"
	"github.com/tailscale/wireguard-go/peerindex"
)

func TestTableOwnerCheckedRelease(t *testing.T) {
	var table peerindex.Table[int]
	index, err := table.Allocate(1)
	if err != nil || index == 0 {
		t.Fatal(index, err)
	}
	table.Release(index, 2)
	if owner, ok := table.Lookup(index); !ok || owner != 1 {
		t.Fatal("wrong owner deleted mapping")
	}
	table.Release(index, 1)
	table.Release(index, 1)
	table.Release(0, 1)
	if table.Len() != 0 {
		t.Fatal("leak")
	}
}

func TestTableConcurrentNamespace(t *testing.T) {
	var table peerindex.Table[int]
	var wg sync.WaitGroup
	for owner := 1; owner <= 8; owner++ {
		wg.Go(func() {
			indexes := make([]uint32, 100)
			for i := range indexes {
				var err error
				indexes[i], err = table.Allocate(owner)
				if err != nil {
					t.Error(err)
					return
				}
			}
			for _, index := range indexes {
				if got, ok := table.Lookup(index); !ok || got != owner {
					t.Error("misroute")
				}
			}
			for _, index := range indexes {
				table.Release(index, owner)
			}
		})
	}
	wg.Wait()
	if table.Len() != 0 {
		t.Fatal("leak")
	}
}

func TestSharedIndexRoutingAcrossIdentities(t *testing.T) {
	var table peerindex.Table[*peer.Peer]
	now := time.Unix(1700000000, 0)
	peers := make([]*peer.Peer, 0, 16)
	for i := 0; i < 8; i++ {
		ka, err := peer.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		kb, err := peer.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		ia, ib := peer.NewIdentity(ka), peer.NewIdentity(kb)
		ga, err := peer.NewLocalIdentity(1, ia)
		if err != nil {
			t.Fatal(err)
		}
		gb, err := peer.NewLocalIdentity(1, ib)
		if err != nil {
			t.Fatal(err)
		}
		aa, err := peer.NewAdmission(ga)
		if err != nil {
			t.Fatal(err)
		}
		ab, err := peer.NewAdmission(gb)
		if err != nil {
			t.Fatal(err)
		}
		a, _, err := peer.New(now, ga, &table, ib.Public(), peer.Config{})
		if err != nil {
			t.Fatal(err)
		}
		b, _, err := peer.New(now, gb, &table, ia.Public(), peer.Config{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Close() })
		t.Cleanup(func() { b.Close() })
		peers = append(peers, a, b)
		buffer := func() peer.Packet { return peer.Packet{Buffer: make([]byte, 160)} }
		init, _, err := a.Initiate(now, buffer())
		if err != nil {
			t.Fatal(err)
		}
		token, err := ab.Admit(now, init.Bytes(), nil, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := peer.PrepareInitiation(token)
		if err != nil {
			t.Fatal(err)
		}
		if prepared.RemoteStatic() != ia.Public() {
			t.Fatal("wrong routing hint")
		}
		resp, _, err := b.HandleInitiation(now, prepared, buffer())
		if err != nil {
			t.Fatal(err)
		}
		_, index, err := peer.ParseHeader(resp.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		routed, ok := table.Lookup(index)
		if !ok || routed != a {
			t.Fatal("response misroute")
		}
		token, err = aa.Admit(now, resp.Bytes(), nil, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		confirm, _, err := routed.HandleResponse(now, token, buffer())
		if err != nil {
			t.Fatal(err)
		}
		_, index, err = peer.ParseHeader(confirm.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		routed, ok = table.Lookup(index)
		if !ok || routed != b {
			t.Fatal("confirmation misroute")
		}
		result := make([]peer.ReceiveResult, 1)
		if _, err = routed.Receive(now, []peer.Packet{confirm}, result); err != nil || result[0].Err != nil {
			t.Fatal(err, result)
		}
	}
	if table.Len() != 16 {
		t.Fatal("live sessions not independently routed")
	}
	for _, p := range peers {
		p.Close()
	}
	if table.Len() != 0 {
		t.Fatal("teardown leak")
	}
}
