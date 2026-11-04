// SPDX-License-Identifier: MIT

package peer_test

import (
	"fmt"
	"time"

	"github.com/tailscale/wireguard-go/peer"
	"github.com/tailscale/wireguard-go/peerindex"
)

func ExamplePeer() {
	check := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	newIdentity := func() (peer.LocalIdentity, peer.PublicKey) {
		key, err := peer.NewPrivateKey()
		check(err)
		provider := peer.NewIdentity(key)
		id, err := peer.NewLocalIdentity(1, provider)
		check(err)
		return id, provider.Public()
	}
	idA, publicA := newIdentity()
	idB, publicB := newIdentity()
	var indexes peerindex.Table[*peer.Peer]
	now := time.Now()
	a, _, err := peer.New(now, idA, &indexes, publicB, peer.Config{})
	check(err)
	defer a.Close()
	b, _, err := peer.New(now, idB, &indexes, publicA, peer.Config{})
	check(err)
	defer b.Close()
	admitA, err := peer.NewAdmission(idA)
	check(err)
	admitB, err := peer.NewAdmission(idB)
	check(err)

	// A real adapter routes these flights over its transport and schedules
	// each returned Update. This example exchanges them directly at one time.
	control := func() peer.Packet {
		return peer.Packet{Buffer: make([]byte, peer.MessageInitiationSize)}
	}
	initiation, _, err := a.Initiate(now, control())
	check(err)
	admitted, err := admitB.Admit(now, initiation.Bytes(), nil, false, nil)
	check(err)
	prepared, err := peer.PrepareInitiation(admitted)
	check(err)
	// RemoteStatic is a routing hint, not authentication. HandleInitiation
	// checks the configured remote and authenticates its timestamp.
	response, _, err := b.HandleInitiation(now, prepared, control())
	check(err)
	admitted, err = admitA.Admit(now, response.Bytes(), nil, false, nil)
	check(err)
	confirmation, _, err := a.HandleResponse(now, admitted, control())
	check(err)
	var results [1]peer.ReceiveResult
	_, err = b.Receive(now, []peer.Packet{confirmation}, results[:])
	check(err)
	check(results[0].Err)

	// The application knows this record's length. An IP adapter would instead
	// validate IP lengths, trim padding and check AllowedIPs before delivery.
	message := []byte("hello")
	packets := []peer.Packet{{
		Buffer: make([]byte, peer.TransportHeaderSize+len(message)+peer.PaddingMultiple-1+16),
		Offset: peer.TransportHeaderSize,
		Size:   len(message),
	}}
	copy(packets[0].Bytes(), message)
	_, err = a.Send(now, packets)
	check(err)
	_, err = b.Receive(now, packets, results[:])
	check(err)
	check(results[0].Err)
	fmt.Println(string(results[0].Packet.Bytes()[:len(message)]))
	// Output: hello
}
