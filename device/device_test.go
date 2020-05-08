/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2019 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun/tuntest"
	"github.com/tailscale/wireguard-go/wgcfg"
)

// TODO(crawshaw): pick unused ports on localhost
var cfg1 = `private_key=481eb0d8113a4a5da532d2c3e9c14b53c8454b34ab109676f6b58c2245e37b58
listen_port=53511
replace_peers=true
public_key=f70dbb6b1b92a1dde1c783b297016af3f572fef13b0abb16a2623d89a58e9725
protocol_version=1
replace_allowed_ips=true
allowed_ip=1.0.0.2/32
endpoint=127.0.0.1:53512`

var cfg2 = `private_key=98c7989b1661a0d64fd6af3502000f87716b7c4bbcf00d04fc6073aa7b539768
listen_port=53512
replace_peers=true
public_key=49e80929259cebdda4f322d6d2b1a6fad819d603acd26fd5d845e7a123036427
protocol_version=1
replace_allowed_ips=true
allowed_ip=1.0.0.1/32
endpoint=127.0.0.1:53511`

func TestTwoDevicePing(t *testing.T) {
	tun1 := tuntest.NewChannelTUN()
	dev1 := NewDevice(tun1.TUN(), &DeviceOptions{
		Logger: NewLogger(LogLevelDebug, "dev1: "),
	})
	dev1.Up()
	defer dev1.Close()
	if err := dev1.IpcSetOperation(bufio.NewReader(strings.NewReader(cfg1))); err != nil {
		t.Fatal(err)
	}

	tun2 := tuntest.NewChannelTUN()
	dev2 := NewDevice(tun2.TUN(), &DeviceOptions{
		Logger: NewLogger(LogLevelDebug, "dev2: "),
	})
	dev2.Up()
	defer dev2.Close()
	if err := dev2.IpcSetOperation(bufio.NewReader(strings.NewReader(cfg2))); err != nil {
		t.Fatal(err)
	}

	t.Run("ping 1.0.0.1", func(t *testing.T) {
		msg2to1 := tuntest.Ping(net.ParseIP("1.0.0.1"), net.ParseIP("1.0.0.2"))
		tun2.Outbound <- msg2to1
		select {
		case msgRecv := <-tun1.Inbound:
			if !bytes.Equal(msg2to1, msgRecv) {
				t.Error("ping did not transit correctly")
			}
		case <-time.After(300 * time.Millisecond):
			t.Error("ping did not transit")
		}
	})

	t.Run("ping 1.0.0.2", func(t *testing.T) {
		msg1to2 := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
		tun1.Outbound <- msg1to2
		select {
		case msgRecv := <-tun2.Inbound:
			if !bytes.Equal(msg1to2, msgRecv) {
				t.Error("return ping did not transit correctly")
			}
		case <-time.After(300 * time.Millisecond):
			t.Error("return ping did not transit")
		}
	})
}

func TestSimultaneousHandshake(t *testing.T) {
	const maxWait = 300 * time.Millisecond

	tun1 := tuntest.NewChannelTUN()
	dev1 := NewDevice(tun1.TUN(), &DeviceOptions{
		Logger: NewLogger(LogLevelDebug, "dev1: "),
	})
	dev1.Up()
	defer dev1.Close()
	if err := dev1.IpcSetOperation(bufio.NewReader(strings.NewReader(cfg1))); err != nil {
		t.Fatal(err)
	}

	tun2 := tuntest.NewChannelTUN()
	dev2 := NewDevice(tun2.TUN(), &DeviceOptions{
		Logger: NewLogger(LogLevelDebug, "dev2: "),
	})
	dev2.Up()
	defer dev2.Close()
	if err := dev2.IpcSetOperation(bufio.NewReader(strings.NewReader(cfg2))); err != nil {
		t.Fatal(err)
	}

	msg2to1 := tuntest.Ping(net.ParseIP("1.0.0.1"), net.ParseIP("1.0.0.2"))
	msg1to2 := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		tun1.Outbound <- msg1to2
		wg.Done()
	}()
	go func() {
		tun2.Outbound <- msg2to1
		wg.Done()
	}()
	wg.Wait()

	select {
	case msgRecv := <-tun1.Inbound:
		if !bytes.Equal(msg2to1, msgRecv) {
			t.Error("ping did not transit correctly")
		}
	case <-time.After(maxWait):
		t.Error("ping 1.0.0.1 did not transit")
	}

	select {
	case msgRecv := <-tun2.Inbound:
		if !bytes.Equal(msg1to2, msgRecv) {
			t.Error("return ping did not transit correctly")
		}
	case <-time.After(maxWait):
		t.Error("ping 1.0.0.2 did not transit")
	}
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := wgcfg.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	tun := newDummyTUN("dummy")
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun, &DeviceOptions{
		Logger: logger,
	})
	device.SetPrivateKey(sk)
	return device
}
