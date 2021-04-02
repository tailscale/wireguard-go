/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package bindtest

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"

	"github.com/tailscale/wireguard-go/conn"
)

type ChannelBind struct {
	rx4, tx4         *chan []byte
	rx6, tx6         *chan []byte
	closeSignal      chan bool
	source4, source6 ChannelEndpoint
	target4, target6 ChannelEndpoint
}

type ChannelEndpoint uint16

var _ conn.Bind = (*ChannelBind)(nil)
var _ conn.Endpoint = (*ChannelEndpoint)(nil)

func NewChannelBinds() [2]conn.Bind {
	arx4 := make(chan []byte, 8192)
	brx4 := make(chan []byte, 8192)
	arx6 := make(chan []byte, 8192)
	brx6 := make(chan []byte, 8192)
	var binds [2]ChannelBind
	binds[0].rx4 = &arx4
	binds[0].tx4 = &brx4
	binds[1].rx4 = &brx4
	binds[1].tx4 = &arx4
	binds[0].rx6 = &arx6
	binds[0].tx6 = &brx6
	binds[1].rx6 = &brx6
	binds[1].tx6 = &arx6
	binds[0].target4 = ChannelEndpoint(1)
	binds[1].target4 = ChannelEndpoint(2)
	binds[0].target6 = ChannelEndpoint(3)
	binds[1].target6 = ChannelEndpoint(4)
	binds[0].source4 = binds[1].target4
	binds[0].source6 = binds[1].target6
	binds[1].source4 = binds[0].target4
	binds[1].source6 = binds[0].target6
	return [2]conn.Bind{&binds[0], &binds[1]}
}

func (c ChannelEndpoint) ClearSrc() {}

func (c ChannelEndpoint) SrcToString() string { return "" }

func (c ChannelEndpoint) DstToString() string { return fmt.Sprintf("127.0.0.1:%d", c) }

func (c ChannelEndpoint) DstToBytes() []byte { return []byte{byte(c)} }

func (c ChannelEndpoint) DstIP() net.IP { return net.IPv4(127, 0, 0, 1) }

func (c ChannelEndpoint) SrcIP() net.IP { return nil }

func (c *ChannelBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	c.closeSignal = make(chan bool)
	fns = append(fns, c.makeReceiveFunc(*c.rx4))
	fns = append(fns, c.makeReceiveFunc(*c.rx6))
	if rand.Uint32()&1 == 0 {
		return fns, uint16(c.source4), nil
	} else {
		return fns, uint16(c.source6), nil
	}
}

func (c *ChannelBind) Close() error {
	if c.closeSignal != nil {
		select {
		case <-c.closeSignal:
		default:
			close(c.closeSignal)
		}
	}
	return nil
}

func (c *ChannelBind) SetMark(mark uint32) error { return nil }

func (c *ChannelBind) makeReceiveFunc(ch chan []byte) conn.ReceiveFunc {
	return func(b []byte) (n int, ep conn.Endpoint, err error) {
		select {
		case <-c.closeSignal:
			return 0, nil, net.ErrClosed
		case rx := <-ch:
			return copy(b, rx), c.target6, nil
		}
	}
}

func (c *ChannelBind) Send(b []byte, ep conn.Endpoint) error {
	select {
	case <-c.closeSignal:
		return net.ErrClosed
	default:
		bc := make([]byte, len(b))
		copy(bc, b)
		if ep.(ChannelEndpoint) == c.target4 {
			*c.tx4 <- bc
		} else if ep.(ChannelEndpoint) == c.target6 {
			*c.tx6 <- bc
		} else {
			return os.ErrInvalid
		}
	}
	return nil
}

func (c *ChannelBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	i, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	return ChannelEndpoint(i), nil
}
