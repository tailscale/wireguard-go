/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"testing"

	"github.com/tailscale/wireguard-go/iobuf"
	"github.com/tailscale/wireguard-go/waitpool"
)

func TestAutodrainingQueueFinalizerNeedTracksPoolAccounting(t *testing.T) {
	unbounded := func() *waitpool.WaitPool { return waitpool.New(0, func() any { return nil }) }
	bounded := func() *waitpool.WaitPool { return waitpool.New(1, func() any { return nil }) }

	// Force the default raw pool unbounded for the bulk of the test.
	origPool := iobuf.DefaultRawPool
	iobuf.DefaultRawPool = iobuf.NewRawPool(0)
	t.Cleanup(func() { iobuf.DefaultRawPool = origPool })

	device := &Device{}
	device.pool.inboundElements = unbounded()
	device.pool.inboundElementsContainer = unbounded()
	device.pool.outboundElements = unbounded()
	device.pool.outboundElementsContainer = unbounded()

	if device.needsInboundQueueFinalizer() {
		t.Fatal("unbounded inbound pools should not need queue finalizer")
	}
	if device.needsOutboundQueueFinalizer() {
		t.Fatal("unbounded outbound pools should not need queue finalizer")
	}

	device.pool.inboundElementsContainer = bounded()
	if !device.needsInboundQueueFinalizer() {
		t.Fatal("bounded inbound pool should need queue finalizer")
	}
	if device.needsOutboundQueueFinalizer() {
		t.Fatal("bounded inbound pool should not affect outbound queue finalizer")
	}

	device.pool.inboundElementsContainer = unbounded()
	device.pool.outboundElementsContainer = bounded()
	if device.needsInboundQueueFinalizer() {
		t.Fatal("bounded outbound pool should not affect inbound queue finalizer")
	}
	if !device.needsOutboundQueueFinalizer() {
		t.Fatal("bounded outbound pool should need queue finalizer")
	}

	device.pool.outboundElementsContainer = unbounded()
	iobuf.DefaultRawPool = iobuf.NewRawPool(1)
	if !device.needsInboundQueueFinalizer() {
		t.Fatal("bounded raw buffer pool should need inbound queue finalizer")
	}
	if !device.needsOutboundQueueFinalizer() {
		t.Fatal("bounded raw buffer pool should need outbound queue finalizer")
	}
}
