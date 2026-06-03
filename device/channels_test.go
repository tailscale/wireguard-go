/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import "testing"

func TestAutodrainingQueueFinalizerNeedTracksPoolAccounting(t *testing.T) {
	unbounded := func() *WaitPool { return NewWaitPool(0, func() any { return nil }) }
	bounded := func() *WaitPool { return NewWaitPool(1, func() any { return nil }) }

	device := &Device{}
	device.pool.messageBuffers = unbounded()
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
	device.pool.messageBuffers = bounded()
	if !device.needsInboundQueueFinalizer() {
		t.Fatal("bounded message buffer pool should need inbound queue finalizer")
	}
	if !device.needsOutboundQueueFinalizer() {
		t.Fatal("bounded message buffer pool should need outbound queue finalizer")
	}
}
