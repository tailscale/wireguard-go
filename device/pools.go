/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
)

type WaitPool struct {
	pool  sync.Pool
	cond  sync.Cond
	lock  sync.Mutex
	count uint32 // Get calls not yet Put back
	max   uint32
}

func NewWaitPool(max uint32, new func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *WaitPool) Get() any {
	if p.max != 0 {
		p.lock.Lock()
		for p.count >= p.max {
			p.cond.Wait()
		}
		p.count++
		p.lock.Unlock()
	}
	return p.pool.Get()
}

func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	p.count--
	p.cond.Signal()
}

func (device *Device) PopulatePools() {
	device.pool.inboundElementsContainer = NewWaitPool(device.config.preallocatedBuffersPerPool, func() any {
		s := make([]*QueueInboundElement, 0, device.BatchSize())
		return &QueueInboundElementsContainer{elems: s}
	})
	device.pool.outboundElementsContainer = NewWaitPool(device.config.preallocatedBuffersPerPool, func() any {
		s := make([]*QueueOutboundElement, 0, device.BatchSize())
		return &QueueOutboundElementsContainer{elems: s}
	})
	device.pool.inboundElements = NewWaitPool(device.config.preallocatedBuffersPerPool, func() any {
		return new(QueueInboundElement)
	})
	device.pool.outboundElements = NewWaitPool(device.config.preallocatedBuffersPerPool, func() any {
		return new(QueueOutboundElement)
	})
	packetBufSize := singlePacketSlabSize
	if device.BatchSize() > 1 {
		packetBufSize = batchingSlabSize
	}
	device.pool.packetBufs = NewWaitPool(device.config.preallocatedBuffersPerPool, func() any {
		return newPacketBuf(packetBufSize, func(buf *packetBuf) {
			device.pool.packetBufs.Put(buf)
		})
	})
}

func (device *Device) GetInboundElementsContainer() *QueueInboundElementsContainer {
	c := device.pool.inboundElementsContainer.Get().(*QueueInboundElementsContainer)
	return c
}

func (device *Device) PutInboundElementsContainer(c *QueueInboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	device.pool.inboundElementsContainer.Put(c)
}

func (device *Device) GetOutboundElementsContainer() *QueueOutboundElementsContainer {
	c := device.pool.outboundElementsContainer.Get().(*QueueOutboundElementsContainer)
	return c
}

func (device *Device) PutOutboundElementsContainer(c *QueueOutboundElementsContainer) {
	for i := range c.elems {
		c.elems[i] = nil
	}
	c.elems = c.elems[:0]
	device.pool.outboundElementsContainer.Put(c)
}

func (device *Device) getPacketBuf() *packetBuf {
	b := device.pool.packetBufs.Get().(*packetBuf)
	b.incRef()
	return b
}

func (device *Device) GetInboundElement() *QueueInboundElement {
	return device.pool.inboundElements.Get().(*QueueInboundElement)
}

func (device *Device) PutInboundElement(elem *QueueInboundElement) {
	elem.buffer.decRef()
	elem.clearPointers()
	device.pool.inboundElements.Put(elem)
}

// GetOutboundElement returns a [*QueueOutboundElement] with all its fields
// set to their respective zero values.
func (device *Device) GetOutboundElement() *QueueOutboundElement {
	elem := device.pool.outboundElements.Get().(*QueueOutboundElement)
	elem.plaintextOffset = 0
	elem.nonce = 0
	// buffer, packet, keypair, and peer were cleared (if necessary) by [QueueOutboundElement.clearPointers].
	return elem
}

func (device *Device) PutOutboundElement(elem *QueueOutboundElement) {
	if elem.buffer != nil {
		elem.buffer.decRef()
	}
	elem.clearPointers()
	device.pool.outboundElements.Put(elem)
}
