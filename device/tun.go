/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync/atomic"

	"github.com/tailscale/wireguard-go/tun"
)

const DefaultMTU = 1420

func (device *Device) RoutineTUNEventReader() {
	setUp := false
	logDebug := device.log.Debug
	logInfo := device.log.Info
	logError := device.log.Error

	logDebug.Println("Routine: event worker - started")
	device.state.starting.Done()

	for event := range device.tun.device.Events() {
		if event&tun.EventMTUUpdate != 0 {
			mtu, err := device.tun.device.MTU()
			old := atomic.LoadInt32(&device.tun.mtu)
			if err != nil {
				logError.Println("Failed to load updated MTU of device:", err)
			} else if int(old) != mtu {
				if mtu+MessageTransportSize > MaxMessageSize {
					logInfo.Println("MTU updated:", mtu, "(too large)")
				} else {
					logInfo.Println("MTU updated:", mtu)
				}
				atomic.StoreInt32(&device.tun.mtu, int32(mtu))
			}
		}

		if event&tun.EventUp != 0 && !setUp {
			logInfo.Println("Interface set up")
			setUp = true
			err := device.Up()
			if err != nil {
				logError.Printf("failed to bring up device %v: %v", device, err)
			}
		}

		if event&tun.EventDown != 0 && setUp {
			logInfo.Println("Interface set down")
			setUp = false
			err := device.Down()
			if err != nil {
				logError.Printf("failed to bring down device %v: %v", device, err)
			}
		}
	}

	logDebug.Println("Routine: event worker - stopped")
	device.state.stopping.Done()
}
