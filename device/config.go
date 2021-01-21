// SPDX-License-Identifier: MIT

package device

import (
	"io"
	"sort"

	"github.com/tailscale/wireguard-go/wgcfg"
)

func (device *Device) Config() *wgcfg.Config {
	cfg, err := device.config()
	if err != nil {
		device.log.Error.Println("Config failed:", err.Error())
	}
	return cfg
}

func (device *Device) config() (*wgcfg.Config, error) {
	r, w := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		errc <- device.IpcGetOperation(w)
		w.Close()
	}()
	cfg, err := wgcfg.FromUAPI(r)
	if err != nil {
		return nil, err
	}
	if err := <-errc; err != nil {
		return nil, err
	}

	sort.Slice(cfg.Peers, func(i, j int) bool {
		return cfg.Peers[i].PublicKey.LessThan(&cfg.Peers[j].PublicKey)
	})
	return cfg, nil
}

// Reconfig replaces the existing device configuration with cfg.
func (device *Device) Reconfig(cfg *wgcfg.Config) (err error) {
	defer func() {
		if err != nil {
			device.log.Debug.Printf("device.Reconfig failed: %v", err)
		}
	}()

	prev, err := device.config()
	if err != nil {
		return err
	}

	r, w := io.Pipe()
	errc := make(chan error)
	go func() {
		errc <- device.IpcSetOperation(r)
	}()

	err = cfg.ToUAPI(w, prev)
	if err != nil {
		return err
	}
	w.Close()
	return <-errc
}
