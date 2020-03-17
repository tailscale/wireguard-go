// SPDX-License-Identifier: MIT

package device

import (
	"fmt"
	"sort"
	"time"

	"github.com/tailscale/wireguard-go/ipc"
	"github.com/tailscale/wireguard-go/wgcfg"
)

func (device *Device) Config() *wgcfg.Config {
	// Lock everything.
	device.net.Lock()
	device.net.Unlock()
	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()
	device.peers.Lock()
	defer device.peers.Unlock()

	cfg := &wgcfg.Config{
		PrivateKey: device.staticIdentity.privateKey,
		ListenPort: device.net.port,
	}
	for _, peer := range device.peers.keyMap {
		peer.RLock()
		p := wgcfg.Peer{
			PublicKey:           peer.handshake.remoteStatic,
			PresharedKey:        peer.handshake.presharedKey,
			PersistentKeepalive: peer.persistentKeepaliveInterval,
		}
		if peer.endpoint != nil {
			p.Endpoints = peer.endpoint.Addrs()
		}
		for _, ipnet := range device.allowedips.EntriesForPeer(peer) {
			ones, _ := ipnet.Mask.Size()
			cidr := wgcfg.CIDR{
				Mask: uint8(ones),
			}
			copy(cidr.IP.Addr[:], ipnet.IP.To16())
			p.AllowedIPs = append(p.AllowedIPs, cidr)
		}
		peer.RUnlock()

		cfg.Peers = append(cfg.Peers, p)
	}
	sort.Slice(cfg.Peers, func(i, j int) bool {
		return cfg.Peers[i].PublicKey.LessThan(&cfg.Peers[j].PublicKey)
	})

	return cfg
}

// Reconfig replaces the existing device configuration with cfg.
func (device *Device) Reconfig(cfg *wgcfg.Config) (err error) {
	defer func() {
		if err != nil {
			device.log.Debug.Printf("device.Reconfig: failed: %v", err)
			device.RemoveAllPeers()
		}
	}()

	// Remove any currentt peers not in the new configuration.
	device.peers.RLock()
	oldPeers := make(map[wgcfg.Key]bool)
	for k := range device.peers.keyMap {
		oldPeers[k] = true
	}
	device.peers.RUnlock()
	for _, p := range cfg.Peers {
		delete(oldPeers, p.PublicKey)
	}
	for k := range oldPeers {
		device.log.Debug.Printf("device.Reconfig: removing old peer %s", k.ShortString())
		device.RemovePeer(k)
	}

	device.staticIdentity.Lock()
	curPrivKey := device.staticIdentity.privateKey
	device.staticIdentity.Unlock()

	if !curPrivKey.Equal(cfg.PrivateKey) {
		device.log.Debug.Println("device.Reconfig: resetting private key")
		if err := device.SetPrivateKey(cfg.PrivateKey); err != nil {
			return err
		}
	}

	device.net.Lock()
	device.net.port = cfg.ListenPort
	device.net.Unlock()

	if err := device.BindUpdate(); err != nil {
		return ErrPortInUse
	}

	// TODO(crawshaw): UAPI supports an fwmark field

	newKeepalivePeers := make(map[wgcfg.Key]*Peer)
	for _, p := range cfg.Peers {
		peer := device.LookupPeer(p.PublicKey)
		if peer == nil {
			device.log.Debug.Printf("device.Reconfig: new peer %s", p.PublicKey.ShortString())
			peer, err = device.NewPeer(p.PublicKey)
			if err != nil {
				return err
			}
			if p.PersistentKeepalive != 0 && device.isUp.Get() {
				newKeepalivePeers[p.PublicKey] = peer
			}
		}

		if !p.PresharedKey.IsZero() {
			peer.handshake.mutex.Lock()
			peer.handshake.presharedKey = p.PresharedKey
			peer.handshake.mutex.Unlock()

			device.log.Debug.Printf("device.Reconfig: setting preshared key for peer %s", p.PublicKey.ShortString())
		}

		peer.Lock()
		peer.persistentKeepaliveInterval = p.PersistentKeepalive
		if len(p.Endpoints) > 0 && (peer.endpoint == nil || !endpointsEqual(p.Endpoints, peer.endpoint.Addrs())) {
			str := p.Endpoints[0].String()
			for _, cfgEp := range p.Endpoints[1:] {
				str += "," + cfgEp.String()
			}
			ep, err := device.createEndpoint(p.PublicKey, str)
			if err != nil {
				peer.Unlock()
				return err
			}
			peer.endpoint = ep

			// TODO(crawshaw): whether or not a new keepalive is necessary
			// on changing the endpoint depends on the semantics of the
			// CreateEndpoint func, which is not properly defined. Define it.
			if p.PersistentKeepalive != 0 && device.isUp.Get() {
				newKeepalivePeers[p.PublicKey] = peer

				// Make sure the new handshake will get fired.
				peer.handshake.mutex.Lock()
				peer.handshake.lastSentHandshake = time.Now().Add(-RekeyTimeout)
				peer.handshake.mutex.Unlock()
			}
		}
		peer.Unlock()

		device.allowedips.RemoveByPeer(peer)
		// DANGER: allowedIP is a value type. Its contents (the IP and
		// Mask) are overwritten on every iteration through the
		// loop. If you try to pass references into other things, the
		// content of those references will mutate in surprising ways.
		//
		// It's safe to use allowedIP.IP.IP(), because that function
		// makes a copy of the bytes. Be very careful when doing other
		// things to allowedIP.
		for _, allowedIP := range p.AllowedIPs {
			ones := uint(allowedIP.Mask)
			ip := allowedIP.IP.IP()
			if allowedIP.IP.Is4() {
				ip = ip.To4()
			}
			device.allowedips.Insert(ip, ones, peer)
		}
	}

	// Send immediate keepalive if we're turning it on and before it wasn't on.
	for k, peer := range newKeepalivePeers {
		device.log.Debug.Printf("device.Reconfig: sending keepalive to peer %s", k.ShortString())
		peer.SendKeepalive()
	}

	return nil
}

func endpointsEqual(x, y []wgcfg.Endpoint) bool {
	if len(x) != len(y) {
		return false
	}
	eps := make(map[wgcfg.Endpoint]bool)
	for _, ep := range x {
		eps[ep] = true
	}
	for _, ep := range y {
		if !eps[ep] {
			return false
		}
	}
	return true
}

var ErrPortInUse = fmt.Errorf("wireguard: local port in use: %w", &IPCError{ipc.IpcErrorPortInUse})
