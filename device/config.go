// SPDX-License-Identifier: MIT

package device

import (
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/ipc"
	"github.com/tailscale/wireguard-go/wgcfg"
	"inet.af/netaddr"
)

func (device *Device) Config() *wgcfg.Config {
	device.net.RLock()
	listenPort := device.net.port
	device.net.RUnlock()

	device.staticIdentity.RLock()
	privateKey := device.staticIdentity.privateKey
	device.staticIdentity.RUnlock()

	device.peers.RLock()
	keyMap := device.peers.keyMap
	device.peers.RUnlock()

	cfg := &wgcfg.Config{
		PrivateKey: wgcfg.PrivateKey(privateKey),
		ListenPort: listenPort,
	}
	for _, peer := range keyMap {
		peer.RLock()
		p := wgcfg.Peer{
			PublicKey:           wgcfg.Key(peer.handshake.remoteStatic),
			PresharedKey:        wgcfg.SymmetricKey(peer.handshake.presharedKey),
			PersistentKeepalive: uint16(atomic.LoadUint32(&peer.persistentKeepaliveInterval)),
		}
		if peer.endpoint != nil {
			p.Endpoints = peer.endpoint.Addrs()
		}
		for _, ipnet := range device.allowedips.EntriesForPeer(peer) {
			cidr, ok := netaddr.FromStdIPNet(&ipnet)
			if !ok {
				device.log.Error.Println("bad ipnet " + ipnet.String())
				continue
			}
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

	// Remove any current peers not in the new configuration.
	device.peers.RLock()
	oldPeers := make(map[NoisePublicKey]bool)
	for k := range device.peers.keyMap {
		oldPeers[k] = true
	}
	device.peers.RUnlock()
	for _, p := range cfg.Peers {
		delete(oldPeers, NoisePublicKey(p.PublicKey))
	}
	for k := range oldPeers {
		wk := wgcfg.Key(k)
		device.log.Debug.Printf("device.Reconfig: removing old peer %s", wk.ShortString())
		device.RemovePeer(k)
	}

	device.staticIdentity.Lock()
	curPrivKey := device.staticIdentity.privateKey
	device.staticIdentity.Unlock()

	if !curPrivKey.Equals(NoisePrivateKey(cfg.PrivateKey)) {
		device.log.Debug.Println("device.Reconfig: resetting private key")
		if err := device.SetPrivateKey(NoisePrivateKey(cfg.PrivateKey)); err != nil {
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
		peer := device.LookupPeer(NoisePublicKey(p.PublicKey))
		if peer == nil {
			device.log.Debug.Printf("device.Reconfig: new peer %s", p.PublicKey.ShortString())
			peer, err = device.NewPeer(NoisePublicKey(p.PublicKey))
			if err != nil {
				return err
			}
			if p.PersistentKeepalive != 0 && device.isUp.Get() {
				newKeepalivePeers[p.PublicKey] = peer
			}
		}

		if !p.PresharedKey.IsZero() {
			peer.handshake.mutex.Lock()
			peer.handshake.presharedKey = NoiseSymmetricKey(p.PresharedKey)
			peer.handshake.mutex.Unlock()

			device.log.Debug.Printf("device.Reconfig: setting preshared key for peer %s", p.PublicKey.ShortString())
		}

		peer.Lock()
		atomic.StoreUint32(&peer.persistentKeepaliveInterval, uint32(p.PersistentKeepalive))
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
		allowedIPsChanged := !cidrsEqual(peer.allowedIPs, p.AllowedIPs)
		if allowedIPsChanged {
			peer.allowedIPs = append([]netaddr.IPPrefix(nil), p.AllowedIPs...)
		}
		peer.Unlock()

		if allowedIPsChanged {
			// RemoveByPeer is currently (2020-07-24) very
			// expensive on large networks, so we avoid
			// calling it when possible.
			device.allowedips.RemoveByPeer(peer)
		}
		// DANGER: allowedIP is a value type. Its contents (the IP and
		// Mask) are overwritten on every iteration through the
		// loop. The loop owns its memory; don't retain references into it.
		for _, allowedIP := range p.AllowedIPs {
			ones := uint(allowedIP.Bits)
			ip := allowedIP.IP.IPAddr().IP
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
	// First see if they're equal in order, without allocating.
	exact := true
	for i := range x {
		if x[i] != y[i] {
			exact = false
			break
		}
	}
	if exact {
		return true
	}

	// Otherwise, see if they're the same, but out of order.
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

func cidrsEqual(x, y []netaddr.IPPrefix) bool {
	if len(x) != len(y) {
		return false
	}
	// First see if they're equal in order, without allocating.
	exact := true
	for i := range x {
		if x[i] != y[i] {
			exact = false
			break
		}
	}
	if exact {
		return true
	}

	// Otherwise, see if they're the same, but out of order.
	m := make(map[netaddr.IPPrefix]bool)
	for _, v := range x {
		m[v] = true
	}
	for _, v := range y {
		if !m[v] {
			return false
		}
	}
	return true
}

var ErrPortInUse = fmt.Errorf("wireguard: local port in use: %w", &IPCError{ipc.IpcErrorPortInUse})
