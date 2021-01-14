/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

// Package wgcfg has types and a parser for representing WireGuard config.
package wgcfg

import (
	"inet.af/netaddr"
)

// Config is a wireguard configuration.
type Config struct {
	Name       string
	PrivateKey PrivateKey
	Addresses  []netaddr.IPPrefix
	ListenPort uint16
	MTU        uint16
	DNS        []netaddr.IP
	Peers      []Peer
}

type Peer struct {
	PublicKey           Key
	PresharedKey        SymmetricKey
	AllowedIPs          []netaddr.IPPrefix
	Endpoints           string // comma-separated host/port pairs: "1.2.3.4:56,[::]:80"
	PersistentKeepalive uint16
}

// Copy makes a deep copy of Config.
// The result aliases no memory with the original.
func (cfg Config) Copy() Config {
	res := cfg
	if res.Addresses != nil {
		res.Addresses = append([]netaddr.IPPrefix{}, res.Addresses...)
	}
	if res.DNS != nil {
		res.DNS = append([]netaddr.IP{}, res.DNS...)
	}
	peers := make([]Peer, 0, len(res.Peers))
	for _, peer := range res.Peers {
		peers = append(peers, peer.Copy())
	}
	res.Peers = peers
	return res
}

// Copy makes a deep copy of Peer.
// The result aliases no memory with the original.
func (peer Peer) Copy() Peer {
	res := peer
	if res.AllowedIPs != nil {
		res.AllowedIPs = append([]netaddr.IPPrefix{}, res.AllowedIPs...)
	}
	return res
}
