/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package wgcfg

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"inet.af/netaddr"
)

type ParseError struct {
	why      string
	offender string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: ‘%s’", e.why, e.offender)
}

func validateEndpoints(s string) error {
	vals := strings.Split(s, ",")
	for _, val := range vals {
		_, _, err := parseEndpoint(val)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseEndpoint(s string) (host string, port uint16, err error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, &ParseError{"Missing port from endpoint", s}
	}
	host, portStr := s[:i], s[i+1:]
	if len(host) < 1 {
		return "", 0, &ParseError{"Invalid endpoint host", host}
	}
	port, err = parsePort(portStr)
	if err != nil {
		return "", 0, err
	}
	hostColon := strings.IndexByte(host, ':')
	if host[0] == '[' || host[len(host)-1] == ']' || hostColon > 0 {
		err := &ParseError{"Brackets must contain an IPv6 address", host}
		if len(host) > 3 && host[0] == '[' && host[len(host)-1] == ']' && hostColon > 0 {
			maybeV6 := net.ParseIP(host[1 : len(host)-1])
			if maybeV6 == nil || len(maybeV6) != net.IPv6len {
				return "", 0, err
			}
		} else {
			return "", 0, err
		}
		host = host[1 : len(host)-1]
	}
	return host, uint16(port), nil
}

func parseMTU(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 576 || m > 65535 {
		return 0, &ParseError{"Invalid MTU", s}
	}
	return uint16(m), nil
}

func parsePort(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{"Invalid port", s}
	}
	return uint16(m), nil
}

func parsePersistentKeepalive(s string) (uint16, error) {
	if s == "off" {
		return 0, nil
	}
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{"Invalid persistent keepalive", s}
	}
	return uint16(m), nil
}

func parseKeyHex(s string) (*Key, error) {
	k, err := hex.DecodeString(s)
	if err != nil {
		return nil, &ParseError{"Invalid key: " + err.Error(), s}
	}
	if len(k) != KeySize {
		return nil, &ParseError{"Keys must decode to exactly 32 bytes", s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func parseBytesOrStamp(s string) (uint64, error) {
	b, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, &ParseError{"Number must be a number between 0 and 2^64-1: " + err.Error(), s}
	}
	return b, nil
}

func splitList(s string) ([]string, error) {
	var out []string
	for _, split := range strings.Split(s, ",") {
		trim := strings.TrimSpace(split)
		if len(trim) == 0 {
			return nil, &ParseError{"Two commas in a row", s}
		}
		out = append(out, trim)
	}
	return out, nil
}

type parserState int

const (
	inInterfaceSection parserState = iota
	inPeerSection
	notInASection
)

func (c *Config) maybeAddPeer(p *Peer) {
	if p != nil {
		c.Peers = append(c.Peers, *p)
	}
}

func FromWgQuick(s string, name string) (*Config, error) {
	if !TunnelNameIsValid(name) {
		return nil, &ParseError{"Tunnel name is not valid", name}
	}
	lines := strings.Split(s, "\n")
	parserState := notInASection
	conf := Config{Name: name}
	sawPrivateKey := false
	var peer *Peer
	for _, line := range lines {
		pound := strings.IndexByte(line, '#')
		if pound >= 0 {
			line = line[:pound]
		}
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)
		if len(line) == 0 {
			continue
		}
		if lineLower == "[interface]" {
			conf.maybeAddPeer(peer)
			parserState = inInterfaceSection
			continue
		}
		if lineLower == "[peer]" {
			conf.maybeAddPeer(peer)
			peer = &Peer{}
			parserState = inPeerSection
			continue
		}
		if parserState == notInASection {
			return nil, &ParseError{"Line must occur in a section", line}
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 {
			return nil, &ParseError{"Invalid config key is missing an equals separator", line}
		}
		key, val := strings.TrimSpace(lineLower[:equals]), strings.TrimSpace(line[equals+1:])
		if len(val) == 0 {
			return nil, &ParseError{"Key must have a value", line}
		}
		if parserState == inInterfaceSection {
			switch key {
			case "privatekey":
				k, err := ParseKey(val)
				if err != nil {
					return nil, err
				}
				conf.PrivateKey = PrivateKey(*k)
				sawPrivateKey = true
			case "listenport":
				p, err := parsePort(val)
				if err != nil {
					return nil, err
				}
				conf.ListenPort = p
			case "mtu":
				m, err := parseMTU(val)
				if err != nil {
					return nil, err
				}
				conf.MTU = m
			case "address":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := netaddr.ParseIPPrefix(address)
					if err != nil {
						return nil, err
					}
					conf.Addresses = append(conf.Addresses, a)
				}
			case "dns":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := netaddr.ParseIP(address)
					if err != nil {
						return nil, &ParseError{"Invalid IP address", address}
					}
					conf.DNS = append(conf.DNS, a)
				}
			default:
				return nil, &ParseError{"Invalid key for [Interface] section", key}
			}
		} else if parserState == inPeerSection {
			switch key {
			case "publickey":
				k, err := ParseKey(val)
				if err != nil {
					return nil, err
				}
				peer.PublicKey = *k
			case "presharedkey":
				k, err := ParseKey(val)
				if err != nil {
					return nil, err
				}
				peer.PresharedKey = SymmetricKey(*k)
			case "allowedips":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := netaddr.ParseIPPrefix(address)
					if err != nil {
						return nil, err
					}
					peer.AllowedIPs = append(peer.AllowedIPs, a)
				}
			case "persistentkeepalive":
				p, err := parsePersistentKeepalive(val)
				if err != nil {
					return nil, err
				}
				peer.PersistentKeepalive = p
			case "endpoint":
				err := validateEndpoints(val)
				if err != nil {
					return nil, err
				}
				peer.Endpoints = val
			default:
				return nil, &ParseError{"Invalid key for [Peer] section", key}
			}
		}
	}
	conf.maybeAddPeer(peer)

	if !sawPrivateKey {
		return nil, &ParseError{"An interface must have a private key", "[none specified]"}
	}
	for _, p := range conf.Peers {
		if p.PublicKey.IsZero() {
			return nil, &ParseError{"All peers must have public keys", "[none specified]"}
		}
	}

	return &conf, nil
}

// FromUAPI generates a Config from r.
// r should be generated by calling device.IpcGetOperation;
// it is not compatible with other uapi streams.
func FromUAPI(r io.Reader) (*Config, error) {
	cfg := new(Config)
	var peer *Peer // current peer being operated on
	deviceConfig := true

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.Split(line, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("failed to parse line %q, found %d =-separated parts, want 2", line, len(parts))
		}
		key := parts[0]
		value := parts[1]

		if key == "public_key" {
			if deviceConfig {
				deviceConfig = false
			}
			// Load/create the peer we are now configuring.
			var err error
			peer, err = cfg.handlePublicKeyLine(value)
			if err != nil {
				return nil, err
			}
			continue
		}

		var err error
		if deviceConfig {
			err = cfg.handleDeviceLine(key, value)
		} else {
			err = cfg.handlePeerLine(peer, key, value)
		}
		if err != nil {
			return nil, err
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (cfg *Config) handleDeviceLine(key, value string) error {
	switch key {
	case "private_key":
		k, err := parseKeyHex(value)
		if err != nil {
			return err
		}
		// wireguard-go guarantees not to send zero value; private keys are already clamped.
		cfg.PrivateKey = PrivateKey(*k)
	case "listen_port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("failed to parse listen_port: %w", err)
		}
		cfg.ListenPort = uint16(port)
	case "fwmark":
		// ignore
	default:
		return fmt.Errorf("unexpected IpcGetOperation key: %v", key)
	}
	return nil
}

func (cfg *Config) handlePublicKeyLine(value string) (*Peer, error) {
	k, err := parseKeyHex(value)
	if err != nil {
		return nil, err
	}
	cfg.Peers = append(cfg.Peers, Peer{})
	peer := &cfg.Peers[len(cfg.Peers)-1]
	peer.PublicKey = *k
	return peer, nil
}

func (cfg *Config) handlePeerLine(peer *Peer, key, value string) error {
	switch key {
	case "preshared_key":
		k, err := parseKeyHex(value)
		if err != nil {
			return err
		}
		peer.PresharedKey = SymmetricKey(*k)
	case "endpoint":
		err := validateEndpoints(value)
		if err != nil {
			return err
		}
		peer.Endpoints = value
	case "persistent_keepalive_interval":
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return err
		}
		peer.PersistentKeepalive = uint16(n)
	case "allowed_ip":
		ipp, err := netaddr.ParseIPPrefix(value)
		if err != nil {
			return err
		}
		peer.AllowedIPs = append(peer.AllowedIPs, ipp)
	case "protocol_version":
		if value != "1" {
			return fmt.Errorf("invalid protocol version: %v", value)
		}
	case "last_handshake_time_sec", "last_handshake_time_nsec", "tx_bytes", "rx_bytes":
		// ignore
	default:
		return fmt.Errorf("unexpected IpcGetOperation key: %v", key)
	}
	return nil
}
