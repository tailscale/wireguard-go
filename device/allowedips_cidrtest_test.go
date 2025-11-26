/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"net/netip"
	"testing"
)

func TestMkIPInCIDRsTestFunc(t *testing.T) {
	a := netip.MustParseAddr
	p := netip.MustParsePrefix

	tests := []struct {
		name  string
		cidrs []netip.Prefix
		want  map[netip.Addr]bool
	}{
		{
			name:  "zero-cidrs",
			cidrs: nil,
			want: map[netip.Addr]bool{
				a("0.0.0.0"):         false,
				a("10.0.0.1"):        false,
				a("::1"):             false,
				a("255.255.255.255"): false,
			},
		},
		{
			name:  "one-cidr-v4",
			cidrs: []netip.Prefix{p("10.0.0.0/24")},
			want: map[netip.Addr]bool{
				a("10.0.0.0"):        true,
				a("10.0.0.1"):        true,
				a("10.0.0.255"):      true,
				a("::ffff:10.0.0.1"): false, // v6-mapped v4; no implicit Unmap
				a("10.0.1.0"):        false,
				a("10.0.1.1"):        false,
				a("192.168.0.1"):     false,
			},
		},
		{
			name:  "one-cidr-v6",
			cidrs: []netip.Prefix{p("2600:1700::/32")},
			want: map[netip.Addr]bool{
				a("2600:1700::1"):      true,
				a("2600:1700:ffff::1"): true,
				a("2600:1701::1"):      false,
				a("::1"):               false,
			},
		},
		{
			name:  "one-cidr-host-v4",
			cidrs: []netip.Prefix{p("10.1.2.3/32")},
			want: map[netip.Addr]bool{
				a("10.1.2.3"): true,
				a("10.1.2.4"): false,
				a("10.1.2.2"): false,
			},
		},
		{
			name: "two-cidrs-linear",
			cidrs: []netip.Prefix{
				p("10.0.0.0/24"),
				p("192.168.1.0/24"),
			},
			want: map[netip.Addr]bool{
				a("10.0.0.1"):      true,
				a("10.0.0.200"):    true,
				a("192.168.1.1"):   true,
				a("192.168.1.254"): true,
				a("10.0.1.1"):      false,
				a("192.168.2.1"):   false,
				a("172.16.0.1"):    false,
			},
		},
		{
			name: "three-cidrs-mixed-v4-v6",
			cidrs: []netip.Prefix{
				p("10.0.0.0/8"),
				p("172.16.0.0/12"),
				p("fd00::/8"),
			},
			want: map[netip.Addr]bool{
				a("10.0.0.1"):       true,
				a("10.255.255.255"): true,
				a("172.16.0.1"):     true,
				a("172.31.255.255"): true,
				a("172.32.0.0"):     false,
				a("192.168.0.1"):    false,
				a("fd00::1"):        true,
				a("fdff::1"):        true,
				a("fe00::1"):        false,
				a("::1"):            false,
			},
		},
		{
			name: "four-cidrs-linear",
			cidrs: []netip.Prefix{
				p("10.0.0.0/24"),
				p("10.0.1.0/24"),
				p("10.0.2.0/24"),
				p("10.0.3.0/24"),
			},
			want: map[netip.Addr]bool{
				a("10.0.0.1"):   true,
				a("10.0.1.1"):   true,
				a("10.0.2.1"):   true,
				a("10.0.3.1"):   true,
				a("10.0.4.1"):   false,
				a("10.0.0.0"):   true,
				a("10.0.3.255"): true,
			},
		},
		{
			name: "five-cidrs-trie",
			cidrs: []netip.Prefix{
				p("10.0.0.0/24"),
				p("10.0.1.0/24"),
				p("10.0.2.0/24"),
				p("10.0.3.0/24"),
				p("192.168.0.0/16"),
			},
			want: map[netip.Addr]bool{
				a("10.0.0.50"):     true,
				a("10.0.1.50"):     true,
				a("10.0.2.50"):     true,
				a("10.0.3.50"):     true,
				a("10.0.4.50"):     false,
				a("192.168.0.1"):   true,
				a("192.168.255.1"): true,
				a("192.169.0.1"):   false,
				a("172.16.0.1"):    false,
			},
		},
		{
			name: "six-cidrs-trie-v6",
			cidrs: []netip.Prefix{
				p("2001:db8:1::/48"),
				p("2001:db8:2::/48"),
				p("2001:db8:3::/48"),
				p("2001:db8:4::/48"),
				p("2001:db8:5::/48"),
				p("fd00::/8"),
			},
			want: map[netip.Addr]bool{
				a("2001:db8:1::1"): true,
				a("2001:db8:2::1"): true,
				a("2001:db8:3::1"): true,
				a("2001:db8:4::1"): true,
				a("2001:db8:5::1"): true,
				a("2001:db8:6::1"): false,
				a("fd00::1"):       true,
				a("fdff:ffff::1"):  true,
				a("fe00::1"):       false,
				a("::1"):           false,
			},
		},
		{
			name: "overlapping-cidrs-trie",
			cidrs: []netip.Prefix{
				p("10.0.0.0/8"),
				p("10.0.0.0/16"),
				p("10.0.0.0/24"),
				p("10.0.0.0/32"),
				p("10.0.0.1/32"),
			},
			want: map[netip.Addr]bool{
				a("10.0.0.0"):       true,
				a("10.0.0.1"):       true,
				a("10.0.0.2"):       true,
				a("10.0.1.0"):       true,
				a("10.1.0.0"):       true,
				a("10.255.255.255"): true,
				a("11.0.0.0"):       false,
			},
		},
		{
			name:  "default-route-v4",
			cidrs: []netip.Prefix{p("0.0.0.0/0")},
			want: map[netip.Addr]bool{
				a("0.0.0.0"):         true,
				a("1.2.3.4"):         true,
				a("255.255.255.255"): true,
			},
		},
		{
			name:  "default-route-v6",
			cidrs: []netip.Prefix{p("::/0")},
			want: map[netip.Addr]bool{
				a("::"):          true,
				a("::1"):         true,
				a("2001:db8::1"): true,
				a("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"): true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := mkIPInCIDRsTestFunc(tt.cidrs)
			for addr, want := range tt.want {
				if got := f(addr); got != want {
					t.Errorf("mkIPInCIDRsTestFunc(%v)(%v) = %v, want %v", tt.cidrs, addr, got, want)
				}
			}
		})
	}
}
