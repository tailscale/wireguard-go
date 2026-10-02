// SPDX-License-Identifier: MIT

//go:build !ts_lowmem

package tun

import "github.com/tailscale/wireguard-go/conn"

const initialGROFlowCapacity = conn.IdealBatchSize
const initialGROVectorCapacity = conn.IdealBatchSize
