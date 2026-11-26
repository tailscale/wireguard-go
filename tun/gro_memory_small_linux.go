// SPDX-License-Identifier: MIT

//go:build ts_lowmem

package tun

// Keep the batch and flow limits unchanged, but avoid reserving a full
// batch for every possible flow at device creation. append grows these
// slices normally when a batch needs more entries. This trades allocations
// during the first busy batches for a smaller persistent idle working set.
const initialGROFlowCapacity = 1

// One virtio header and one packet. Coalesced fragments grow on demand.
const initialGROVectorCapacity = 2
