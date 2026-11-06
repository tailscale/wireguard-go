/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import (
	"crypto/cipher"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/replay"
	"golang.org/x/sys/cpu"
)

// keypair holds immutable key material and metadata. The send counter is shared
// by the send lane and control output. The replay filter belongs to the receive
// lane. Retirement must not overwrite key material pinned by in-flight calls.
type keypair struct {
	sendNonce               atomic.Uint64
	sendDisabled, retired   atomic.Bool
	_                       cpu.CacheLinePad // TX counter writes must not false-share RX replay state.
	send, receive           cipher.AEAD
	replayFilter            replay.Filter
	isInitiator             bool
	created                 time.Time
	localIndex, remoteIndex uint32
}

type keypairs struct{ current, previous, next *keypair }

func (k *keypairs) lookup(index uint32) *keypair {
	for _, kp := range [...]*keypair{k.current, k.previous, k.next} {
		if kp != nil && kp.localIndex == index {
			return kp
		}
	}
	return nil
}
func usable(k *keypair, now time.Time) bool {
	return k != nil && !now.Before(k.created) && !k.sendDisabled.Load() && k.sendNonce.Load() < RejectAfterMessages && now.Sub(k.created) < RejectAfterTime
}

// reserve allocates a counter range without crossing RejectAfterMessages,
// including with concurrent control output. It returns a shorter range if needed.
func (k *keypair) reserve(want int) (first uint64, n int) {
	for {
		first = k.sendNonce.Load()
		if k.sendDisabled.Load() || first >= RejectAfterMessages {
			return first, 0
		}
		n = want
		if available := uint64(RejectAfterMessages) - first; uint64(n) > available {
			n = int(available)
		}
		if k.sendNonce.CompareAndSwap(first, first+uint64(n)) {
			return first, n
		}
	}
}
