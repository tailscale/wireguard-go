/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 *
 * This is based heavily on timers.c from the kernel implementation.
 */

package device

import (
	"sync"
	"time"
	_ "unsafe"
)

//go:linkname fastrandn runtime.fastrandn
func fastrandn(n uint32) uint32

// A Timer manages time-based aspects of the WireGuard protocol.
// Timer roughly copies the interface of the Linux kernel's struct timer_list.
type Timer struct {
	*time.Timer
	modifyingLock sync.RWMutex
	runningLock   sync.Mutex
	isPending     bool
}

func (peer *Peer) NewTimer(expirationFunction func(*Peer)) *Timer {
	timer := &Timer{}
	timer.Timer = time.AfterFunc(time.Hour, func() {
		timer.runningLock.Lock()
		defer timer.runningLock.Unlock()

		timer.modifyingLock.Lock()
		if !timer.isPending {
			timer.modifyingLock.Unlock()
			return
		}
		timer.isPending = false
		timer.modifyingLock.Unlock()

		expirationFunction(peer)
	})
	timer.Stop()
	return timer
}

func (timer *Timer) Mod(d time.Duration) {
	timer.modifyingLock.Lock()
	timer.isPending = true
	timer.Reset(d)
	timer.modifyingLock.Unlock()
}

func (timer *Timer) Del() {
	timer.modifyingLock.Lock()
	timer.isPending = false
	timer.Stop()
	timer.modifyingLock.Unlock()
}

func (timer *Timer) DelSync() {
	timer.Del()
	timer.runningLock.Lock()
	timer.Del()
	timer.runningLock.Unlock()
}

func (timer *Timer) IsPending() bool {
	timer.modifyingLock.RLock()
	defer timer.modifyingLock.RUnlock()
	return timer.isPending
}

func (peer *Peer) ifTimersActive(f func()) bool {
	active := false
	peer.ifRunning(func() {
		if peer.device != nil && peer.device.isUp() {
			active = true
			f()
		}
	})
	return active
}

func expiredRetransmitHandshake(peer *Peer) {
	if peer.timers.handshakeAttempts.Load() > MaxTimerHandshakes {
		peer.device.log.Verbosef("%s - Handshake did not complete after %d attempts, giving up", peer, MaxTimerHandshakes+2)

		peer.ifTimersActive(func() {
			peer.timers.sendKeepalive.Del()

			/* We drop all packets without a keypair and don't try again,
			 * if we try unsuccessfully for too long to make a handshake.
			 */
			peer.FlushStagedPackets()

			peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)

			peer.noteSessionHandshakeStopped()
		})
	} else {
		peer.timers.handshakeAttempts.Add(1)
		peer.device.log.Verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", peer, int(RekeyTimeout.Seconds()), peer.timers.handshakeAttempts.Load()+1)

		/* We clear the endpoint address src address, in case this is the cause of trouble. */
		peer.markEndpointSrcForClearing()

		peer.SendHandshakeInitiation(true)
	}
}

func expiredSendKeepalive(peer *Peer) {
	peer.SendKeepalive()
	if peer.timers.needAnotherKeepalive.Load() {
		peer.timers.needAnotherKeepalive.Store(false)
		peer.ifTimersActive(func() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		})
	}
}

func expiredNewHandshake(peer *Peer) {
	peer.device.log.Verbosef("%s - Retrying handshake because we stopped hearing back after %d seconds", peer, int((KeepaliveTimeout + RekeyTimeout).Seconds()))
	/* We clear the endpoint address src address, in case this is the cause of trouble. */
	peer.markEndpointSrcForClearing()
	peer.SendHandshakeInitiation(false)
}

func expiredZeroKeyMaterial(peer *Peer) {
	peer.device.log.Verbosef("%s - Removing all keys, since we haven't received a new one in %d seconds", peer, int((RejectAfterTime * 3).Seconds()))
	peer.ZeroAndFlushAll()
	if peer.deleteOnIdle {
		peer.device.log.Verbosef("%s - Removing idle lazy peer", peer)
		// Remove the peer from the device in a new goroutine as we're currently
		// holding timer locks which RemovePeer also needs. This is TOCTOU, but
		// acceptable since the worst case is we remove the peer and the lazy
		// peerfunc created it again after. We might lose some packets.
		go peer.device.RemovePeer(peer.handshake.remoteStatic)
	}
}

func expiredSession(peer *Peer) {
	peer.sessionState.Lock()
	defer peer.sessionState.Unlock()
	if peer.sessionState.sessionExpires.IsZero() || time.Now().Before(peer.sessionState.sessionExpires) {
		return
	}
	peer.device.log.Verbosef("%s - Session expired after %d seconds", peer, int(RejectAfterTime.Seconds()))
	peer.noteSessionStateLocked(PeerSessionExpired)
}

func expiredPersistentKeepalive(peer *Peer) {
	if peer.persistentKeepaliveInterval.Load() > 0 {
		peer.SendKeepalive()
	}
}

/* Should be called after an authenticated data packet is sent. */
func (peer *Peer) timersDataSent() {
	peer.ifTimersActive(func() {
		if !peer.timers.newHandshake.IsPending() {
			peer.timers.newHandshake.Mod(KeepaliveTimeout + RekeyTimeout + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
		}
	})
}

/* Should be called after an authenticated data packet is received. */
func (peer *Peer) timersDataReceived() {
	peer.ifTimersActive(func() {
		if !peer.timers.sendKeepalive.IsPending() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		} else {
			peer.timers.needAnotherKeepalive.Store(true)
		}
	})
}

/* Should be called after any type of authenticated packet is sent -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketSent() {
	peer.ifTimersActive(func() {
		peer.timers.sendKeepalive.Del()
	})
}

/* Should be called after any type of authenticated packet is received -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketReceived() {
	peer.ifTimersActive(func() {
		peer.timers.newHandshake.Del()
	})
}

/* Should be called after a handshake initiation message is sent. */
func (peer *Peer) timersHandshakeInitiated() {
	peer.ifTimersActive(func() {
		peer.timers.retransmitHandshake.Mod(RekeyTimeout + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
		peer.noteSessionHandshakeStarted()
	})
}

/* Should be called after a handshake response message is received and processed or when getting key confirmation via the first data message. */
func (peer *Peer) timersHandshakeComplete() {
	peer.ifTimersActive(func() {
		peer.timers.retransmitHandshake.Del()
		peer.timers.handshakeAttempts.Store(0)
		peer.timers.sentLastMinuteHandshake.Store(false)
		peer.lastHandshakeNano.Store(time.Now().UnixNano())
	})
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
func (peer *Peer) timersSessionDerived() {
	if active := peer.ifTimersActive(func() {
		peer.sessionState.Lock()
		peer.sessionState.sessionExpires = time.Now().Add(RejectAfterTime)
		peer.noteSessionStateLocked(PeerSessionEstablished)
		peer.sessionState.Unlock()
		peer.timers.sessionExpired.Mod(RejectAfterTime)
		peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
	}); !active {
		peer.noteSessionState(PeerSessionEstablished)
	}
}

/* Should be called before a packet with authentication -- keepalive, data, or handshake -- is sent, or after one is received. */
func (peer *Peer) timersAnyAuthenticatedPacketTraversal() {
	keepalive := peer.persistentKeepaliveInterval.Load()
	peer.ifTimersActive(func() {
		if keepalive > 0 {
			peer.timers.persistentKeepalive.Mod(time.Duration(keepalive) * time.Second)
		}
	})
}

func (peer *Peer) timersInit() {
	peer.timers.retransmitHandshake = peer.NewTimer(expiredRetransmitHandshake)
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)
	peer.timers.sessionExpired = peer.NewTimer(expiredSession)
	peer.timers.zeroKeyMaterial = peer.NewTimer(expiredZeroKeyMaterial)
	peer.timers.persistentKeepalive = peer.NewTimer(expiredPersistentKeepalive)
}

func (peer *Peer) timersStart() {
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.timers.needAnotherKeepalive.Store(false)
}

func (peer *Peer) timersStop() {
	peer.timers.retransmitHandshake.DelSync()
	peer.timers.sendKeepalive.DelSync()
	peer.timers.newHandshake.DelSync()
	peer.timers.sessionExpired.DelSync()
	peer.timers.zeroKeyMaterial.DelSync()
	peer.timers.persistentKeepalive.DelSync()
}
