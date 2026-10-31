/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Artus KG. All Rights Reserved.
 */

package device

import (
	"encoding/hex"
	"fmt"
	"testing"
	"testing/synctest"
	"time"
)

func keepalivePoolOptions() []Option {
	// Tailscale's iOS pool and queue sizes, with batch size 1 from ChannelBind.
	return []Option{
		WithPreallocatedBuffersPerPool(64),
		WithQueueStagedSize(64),
		WithQueueOutboundSize(64),
		WithQueueInboundSize(64),
		WithQueueHandshakeSize(64),
	}
}

func waitKeepalive(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		f()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("keepalive blocked on bounded pool")
	}
}

// TestKeepaliveBoundedPool exercises UAPI configuration and real handshake,
// encryption, receive and timer workers over the in-memory ChannelBind. No
// application packets arrive to trigger staged-queue trimming while the
// unreachable peers are configured. Keepalives alone must not fill the pool.
func TestKeepaliveBoundedPool(t *testing.T) {
	for _, hybrid := range []bool{false, true} {
		t.Run(fmt.Sprintf("hybrid=%v", hybrid), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pair := genTestPair(t, false, hybrid, keepalivePoolOptions()...)
				dev := pair[0].dev
				// Allow the unfixed code to fail without hanging Close on staged
				// buffers. This cleanup runs before the device cleanups.
				t.Cleanup(func() {
					dev.peers.RLock()
					defer dev.peers.RUnlock()
					for _, p := range dev.peers.keyMap {
						p.FlushStagedPackets()
					}
				})
				for range 80 {
					key, err := newPrivateKey()
					if err != nil {
						t.Fatal(err)
					}
					pk := key.publicKey()
					cfg := uapiCfg(
						"public_key", hex.EncodeToString(pk[:]),
						// ChannelBind rejects this endpoint, so no handshake
						// can complete, without using real network sockets.
						"endpoint", "127.0.0.1:9",
						"persistent_keepalive_interval", "25",
					)
					waitKeepalive(t, func() {
						if err := dev.IpcSet(cfg); err != nil {
							t.Error(err)
						}
					})
				}
				synctest.Wait()

				peer := dev.LookupPeer(pair[1].dev.staticIdentity.publicKey)
				remote := pair[1].dev.LookupPeer(dev.staticIdentity.publicKey)
				// A handshake initiated only by a keepalive must be confirmed,
				// without an application packet being needed to finish it.
				for _, phase := range []string{"initial", "expired", "exhausted_nonce"} {
					old := peer.keypairs.Current()
					switch phase {
					case "expired":
						time.Sleep(RejectAfterTime + time.Second)
					case "exhausted_nonce":
						peer.ExpireCurrentKeypairs()
						// Honor the normal handshake rate limit.
						time.Sleep(RekeyTimeout + time.Second)
					}
					waitKeepalive(t, peer.SendKeepalive)
					synctest.Wait()
					if kp := peer.keypairs.Current(); kp == nil || kp == old {
						t.Fatalf("%s: keepalive did not establish a new session", phase)
					}
					if kp := remote.keypairs.Current(); kp == nil || kp.remoteIndex != peer.keypairs.Current().localIndex {
						t.Fatalf("%s: keepalive did not confirm the session at the responder", phase)
					}
					pair.Send(t, Ping, nil)
					pair.Send(t, Pong, nil)
				}
			})
		})
	}
}

// TestKeepalivePoolPressure covers each partial-allocation rollback and the
// retry of a keepalive when pool space becomes available. In particular, a
// timer callback must return rather than pinning the peer's stop operation.
func TestKeepalivePoolPressure(t *testing.T) {
	for _, which := range []string{"elements", "buffers", "containers"} {
		t.Run(which, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pair := genTestPair(t, false, false, keepalivePoolOptions()...)
				dev := pair[0].dev
				peer := dev.LookupPeer(pair[1].dev.staticIdentity.publicKey)
				remote := pair[1].dev.LookupPeer(dev.staticIdentity.publicKey)
				peer.SendKeepalive()
				synctest.Wait()
				if remote.keypairs.Current() == nil {
					t.Fatal("initial handshake was not confirmed")
				}
				pools := map[string]*WaitPool{
					"elements":   dev.pool.outboundElements,
					"buffers":    dev.pool.smallPacketBufs,
					"containers": dev.pool.outboundElementsContainer,
				}
				p := pools[which]
				var held []any
				fill := func() {
					for {
						v, ok := p.TryGet()
						if !ok {
							break
						}
						held = append(held, v)
					}
				}
				fill()
				release := func() {
					for _, v := range held {
						p.Put(v)
					}
					held = nil
				}
				t.Cleanup(release)
				counts := make(map[string]uint32)
				for name, p := range pools {
					p.lock.Lock()
					counts[name] = p.count
					p.lock.Unlock()
				}
				before := remote.rxBytes.Load()
				waitKeepalive(t, peer.SendKeepalive)
				// Exercise the actual retry timer under continued pressure.
				time.Sleep(3 * time.Second)
				synctest.Wait()
				for name, p := range pools {
					p.lock.Lock()
					got := p.count
					p.lock.Unlock()
					if got != counts[name] {
						t.Errorf("%s: pool count after failed allocation = %d, want %d", name, got, counts[name])
					}
				}
				release()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if remote.rxBytes.Load() == before {
					t.Fatal("keepalive was not retried after pool pressure subsided")
				}
				pair.Send(t, Ping, nil)
				pair.Send(t, Pong, nil)
				synctest.Wait()
				fill()
				waitKeepalive(t, peer.SendKeepalive)
				time.Sleep(time.Second)
				synctest.Wait()
				// Stop cancels the retry and must complete with the pool still
				// exhausted. Release held items only after Stop has returned.
				waitKeepalive(t, peer.Stop)
				release()
			})
		})
	}
}
