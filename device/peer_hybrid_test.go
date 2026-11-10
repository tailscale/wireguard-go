// SPDX-License-Identifier: MIT

package device

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	core "github.com/tailscale/wireguard-go/peer"
)

func TestPeerHybridRetryInterop(t *testing.T) {
	for _, sender := range []string{"core-manual", "core-automatic", "device-automatic"} {
		t.Run(sender, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newInteropPairMode(t, core.PresharedKey{}, core.PresharedKey{}, true)
				var retry []byte
				if sender == "device-automatic" {
					if err := h.dp.SendHandshakeInitiation(false); err != nil {
						t.Fatal(err)
					}
					initial := h.wire(core.MessageInitiationType)
					if core.PacketIsRetry(initial) || PacketIsRetry(initial) {
						t.Fatal("initial packet marked retry")
					}
					time.Sleep(6 * time.Second)
					retry = h.wire(core.MessageInitiationType)
				} else {
					if sender == "core-automatic" {
						if _, err := h.p.SetHandshakePolicy(time.Now(), core.HandshakePolicy{Retry: true}); err != nil {
							t.Fatal(err)
						}
					}
					_ = h.initiate()
					time.Sleep(5 * time.Second)
					var packet core.Packet
					if sender == "core-automatic" {
						slots := []core.Packet{interopOutput()}
						if r, err := h.p.HandleWake(time.Now(), slots); err != nil || r.N != 1 {
							t.Fatal(r, err)
						}
						packet = slots[0]
					} else {
						var err error
						packet, h.update, err = h.p.RetryInitiation(time.Now(), interopOutput())
						if err != nil {
							t.Fatal(err)
						}
					}
					retry = bytes.Clone(packet.Bytes())
				}
				if len(retry) != MessageHybridInitiationSize || !core.PacketIsRetry(retry) || !PacketIsRetry(retry) {
					t.Fatal("hybrid retry framing")
				}
				var init MessageInitiation
				if err := init.unmarshal(retry); err != nil || !init.HasKEM || !init.IsRetry {
					t.Fatal("device initiation decoder", err)
				}
				roundTrip := make([]byte, len(retry))
				if err := init.marshal(roundTrip); err != nil || !bytes.Equal(roundTrip, retry) {
					t.Fatal("initiation wire mismatch", err)
				}
				var response []byte
				if sender == "device-automatic" {
					packet, err := h.handle(retry)
					if err != nil {
						t.Fatal(err)
					}
					response = bytes.Clone(packet.Bytes())
				} else {
					h.inject(retry)
					response = h.wire(core.MessageResponseType)
				}
				if len(response) != MessageHybridResponseSize || !core.PacketIsRetry(response) || !PacketIsRetry(response) {
					t.Fatal("response did not echo retry hint")
				}
				var resp MessageResponse
				if err := resp.unmarshal(response); err != nil || !resp.HasKEM || !resp.IsRetry {
					t.Fatal("device response decoder", err)
				}
				roundTrip = make([]byte, len(response))
				if err := resp.marshal(roundTrip); err != nil || !bytes.Equal(roundTrip, response) {
					t.Fatal("response wire mismatch", err)
				}
				if sender == "device-automatic" {
					h.inject(response)
					if r := h.open(h.wire(core.MessageTransportType)); r.Disposition != core.Keepalive {
						t.Fatal(r)
					}
				} else {
					confirmation, err := h.handle(response)
					if err != nil {
						t.Fatal(err)
					}
					h.inject(confirmation.Bytes())
					synctest.Wait()
				}
				if !h.p.HasHybridSession(time.Now()) || h.dp.keypairs.current == nil || !h.dp.keypairs.current.isHybrid {
					t.Fatal("hybrid session metadata")
				}
				ip := interopIP(true, true, 63, 1)
				h.inject(h.seal(ip))
				h.deliveredIP(ip)
				ip = interopIP(false, false, 63, 2)
				h.checkPlain(h.open(h.fromDevice(ip)), ip)
			})
		})
	}
}

func TestPeerHybridModeMismatchInterop(t *testing.T) {
	for _, coreHybrid := range []bool{false, true} {
		for _, coreInitiator := range []bool{false, true} {
			t.Run(fmt.Sprintf("coreHybrid=%t/coreInitiator=%t", coreHybrid, coreInitiator), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					h := newInteropPairMode(t, core.PresharedKey{}, core.PresharedKey{}, coreHybrid)
					h.dp.SetHybridHandshake(!coreHybrid)
					if coreInitiator {
						h.inject(h.initiate().Bytes())
						h.noWire()
					} else {
						if err := h.dp.SendHandshakeInitiation(false); err != nil {
							t.Fatal(err)
						}
						if _, err := h.handle(h.wire(core.MessageInitiationType)); !errors.Is(err, core.ErrHandshake) {
							t.Fatal("mode mismatch accepted", err)
						}
					}
					if h.p.HasSession(time.Now()) || h.dp.keypairs.current != nil || h.dp.keypairs.next.Load() != nil {
						t.Fatal("mode mismatch derived session")
					}
				})
			})
		}
	}
}
