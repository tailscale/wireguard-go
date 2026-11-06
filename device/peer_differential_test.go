// SPDX-License-Identifier: MIT

package device

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	core "github.com/tailscale/wireguard-go/peer"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

// These tests run a device and a peer copy of each endpoint with the same
// identity. Entropy, receiver indices, and time are held equal. Sessions are
// derived independently. Complete datagrams are compared, including MAC1 and MAC2.
// Device transport uses actual TUN and packet workers. Handshakes use synchronous
// primitives, not timer-bearing send wrappers. This does not prove scheduling
// equivalence or replace independent security review.
//
// Do not use t.Parallel here. differentialEntropy temporarily replaces
// crypto/rand.Reader. Device workers are idle during these synchronous handshake
// calls, and no timer becomes due while Reader is replaced.
func TestPeerDeviceIdenticalWire(t *testing.T) {
	for _, duplex := range []bool{false, true} {
		for _, withPSK := range []bool{false, true} {
			for _, mtu := range []int{1280, 1420, 1500} {
				t.Run(fmt.Sprintf("transport=%t/psk=%t/mtu=%d", duplex, withPSK, mtu), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						// Exercise timestamp whitening at a nonzero subsecond offset.
						time.Sleep(123456789 * time.Nanosecond)
						var private [2]core.PrivateKey
						private[0][0], private[1][0] = 7, 9
						var psk core.PresharedKey
						if withPSK {
							psk = core.PresharedKey(sha256.Sum256([]byte("differential PSK")))
						}
						a, ai := newDifferentialEndpoint(t, private[0], private[1].Public(), psk, mtu, 2)
						b, bi := newDifferentialEndpoint(t, private[1], private[0].Public(), psk, mtu, 1)
						a.duplex, b.duplex = duplex, duplex
						for round := 0; round < 4; round++ {
							if round != 0 {
								time.Sleep(6 * time.Second)
							}
							if round%2 == 0 {
								differentialHandshake(t, a, b, ai, bi, round)
							} else {
								differentialHandshake(t, b, a, bi, ai, round)
							}
							for _, sender := range []*interopPair{a, b} {
								receiver := b
								if sender == b {
									receiver = a
								}
								// Include empty transport, both IP versions, block boundaries,
								// and lengths on either side of the configured MTU.
								var payloads [][]byte
								for _, size := range []int{0, 63, 64, 65, mtu - 1, mtu, mtu + 1, 2*mtu + 1} {
									if size == 0 {
										payloads = append(payloads, nil)
										continue
									}
									for _, v6 := range []bool{false, true} {
										payloads = append(payloads, interopIP(v6, sender == a, size, byte(round)))
									}
								}
								differentialTransport(t, sender, receiver, payloads)
							}
						}
					})
				})
			}
		}
	}
}

// An authenticated previous-key packet must refresh an aging initiator-current
// session, even though that packet did not use the current receive key.
func TestPeerDevicePreviousKeyReceiveRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var ka, kb core.PrivateKey
		ka[0], kb[0] = 7, 9
		a, ai := newDifferentialEndpoint(t, ka, kb.Public(), core.PresharedKey{}, 1420, 2)
		b, bi := newDifferentialEndpoint(t, kb, ka.Public(), core.PresharedKey{}, 1420, 1)
		start := time.Now()
		differentialHandshake(t, a, b, ai, bi, 0)
		ip := interopIP(false, false, 63, 1)
		held := b.fromDevice(ip)
		checkDifferentialWire(t, "held previous-key packet", b.seal(ip), held)
		time.Sleep(5 * time.Second)
		differentialHandshake(t, a, b, ai, bi, 1)
		if _, err := a.p.SetHandshakePolicy(time.Now(), core.HandshakePolicy{Rekey: true}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(start.Add(171 * time.Second).Sub(time.Now()))
		a.noWire()
		b.noWire()
		a.checkPlain(a.open(held), ip)
		if a.update.Handshake.Reasons&core.HandshakeRekey == 0 {
			t.Fatal("peer did not request current-key refresh")
		}
		outputs := []core.Packet{interopOutput()}
		ai.next = 200
		if n, err := a.p.HandleWake(time.Now(), outputs); err != nil || n.N != 1 {
			t.Fatalf("peer refresh: %d, %v", n.N, err)
		}
		if typ, _, err := core.ParseHeader(outputs[0].Bytes()); err != nil || typ != core.MessageInitiationType {
			t.Fatalf("peer refresh packet: type=%d, err=%v", typ, err)
		}
		a.inject(held)
		a.deliveredIP(ip)
		_ = a.wire(core.MessageInitiationType)
	})
}

type differentialIndices struct {
	next uint32
	live map[uint32]*core.Peer
}

func (a *differentialIndices) Allocate(p *core.Peer) (uint32, error) {
	if a.next == 0 || a.live[a.next] != nil {
		return 0, fmt.Errorf("unexpected differential index allocation: %d", a.next)
	}
	i := a.next
	a.next = 0
	a.live[i] = p
	return i, nil
}

func (a *differentialIndices) Release(i uint32, p *core.Peer) {
	if a.live[i] != p {
		panic("differential index released twice or by wrong owner")
	}
	delete(a.live, i)
}

func newDifferentialEndpoint(t *testing.T, private core.PrivateKey, remote core.PublicKey, psk core.PresharedKey, mtu, remoteIP int) (*interopPair, *differentialIndices) {
	t.Helper()
	identity, err := core.NewLocalIdentity(1, core.NewIdentity(private))
	if err != nil {
		t.Fatal(err)
	}
	alloc := &differentialIndices{live: make(map[uint32]*core.Peer)}
	h := &interopPair{t: t, tun: tuntest.NewChannelTUN(), bind: newInteropBind()}
	h.delivered = h.tun.Inbound
	h.admission, err = core.NewAdmission(identity)
	if err != nil {
		t.Fatal(err)
	}
	h.p, h.update, err = core.New(time.Now(), identity, alloc, remote, core.Config{PresharedKey: psk, PaddingMTU: mtu})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		h.p.Close()
		if len(alloc.live) != 0 {
			t.Error("peer leaked receiver indices")
		}
	})
	h.dev = NewDevice(h.tun.TUN(), h.bind, NewLogger(LogLevelError, "differential: "))
	t.Cleanup(h.dev.Close)
	if err := h.dev.IpcSet(uapiCfg(
		"private_key", hex.EncodeToString(private[:]),
		"public_key", hex.EncodeToString(remote[:]),
		"preshared_key", hex.EncodeToString(psk[:]),
		"allowed_ip", fmt.Sprintf("10.0.0.%d/32", remoteIP),
		"allowed_ip", fmt.Sprintf("fd00::%d/128", remoteIP),
		"endpoint", "127.0.0.1:1",
	)); err != nil {
		t.Fatal(err)
	}
	h.dp, _ = h.dev.LookupActivePeer(NoisePublicKey(remote))
	if err := h.dev.Up(); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
	h.dev.tun.mtu.Store(int32(mtu))
	return h, alloc
}

// differentialEntropy supplies the same ephemeral key and index regardless of
// which order the two implementations request them. It rejects other draws.
type differentialEntropy struct {
	ephemeral         [32]byte
	index             uint32
	keys, ids, nonces int
}

func (r *differentialEntropy) Read(p []byte) (int, error) {
	switch len(p) {
	case 32:
		copy(p, r.ephemeral[:])
		r.keys++
	case 4:
		binary.LittleEndian.PutUint32(p, r.index)
		r.ids++
	case 24:
		nonce := sha256.Sum256(r.ephemeral[:])
		copy(p, nonce[:])
		r.nonces++
	default:
		panic(fmt.Sprintf("unexpected differential entropy request: %d", len(p)))
	}
	return len(p), nil
}

func withDifferentialEntropy(t *testing.T, round, side int, device bool, f func()) {
	t.Helper()
	r := &differentialEntropy{
		ephemeral: sha256.Sum256(fmt.Appendf(nil, "ephemeral/%d/%d", round, side)),
		index:     uint32(100 + 2*round + side),
	}
	previous := rand.Reader
	rand.Reader = r
	defer func() { rand.Reader = previous }()
	f()
	wantIDs := 0
	if device {
		wantIDs = 1
	}
	if r.keys != 1 || r.ids != wantIDs {
		t.Fatalf("entropy draws: keys=%d indices=%d, want 1/%d", r.keys, r.ids, wantIDs)
	}
}

func differentialHandshake(t *testing.T, initiator, responder *interopPair, ia, ra *differentialIndices, round int) {
	t.Helper()
	ia.next, ra.next = uint32(100+2*round), uint32(101+2*round)
	var initiation core.Packet
	withDifferentialEntropy(t, round, 0, false, func() { initiation = initiator.initiate() })
	var im *MessageInitiation
	withDifferentialEntropy(t, round, 0, true, func() {
		var err error
		im, err = initiator.dev.CreateMessageInitiation(initiator.dp)
		if err != nil {
			t.Fatal(err)
		}
	})
	wire := make([]byte, MessageInitiationSize)
	if err := im.marshal(wire); err != nil {
		t.Fatal(err)
	}
	initiator.dp.cookieGenerator.AddMacs(wire)
	checkDifferentialWire(t, "initiation", initiation.Bytes(), wire)
	differentialCookie(t, initiator, responder, wire, round, 0)
	if responder.dev.ConsumeMessageInitiation(im, nil) != responder.dp {
		t.Fatal("device rejected identical initiation")
	}
	var response core.Packet
	withDifferentialEntropy(t, round, 1, false, func() {
		var err error
		response, err = responder.handle(wire)
		if err != nil {
			t.Fatal(err)
		}
	})
	var rm *MessageResponse
	withDifferentialEntropy(t, round, 1, true, func() {
		var err error
		rm, err = responder.dev.CreateMessageResponse(responder.dp)
		if err != nil {
			t.Fatal(err)
		}
	})
	wire = make([]byte, MessageResponseSize)
	if err := rm.marshal(wire); err != nil {
		t.Fatal(err)
	}
	responder.dp.cookieGenerator.AddMacs(wire)
	checkDifferentialWire(t, "response", response.Bytes(), wire)
	differentialCookie(t, responder, initiator, wire, round, 1)
	if err := responder.dp.BeginSymmetricSession(); err != nil {
		t.Fatal(err)
	}
	if initiator.dev.ConsumeMessageResponse(rm) != initiator.dp {
		t.Fatal("device rejected identical response")
	}
	if err := initiator.dp.BeginSymmetricSession(); err != nil {
		t.Fatal(err)
	}
	confirmation, err := initiator.handle(wire)
	if err != nil {
		t.Fatal(err)
	}
	initiator.dp.SendKeepalive()
	wire = initiator.wire(core.MessageTransportType)
	checkDifferentialWire(t, "confirmation", confirmation.Bytes(), wire)
	if r := responder.open(wire); r.Disposition != core.Keepalive || r.Err != nil {
		t.Fatalf("peer confirmation: %+v", r)
	}
	responder.inject(wire)
	responder.noDelivery()
	if !responder.p.HasSession(time.Now()) || responder.dp.keypairs.next.Load() != nil || responder.dp.keypairs.current == nil {
		t.Fatal("responder confirmation did not promote keys")
	}
	initiator.noWire()
	responder.noWire()
}

// Challenge both handshake types. Later rounds also compare MAC2 bytes using
// the previously learned cookie. Checker secrets remain live across rekeys.
func differentialCookie(t *testing.T, sender, receiver *interopPair, wire []byte, round, side int) {
	t.Helper()
	source := []byte("canonical-source-ip-and-port")
	if round > 0 {
		if !receiver.dev.cookieChecker.CheckMAC2(wire, source) {
			t.Fatal("device rejected MAC2 after cookie exchange")
		}
		if _, err := receiver.admission.Admit(time.Now(), wire, source, true, new(interopLimiter)); err != nil {
			t.Fatal("peer rejected MAC2 after cookie exchange:", err)
		}
	}
	var cookie core.Packet
	var reply *MessageCookieReply
	for _, device := range []bool{false, true} {
		func() {
			r := &differentialEntropy{ephemeral: sha256.Sum256(fmt.Appendf(nil, "cookie/%d/%d", round, side))}
			previous := rand.Reader
			rand.Reader = r
			defer func() { rand.Reader = previous }()
			var err error
			if device {
				reply, err = receiver.dev.cookieChecker.CreateReply(wire, binary.LittleEndian.Uint32(wire[4:]), source)
			} else {
				cookie, err = receiver.admission.Challenge(time.Now(), wire, source, interopOutput())
			}
			if err != nil {
				t.Fatal(err)
			}
			wantSecrets := 0
			if round == 0 {
				wantSecrets = 1
			}
			if r.keys != wantSecrets || r.nonces != 1 || r.ids != 0 {
				t.Fatalf("cookie entropy draws: %+v", r)
			}
		}()
	}
	encoded := make([]byte, MessageCookieReplySize)
	if err := reply.marshal(encoded); err != nil {
		t.Fatal(err)
	}
	checkDifferentialWire(t, "cookie reply", cookie.Bytes(), encoded)
	receiver.prefix(cookie)
	if _, err := sender.p.ConsumeCookie(time.Now(), encoded); err != nil {
		t.Fatal(err)
	}
	if !sender.dp.cookieGenerator.ConsumeReply(reply) {
		t.Fatal("device rejected identical cookie")
	}
}

func differentialTransport(t *testing.T, sender, receiver *interopPair, payloads [][]byte) {
	t.Helper()
	packets := make([]core.Packet, len(payloads))
	for i, ip := range payloads {
		packets[i] = core.Packet{Buffer: bytes.Repeat([]byte{0xa7}, len(ip)+128), Offset: interopPrefix + core.TransportHeaderSize, Size: len(ip)}
		copy(packets[i].Bytes(), ip)
	}
	if n, err := sender.send(time.Now(), packets); err != nil || n.N != len(packets) {
		t.Fatalf("peer vector send: %d, %v", n.N, err)
	}
	for i, ip := range payloads {
		if len(ip) == 0 {
			sender.dp.SendKeepalive()
		} else {
			sender.tun.Outbound <- ip
		}
		wire := sender.wire(core.MessageTransportType)
		checkDifferentialWire(t, fmt.Sprintf("transport[%d] size=%d", i, len(ip)), packets[i].Bytes(), wire)
		sender.prefix(packets[i])
		r := receiver.open(wire)
		if len(ip) == 0 {
			if r.Disposition != core.Keepalive || r.Err != nil {
				t.Fatalf("peer keepalive: %+v", r)
			}
		} else {
			receiver.checkPlain(r, ip)
		}
		receiver.inject(wire)
		if len(ip) == 0 {
			receiver.noDelivery()
		} else {
			receiver.deliveredIP(ip)
		}
	}
	sender.noWire()
}

func checkDifferentialWire(t *testing.T, stage string, peer, device []byte) {
	t.Helper()
	if !bytes.Equal(peer, device) {
		t.Fatalf("%s differs:\npeer:   %x\ndevice: %x", stage, peer, device)
	}
}
