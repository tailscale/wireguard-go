// SPDX-License-Identifier: MIT

package device

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/conn/bindtest"
	core "github.com/tailscale/wireguard-go/peer"
	"github.com/tailscale/wireguard-go/peerindex"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

// interopBind makes the network ownership copy explicit. It implements the
// current slab API. All channel operations durably block in a synctest bubble.
// Tests drive every datagram, rather than silently pumping away loss/replay.
type interopBind struct {
	rx, tx chan []byte
	closed chan struct{}
}

func newInteropBind() *interopBind {
	return &interopBind{make(chan []byte, 256), make(chan []byte, 256), nil}
}
func (b *interopBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.closed = make(chan struct{})
	return []conn.ReceiveFunc{func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		select {
		case <-b.closed:
			return 0, net.ErrClosed
		case p := <-b.rx:
			if len(p) > len(slab) {
				return 0, fmt.Errorf("interop slab too small")
			}
			copy(slab, p)
			packets[0] = conn.ReceivedPacket{Size: len(p), Endpoint: bindtest.ChannelEndpoint(1)}
			return 1, nil
		}
	}}, 1, nil
}
func (b *interopBind) Close() error {
	if b.closed != nil {
		select {
		case <-b.closed:
		default:
			close(b.closed)
		}
	}
	return nil
}
func (*interopBind) SetMark(uint32) error { return nil }
func (*interopBind) BatchSize() int       { return 1 }
func (*interopBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return bindtest.ChannelEndpoint(1), nil
}
func (b *interopBind) Send(bufs [][]byte, _ conn.Endpoint, offset int) error {
	for _, p := range bufs {
		select {
		case <-b.closed:
			return net.ErrClosed
		case b.tx <- bytes.Clone(p[offset:]):
		}
	}
	return nil
}

type interopPair struct {
	t         testing.TB
	dev       *Device
	dp        *Peer
	tun       *tuntest.ChannelTUN
	delivered chan []byte
	bind      *interopBind
	p         *core.Peer
	duplex    bool // Exercise the concurrent transport surface with owner reconciliation.
	update    core.Update
	admission *core.Admission
	indexes   *peerindex.Table[*core.Peer]
}

func newInteropPair(t testing.TB, psk, devicePSK core.PresharedKey) *interopPair {
	t.Helper()
	var ck core.PrivateKey
	ck[0] = 7
	var dk NoisePrivateKey
	dk[0] = 9
	dk.clamp()
	id := core.NewIdentity(ck)
	generation, err := core.NewLocalIdentity(1, id)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := core.NewAdmission(generation)
	if err != nil {
		t.Fatal(err)
	}
	h := &interopPair{t: t, tun: tuntest.NewChannelTUN(), bind: newInteropBind(), delivered: make(chan []byte, 256), indexes: new(peerindex.Table[*core.Peer]), admission: admission}
	h.dev = NewDevice(h.tun.TUN(), h.bind, NewLogger(LogLevelError, "interop: "))
	t.Cleanup(h.dev.Close)
	public := id.Public()
	if err := h.dev.IpcSet(uapiCfg("private_key", hex.EncodeToString(dk[:]), "public_key", hex.EncodeToString(public[:]), "preshared_key", hex.EncodeToString(devicePSK[:]), "allowed_ip", "10.0.0.1/32", "allowed_ip", "fd00::1/128", "endpoint", "127.0.0.1:1")); err != nil {
		t.Fatal(err)
	}
	h.dp, _ = h.dev.LookupActivePeer(NoisePublicKey(public))
	h.p, h.update, err = core.New(time.Now(), generation, h.indexes, core.PublicKey(dk.publicKey()), core.Config{PresharedKey: psk, PaddingMTU: 1420})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		h.p.Close()
		if h.indexes.Len() != 0 {
			t.Error("core indices leaked")
		}
	})
	if err = h.dev.Up(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-done:
				return
			case p := <-h.tun.Inbound:
				select {
				case h.delivered <- p:
				case <-done:
					return
				}
			}
		}
	}()
	return h
}

const interopPrefix = 24 // caller's Geneve/outer header, never interpreted by Peer
func interopOutput() core.Packet {
	return core.Packet{Buffer: bytes.Repeat([]byte{0xa7}, 2048), Offset: interopPrefix}
}
func (h *interopPair) prefix(p core.Packet) {
	h.t.Helper()
	if !bytes.Equal(p.Buffer[:interopPrefix], bytes.Repeat([]byte{0xa7}, interopPrefix)) {
		h.t.Fatal("outer/Geneve prefix changed")
	}
}
func (h *interopPair) inject(wire []byte) { h.bind.rx <- bytes.Clone(wire) }
func (h *interopPair) wire(typ uint32) []byte {
	h.t.Helper()
	synctest.Wait()
	select {
	case b := <-h.bind.tx:
		got, _, err := core.ParseHeader(b)
		if err != nil || got != typ {
			h.t.Fatalf("wire type %d, want %d: %v", got, typ, err)
		}
		return b
	default:
		h.t.Fatalf("missing device wire type %d", typ)
		return nil
	}
}
func (h *interopPair) noWire() {
	h.t.Helper()
	synctest.Wait()
	select {
	case p := <-h.bind.tx:
		h.t.Fatalf("unexpected wire %x", p)
	default:
	}
}
func (h *interopPair) noDelivery() {
	h.t.Helper()
	synctest.Wait()
	select {
	case p := <-h.delivered:
		h.t.Fatalf("unexpected TUN packet %x", p)
	default:
	}
}
func (h *interopPair) deliveredIP(want []byte) {
	h.t.Helper()
	synctest.Wait()
	select {
	case got := <-h.delivered:
		if !bytes.Equal(got, want) {
			h.t.Fatalf("TUN payload mismatch: %x != %x", got, want)
		}
	default:
		h.t.Fatal("missing TUN payload")
	}
}
func (h *interopPair) handle(wire []byte) (core.Packet, error) {
	v, err := h.admission.Admit(time.Now(), wire, nil, false, nil)
	if err != nil {
		return core.Packet{}, err
	}
	var out core.Packet
	typ, _, _ := core.ParseHeader(wire)
	if typ == core.MessageInitiationType {
		prepared, e := core.PrepareInitiation(v)
		if e != nil {
			return core.Packet{}, e
		}
		out, h.update, err = h.p.HandleInitiation(time.Now(), prepared, interopOutput())
	} else {
		out, h.update, err = h.p.HandleResponse(time.Now(), v, interopOutput())
	}
	if err == nil {
		h.prefix(out)
	}
	return out, err
}
func (h *interopPair) initiate() core.Packet {
	h.t.Helper()
	p, update, err := h.p.Initiate(time.Now(), interopOutput())
	h.update = update
	if err != nil {
		h.t.Fatal(err)
	}
	h.prefix(p)
	return p
}
func (h *interopPair) establish(coreInitiator bool) {
	h.t.Helper()
	if coreInitiator {
		init := h.initiate()
		h.inject(init.Bytes())
		confirm, err := h.handle(h.wire(core.MessageResponseType))
		if err != nil {
			h.t.Fatal(err)
		}
		if h.dp.keypairs.next.Load() == nil {
			h.t.Fatal("device responder did not retain next")
		}
		h.inject(confirm.Bytes())
		synctest.Wait()
		if h.dp.keypairs.next.Load() != nil || h.dp.keypairs.current == nil {
			h.t.Fatal("device next not confirmed")
		}
	} else {
		if err := h.dp.SendHandshakeInitiation(false); err != nil {
			h.t.Fatal(err)
		}
		before := h.p.LastHandshake()
		response, err := h.handle(h.wire(core.MessageInitiationType))
		if err != nil {
			h.t.Fatal(err)
		}
		if !h.p.LastHandshake().Equal(before) {
			h.t.Fatal("core responder completed before confirmation")
		}
		h.inject(response.Bytes())
		result := h.open(h.wire(core.MessageTransportType))
		if result.Disposition != core.Keepalive {
			h.t.Fatalf("confirmation: %+v", result)
		}
	}
	if !h.p.HasSession(time.Now()) || h.p.LastHandshake().IsZero() {
		h.t.Fatal("core session not established")
	}
	h.noDelivery()
	h.noWire()
}

// IPv4/IPv6 packets have deliberately non-block-aligned lengths. Device must
// trim WireGuard padding. Core callers must validate and trim it themselves.
func interopIP(v6, fromCore bool, size int, seq byte) []byte {
	p := make([]byte, size)
	src, dst := byte(1), byte(2)
	if !fromCore {
		src, dst = dst, src
	}
	if v6 {
		p[0] = 0x60
		binary.BigEndian.PutUint16(p[4:], uint16(size-40))
		p[6] = 59
		p[7] = 64
		p[8] = 0xfd
		p[23] = src
		p[24] = 0xfd
		p[39] = dst
	} else {
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:], uint16(size))
		p[8] = 64
		p[9] = 253
		copy(p[12:], []byte{10, 0, 0, src})
		copy(p[16:], []byte{10, 0, 0, dst})
	}
	p[len(p)-1] = seq
	return p
}
func (h *interopPair) send(now time.Time, packets []core.Packet) (core.BatchResult, error) {
	if !h.duplex {
		return h.p.Send(now, packets)
	}
	r, err := h.p.Transport().Send(now, packets)
	u := h.update
	if r.Activity.Valid() {
		var applyErr error
		u, applyErr = h.p.ApplyTransport(now, r.Activity)
		if applyErr != nil {
			h.t.Fatal("apply TX", applyErr)
		}
	}
	return core.BatchResult{N: r.N, Update: u}, err
}
func (h *interopPair) receive(now time.Time, packets []core.Packet, results []core.ReceiveResult) (core.BatchResult, error) {
	if !h.duplex {
		return h.p.Receive(now, packets, results)
	}
	r, err := h.p.Transport().Receive(now, packets, results)
	u := h.update
	if r.Activity.Valid() {
		var applyErr error
		u, applyErr = h.p.ApplyTransport(now, r.Activity)
		if applyErr != nil {
			h.t.Fatal("apply RX", applyErr)
		}
	}
	return core.BatchResult{N: r.N, Update: u}, err
}
func (h *interopPair) seal(ip []byte) []byte {
	h.t.Helper()
	out := interopOutput()
	out.Offset += core.TransportHeaderSize
	out.Size = len(ip)
	copy(out.Bytes(), ip)
	vec := []core.Packet{out}
	n, err := h.send(time.Now(), vec)
	h.update = n.Update
	if n.N != 1 || err != nil {
		h.t.Fatalf("send %d: %v", n.N, err)
	}
	h.prefix(vec[0])
	return bytes.Clone(vec[0].Bytes())
}
func (h *interopPair) open(wire []byte) core.ReceiveResult {
	h.t.Helper()
	p := interopOutput()
	if len(wire) > len(p.Buffer)-p.Offset {
		p.Buffer = bytes.Repeat([]byte{0xa7}, p.Offset+len(wire))
	}
	p.Size = len(wire)
	copy(p.Bytes(), wire)
	var result [1]core.ReceiveResult
	n, err := h.receive(time.Now(), []core.Packet{p}, result[:])
	h.update = n.Update
	if n.N != 1 || err != nil {
		h.t.Fatalf("receive %d: %v", n.N, err)
	}
	h.prefix(p)
	return result[0]
}
func (h *interopPair) fromDevice(ip []byte) []byte {
	h.tun.Outbound <- ip
	return h.wire(core.MessageTransportType)
}
func (h *interopPair) checkPlain(r core.ReceiveResult, ip []byte) {
	h.t.Helper()
	if r.Disposition != core.Data || r.Err != nil || len(r.Packet.Bytes()) < len(ip) || !bytes.Equal(r.Packet.Bytes()[:len(ip)], ip) {
		h.t.Fatalf("core plaintext: %+v", r)
	}
	if !bytes.Equal(r.Packet.Bytes()[len(ip):], make([]byte, r.Packet.Size-len(ip))) {
		h.t.Fatal("nonzero padding")
	}
}

func TestPeerInteropBothRoles(t *testing.T)          { testPeerInteropBothRoles(t, false) }
func TestPeerInteropTransportBothRoles(t *testing.T) { testPeerInteropBothRoles(t, true) }
func testPeerInteropBothRoles(t *testing.T, duplex bool) {
	for _, initiator := range []bool{true, false} {
		for _, pskEnabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("coreInitiator=%t/psk=%t", initiator, pskEnabled), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					var psk core.PresharedKey
					if pskEnabled {
						psk[0] = 0x42
					}
					h := newInteropPair(t, psk, psk)
					h.duplex = duplex
					h.establish(initiator)
					for _, v6 := range []bool{false, true} {
						for _, size := range []int{63, 1420} {
							ip := interopIP(v6, true, size, 7)
							wire := h.seal(ip)
							h.inject(wire)
							h.deliveredIP(ip)
							h.inject(wire)
							h.noDelivery() // preserved ciphertext, not already decrypted input
							ip = interopIP(v6, false, size, 8)
							wire = h.fromDevice(ip)
							h.checkPlain(h.open(wire), ip)
							r := h.open(wire)
							if !errors.Is(r.Err, core.ErrReplay) || r.Packet.Buffer != nil {
								t.Fatalf("replay %+v", r)
							}
						}
					}
					h.inject(h.seal(nil))
					h.noDelivery()
					h.dp.SendKeepalive()
					if r := h.open(h.wire(core.MessageTransportType)); r.Disposition != core.Keepalive {
						t.Fatalf("keepalive %+v", r)
					}
					// A forged high counter must not advance replay state. A valid lower counter follows.
					ip := interopIP(false, false, 63, 9)
					valid := h.fromDevice(ip)
					bad := bytes.Clone(valid)
					binary.LittleEndian.PutUint64(bad[8:], 1<<50)
					if r := h.open(bad); r.Disposition != core.Dropped || r.Packet.Buffer != nil {
						t.Fatal("forgery accepted")
					}
					h.checkPlain(h.open(valid), ip)
					ip = interopIP(false, true, 63, 10)
					valid = h.seal(ip)
					bad = bytes.Clone(valid)
					bad[len(bad)-1] ^= 1
					h.inject(bad)
					h.noDelivery()
					h.inject(valid)
					h.deliveredIP(ip)
					// Malformed framing in each direction, including reserved bytes and truncation.
					for _, n := range []int{0, 1, 15, 31} {
						h.inject(valid[:n])
						h.noDelivery()
						if r := h.open(valid[:n]); r.Disposition != core.Dropped {
							t.Fatal("short accepted")
						}
					}
					bad = bytes.Clone(valid)
					bad[1] = 1
					h.inject(bad)
					h.noDelivery()
					if r := h.open(bad); r.Disposition != core.Dropped {
						t.Fatal("reserved byte accepted")
					}
					// AllowedIPs remains a device/adapter responsibility, not a peer feature.
					ip = interopIP(false, true, 63, 11)
					ip[15] = 99
					h.inject(h.seal(ip))
					h.noDelivery()
				})
			})
		}
	}
}

func TestPeerInteropPSKFailureAndRotation(t *testing.T) {
	for _, initiator := range []bool{true, false} {
		t.Run(fmt.Sprint(initiator), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var a, b core.PresharedKey
				a[0] = 1
				b[0] = 2
				h := newInteropPair(t, a, b)
				if initiator {
					init := h.initiate()
					h.inject(init.Bytes())
					if _, err := h.handle(h.wire(core.MessageResponseType)); !errors.Is(err, core.ErrHandshake) {
						t.Fatalf("mismatch: %v", err)
					}
				} else {
					if err := h.dp.SendHandshakeInitiation(false); err != nil {
						t.Fatal(err)
					}
					resp, err := h.handle(h.wire(core.MessageInitiationType))
					if err != nil {
						t.Fatal(err)
					}
					h.inject(resp.Bytes())
					h.noWire()
				}
				if h.p.HasSession(time.Now()) {
					t.Fatal("mismatched PSK established")
				}
				h.noDelivery()
				if _, err := h.p.SetPresharedKey(time.Now(), b); err != nil {
					t.Fatal(err)
				}
				time.Sleep(6 * time.Second)
				if !initiator {
					_ = h.wire(core.MessageInitiationType)
				} // discard the mismatched attempt's retry
				h.establish(true)
				// Changing only one PSK does not revoke the already established session.
				if _, err := h.p.SetPresharedKey(time.Now(), a); err != nil {
					t.Fatal(err)
				}
				ip := interopIP(true, true, 63, 33)
				h.inject(h.seal(ip))
				h.deliveredIP(ip)
				h.dp.handshake.mutex.Lock()
				h.dp.handshake.presharedKey = NoisePresharedKey(a)
				h.dp.handshake.mutex.Unlock()
				time.Sleep(6 * time.Second)
				h.establish(false)
				ip = interopIP(true, false, 63, 34)
				h.checkPlain(h.open(h.fromDevice(ip)), ip)
			})
		})
	}
}

func TestPeerInteropRepeatedRekeys(t *testing.T) {
	for _, initiator := range []bool{true, false} {
		t.Run(fmt.Sprint(initiator), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h := newInteropPair(t, core.PresharedKey{}, core.PresharedKey{})
				h.establish(initiator)
				var retiredToDevice, retiredToCore []byte
				for round := 0; round < 4; round++ {
					ipC := interopIP(true, true, 63, byte(round))
					oldToDevice := h.seal(ipC)
					ipD := interopIP(false, false, 63, byte(round))
					oldToCore := h.fromDevice(ipD)
					// Distinct, still-unreceived ciphertext will outlive the next rekey.
					delayedToDevice := h.seal(ipC)
					delayedToCore := h.fromDevice(ipD)
					time.Sleep(6 * time.Second)
					if initiator {
						init := h.initiate()
						h.inject(init.Bytes())
						conf, err := h.handle(h.wire(core.MessageResponseType))
						if err != nil {
							t.Fatal(err)
						}
						// Before confirmation, the responder must still send with current, not next.
						if h.dp.keypairs.next.Load() == nil || h.dp.keypairs.current == nil {
							t.Fatal("missing current/next")
						}
						h.checkPlain(h.open(h.fromDevice(ipD)), ipD)
						h.inject(conf.Bytes())
						synctest.Wait()
					} else {
						if err := h.dp.SendHandshakeInitiation(false); err != nil {
							t.Fatal(err)
						}
						before := h.p.LastHandshake()
						resp, err := h.handle(h.wire(core.MessageInitiationType))
						if err != nil {
							t.Fatal(err)
						}
						h.inject(h.seal(ipC))
						h.deliveredIP(ipC) // core next is not yet send-current
						h.inject(resp.Bytes())
						confirmation := h.wire(core.MessageTransportType)
						if !h.p.LastHandshake().Equal(before) {
							t.Fatal("unconfirmed handshake completed")
						}
						if r := h.open(confirmation); r.Disposition != core.Keepalive {
							t.Fatalf("confirmation %+v", r)
						}
					}
					// Both directions keep the previous key, and its independent replay window.
					h.inject(oldToDevice)
					h.deliveredIP(ipC)
					h.checkPlain(h.open(oldToCore), ipD)
					h.inject(oldToDevice)
					h.noDelivery()
					if r := h.open(oldToCore); !errors.Is(r.Err, core.ErrReplay) {
						t.Fatalf("old replay %+v", r)
					}
					if round > 0 {
						if e := h.dev.indexTable.Lookup(binary.LittleEndian.Uint32(retiredToDevice[4:])); e.keypair != nil {
							t.Fatal("retired device index retained")
						}
						h.inject(retiredToDevice)
						h.noDelivery()
						if r := h.open(retiredToCore); !errors.Is(r.Err, core.ErrTransport) {
							t.Fatalf("retired key %+v", r)
						}
					}
					// Hold unreceived ciphertext from this previous generation until it retires.
					retiredToDevice = delayedToDevice
					retiredToCore = delayedToCore
					h.inject(h.seal(ipC))
					h.deliveredIP(ipC)
					h.checkPlain(h.open(h.fromDevice(ipD)), ipD)
				}
			})
		})
	}
}

type interopLimiter struct{ calls int }

func (l *interopLimiter) Allow(time.Time, []byte) bool { l.calls++; return true }
func TestPeerInteropCookies(t *testing.T) {
	t.Run("device-challenges-core", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newInteropPair(t, core.PresharedKey{}, core.PresharedKey{})
			h.dev.rate.underLoadUntil.Store(time.Now().Add(time.Minute).UnixNano())
			init := h.initiate()
			h.inject(init.Bytes())
			cookie := h.wire(core.MessageCookieReplyType)
			if h.dp.keypairs.next.Load() != nil {
				t.Fatal("session before cookie admission")
			}
			bad := bytes.Clone(cookie)
			bad[len(bad)-1] ^= 1
			if _, err := h.p.ConsumeCookie(time.Now(), bad); !errors.Is(err, core.ErrCookie) {
				t.Fatal(err)
			}
			if _, err := h.p.ConsumeCookie(time.Now(), cookie); err != nil {
				t.Fatal(err)
			}
			if _, _, err := h.p.Initiate(time.Now(), interopOutput()); !errors.Is(err, core.ErrRateLimited) {
				t.Fatal("cookie bypassed guard", err)
			}
			time.Sleep(5 * time.Second)
			h.establish(true)
		})
	})
	t.Run("core-challenges-device", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newInteropPair(t, core.PresharedKey{}, core.PresharedKey{})
			source := []byte("canonical-ip-and-port")
			limiter := new(interopLimiter)
			if err := h.dp.SendHandshakeInitiation(false); err != nil {
				t.Fatal(err)
			}
			init := h.wire(core.MessageInitiationType)
			if _, err := h.admission.Admit(time.Now(), init, source, true, limiter); !errors.Is(err, core.ErrCookieRequired) {
				t.Fatal(err)
			}
			if limiter.calls != 0 {
				t.Fatal("limiter before cookie")
			}
			cookie, err := h.admission.Challenge(time.Now(), init, source, interopOutput())
			if err != nil {
				t.Fatal(err)
			}
			h.prefix(cookie)
			h.inject(cookie.Bytes())
			synctest.Wait()
			// Device automatic retry includes its cookie. Fake time bounds the loss path.
			time.Sleep(6 * time.Second)
			retry := h.wire(core.MessageInitiationType)
			if _, err := h.admission.Admit(time.Now(), retry, []byte("other-source"), true, limiter); !errors.Is(err, core.ErrCookieRequired) {
				t.Fatal("cookie source binding", err)
			}
			admitted, err := h.admission.Admit(time.Now(), retry, source, true, limiter)
			if err != nil {
				t.Fatal(err)
			}
			if limiter.calls != 1 {
				t.Fatalf("limiter calls %d", limiter.calls)
			}
			prepared, err := core.PrepareInitiation(admitted)
			if err != nil {
				t.Fatal(err)
			}
			resp, update, err := h.p.HandleInitiation(time.Now(), prepared, interopOutput())
			h.update = update
			if err != nil {
				t.Fatal(err)
			}
			h.inject(resp.Bytes())
			if r := h.open(h.wire(core.MessageTransportType)); r.Disposition != core.Keepalive {
				t.Fatalf("confirmation %+v", r)
			}
		})
	})
}

func TestPeerInteropManualLossAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newInteropPair(t, core.PresharedKey{}, core.PresharedKey{})
		_ = h.initiate() // application intentionally drops the initiation
		time.Sleep(6 * time.Second)
		controls := []core.Packet{interopOutput(), interopOutput()}
		if n, err := h.p.HandleWake(time.Now(), controls); n.N != 0 || err != nil {
			t.Fatalf("manual retry %d %v", n.N, err)
		}
		h.establish(true)
		ip := interopIP(false, false, 63, 1)
		held := h.fromDevice(ip)
		heldToDevice := h.seal(interopIP(false, true, 63, 2))
		// Do not service the core schedule. Age rejection must still apply.
		time.Sleep(core.RejectAfterTime)
		if r := h.open(held); r.Disposition != core.Dropped {
			t.Fatal("expired key accepted")
		}
		p := interopOutput()
		p.Offset += 16
		p.Size = 63
		if n, err := h.send(time.Now(), []core.Packet{p}); n.N != 0 || !errors.Is(err, core.ErrNoSession) {
			t.Fatalf("expired send %d %v", n.N, err)
		}
		// Device ingress uses a strict Before check, unlike core's inclusive age
		// limit. One nanosecond beyond the boundary rejects in both contracts.
		time.Sleep(time.Nanosecond)
		h.inject(heldToDevice)
		h.noDelivery()
		time.Sleep(2 * core.RejectAfterTime)
		if n, err := h.p.HandleWake(time.Now(), controls); n.N != 0 || err != nil {
			t.Fatalf("cleanup %d %v", n.N, err)
		}
		if h.indexes.Len() != 0 {
			t.Fatal("expired core index retained")
		}
	})
}

func TestPeerInteropResponseCookies(t *testing.T) {
	t.Run("device-challenges-core-response", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newInteropPair(t, core.PresharedKey{}, core.PresharedKey{})
			h.dev.rate.underLoadUntil.Store(time.Now().Add(time.Minute).UnixNano())
			if err := h.dp.SendHandshakeInitiation(false); err != nil {
				t.Fatal(err)
			}
			resp, err := h.handle(h.wire(core.MessageInitiationType))
			if err != nil {
				t.Fatal(err)
			}
			h.inject(resp.Bytes())
			cookie := h.wire(core.MessageCookieReplyType)
			if _, err := h.p.ConsumeCookie(time.Now(), cookie); err != nil {
				t.Fatal("response cookie", err)
			}
			time.Sleep(6 * time.Second) // device retries its unconfirmed initiation
			resp, err = h.handle(h.wire(core.MessageInitiationType))
			if err != nil {
				t.Fatal(err)
			}
			h.inject(resp.Bytes())
			if r := h.open(h.wire(core.MessageTransportType)); r.Disposition != core.Keepalive {
				t.Fatalf("confirmation %+v", r)
			}
			ip := interopIP(true, true, 63, 6)
			h.inject(h.seal(ip))
			h.deliveredIP(ip)
		})
	})
	t.Run("core-challenges-device-response", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			h := newInteropPair(t, core.PresharedKey{}, core.PresharedKey{})
			src := []byte("pinned-source")
			limiter := new(interopLimiter)
			init := h.initiate()
			h.inject(init.Bytes())
			resp := h.wire(core.MessageResponseType)
			if _, err := h.admission.Admit(time.Now(), resp, src, true, limiter); !errors.Is(err, core.ErrCookieRequired) {
				t.Fatal(err)
			}
			cookie, err := h.admission.Challenge(time.Now(), resp, src, interopOutput())
			if err != nil {
				t.Fatal(err)
			}
			h.inject(cookie.Bytes())
			synctest.Wait()
			time.Sleep(5 * time.Second)
			init = h.initiate()
			h.inject(init.Bytes())
			resp = h.wire(core.MessageResponseType)
			admitted, err := h.admission.Admit(time.Now(), resp, src, true, limiter)
			if err != nil {
				t.Fatal(err)
			}
			conf, update, err := h.p.HandleResponse(time.Now(), admitted, interopOutput())
			h.update = update
			if err != nil {
				t.Fatal(err)
			}
			h.inject(conf.Bytes())
			h.noDelivery()
			if limiter.calls != 1 {
				t.Fatal("response MAC2 not admitted")
			}
			ip := interopIP(true, false, 63, 7)
			h.checkPlain(h.open(h.fromDevice(ip)), ip)
		})
	})
}

func TestPeerInteropTimestampReplayAndPassiveKeepalive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h := newInteropPair(t, core.PresharedKey{}, core.PresharedKey{})
		init := h.initiate()
		h.inject(init.Bytes())
		resp := h.wire(core.MessageResponseType)
		h.inject(init.Bytes())
		h.noWire() // duplicate timestamp cannot generate another response
		conf, err := h.handle(resp)
		if err != nil {
			t.Fatal(err)
		}
		h.inject(conf.Bytes())
		h.noDelivery()
		if _, err := h.handle(resp); !errors.Is(err, core.ErrHandshake) {
			t.Fatal("response replay", err)
		}
		ip := interopIP(false, false, 63, 2)
		h.checkPlain(h.open(h.fromDevice(ip)), ip)
		wake := h.update.Wake
		if wake.Earliest.IsZero() || wake.Deadline.Sub(time.Now()) > 11*time.Second {
			t.Fatalf("passive wake %+v", wake)
		}
		time.Sleep(wake.Deadline.Sub(time.Now()))
		outputs := []core.Packet{interopOutput(), interopOutput()}
		n, err := h.p.HandleWake(time.Now(), outputs)
		if err != nil || n.N != 1 || outputs[0].Size != core.MessageKeepaliveSize {
			t.Fatalf("passive keepalive %d %v", n.N, err)
		}
		h.inject(outputs[0].Bytes())
		h.noDelivery()
		h.noWire()
	})
}

func TestPeerInteropVectors(t *testing.T)          { testPeerInteropVectors(t, false) }
func TestPeerInteropTransportVectors(t *testing.T) { testPeerInteropVectors(t, true) }
func testPeerInteropVectors(t *testing.T, duplex bool) {
	synctest.Test(t, func(t *testing.T) {
		h := newInteropPair(t, core.PresharedKey{}, core.PresharedKey{})
		h.duplex = duplex
		h.establish(true)
		const count = 16
		vectors := make([]core.Packet, count)
		wants := make([][]byte, count)
		slab := bytes.Repeat([]byte{0xa7}, count*2048)
		for i := range vectors {
			size := 63
			if i%2 == 0 {
				size = 1420
			}
			wants[i] = interopIP(i%3 == 0, true, size, byte(i))
			offset := interopPrefix + i
			vectors[i] = core.Packet{Buffer: slab[i*2048 : (i+1)*2048 : (i+1)*2048], Offset: offset + 16, Size: size}
			copy(vectors[i].Bytes(), wants[i])
		}
		if n, err := h.send(time.Now(), vectors); n.N != count || err != nil {
			t.Fatalf("vector send %d %v", n.N, err)
		}
		for i, p := range vectors {
			if !bytes.Equal(p.Buffer[:p.Offset], bytes.Repeat([]byte{0xa7}, p.Offset)) {
				t.Fatal("vector prefix changed")
			}
			h.inject(p.Bytes())
			h.deliveredIP(wants[i])
		}
		clear(slab)
		for i := range vectors {
			wants[i] = interopIP(i%2 == 0, false, 63, byte(i))
			wire := h.fromDevice(wants[i])
			offset := interopPrefix + i
			vectors[i] = core.Packet{Buffer: slab[i*2048 : (i+1)*2048 : (i+1)*2048], Offset: offset, Size: len(wire)}
			copy(vectors[i].Bytes(), wire)
		}
		// Mix malformed framing, authenticated data, replay, and bad authentication.
		replay := bytes.Clone(vectors[3].Bytes())
		h.checkPlain(h.open(replay), wants[3])
		vectors[1].Buffer[vectors[1].Offset+1] = 1
		vectors[5].Buffer[vectors[5].Offset+vectors[5].Size-1] ^= 1
		results := make([]core.ReceiveResult, count)
		if n, err := h.receive(time.Now(), vectors, results); n.N != count || err != nil {
			t.Fatalf("vector receive %d %v", n.N, err)
		}
		for i, r := range results {
			if i == 1 || i == 3 || i == 5 {
				if r.Disposition != core.Dropped || r.Packet.Buffer != nil {
					t.Fatalf("slot %d %+v", i, r)
				}
			} else {
				h.checkPlain(r, wants[i])
			}
			if !bytes.Equal(vectors[i].Buffer[:vectors[i].Offset], make([]byte, vectors[i].Offset)) {
				t.Fatal("receive vector prefix changed")
			}
		}
	})
}
