/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package peer

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
	"unsafe"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// CookieRefreshTime is the lifetime of a cookie secret or received cookie.
const CookieRefreshTime = 120 * time.Second

var (
	// ErrMAC1 indicates invalid handshake framing or MAC1.
	ErrMAC1 = errors.New("peer: invalid MAC1")
	// ErrCookieRequired indicates a missing, invalid, or expired source cookie.
	ErrCookieRequired = errors.New("peer: source cookie required")
	// ErrAdmission indicates a missing limiter or a rejected source.
	ErrAdmission = errors.New("peer: source rate limited or missing limiter")
	// ErrCookie indicates a rejected cookie reply.
	ErrCookie = errors.New("peer: invalid cookie reply")
)

func labelKey(label string, public PublicKey) (key [32]byte) {
	h, _ := blake2s.New256(nil)
	h.Write([]byte(label))
	h.Write(public[:])
	h.Sum(key[:0])
	return
}
func mac128(key, data []byte) (sum [16]byte) {
	h, _ := blake2s.New128(key)
	h.Write(data)
	h.Sum(sum[:0])
	return
}
func handshakeFraming(wire []byte) bool {
	typ, _, err := ParseHeader(wire)
	return err == nil && (typ == MessageInitiationType || typ == MessageResponseType)
}
func checkMAC1(key [32]byte, wire []byte) bool {
	if !handshakeFraming(wire) {
		return false
	}
	at := len(wire) - 32
	mac := mac128(key[:], wire[:at])
	return hmac.Equal(mac[:], wire[at:at+16])
}

// Admission checks handshakes and issues cookie challenges for one LocalIdentity
// without performing DH. The caller must serialize its methods and replace it
// on identity rotation. The zero value is not usable. Use NewAdmission.
//
// src must canonically encode the remote IP and port, including any required
// address family or scope, not packet payload. Socket shards may share a
// serialized Admission or use separate instances. Separate instances require
// stable source routing during cookie challenges.
type Admission struct {
	identity                   *identityRecord
	mac1Key, cookieKey, secret [32]byte
	secretSet, now             time.Time
}

// NewAdmission returns an ingress checker for id, or ErrConfig for a zero id.
// Share id with the peers served by this checker.
func NewAdmission(id LocalIdentity) (*Admission, error) {
	if id.record == nil {
		return nil, ErrConfig
	}
	return &Admission{identity: id.record, mac1Key: labelKey(labelMAC1, id.record.public), cookieKey: labelKey(labelCookie, id.record.public)}, nil
}

// SourceLimiter supplies rate policy under load. Admission requires it only
// under load and calls it after MAC1 and source-bound MAC2 pass. Implementations
// must use the supplied clock and bound source state. Admission does not retain src.
type SourceLimiter interface {
	// Allow reports whether src may proceed at now.
	Allow(now time.Time, src []byte) bool
}

// AdmittedHandshake holds a copy of an admitted handshake, not an authenticated
// Noise transcript. Input storage may be reused after Admit returns. Tokens may
// be retried after output backpressure. Peer replay state guards successful use.
type AdmittedHandshake struct {
	wire     [MessageInitiationSize]byte
	size     int
	identity *identityRecord
}

// Admit checks framing and MAC1, then MAC2 and limiter if underLoad is true.
// It copies wire and performs no DH. ErrCookieRequired may be answered with
// Challenge. Framing or MAC1 failures must be dropped without a challenge.
// With underLoad false, it skips cookie and rate checks.
func (a *Admission) Admit(now time.Time, wire, src []byte, underLoad bool, limiter SourceLimiter) (AdmittedHandshake, error) {
	if now.IsZero() || (!a.now.IsZero() && now.Before(a.now)) {
		return AdmittedHandshake{}, ErrTime
	}
	a.now = now
	if !handshakeFraming(wire) {
		return AdmittedHandshake{}, ErrMAC1
	}
	v := AdmittedHandshake{size: len(wire), identity: a.identity}
	copy(v.wire[:], wire)
	wire = v.wire[:v.size]
	if !checkMAC1(a.mac1Key, wire) {
		return AdmittedHandshake{}, ErrMAC1
	}
	if underLoad {
		if !a.checkMAC2(now, wire, src) {
			return AdmittedHandshake{}, ErrCookieRequired
		}
		if limiter == nil || !limiter.Allow(now, src) {
			return AdmittedHandshake{}, ErrAdmission
		}
	}
	return v, nil
}
func (a *Admission) checkMAC2(now time.Time, wire, src []byte) bool {
	if a.secretSet.IsZero() || now.Sub(a.secretSet) >= CookieRefreshTime {
		return false
	}
	cookie := mac128(a.secret[:], src)
	mac := mac128(cookie[:], wire[:len(wire)-16])
	return hmac.Equal(mac[:], wire[len(wire)-16:])
}

// overlap reports whether two slice ranges overlap. It is used only for cookie
// challenges, not packet vectors. Slices remain live during address comparison.
func overlap(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	x, y := uintptr(unsafe.Pointer(unsafe.SliceData(a))), uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	return x < y+uintptr(len(b)) && y < x+uintptr(len(a))
}

// Challenge writes a cookie reply at out.Offset, preserving its prefix.
// wire must be a correctly framed handshake with valid MAC1. Neither wire nor
// src may overlap the output range. Buffer and overlap checks precede secret
// refresh or output writes. The caller must limit reply bandwidth. Rate-limiter
// rejection does not require a challenge.
func (a *Admission) Challenge(now time.Time, wire, src []byte, out Packet) (Packet, error) {
	out, err := output(out, MessageCookieReplySize)
	if err != nil {
		return Packet{}, err
	}
	if overlap(wire, out.Bytes()) || overlap(src, out.Bytes()) {
		return Packet{}, ErrOverlap
	}
	if now.IsZero() || (!a.now.IsZero() && now.Before(a.now)) {
		return Packet{}, ErrTime
	}
	if !checkMAC1(a.mac1Key, wire) {
		return Packet{}, ErrMAC1
	}
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return Packet{}, err
	}
	if a.secretSet.IsZero() || now.Sub(a.secretSet) >= CookieRefreshTime {
		var secret [32]byte
		if _, err = rand.Read(secret[:]); err != nil {
			return Packet{}, err
		}
		a.secret = secret
		a.secretSet = now
	}
	a.now = now
	cookie := mac128(a.secret[:], src)
	b := out.Bytes()
	binary.LittleEndian.PutUint32(b, MessageCookieReplyType)
	binary.LittleEndian.PutUint32(b[4:], binary.LittleEndian.Uint32(wire[4:8]))
	copy(b[8:32], nonce[:])
	aead, _ := chacha20poly1305.NewX(a.cookieKey[:])
	aead.Seal(b[32:32], nonce[:], cookie[:], wire[len(wire)-32:len(wire)-16])
	return out, nil
}

type cookieGenerator struct {
	mac1Key, cookieKey      [32]byte
	cookie, lastMAC1        [16]byte
	cookieSet, lastMAC1Sent time.Time
	lastIndex               uint32
	hasLastMAC1             bool
}

func (g *cookieGenerator) init(public PublicKey) {
	*g = cookieGenerator{mac1Key: labelKey(labelMAC1, public), cookieKey: labelKey(labelCookie, public)}
}
func (g *cookieGenerator) addMACs(now time.Time, wire []byte) {
	at := len(wire) - 32
	mac := mac128(g.mac1Key[:], wire[:at])
	copy(wire[at:at+16], mac[:])
	g.lastMAC1 = mac
	g.hasLastMAC1 = true
	g.lastMAC1Sent = now
	g.lastIndex = binary.LittleEndian.Uint32(wire[4:8])
	clear(wire[at+16:])
	if !g.cookieSet.IsZero() && now.Sub(g.cookieSet) < CookieRefreshTime {
		mac = mac128(g.cookie[:], wire[:at+16])
		copy(wire[at+16:], mac[:])
	}
}

// ConsumeCookie authenticates a reply for the latest emitted MAC1 and a live
// local index. It stores the cookie without retrying or changing the handshake
// rate limit. Retry through HandleWake or Initiate.
func (p *Peer) ConsumeCookie(now time.Time, wire []byte) (u Update, err error) {
	defer func() { u = p.update() }()
	if err := p.advance(now); err != nil {
		return u, err
	}
	typ, index, err := ParseHeader(wire)
	g := &p.cookieGen
	if err != nil || typ != MessageCookieReplyType || !g.hasLastMAC1 || now.Sub(g.lastMAC1Sent) >= CookieRefreshTime || index != g.lastIndex || (index != p.handshake.localIndex && p.keypairs.lookup(index) == nil) {
		return u, ErrCookie
	}
	var cookie [16]byte
	aead, _ := chacha20poly1305.NewX(g.cookieKey[:])
	if _, err = aead.Open(cookie[:0], wire[8:32], wire[32:], g.lastMAC1[:]); err != nil {
		return u, ErrCookie
	}
	g.cookie = cookie
	g.cookieSet = now
	return u, nil
}
