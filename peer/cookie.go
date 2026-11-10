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

// CookieRefreshTime is the lifetime of a source-cookie secret or received cookie.
const CookieRefreshTime = 120 * time.Second

var (
	// ErrMAC1 reports malformed handshake framing or an invalid first MAC.
	ErrMAC1 = errors.New("peer: invalid MAC1")

	// ErrCookieRequired reports that the source must supply a valid cookie.
	ErrCookieRequired = errors.New("peer: source cookie required")

	// ErrAdmission reports a missing source limiter or a source denied by it.
	ErrAdmission = errors.New("peer: source rate limited or missing limiter")

	// ErrCookie reports an invalid or stale cookie reply.
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

// Admission checks handshake MACs and issues source-bound cookies for one local
// generation. Construct it with [NewAdmission]. Calls on an Admission must be
// serialized and use nonzero, nondecreasing times.
// Source bytes must consistently encode the source address and port for both
// [Admission.Admit] and [Admission.Challenge].
// Route a source to the same Admission instance throughout its cookie exchange.
type Admission struct {
	identity                   *identityRecord
	mac1Key, cookieKey, secret [32]byte
	secretSet, now             time.Time
}

// NewAdmission returns an admission checker for id.
// It returns nil and [ErrConfig] if id is the zero value.
func NewAdmission(id LocalIdentity) (*Admission, error) {
	if id.record == nil {
		return nil, ErrConfig
	}
	return &Admission{identity: id.record, mac1Key: labelKey(labelMAC1, id.record.public), cookieKey: labelKey(labelCookie, id.record.public)}, nil
}

// SourceLimiter decides which sources may proceed after cookie validation.
type SourceLimiter interface {
	// Allow reports whether src may proceed at now. The slice is borrowed
	// for this call. An implementation that retains it must copy it.
	Allow(now time.Time, src []byte) bool
}

// AdmittedHandshake owns a copy of an initiation or response that passed
// admission for a local generation. It may be copied or passed to another
// goroutine. [Admission] does not authenticate the remote peer.
type AdmittedHandshake struct {
	wire     [MessageHybridInitiationSize]byte
	size     int
	identity *identityRecord
}

// Admit checks framing and MAC1 and returns an owned handshake token.
// Under load, it also requires a valid source cookie and limiter approval,
// in that order. Otherwise src and limiter are unused and may be nil.
// It returns [ErrMAC1], [ErrCookieRequired], or [ErrAdmission] on rejection,
// and [ErrTime] for a zero or decreasing time.
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

func overlap(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	x, y := uintptr(unsafe.Pointer(unsafe.SliceData(a))), uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	return x < y+uintptr(len(b)) && y < x+uintptr(len(a))
}

// Challenge writes a source-cookie reply at out.Offset for a handshake with
// a valid MAC1. It requires [MessageCookieReplySize] bytes after the offset.
// The output range must not overlap wire or src. It returns [ErrShortBuffer]
// for insufficient output, [ErrOverlap] for overlap, [ErrMAC1] for an invalid
// handshake, or [ErrTime] for a zero or decreasing time.
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
	var nonce [chacha20poly1305.NonceSizeX]byte
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

// ConsumeCookie stores a cookie reply for use in subsequent handshakes.
// It returns [ErrCookie] if the reply cannot be authenticated against the most
// recent sent handshake and its still-live index, or that handshake is stale.
// The caller must initiate again to send a handshake using the cookie.
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
