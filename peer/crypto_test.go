// SPDX-License-Identifier: MIT

package peer

import (
	"errors"
	"reflect"
	"testing"

	"github.com/tailscale/wireguard-go/internal/aead"
)

func TestSharedSecret(t *testing.T) {
	a, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ab, err := a.sharedSecret(b.Public())
	if err != nil || isZero(ab[:]) {
		t.Fatal("valid shared secret", err)
	}
	ba, err := b.sharedSecret(a.Public())
	if err != nil || ab != ba {
		t.Fatal("shared secrets differ", err)
	}
	for _, public := range []PublicKey{{}, {1}} {
		ss, err := a.sharedSecret(public)
		if !errors.Is(err, errInvalidPublicKey) || !isZero(ss[:]) {
			t.Fatal("low-order point did not return a zero secret and errInvalidPublicKey", public, ss, err)
		}
	}
}

func TestSessionAEADBackend(t *testing.T) {
	want, err := aead.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	q := newPair(t, Config{})
	establish(t, q, epoch)
	for _, p := range []*Peer{q.a, q.b} {
		k := p.keypairs.current
		if reflect.TypeOf(k.send) != reflect.TypeOf(want) || reflect.TypeOf(k.receive) != reflect.TypeOf(want) {
			t.Fatalf("session AEADs = %T, %T; want %T", k.send, k.receive, want)
		}
	}
}
