// SPDX-License-Identifier: MIT

package aead

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestNew(t *testing.T) {
	for _, size := range []int{0, 31, 33} {
		if _, err := New(make([]byte, size)); err == nil {
			t.Fatalf("New accepted key length %d", size)
		}
	}
	key := make([]byte, chacha20poly1305.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	got, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	want, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	if got.NonceSize() != want.NonceSize() || got.Overhead() != want.Overhead() {
		t.Fatal("AEAD dimensions differ from x/crypto")
	}
	var nonce [chacha20poly1305.NonceSize]byte
	for i, size := range []int{0, 1, 15, 16, 64, 1420} {
		binary.LittleEndian.PutUint64(nonce[4:], uint64(i))
		plain := bytes.Repeat([]byte{0xa5}, size)
		additional := []byte("shared dispatch")
		sealed := got.Seal(nil, nonce[:], plain, additional)
		if !bytes.Equal(sealed, want.Seal(nil, nonce[:], plain, additional)) {
			t.Fatalf("Seal differs from x/crypto at size %d", size)
		}
		opened, err := got.Open(nil, nonce[:], sealed, additional)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatalf("Open at size %d: %v", size, err)
		}
		sealed[len(sealed)-1] ^= 1
		if _, err := got.Open(nil, nonce[:], sealed, additional); err == nil {
			t.Fatalf("Open accepted tampering at size %d", size)
		}
	}
}
