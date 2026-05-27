//go:build mips || mipsle

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package chacha20poly1305

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"

	xchacha20poly1305 "golang.org/x/crypto/chacha20poly1305"
)

type aeadCtorEntry struct {
	name string
	new  func(key []byte) (cipher.AEAD, error)
}

var aeadCtors = []aeadCtorEntry{
	{"go-chacha20poly1305", xchacha20poly1305.New},
	{"asm-chacha20poly1305", New},
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestAEAD_RFC8439Vector(t *testing.T) {
	key := mustHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex("070000004041424344454647")
	aad := mustHex("50515253c0c1c2c3c4c5c6c7")
	src := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	plaintext := make([]byte, len(src))
	copy(plaintext, src)
	wantCT := mustHex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
	wantTag := mustHex("1ae10b594f09e26a7e902ecbd0600691")
	want := append(append([]byte{}, wantCT...), wantTag...)

	for _, c := range aeadCtors {
		t.Run(c.name, func(t *testing.T) {
			aead, err := c.new(key)
			if err != nil {
				t.Fatal(err)
			}
			got := aead.Seal(nil, nonce, plaintext, aad)
			if !bytes.Equal(got, want) {
				t.Errorf("Seal mismatch:\n got: %x\nwant: %x", got, want)
			}
			opened, err := aead.Open(nil, nonce, want, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(opened, plaintext) {
				t.Errorf("Open mismatch:\n got: %q\nwant: %q", opened, plaintext)
			}
		})
	}
}

func TestAEAD_AgreesWithReference(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 1024, 1500, 4096}
	aadSizes := []int{0, 1, 13, 64}

	var key [32]byte
	rand.Read(key[:])
	var nonce [12]byte
	rand.Read(nonce[:])

	ref, err := xchacha20poly1305.New(key[:])
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range aeadCtors {
		aead, err := c.new(key[:])
		if err != nil {
			t.Fatalf("%s: New: %v", c.name, err)
		}
		for _, plen := range sizes {
			plaintext := make([]byte, plen)
			rand.Read(plaintext)
			for _, alen := range aadSizes {
				aad := make([]byte, alen)
				rand.Read(aad)
				wantCT := ref.Seal(nil, nonce[:], plaintext, aad)
				name := fmt.Sprintf("%s/pt=%d/aad=%d", c.name, plen, alen)
				t.Run(name, func(t *testing.T) {
					gotCT := aead.Seal(nil, nonce[:], plaintext, aad)
					if !bytes.Equal(gotCT, wantCT) {
						t.Fatalf("Seal mismatch")
					}
					pt, err := aead.Open(nil, nonce[:], wantCT, aad)
					if err != nil {
						t.Fatalf("Open: %v", err)
					}
					if !bytes.Equal(pt, plaintext) {
						t.Fatalf("Open mismatch")
					}
				})
			}
		}
	}
}

func TestAEAD_OpenRejectsTamper(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])
	var nonce [12]byte
	rand.Read(nonce[:])
	src := "the quick brown fox jumps over the lazy dog"
	plaintext := make([]byte, len(src))
	copy(plaintext, src)
	aad := []byte("metadata")

	for _, c := range aeadCtors {
		t.Run(c.name, func(t *testing.T) {
			aead, err := c.new(key[:])
			if err != nil {
				t.Fatal(err)
			}
			ct := aead.Seal(nil, nonce[:], plaintext, aad)

			tamper := append([]byte{}, ct...)
			tamper[0] ^= 1
			if _, err := aead.Open(nil, nonce[:], tamper, aad); err == nil {
				t.Error("Open accepted tampered ciphertext")
			}

			tamper = append([]byte{}, ct...)
			tamper[len(tamper)-1] ^= 1
			if _, err := aead.Open(nil, nonce[:], tamper, aad); err == nil {
				t.Error("Open accepted tampered tag")
			}
		})
	}
}

func TestAEAD_Concurrent(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])
	plaintext := []byte("wireguard concurrent aead test")
	aad := []byte("aad")

	for _, c := range aeadCtors {
		t.Run(c.name, func(t *testing.T) {
			aead, err := c.new(key[:])
			if err != nil {
				t.Fatal(err)
			}
			const goroutines = 4
			const iters = 50
			var wg sync.WaitGroup
			wg.Add(goroutines)
			errs := make(chan error, goroutines)
			for g := range goroutines {
				go func(id int) {
					defer wg.Done()
					var nonce [12]byte
					binary.BigEndian.PutUint64(nonce[4:], uint64(id))
					for i := range iters {
						binary.BigEndian.PutUint32(nonce[:4], uint32(i))
						ct := aead.Seal(nil, nonce[:], plaintext, aad)
						pt, err := aead.Open(nil, nonce[:], ct, aad)
						if err != nil {
							errs <- fmt.Errorf("goroutine %d iter %d: Open: %w", id, i, err)
							return
						}
						if !bytes.Equal(pt, plaintext) {
							errs <- fmt.Errorf("goroutine %d iter %d: plaintext mismatch", id, i)
							return
						}
					}
				}(g)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
		})
	}
}

func BenchmarkAEAD_Seal(b *testing.B) { benchmarkAEAD(b, false) }
func BenchmarkAEAD_Open(b *testing.B) { benchmarkAEAD(b, true) }

func benchmarkAEAD(b *testing.B, open bool) {
	const ptSize = 1420
	var key [32]byte
	rand.Read(key[:])
	var nonce [12]byte
	plaintext := make([]byte, ptSize)
	rand.Read(plaintext)

	for _, c := range aeadCtors {
		b.Run(c.name, func(b *testing.B) {
			aead, err := c.new(key[:])
			if err != nil {
				b.Fatal(err)
			}
			ctBuf := make([]byte, 0, ptSize+aead.Overhead())
			ct := aead.Seal(ctBuf, nonce[:], plaintext, nil)
			ptBuf := make([]byte, 0, ptSize)
			b.SetBytes(int64(ptSize))
			b.ResetTimer()
			if open {
				for range b.N {
					if _, err := aead.Open(ptBuf[:0], nonce[:], ct, nil); err != nil {
						b.Fatal(err)
					}
				}
			} else {
				for range b.N {
					_ = aead.Seal(ctBuf[:0], nonce[:], plaintext, nil)
				}
			}
		})
	}
}
