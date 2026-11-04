// SPDX-License-Identifier: MIT

package peer

import (
	"encoding/binary"
	"fmt"
	"sync"
	"testing"

	"github.com/tailscale/wireguard-go/peerindex"
)

func BenchmarkTransport(b *testing.B) {
	for _, size := range []int{64, 1280, 1420} {
		for _, batch := range []int{1, 16, 64} {
			for _, direction := range []string{"Send", "Receive"} {
				for _, raw := range []bool{false, true} {
					name := "Peer"
					if raw {
						name = "AEAD"
					}
					b.Run(fmt.Sprintf("%s/%s/bytes=%d/batch=%d", name, direction, size, batch), func(b *testing.B) { benchmarkTransport(b, size, batch, direction == "Receive", raw) })
				}
			}
		}
	}
}

func reportPackets(b *testing.B, batch int) {
	b.ReportMetric(float64(b.N)*float64(batch)/b.Elapsed().Seconds(), "packets/s")
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(batch), "ns/packet")
}

func benchmarkTransport(b *testing.B, size, batch int, receive, raw bool) {
	q := newPair(b, Config{PaddingMTU: 1420, HandshakePolicy: manualPolicy})
	establish(b, q, epoch)
	results := make([]ReceiveResult, batch)
	var nonce noiseNonce
	counter := uint64(1)
	b.ReportAllocs()
	b.SetBytes(int64(size * batch))
	if !receive {
		packets := benchPackets(batch, size)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Both baselines evolve payloads in place rather than timing a copy.
			resetPackets(packets, size)
			if raw {
				for j, p := range packets {
					wire, _ := sendRange(p, 1420)
					header := wire.Bytes()[:16]
					binary.LittleEndian.PutUint32(header, MessageTransportType)
					binary.LittleEndian.PutUint32(header[4:], q.a.keypairs.current.remoteIndex)
					binary.LittleEndian.PutUint64(header[8:], counter)
					binary.LittleEndian.PutUint64(nonce[4:], counter)
					counter++
					content := p.Buffer[p.Offset : p.Offset+size+paddingSize(size, 1420)]
					clear(content[size:])
					sealed := q.a.keypairs.current.send.Seal(content[:0], nonce[:], content, nil)
					if len(sealed) != wire.Size-16 {
						b.Fatal("seal length")
					}
					packets[j] = wire
				}
			} else if n, err := q.a.Send(epoch, packets); err != nil || n.N != batch || n.Update.Wake.Earliest.IsZero() || n.Update.Handshake.Reasons != 0 {
				b.Fatalf("send %d %v", n.N, err)
			}
		}
		b.StopTimer()
		reportPackets(b, batch)
		return
	}

	const chunks = 64
	corpus := make([][]Packet, chunks)
	for i := range corpus {
		corpus[i] = benchPackets(batch, size)
	}
	b.ResetTimer()
	b.StopTimer()
	for done := 0; done < b.N; {
		count := min(chunks, b.N-done)
		for _, packets := range corpus[:count] {
			resetPackets(packets, size)
			if n, err := q.a.Send(epoch, packets); n.N != batch || err != nil || n.Update.Wake.Earliest.IsZero() || n.Update.Handshake.Reasons != 0 {
				b.Fatalf("prepare %d %v", n.N, err)
			}
		}
		b.StartTimer()
		for _, packets := range corpus[:count] {
			if raw {
				for _, p := range packets {
					wire := p.Bytes()
					binary.LittleEndian.PutUint64(nonce[4:], binary.LittleEndian.Uint64(wire[8:]))
					content := wire[16:]
					plain, err := q.b.keypairs.current.receive.Open(content[:0], nonce[:], content, nil)
					if err != nil || len(plain) != size+paddingSize(size, 1420) {
						b.Fatal("open", err)
					}
				}
			} else {
				if n, err := q.b.Receive(epoch, packets, results); n.N != batch || err != nil || n.Update.Wake.Earliest.IsZero() || n.Update.Handshake.Reasons != 0 {
					b.Fatalf("receive %d %v", n.N, err)
				}
				for _, r := range results {
					if r.Disposition != Data || r.Err != nil || r.Packet.Size != size+paddingSize(size, 1420) {
						b.Fatalf("result %+v", r)
					}
				}
			}
		}
		b.StopTimer()
		done += count
	}
	reportPackets(b, batch)
}

func BenchmarkOwnerScaling(b *testing.B) {
	for _, owners := range []int{1, 2, 4} {
		for _, peers := range []int{1, 64} {
			b.Run(fmt.Sprintf("owners=%d/peers-per-owner=%d", owners, peers), func(b *testing.B) {
				table := new(peerindex.Table[*Peer])
				sets := make([][]pair, owners)
				for owner := range sets {
					for range peers {
						ka, err := NewPrivateKey()
						if err != nil {
							b.Fatal(err)
						}
						kb, err := NewPrivateKey()
						if err != nil {
							b.Fatal(err)
						}
						ia, ib := NewIdentity(ka), NewIdentity(kb)
						a, _, err := New(epoch, localIdentity(b, 1, ia), table, ib.Public(), Config{HandshakePolicy: manualPolicy, PaddingMTU: 1420})
						if err != nil {
							b.Fatal(err)
						}
						c, _, err := New(epoch, localIdentity(b, 1, ib), table, ia.Public(), Config{HandshakePolicy: manualPolicy, PaddingMTU: 1420})
						if err != nil {
							b.Fatal(err)
						}
						q := pair{a, c, ia, ib, admission(b, a.identity), admission(b, c.identity), table}
						establish(b, q, epoch)
						sets[owner] = append(sets[owner], q)
					}
				}
				b.Cleanup(func() {
					for _, set := range sets {
						for _, q := range set {
							q.a.Close()
							q.b.Close()
						}
					}
					if table.Len() != 0 {
						b.Error("index leak")
					}
				})
				const batch, size = 16, 1420
				vectors := make([][]Packet, owners)
				results := make([][]ReceiveResult, owners)
				for i := range vectors {
					vectors[i] = benchPackets(batch, size)
					results[i] = make([]ReceiveResult, batch)
				}
				var wg sync.WaitGroup
				wg.Add(owners)
				start := make(chan struct{})
				errors := make(chan error, owners)
				for owner := range owners {
					go func() {
						defer wg.Done()
						<-start
						for i := owner; i < b.N; i += owners {
							q := sets[owner][(i/owners)%peers]
							packets := vectors[owner]
							resetPackets(packets, size)
							if n, err := q.a.Send(epoch, packets); n.N != batch || err != nil || n.Update.Wake.Earliest.IsZero() || n.Update.Handshake.Reasons != 0 {
								errors <- fmt.Errorf("send %d %v", n.N, err)
								return
							}
							for _, p := range packets {
								r, ok := table.Lookup(binary.LittleEndian.Uint32(p.Bytes()[4:]))
								if !ok || r != q.b {
									errors <- fmt.Errorf("route")
									return
								}
							}
							if n, err := q.b.Receive(epoch, packets, results[owner]); n.N != batch || err != nil || n.Update.Wake.Earliest.IsZero() || n.Update.Handshake.Reasons != 0 {
								errors <- fmt.Errorf("receive %d %v", n.N, err)
								return
							}
							for _, r := range results[owner] {
								if r.Disposition != Data || r.Err != nil {
									errors <- fmt.Errorf("result %v", r.Err)
									return
								}
							}
						}
					}()
				}
				b.ReportAllocs()
				b.SetBytes(batch * size)
				b.ResetTimer()
				close(start)
				wg.Wait()
				b.StopTimer()
				close(errors)
				for err := range errors {
					b.Fatal(err)
				}
				reportPackets(b, batch)
			})
		}
	}
}
