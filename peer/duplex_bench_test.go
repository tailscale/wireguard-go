// SPDX-License-Identifier: MIT

package peer

import (
	"fmt"
	"sync"
	"testing"
)

// BenchmarkDuplexTransport measures lane crypto and receipt application without
// queues, I/O, or goroutines. Compare with BenchmarkTransport/Peer, which also
// computes an authoritative Update once per vector.
func BenchmarkDuplexTransport(b *testing.B) {
	for _, size := range []int{64, 1280} {
		for _, batch := range []int{1, 16, 64} {
			for _, rx := range []bool{false, true} {
				direction := "Send"
				if rx {
					direction = "Receive"
				}
				b.Run(fmt.Sprintf("%s/bytes=%d/batch=%d", direction, size, batch), func(b *testing.B) {
					benchmarkDuplexTransport(b, size, batch, rx)
				})
			}
		}
	}
}

// BenchmarkDuplexPipeline measures two-way seal/open with control receipt
// reconciliation. Concurrent includes bounded channel/slab handoffs and four
// lane workers. Serial has no handoff queues. Each delivered packet is counted
// once. Reported throughput is plaintext for this hot-buffer in-process harness,
// not UDP/TUN VPN throughput.
func BenchmarkDuplexPipeline(b *testing.B) {
	for _, batch := range []int{1, 16, 64} {
		for _, concurrent := range []bool{false, true} {
			mode := "Serial"
			if concurrent {
				mode = "Concurrent"
			}
			b.Run(fmt.Sprintf("%s/bytes=1280/batch=%d", mode, batch), func(b *testing.B) {
				benchmarkDuplexPipeline(b, batch, concurrent, false)
			})
		}
	}
}

// BenchmarkDuplexPipelineBulk uses the same concurrent crypto/slab/channel
// harness, but the owner drains up to 16 currently-ready receipts per turn and
// reconciles once per peer. It never waits to fill a turn or changes wake slack.
func BenchmarkDuplexPipelineBulk(b *testing.B) {
	for _, batch := range []int{1, 16, 64} {
		b.Run(fmt.Sprintf("bytes=1280/batch=%d", batch), func(b *testing.B) {
			benchmarkDuplexPipeline(b, batch, true, true)
		})
	}
}

func benchmarkDuplexPipeline(b *testing.B, batch int, concurrent, bulk bool) {
	q := newPair(b, Config{PaddingMTU: 1420})
	establish(b, q, epoch)
	b.ReportAllocs()
	b.SetBytes(int64(2 * batch * 1280))
	if !concurrent {
		ab, ba := benchPackets(batch, 1280), benchPackets(batch, 1280)
		results := make([]ReceiveResult, batch)
		b.ResetTimer()
		for range b.N {
			for _, d := range []struct {
				from, to *Peer
				packets  []Packet
			}{{q.a, q.b, ab}, {q.b, q.a, ba}} {
				resetPackets(d.packets, 1280)
				tx, err := d.from.Transport().Send(epoch, d.packets)
				if err != nil || tx.N != batch {
					b.Fatal(tx, err)
				}
				if _, err := d.from.ApplyTransport(epoch, tx.Activity); err != nil {
					b.Fatal(err)
				}
				rx, err := d.to.Transport().Receive(epoch, d.packets, results)
				if err != nil || rx.N != batch {
					b.Fatal(rx, err)
				}
				if _, err := d.to.ApplyTransport(epoch, rx.Activity); err != nil {
					b.Fatal(err)
				}
				for _, rr := range results {
					if rr.Err != nil || rr.Disposition != Data || rr.Packet.Size != 1280 {
						b.Fatal(rr)
					}
				}
			}
		}
		b.StopTimer()
		reportPackets(b, 2*batch)
		return
	}
	type receipt struct {
		owner *Peer
		r     TransportResult
		err   error
		valid bool
	}
	const depth = 4
	start := make(chan struct{})
	events := make(chan receipt, 16)
	var ready, workers sync.WaitGroup
	ready.Add(4)
	for _, direction := range [][2]*Peer{{q.a, q.b}, {q.b, q.a}} {
		from, to := direction[0], direction[1]
		tx, rx := from.Transport(), to.Transport()
		free, wire := make(chan []Packet, depth), make(chan []Packet, depth)
		for range depth {
			free <- benchPackets(batch, 1280)
		}
		workers.Go(func() {
			ready.Done()
			<-start
			for range b.N {
				packets := <-free
				resetPackets(packets, 1280)
				r, err := tx.Send(epoch, packets)
				events <- receipt{from, r, err, r.N == batch}
				wire <- packets
			}
		})
		workers.Go(func() {
			results := make([]ReceiveResult, batch)
			ready.Done()
			<-start
			for range b.N {
				packets := <-wire
				r, err := rx.Receive(epoch, packets, results)
				valid := r.N == batch
				for _, rr := range results {
					valid = valid && rr.Err == nil && rr.Disposition == Data && rr.Packet.Size == 1280
				}
				events <- receipt{to, r, err, valid}
				free <- packets
			}
		})
	}
	var pendingA, pendingB [16]TransportActivity
	ready.Wait()
	b.ResetTimer()
	close(start)
	for handled := 0; handled < b.N*4; {
		na, nb := 0, 0
	collect:
		for turn := 0; turn < 16 && handled < b.N*4; turn++ {
			var e receipt
			if turn == 0 {
				e = <-events
			} else {
				select {
				case e = <-events:
				default:
					break collect
				}
			}
			handled++
			if e.err != nil || !e.valid {
				b.Error("transport", e.r.N, e.err)
			}
			if !bulk {
				if _, err := e.owner.ApplyTransport(epoch, e.r.Activity); err != nil {
					b.Error("reconcile", err)
				}
				break
			}
			if e.owner == q.a {
				pendingA[na] = e.r.Activity
				na++
			} else {
				pendingB[nb] = e.r.Activity
				nb++
			}
		}
		if na > 0 {
			if r, err := q.a.ApplyTransportBatch(epoch, pendingA[:na]); err != nil || r.N != na {
				b.Error("bulk A", r, err)
			}
		}
		if nb > 0 {
			if r, err := q.b.ApplyTransportBatch(epoch, pendingB[:nb]); err != nil || r.N != nb {
				b.Error("bulk B", r, err)
			}
		}
	}
	workers.Wait()
	b.StopTimer()
	reportPackets(b, 2*batch)
}

func benchmarkDuplexTransport(b *testing.B, size, batch int, rx bool) {
	q := newPair(b, Config{PaddingMTU: 1420})
	establish(b, q, epoch)
	b.ReportAllocs()
	b.SetBytes(int64(size * batch))
	if !rx {
		tr := q.a.Transport()
		packets := benchPackets(batch, size)
		b.ResetTimer()
		for range b.N {
			resetPackets(packets, size)
			r, err := tr.Send(epoch, packets)
			if err != nil || r.N != batch {
				b.Fatal(r, err)
			}
			if u, err := q.a.ApplyTransport(epoch, r.Activity); err != nil || u.Handshake.Reasons != 0 {
				b.Fatal(u, err)
			}
		}
		b.StopTimer()
		reportPackets(b, batch)
		return
	}
	tr := q.b.Transport()
	results := make([]ReceiveResult, batch)
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
			if r, err := q.a.Send(epoch, packets); err != nil || r.N != batch {
				b.Fatal(r, err)
			}
		}
		b.StartTimer()
		for _, packets := range corpus[:count] {
			r, err := tr.Receive(epoch, packets, results)
			if err != nil || r.N != batch {
				b.Fatal(r, err)
			}
			if u, err := q.b.ApplyTransport(epoch, r.Activity); err != nil || u.Handshake.Reasons != 0 {
				b.Fatal(u, err)
			}
			for _, rr := range results {
				if rr.Err != nil || rr.Disposition != Data || rr.Packet.Size != size+paddingSize(size, 1420) {
					b.Fatal(rr)
				}
			}
		}
		b.StopTimer()
		done += count
	}
	reportPackets(b, batch)
}
