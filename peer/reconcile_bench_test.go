// SPDX-License-Identifier: MIT

package peer

import (
	"fmt"
	"testing"
	"time"
)

// BenchmarkReceiptReconciliation isolates bookkeeping with synthetic receipts
// from an established session. Alternating TX/RX data arms and cancels passive
// keepalives. Advancing the control clock also moves persistent keepalives.
// No crypto, I/O, queues, receipt handoff, or packet storage is timed. Results
// report cost per receipt, not delivered packet throughput.
func BenchmarkReceiptReconciliation(b *testing.B) {
	for _, persistent := range []time.Duration{0, 25 * time.Second} {
		for _, count := range []int{1, 4, 16, 64} {
			for _, bulk := range []bool{false, true} {
				mode := "Single"
				if bulk {
					mode = "Bulk"
				}
				b.Run(fmt.Sprintf("%s/keepalive=%s/receipts=%d", mode, persistent, count), func(b *testing.B) {
					benchmarkReceiptReconciliation(b, persistent, count, bulk)
				})
			}
		}
	}
}

func benchmarkReceiptReconciliation(b *testing.B, persistent time.Duration, count int, bulk bool) {
	q := newPair(b, Config{PersistentKeepalive: persistent})
	establish(b, q, epoch)
	p := q.a
	view := p.Transport().view.Load()
	activities := make([]TransportActivity, count)
	for i := range activities {
		a := &activities[i]
		a.transport, a.view = p.Transport(), view
		a.tx = i%2 == 0
		if a.tx {
			a.sent, a.data = view.keys.current, true
		} else {
			a.received.auth[0], a.received.data[0] = true, 1
		}
	}
	var txSeq, rxSeq uint64
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		at := epoch.Add(time.Duration(i+1) * time.Nanosecond)
		for j := range activities {
			a := &activities[j]
			a.at = at
			if a.tx {
				txSeq++
				a.seq = txSeq
			} else {
				rxSeq++
				a.seq = rxSeq
			}
		}
		if bulk {
			if r, err := p.ApplyTransportBatch(at, activities); err != nil || r.N != count {
				b.Fatal(r, err)
			}
		} else {
			for _, a := range activities {
				if _, err := p.ApplyTransport(at, a); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(count), "ns/receipt")
	b.ReportMetric(float64(b.N)*float64(count)/b.Elapsed().Seconds(), "receipts/s")
}
