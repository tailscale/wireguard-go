// SPDX-License-Identifier: MIT

package peer

import (
	"testing"
	"time"
)

// BenchmarkHandshake measures both endpoints through confirmation with reused
// packet storage. It includes admission, preparation, crypto, and index updates.
func BenchmarkHandshake(b *testing.B) {
	for _, mode := range []struct {
		name   string
		hybrid bool
	}{{"Classical", false}, {"Hybrid", true}} {
		b.Run(mode.name, func(b *testing.B) {
			q := newPair(b, Config{Hybrid: mode.hybrid})
			initOut, respOut := control(), control()
			var results [1]ReceiveResult
			now := epoch
			b.ReportAllocs()
			for b.Loop() {
				now = now.Add(6 * time.Second)
				init, _, err := q.a.Initiate(now, initOut)
				if err != nil {
					b.Fatal(err)
				}
				token, err := q.ab.Admit(now, init.Bytes(), nil, false, nil)
				if err != nil {
					b.Fatal(err)
				}
				prepared, err := PrepareInitiation(token)
				if err != nil {
					b.Fatal(err)
				}
				response, _, err := q.b.HandleInitiation(now, prepared, respOut)
				if err != nil {
					b.Fatal(err)
				}
				token, err = q.aa.Admit(now, response.Bytes(), nil, false, nil)
				if err != nil {
					b.Fatal(err)
				}
				confirmation, _, err := q.a.HandleResponse(now, token, initOut)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := q.b.Receive(now, []Packet{confirmation}, results[:]); err != nil || results[0].Err != nil {
					b.Fatal(err, results[0].Err)
				}
			}
		})
	}
}
