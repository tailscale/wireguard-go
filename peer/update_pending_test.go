// SPDX-License-Identifier: MIT

package peer

import (
	"errors"
	"testing"
	"time"
)

func TestPendingRequiresConfirmableResponderKey(t *testing.T) {
	for _, mode := range []string{"SameKeyRotation", "DifferentKeyRotation", "FailedReplacement", "Expiry"} {
		t.Run(mode, func(t *testing.T) {
			q := newPair(t, Config{})
			init, _, err := q.a.Initiate(epoch, control())
			if err != nil {
				t.Fatal(err)
			}
			response, u, err := q.b.HandleInitiation(epoch, prepare(t, admit(t, q.ab, epoch, init)), control())
			if err != nil || !u.Handshake.Pending {
				t.Fatal("live responder key is not pending", u, err)
			}
			confirmation, _, err := q.a.HandleResponse(epoch, admit(t, q.aa, epoch, response), control())
			if err != nil {
				t.Fatal(err)
			}
			next := q.b.keypairs.next
			index := next.localIndex
			at := epoch.Add(time.Second)
			if mode == "Expiry" {
				at = epoch.Add(RejectAfterTime)
				r, err := q.b.Send(at.Add(-time.Nanosecond), nil)
				if err != nil || !r.Update.Handshake.Pending {
					t.Fatal("confirmation eligibility ended early", r, err)
				}
			} else {
				var provider Static = q.ib
				switch mode {
				case "DifferentKeyRotation":
					key, err := NewPrivateKey()
					if err != nil {
						t.Fatal(err)
					}
					provider = NewIdentity(key)
				case "FailedReplacement":
					provider = errorIdentity{q.ib.Public()}
				}
				u, err = q.b.ReplaceIdentity(at, localIdentity(t, 2, provider))
				if (err != nil) != (mode == "FailedReplacement") {
					t.Fatal("replacement", err)
				}
				if u.Handshake.Pending {
					t.Error("receive-only old generation reported pending after replacement")
				}
			}

			var results [1]ReceiveResult
			r, err := q.b.Receive(at, []Packet{confirmation}, results[:])
			if err != nil || r.N != 1 {
				t.Fatal(r, err)
			}
			if mode == "Expiry" {
				if !errors.Is(results[0].Err, ErrTransport) || results[0].Disposition != Dropped {
					t.Fatal("expired confirmation accepted", results[0])
				}
			} else if results[0].Err != nil || results[0].Disposition != Keepalive {
				t.Fatal("old-generation receive grace rejected", results[0])
			}
			if r.Update.Handshake.Pending || r.Update.Handshake.Reasons&HandshakeNoSession == 0 {
				t.Error("unconfirmable responder key reported pending", r.Update)
			}
			if q.b.keypairs.next != next || q.b.keypairs.current != nil || !q.b.LastHandshake().IsZero() {
				t.Fatal("unconfirmable key promoted or completed handshake")
			}
			if owner, ok := q.indexes.Lookup(index); !ok || owner != q.b {
				t.Fatal("pending advice change retired receive index early")
			}
			cleanup := epoch.Add(3 * RejectAfterTime)
			if r.Update.Wake.Earliest != cleanup || r.Update.Wake.Deadline != cleanup {
				t.Fatal("receive retention lost hard cleanup schedule", r.Update)
			}
			r, err = q.b.HandleWake(cleanup, nil)
			if err != nil || r.N != 0 || r.Update.Handshake.Pending || !r.Update.Wake.Earliest.IsZero() || q.b.keypairs.next != nil {
				t.Fatal("cleanup", r, err)
			}
			if _, ok := q.indexes.Lookup(index); ok {
				t.Fatal("receive index leaked after cleanup")
			}
		})
	}
}
