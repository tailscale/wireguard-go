package device

// Reproduction for a PERMANENT memory leak: tearing a peer down while a
// handshake is in flight leaves a stale entry in device.indexTable, and the
// peer's autodraining queues carry a finalizer that captures *device. A
// finalizable object trapped in a reference cycle is never collected by Go, so
// the whole *Device — including its 64 KiB PopulatePools packet buffers and all
// magicsock/netmap state hanging off it — leaks until the process exits. No
// goroutine is leaked and `go test -race` is clean, so the leak is invisible to
// goroutine-count and data-race detectors while RSS climbs without bound.
//
// THE CYCLE
//
//	device ──indexTable.table[idx]──▶ IndexTableEntry ──▶ peer
//	  ▲                                                     │
//	  │                                          peer.queue.inbound (q)
//	  │                                                     │
//	  └──────────── q's finalizer = device.flushInboundQueue (captures device)
//
// device/channels.go sets, for every peer queue:
//
//	runtime.SetFinalizer(q, device.flushInboundQueue)   // method value pins device
//
// Normally fine: peer.Stop() clears the peer's indexTable entry (via
// ZeroAndFlushAll), so after RemoveAllPeers the device no longer reaches the
// peer; the q→device finalizer is not in a cycle, runs, and everything collects.
//
// THE BUG (two coupled defects in wireguard-go)
//
//  1. peer.Stop() early-returns on !isRunning, so it runs ZeroAndFlushAll (the
//     indexTable cleanup) only on the FIRST stop:
//
//     func (peer *Peer) Stop() {
//         if !peer.isRunning.Swap(false) { return }   // 2nd stop / racing stop: skips cleanup
//         ...
//         peer.ZeroAndFlushAll()                      // indexTable.Delete + handshake.Clear
//     }
//
//  2. Re-arming a timer (Timer.Mod) and sending a handshake
//     (SendHandshakeInitiation → CreateMessageInitiation, which calls
//     indexTable.NewIndexForHandshake) are guarded by timersActive()
//     (isRunning && device.isUp()) but the guard check is NOT atomic with
//     Stop(). A handshake send (directly, or via a leaked pending handshake
//     timer that fires after the stop) can register a fresh indexTable entry
//     *after* ZeroAndFlushAll already ran. isRunning is now false, so no
//     subsequent Stop() will ever clear it. The stale entry + the queue
//     finalizer form the uncollectable cycle above.
//
// This is what a tsnet.Server / wgengine teardown that races the in-flight
// handshake pipeline (e.g. an instance that fails to start and is Close()d while
// it was connecting) hits in production.
//
// Affected: github.com/tailscale/wireguard-go@v0.0.0-20260427181203-e3ac4a0afb4e
// (the relevant files are identical on tailscale main's pin -b48af7099cad).
//
// Run:
//	go test ./device/ -run TestLeak -v
//	go test ./device/ -run TestLeak_StopRace -race

import (
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

func newLeakTestDevice(tb testing.TB) *Device {
	tb.Helper()
	tun := tuntest.NewChannelTUN().TUN()
	dev := NewDevice(tun, conn.NewDefaultBind(), NewLogger(LogLevelSilent, "leak"))
	sk, err := newPrivateKey()
	if err != nil {
		tb.Fatalf("newPrivateKey: %v", err)
	}
	if err := dev.SetPrivateKey(sk); err != nil {
		tb.Fatalf("SetPrivateKey: %v", err)
	}
	if err := dev.Up(); err != nil {
		tb.Fatalf("Up: %v", err)
	}
	return dev
}

func newLeakTestPeer(tb testing.TB, dev *Device) *Peer {
	tb.Helper()
	psk, err := newPrivateKey()
	if err != nil {
		tb.Fatalf("newPrivateKey: %v", err)
	}
	peer, err := dev.NewPeer(psk.publicKey())
	if err != nil {
		tb.Fatalf("NewPeer: %v", err)
	}
	return peer
}

// buildAndDrop creates a device + peer, runs setup against the (stopped) peer,
// closes the device, and returns ONLY a weak pointer to the device. Because
// dev/peer live in this frame and it returns before the caller GCs, no live
// stack slot or register can conservatively pin the device — so a non-nil
// wp.Value() after GC reflects a genuine heap reference, not a measurement
// artifact.
//
//go:noinline
func buildAndDrop(t *testing.T, setup func(p *Peer)) weak.Pointer[Device] {
	dev := newLeakTestDevice(t)
	peer := newLeakTestPeer(t, dev)
	peer.Start()
	peer.Stop() // clean stop: ZeroAndFlushAll runs, indexTable is clear
	setup(peer) // model what races/follows the stop
	dev.Close()
	return weak.Make(dev)
}

// leaks reports whether the device is still reachable after teardown + GC.
func leaks(t *testing.T, setup func(p *Peer)) bool {
	wp := buildAndDrop(t, setup)
	for i := 0; i < 10; i++ {
		runtime.GC()
	}
	time.Sleep(20 * time.Millisecond) // let any finalizer that *can* run, run
	for i := 0; i < 4; i++ {
		runtime.GC()
	}
	return wp.Value() != nil
}

// clearQueueFinalizers removes the device-capturing finalizers from a peer's
// queues — used only to prove they are the thing preventing collection.
func clearQueueFinalizers(p *Peer) {
	runtime.SetFinalizer(p.queue.inbound, nil)
	runtime.SetFinalizer(p.queue.outbound, nil)
}

// TestLeak_PermanentFinalizerCycle is the headline result: a stale indexTable
// entry combined with the queue's device-capturing finalizer makes the device
// uncollectable, and removing either the entry's effect (clean removal) or the
// finalizer lets it collect.
func TestLeak_PermanentFinalizerCycle(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(p *Peer)
		wantLeaks bool
	}{
		{
			// Clean teardown: no stale indexTable entry. Collects.
			name:      "clean removal",
			setup:     func(p *Peer) {},
			wantLeaks: false,
		},
		{
			// A handshake registers the peer in device.indexTable; the stale
			// entry + queue finalizer trap the device. Leaks forever.
			name:      "handshake leaves stale indexTable entry",
			setup:     func(p *Peer) { p.device.CreateMessageInitiation(p) },
			wantLeaks: true,
		},
		{
			// Same handshake, but drop the device-capturing finalizers: the
			// cycle is broken and the device collects. Proves the finalizer is
			// the thing preventing collection.
			name:      "handshake + queue finalizers cleared",
			setup:     func(p *Peer) { p.device.CreateMessageInitiation(p); clearQueueFinalizers(p) },
			wantLeaks: false,
		},
		{
			// No crypto at all — just the bare device→indexTable→peer edge.
			// Still leaks, proving the stale reference (not the handshake
			// machinery) is what matters.
			name:      "bare indexTable entry, no crypto",
			setup:     func(p *Peer) { p.device.indexTable.NewIndexForHandshake(p, &p.handshake) },
			wantLeaks: true,
		},
		{
			name:      "bare indexTable entry + finalizers cleared",
			setup:     func(p *Peer) { p.device.indexTable.NewIndexForHandshake(p, &p.handshake); clearQueueFinalizers(p) },
			wantLeaks: false,
		},
	}
	for _, c := range cases {
		got := leaks(t, c.setup)
		if got != c.wantLeaks {
			t.Errorf("%-44s leaked=%v, want %v", c.name, got, c.wantLeaks)
		} else {
			t.Logf("%-44s leaked=%v (as expected)", c.name, got)
		}
	}
}

// TestLeak_DoesNotSelfHeal shows the leak is NOT bounded by the timer lifetime.
// A leaked pending timer that fires re-pins the device permanently when its
// callback initiates a handshake (retransmitHandshake, newHandshake), because
// that re-creates the stale indexTable entry. The keepalive/zero-key timers,
// whose callbacks don't initiate a handshake, do self-heal.
func TestLeak_DoesNotSelfHeal(t *testing.T) {
	type tc struct {
		name        string
		pick        func(p *Peer) *Timer
		wantPermane bool
	}
	cases := []tc{
		{"retransmitHandshake", func(p *Peer) *Timer { return p.timers.retransmitHandshake }, true},
		{"newHandshake", func(p *Peer) *Timer { return p.timers.newHandshake }, true},
		{"sendKeepalive", func(p *Peer) *Timer { return p.timers.sendKeepalive }, false},
		{"zeroKeyMaterial", func(p *Peer) *Timer { return p.timers.zeroKeyMaterial }, false},
		{"persistentKeepalive", func(p *Peer) *Timer { return p.timers.persistentKeepalive }, false},
	}
	for _, c := range cases {
		// Raced Mod to a short duration, then wait long enough that it fires.
		stillPinnedAfterFire := leaks(t, func(p *Peer) {
			c.pick(p).Mod(80 * time.Millisecond)
			time.Sleep(220 * time.Millisecond) // timer fires during teardown window
		})
		if stillPinnedAfterFire != c.wantPermane {
			t.Errorf("%-22s permanent=%v, want %v", c.name, stillPinnedAfterFire, c.wantPermane)
		} else {
			verdict := "SELF-HEALED after fire"
			if stillPinnedAfterFire {
				verdict = "PERMANENT (re-pinned via handshake)"
			}
			t.Logf("%-22s -> %s", c.name, verdict)
		}
	}
}

// TestLeak_StopRace shows the leaked state arising from genuine concurrency with
// no hand-chosen interleaving: it races a real handshake send (which registers
// an indexTable entry) against Stop(), and counts how often the peer ends up
// stopped while still holding a stale indexTable entry — the uncollectable
// state. Run with -race to confirm this is NOT a data race (the detector stays
// silent; it is a logical check-then-act race).
func TestLeak_StopRace(t *testing.T) {
	dev := newLeakTestDevice(t)
	defer dev.Close()
	peer := newLeakTestPeer(t, dev)

	const iters = 100000
	staleAfterStop := 0
	for i := 0; i < iters; i++ {
		peer.Start()
		// Allow a fresh handshake send (SendHandshakeInitiation early-returns
		// if one was sent within RekeyTimeout).
		peer.handshake.mutex.Lock()
		peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
		peer.handshake.mutex.Unlock()

		done := make(chan struct{}, 2)
		go func() { peer.SendHandshakeInitiation(true); done <- struct{}{} }() // may register indexTable entry
		go func() { peer.Stop(); done <- struct{}{} }()                        // may run (or skip) ZeroAndFlushAll
		<-done
		<-done

		// Leaked state: peer is stopped, yet still owns an indexTable entry that
		// nothing will ever clear (a later Stop early-returns on !isRunning).
		peer.handshake.mutex.RLock()
		stale := !peer.isRunning.Load() && peer.handshake.localIndex != 0
		peer.handshake.mutex.RUnlock()
		if stale {
			staleAfterStop++
			peer.ZeroAndFlushAll() // clean up so the loop can continue
		}
	}

	t.Logf("over %d Start/handshake/Stop races, the peer was left stopped-with-stale-indexTable-entry %d times", iters, staleAfterStop)
	if staleAfterStop == 0 {
		t.Skip("did not hit the race window this run (timing-dependent); see TestLeak_PermanentFinalizerCycle for the deterministic proof")
	}
}
