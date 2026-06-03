package device

// Repro for a memory leak: a peer's per-peer timers (time.AfterFunc) can be
// left *pending* in the runtime timer heap after the peer is stopped, pinning
// the *Peer -> *Device -> the device's 64 KiB PopulatePools packet buffers for
// the (up to one hour) lifetime of the timer. No goroutine is leaked, so the
// leak is invisible to goroutine-based leak detectors while RSS climbs.
//
// Root cause: every .Mod() that arms a timer is guarded by timersActive()
// (isRunning && device.isUp()), but the guard check and the Mod are not atomic
// with Peer.Stop(). Peer.Stop() does:
//
//	if !peer.isRunning.Swap(false) { return }   // a 2nd Stop no-ops
//	...
//	peer.timersStop()                           // DelSync all 5 timers
//
// so a send/handshake goroutine that passes timersActive()==true, is then
// preempted while Stop() runs to completion (isRunning=false, timersStop()),
// and finally executes its .Mod(), re-arms a timer that nothing will ever
// stop again (isRunning is false, so timersStop() won't run a second time).
//
// Run: go test ./device/ -run TestTimerLeak -v
//
//	go test ./device/ -run TestTimerLeakRace -race -v

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

// TestTimerLeak demonstrates the leak deterministically by reproducing the
// exact interleaving the race produces: a Mod that lands just after Stop().
// It then proves, via a weak pointer, that the pending timer keeps the whole
// *Device alive after Close() and after every strong reference is dropped.
func TestTimerLeak(t *testing.T) {
	check := func(t *testing.T, racedMod bool) (alive bool) {
		dev := newLeakTestDevice(t)
		peer := newLeakTestPeer(t, dev)

		// Peer runs normally for a while (isRunning=true, device up): this is
		// the state in which a real handshake/keepalive send would pass the
		// timersActive() guard and be about to call .Mod().
		peer.Start()

		// Stop() runs to completion: isRunning=false, timersStop() DelSyncs all
		// timers (none pending yet, so this is a clean stop).
		peer.Stop()

		if racedMod {
			// The send goroutine that already passed timersActive()==true now
			// executes its .Mod(), AFTER timersStop() has run. This is the
			// raced ordering; the only difference from a benign run is timing.
			peer.timers.retransmitHandshake.Mod(time.Hour)

			if !peer.timers.retransmitHandshake.IsPending() {
				t.Fatal("expected timer pending after raced Mod")
			}
			// A second Stop() cannot save us: it early-returns on !isRunning.
			peer.Stop()
			if !peer.timers.retransmitHandshake.IsPending() {
				t.Fatal("timer unexpectedly cleared by second Stop()")
			}
		}

		// Tear the device down the way production does on instance shutdown.
		// Close() -> RemoveAllPeers() -> peer.Stop() (early-returns) and stops
		// the device's own worker goroutines, so nothing but a leaked timer can
		// keep the device alive.
		dev.Close()

		wp := weak.Make(dev)
		// Drop every strong reference we hold.
		peer = nil
		dev = nil
		_ = peer
		for i := 0; i < 6; i++ {
			runtime.GC()
		}
		return wp.Value() != nil
	}

	t.Run("clean-stop", func(t *testing.T) {
		if check(t, false) {
			t.Fatal("device still alive after clean stop+close (unexpected)")
		}
		t.Log("clean stop: device was collected (no leak), as expected")
	})

	t.Run("raced-mod", func(t *testing.T) {
		if !check(t, true) {
			t.Fatal("device was collected despite a pending timer (no leak reproduced)")
		}
		t.Log("LEAK REPRODUCED: a pending timer left after Stop() keeps the whole *Device (and its 64 KiB buffer pools) alive through Close() and GC")
	})
}

// TestTimerLeakRace shows the leak arising from genuine concurrency, with no
// hand-chosen interleaving: it races the real guarded send-path Mod
// (timersHandshakeInitiated) against Stop() and counts how often a timer ends
// up pending while the peer is stopped — the leaked state.
func TestTimerLeakRace(t *testing.T) {
	dev := newLeakTestDevice(t)
	defer dev.Close()
	peer := newLeakTestPeer(t, dev)

	const iters = 200000
	leaks := 0
	for i := 0; i < iters; i++ {
		peer.Start() // isRunning=true; timersActive() is now true (device is up)

		done := make(chan struct{}, 2)
		go func() {
			// Real send-path call: guarded by timersActive(), then Mod.
			peer.timersHandshakeInitiated()
			done <- struct{}{}
		}()
		go func() {
			peer.Stop()
			done <- struct{}{}
		}()
		<-done
		<-done

		// Leaked state: peer is stopped but a timer is still pending. Nothing
		// will ever stop it, so it pins peer->device until it fires (~RekeyTimeout
		// here, but up to an hour for the keepalive/zeroKey timers in practice).
		if !peer.isRunning.Load() && peer.timers.retransmitHandshake.IsPending() {
			leaks++
			peer.timers.retransmitHandshake.DelSync() // clean up so we can continue
		}
	}

	t.Logf("over %d Start/Stop races, the guarded send-path Mod landed after Stop() %d times (each leaks a pending timer pinning the device)", iters, leaks)
	if leaks == 0 {
		t.Skip("did not hit the race window this run (timing-dependent); see TestTimerLeak for the deterministic proof")
	}
}
