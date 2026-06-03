# wireguard-go: pending per-peer timer leaked when `Peer.Stop()` races a guarded `Timer.Mod()`

## Summary

A peer's per-peer timers (`device/timers.go`, created with `time.AfterFunc`) can be
left **pending in the runtime timer heap after the peer has been stopped**. Each leaked
timer's `AfterFunc` closure captures the `*Peer`, which references the `*Device`, which
owns the device's `PopulatePools` packet-buffer `sync.Pool`s (including the 64 KiB
`messageBuffers`, `new([MaxMessageSize]byte)`). So one leaked pending timer pins the
**entire device and its buffer pools** for the timer's lifetime (up to one hour).

Because the pin is a runtime *timer*, **no goroutine is leaked** — the leak is invisible
to goroutine-count / goroutine-profile leak detectors, and **`go test -race` does not flag
it** (it is a logical check-then-act race, not a memory data race). The only visible
symptom is climbing RSS in a process that repeatedly brings tsnet/wireguard devices up and
tears them down.

Affected version: `github.com/tailscale/wireguard-go@v0.0.0-20260427181203-e3ac4a0afb4e`
(the relevant files are identical on tailscale main's pin `…-b48af7099cad`).

## Root cause

Every `.Mod()` that arms a per-peer timer is guarded by `timersActive()`:

```go
func (peer *Peer) timersActive() bool {
	return peer.isRunning.Load() && peer.device != nil && peer.device.isUp()
}
```

e.g. on the send/handshake path:

```go
func (peer *Peer) timersHandshakeInitiated() {
	if peer.timersActive() {                       // (1) check
		peer.timers.retransmitHandshake.Mod(...)   // (3) arm
	}
}
```

`Peer.Stop()` clears `isRunning` and stops the timers:

```go
func (peer *Peer) Stop() {
	peer.state.Lock()
	defer peer.state.Unlock()
	if !peer.isRunning.Swap(false) { // (2) a 2nd Stop() no-ops here
		return
	}
	...
	peer.timersStop() // DelSync all 5 timers
	...
}
```

The guard check (1) and the arming `.Mod()` (3) are **not atomic with respect to
`Stop()`**. If a send/handshake goroutine evaluates `timersActive() == true`, is then
preempted while `Stop()` runs to completion (`isRunning=false`, `timersStop()`), and finally
runs its `.Mod()`, it **re-arms a timer after `timersStop()` already ran**. Since
`isRunning` is now false, a subsequent `Stop()` early-returns at (2) and never calls
`timersStop()` again, so the timer stays pending until it fires — pinning `peer → device →
buffer pools` the whole time.

This is exactly the state produced when a device is brought up and is actively handshaking
(timers active) and is then **closed concurrently with the in-flight handshake** — i.e. a
`tsnet.Server` / `wgengine` shutdown that races the running packet pipeline.

## Reproduction

`device/leakrepro_test.go` (a package-internal `device` test).

### Deterministic — `go test ./device/ -run 'TestTimerLeak$' -v`

Reproduces the raced ordering explicitly (`Start` → `Stop` → the raced `Mod`), then uses a
`weak.Pointer[Device]` to prove the device survives `Close()` and GC:

```
=== RUN   TestTimerLeak/clean-stop
    clean stop: device was collected (no leak), as expected
=== RUN   TestTimerLeak/raced-mod
    LEAK REPRODUCED: a pending timer left after Stop() keeps the whole *Device
    (and its 64 KiB buffer pools) alive through Close() and GC
--- PASS: TestTimerLeak
```

### Genuine concurrency — `go test ./device/ -run TestTimerLeakRace -v`

Races the real guarded send-path call against `Stop()` and counts leaked-pending timers:

```
over 200000 Start/Stop races, the guarded send-path Mod landed after Stop()
17 times (each leaks a pending timer pinning the device)
```

`go test ./device/ -run TestTimerLeakRace -race` passes clean — confirming the race
detector does not catch this (it is not a data race).

## Suggested fix direction

Serialize timer arming with `Stop()` so a `.Mod()` cannot survive `timersStop()`. Options:

- Make `Timer.Mod` a no-op (or `Stop` the underlying timer) when the owning peer is not
  running, checked under the same lock `Stop()`/`timersStop()` use; or
- Have the guarded arming sites hold `peer.state` (or a dedicated timers lock) across the
  `timersActive()` check **and** the `.Mod()`, the same lock `Stop()` holds; or
- Have `timersStop()` set a "stopped" flag under `Timer.modifyingLock` that `Mod()` honors,
  so a late `Mod()` after stop is dropped.

## Downstream impact (Aperture)

Aperture's supervisor hosts proxy instances on in-process `tsnet.Server`s. A
misconfigured instance crash-loops (start → connect → fail → `Close()` every ~5 s); each
teardown races the just-started handshake pipeline and leaks pending peer timers, growing
RSS ~5–7 MiB per restart (observed climbing past ~24 GB; reproduced locally to ~1.9 GB).
Mitigations independent of the wireguard fix: stop the crash loop (fix the failing config),
and/or reuse one connected `tsnet.Server` across proxy rebuilds instead of create/teardown
per restart.
