# wireguard-go: permanent device leak from a stale `indexTable` entry trapped in a queue-finalizer cycle

## Summary

Tearing a peer down while a handshake is in flight can leave a stale entry in
`device.indexTable` that points at the removed peer. Because each peer's
autodraining queues carry a finalizer that **captures `*device`**, that stale
`device → peer → queue → finalizer → device` reference forms a cycle containing
a finalizable object — which the Go runtime **never collects** ("there is no
ordering that respects the dependencies"). The entire `*Device` leaks: its
64 KiB `PopulatePools` packet buffers, plus all magicsock/netmap/peer state
hanging off it.

The leak is **permanent** (it is *not* bounded by any timer lifetime — see
below), and it is **invisible to the usual detectors**: no goroutine is leaked,
and `go test -race` is silent because this is a logical check-then-act race, not
a data race. The only external symptom is RSS climbing without bound in a
process that repeatedly brings wireguard/tsnet devices up and tears them down.

Affected: `github.com/tailscale/wireguard-go@v0.0.0-20260427181203-e3ac4a0afb4e`
(the relevant files are byte-identical on tailscale main's pin `-b48af7099cad`,
so this is not version-specific).

## The cycle

```
device ──indexTable.table[idx]──▶ IndexTableEntry ──▶ peer
  ▲                                                    │
  │                                         peer.queue.inbound (q)
  │                                                    │
  └─────────── q's finalizer = device.flushInboundQueue  (method value pins device)
```

`device/channels.go` (`newAutodraining{In,Out}boundQueue`) attaches, for every
peer queue:

```go
runtime.SetFinalizer(q, device.flushInboundQueue)   // bound method value -> captures *device
```

In normal operation this is harmless: `peer.Stop()` clears the peer's
`indexTable` entry (via `ZeroAndFlushAll`), so after `RemoveAllPeers` the device
no longer reaches the peer. The `q → device` finalizer is then *not* part of a
cycle, runs, and the whole graph collects.

## Root cause — two coupled defects

**(1) `Peer.Stop()` runs its cleanup only on the first stop.** It early-returns
on `!isRunning`, so the `indexTable` cleanup (`ZeroAndFlushAll`) is skipped on a
second/racing stop:

```go
func (peer *Peer) Stop() {
    peer.state.Lock(); defer peer.state.Unlock()
    if !peer.isRunning.Swap(false) { return }   // racing/2nd stop: skips cleanup below
    ...
    peer.ZeroAndFlushAll()                       // device.indexTable.Delete + handshake.Clear
}
```

**(2) Registering an `indexTable` entry races `Stop()`.** Arming a timer
(`Timer.Mod`) and sending a handshake (`SendHandshakeInitiation` →
`CreateMessageInitiation` → `indexTable.NewIndexForHandshake`) are guarded by
`timersActive()` (`isRunning && device.isUp()`), but the guard check is **not
atomic** with `Stop()`. A handshake send — directly, or via a leaked *pending*
handshake timer that fires after the stop — can register a fresh `indexTable`
entry **after** `ZeroAndFlushAll` has already run. `isRunning` is now false, so
no later `Stop()` will ever clear it. The stale entry + the queue finalizer are
the cycle above.

This is precisely what a `tsnet.Server` / `wgengine` shutdown that races the
in-flight handshake pipeline hits (an instance that fails to start and is
`Close()`d while it was still connecting).

## Reproduction

`device/leakrepro_test.go` — a package-internal `device` test. Liveness is
measured with a `weak.Pointer[Device]` taken in a helper that fully returns
before GC, so a dead stack slot / register cannot masquerade as a leak.

### `go test ./device/ -run TestLeak_PermanentFinalizerCycle -v`

```
clean removal                                leaked=false (as expected)
handshake leaves stale indexTable entry      leaked=true  (as expected)
handshake + queue finalizers cleared         leaked=false (as expected)   <- clearing the finalizer frees it
bare indexTable entry, no crypto             leaked=true  (as expected)   <- the stale edge alone is enough
bare indexTable entry + finalizers cleared   leaked=false (as expected)
```

This isolates the mechanism to exactly the stale `indexTable` edge **and** the
device-capturing queue finalizer: remove either and the device collects.

### `go test ./device/ -run TestLeak_DoesNotSelfHeal -v`

Proves the leak is not timer-lifetime-bounded. A leaked *pending* timer that
fires re-pins the device permanently when its callback initiates a handshake
(`retransmitHandshake`, `newHandshake`), because that re-creates the stale
`indexTable` entry:

```
retransmitHandshake    -> PERMANENT (re-pinned via handshake)
newHandshake           -> PERMANENT (re-pinned via handshake)
sendKeepalive          -> SELF-HEALED after fire
zeroKeyMaterial        -> SELF-HEALED after fire
persistentKeepalive    -> SELF-HEALED after fire
```

(For context: the `time.Hour` in `NewTimer` is never the live duration — a timer
is only *pending* once `Mod()` overwrites it, so a pending timer lasts ~5–15 s
for the handshake timers and at most `RejectAfterTime*3` ≈ 9 min for
`zeroKeyMaterial`. The permanent leak outlives all of these.)

### `go test ./device/ -run TestLeak_StopRace [-race]`

Genuine concurrency, no hand-chosen interleaving: races a real handshake send
against `Stop()` and counts how often the peer is left stopped while still
owning an `indexTable` entry.

```
over 100000 Start/handshake/Stop races, the peer was left
stopped-with-stale-indexTable-entry 32568 times
```

`-race` passes clean — confirming the detector does not catch this.

## Suggested fix direction

Either break the stale reference or break the finalizer cycle:

- **Clear the peer's `indexTable` entries on removal unconditionally** — make
  `removePeerLocked` (or `RemoveAllPeers`) call `ZeroAndFlushAll`/`indexTable`
  cleanup directly rather than relying on `Stop()`'s `isRunning`-gated path.
  This removes the `device → peer` edge so the cycle can't form even if a stale
  entry is registered. (Most targeted fix.)
- **Don't capture `device` in the queue finalizer** — give `flushInboundQueue`/
  `flushOutboundQueue` the state they need without a `*device` method value, so
  a stale `device → … → queue` reference is never a finalizer cycle.
- **Serialize timer arming / handshake registration with `Stop()`** so an
  `indexTable` entry (or `Timer.Mod`) cannot land after the stop's cleanup.

## Downstream impact (Aperture)

Aperture's supervisor hosts proxy instances on in-process `tsnet.Server`s. A
misconfigured instance crash-loops (start → connect → fail → `Close()` every
~5 s); each teardown races the just-started handshake pipeline and permanently
leaks a device (with its peers' 64 KiB buffers and netmap/magicsock state).
Because the leak is permanent rather than bounded, RSS climbs without plateauing
(observed past ~24 GB; reproduced locally to ~1.9 GB and still climbing). The
runtime timer heap and per-P `sync.Pool` caches both showed the retained device
buffers in a live heap-reference graph (grf).

Mitigations independent of the wireguard fix: stop the crash loop (fix the
failing config), and/or reuse one connected `tsnet.Server` across proxy rebuilds
instead of create/teardown per restart.
