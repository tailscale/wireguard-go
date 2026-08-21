# tsasm/amd64 -- x86-64 crypto assembly for pre-AVX2 CPUs

`golang.org/x/crypto/chacha20poly1305` used to ship an SSE assembly
kernel that ran on any amd64 CPU with SSSE3. It was deleted in
x/crypto commit
[`7ee5970`](https://github.com/golang/crypto/commit/7ee5970)
("chacha20poly1305: drop pre-AVX assembly impl"), which shipped in
v0.52.0 on 2026-05-21. The commit removed 4502 lines of assembly and
changed the dispatch gate from `HasSSSE3` to
`HasSSSE3 && HasAVX2 && HasBMI2`, so an amd64 CPU without AVX2 now
gets no assembly at all and the WireGuard data-path AEAD falls back to
generic Go at roughly half the throughput. The upstream rationale is in
[golang/go#69587](https://github.com/golang/go/issues/69587): "I don't
think at this point they are worth their maintenance cost."

This directory restores that path for exactly the CPUs that lost it.
CPUs with AVX2 are not routed here and keep using x/crypto's
maintained AVX2 kernel.

## Which CPUs this is for

Not only old ones. Intel's entire Atom line had no AVX of any kind
until Gracemont in 2021, and the first Atom-derived part with AVX2 is
Alder Lake-N (N100) in 2023, so a great deal of hardware still sold as
router, firewall and NAS silicon is on the generic Go path:

| CPU family | Codename | Introduced | Where it shows up |
|---|---|---|---|
| Atom N5105/N6005, Celeron N4500, Pentium N6000 | Jasper Lake | 2021 | the ubiquitous 4x/6x i226 fanless firewall box |
| Atom x6000E, Celeron J6412 | Elkhart Lake | 2021 | industrial and embedded network appliances |
| Atom C3000 | Denverton | 2017 | Supermicro and QNAP storage/network appliances |
| Celeron J4125/J5005, Pentium Silver | Gemini Lake | 2017 | thin clients, cheap NAS, Dell Wyse 5070 |
| Celeron N3350, Pentium J3455 | Apollo Lake | 2016 | thin clients, embedded |
| Atom C2000 | Rangeley | 2013 | Netgate/pfSense appliances, Supermicro A1SRi |
| AMD GX-400 series embedded | Jaguar | 2013 | Netgate/pfSense appliances (AVX1, but no AVX2) |
| Celeron 3865U, Celeron 5205U | Kaby Lake-U, Comet Lake-U | 2017-2019 | AVX2 fused off at the SKU level; Comet Lake-U shipped into the 2020s |
| Haswell/Broadwell Celeron and Pentium | | 2013 | AVX fused off at the SKU level |
| Everything Intel before Sandy Bridge | | 2006-2010 | Core 2, Nehalem, Westmere |
| Everything AMD before Excavator | | 2011-2015 | Bobcat, Jaguar, Bulldozer, Piledriver |

## Performance

Host-only AEAD throughput with no network and no other goroutines, so
this is the cipher and nothing else. Gbit/s of plaintext, Seal,
1420-byte payloads (a typical WireGuard data packet), maximum across
three repetitions, `performance` governor, go1.26.5.

| Hardware | topology | generic Go | **this asm** | ratio |
|---|---|---|---|---|
| Xeon E5-2697 v2, Ivy Bridge-EP | 12C/24T | 30.803 | **61.077** | **1.98x** |
| Xeon E5520, Nehalem, dual socket | 8C/16T | 10.801 | **22.523** | **2.09x** |
| Pentium J5005, Goldmont Plus | 4C | 5.503 | **13.643** | **2.48x** |
| Core i5-2450M, Sandy Bridge | 2C/4T | 4.309 | **9.558** | **2.22x** |
| Core 2 Duo P8700, Penryn | 2C | 3.039 | **5.828** | **1.92x** |
| Celeron 5205U, Comet Lake (AVX2 fused off) | 2C | 1.753 | **3.672** | **2.09x** |
| Celeron 3865U, Kaby Lake (AVX2 fused off) | 2C | 1.664 | **3.475** | **2.09x** |
| AMD G-T40N, Bobcat | 2C | **0.982** | 0.614 | **0.63x** |

Single-core figures agree with the same ratio on all eight.

**Bobcat is a real regression and is called out deliberately.** Its
SIMD datapath is 64 bits wide and double-pumps every 128-bit
operation, so a vector kernel loses to scalar Go there. `HasSSSE3` is
true on Bobcat, so a CPUID-only gate re-regresses it. It was measured
end to end as well: 236 Mbps with this assembly against 264 Mbps
without. Bobcat parts are rare enough (AMD C-30/C-50/C-60/E-350 era
netbooks and a few thin clients) that no family exclusion is wired up
here; `TS_WG_ASM=0` is the remedy if anyone hits it. Jaguar (family
16h) has a 128-bit datapath and AVX1 and has not been measured.

End to end through a real tunnel the effect is smaller, because crypto
is only about a fifth of the WireGuard datapath: roughly **20% less
`tailscaled` CPU per byte** on affected hardware, and **no change in
throughput** on a gigabit link, since these machines are limited by
the link or by per-peer sender serialisation rather than by crypto.
Quote it as "about 20% less CPU, no faster", not as "2x".

Setting `TS_WG_ASM=0` in the environment forces the data-path AEAD
back to x/crypto, as an escape hatch for hardware quirks or asm bugs.
This matches `tsasm/arm`.

## Provenance and license

The generator here is the avo program x/crypto deleted, taken from
`chacha20poly1305/_asm/chacha20poly1305_amd64_asm.go` at `7ee5970^`
with three lines changed:

- the `Package()` argument, retargeted to this package's import path,
- the blank import, retargeted the same way (it exists so the
  generator's module graph reaches the package whose function
  signatures avo reads),
- `_asm/go.mod`, which names this module and bumps
  `golang.org/x/tools` because avo v0.6.0's pinned v0.24.0 does not
  compile under go1.26.

`avo` itself is still pinned at the v0.6.0 that upstream used, and the
generated `chacha20poly1305_amd64.s` is **byte-for-byte identical** to
the 9762-line file `7ee5970` deleted. `TestUpstreamProvenance` guards
that claim.

Everything here is BSD-3-Clause, the same license as x/crypto, with no
CryptoGAMS dual-license complication of the kind `tsasm/arm` carries.
The original assembly was contributed to Go by Vlad Krasnov of
CloudFlare in [CL 24717](https://golang.org/cl/24717).

## Layout

Unlike `tsasm/arm` and the proposed `tsasm/mips`, there are no separate
`chacha20/` and `poly1305/` subdirectories. Those exist for arm and
mips because their kernels are separate primitives that Go-side glue
stitches into an AEAD. This kernel is **fused**: `chacha20Poly1305Seal`
is one assembly function that interleaves Poly1305 multiplications into
the ChaCha20 round schedule, which is the entire reason it is fast.
There is no separable ChaCha20 or Poly1305 entry point to put in its
own directory.

```
chacha20poly1305/
  _asm/                          the avo generator (its own module, so avo
                                 never enters wireguard-go's go.mod)
    chacha20poly1305_amd64_asm.go
    go.mod, go.sum
  chacha20poly1305.go            AEAD wrapper and CPU gate
  chacha20poly1305_amd64.s       generated; do not edit
  aead_compat_test.go            differential tests and benchmarks vs x/crypto
  regen_test.go                  reproducibility and provenance tests
```

## Regenerate

    cd tsasm/amd64/chacha20poly1305/_asm && go generate ./...

Prerequisites: the Go toolchain, and the `avo` module in the module
cache. Nothing else. No perl, no C compiler, no cross-assembler, and
no network fetch of upstream sources.

The generator must run with `GOARCH=amd64`, because avo reads the
function signatures of the `//go:noescape` declarations out of the
target package and those files are amd64-only. On an amd64 host that
is automatic. On another host, `GOARCH=amd64 go generate ./...` works
if the platform can execute amd64 binaries (Rosetta 2 on Apple
silicon, for instance).

`TestRegenReproducible` runs the whole pipeline and diffs against the
checked-in `.s`, printing the first 30 differing lines. It is gated:
pass `--run-regen-tests` or set `CI=true`.
