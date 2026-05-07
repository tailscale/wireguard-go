# tsasm/arm -- 32-bit ARM crypto assembly

`golang.org/x/crypto/chacha20poly1305` ships no asm for `GOARCH=arm`
(32-bit ARM, any GOOS), so the WireGuard data-path AEAD falls back
to pure-Go and runs an order of magnitude slower than the same code
on amd64/arm64. This directory plugs a real assembly path into that
gap. The asm itself is GOOS-agnostic (Plan 9 ARM ABI, no syscalls);
build tags are just `arm` / `!arm`.

The asm is regenerated from the upstream
[CryptoGAMS](https://github.com/dot-asm/cryptogams) Perl scripts
(`chacha-armv4.pl`, `poly1305-armv4.pl`), which are vendored under
`upstream/`. Our `plan9-xlate.pl` post-processor turns the GAS-syntax
output into Go's Plan 9 ARM assembler dialect.

## Performance

1420-byte payload (a typical WireGuard packet), median of three runs.

All numbers in MB/s, AEAD Seal at 1420 B, 3 s benchtime.

| Hardware                                    | arm32 pure-Go | AF\_ALG NEON  | **arm32 asm (this)** | arm64 native\* |
|---------------------------------------------|---------------|---------------|----------------------|----------------|
| Pi 1 B+  ARM1176 700 MHz  ARMv6 (no NEON)  | 6.1           | 4.7 (slower!) | **14.7 scalar**      | n/a            |
| Pi 2 v1.1 A7    900 MHz  ARMv7+NEON        | 10.8          | --            | **30.7 NEON**        | n/a            |
| Pi 2 v1.2 A53   900 MHz  ARMv7+NEON        | 14.1          | --            | **54.3 NEON**        | 72.4           |
| Pi 3 B+   A53  1400 MHz  ARMv7+NEON        | 22            | --            | **84.6 NEON**        | 112.6          |
| Pi 4 B    A72  1500 MHz  ARMv7+NEON        | 50            | 73            | **132.3 NEON**       | 159.4          |

\* "arm64 native" is `x/crypto/chacha20poly1305` built and run as
`GOARCH=arm64` on the same hardware. It's not what this CL produces
— it's the upstream Go path you'd already get on those Pis if you
built 64-bit binaries. Listed here just so the arm32 numbers have
a ceiling to compare against; Pi 1 (ARMv6) and Pi 2 (Cortex-A7) are
32-bit only so the column is n/a.

AF\_ALG numbers are from commit 30595e7, which routed crypto through
the kernel's NEON driver via a socket; that helped on NEON hardware
but cost a syscall per chunk and was a net loss on ARMv6. The asm
path here:

- beats AF\_ALG on Pi 4 by ~1.8× (no kernel transition per chunk),
- still ~2.4× faster than pure-Go on Pi 1 where there's no NEON at
  all (we use CryptoGAMS's heavily optimized scalar inner loop).

The Go-side wrapper picks the path at runtime via `cpu.ARM.HasNEON`,
so a single binary works on both.

Setting `TS_WG_ASM=0` in the environment forces the data-path AEAD
back to the pure-Go x/crypto implementation as an escape hatch for
hardware quirks or asm bugs.

## License

Upstream CryptoGAMS files (`chacha-armv4.pl`, `poly1305-armv4.pl`,
`arm-xlate.pl` -- fetched on demand by `regen/regen.sh`, see below)
are **dual-licensed** under BSD-3-Clause and the OpenSSL license at
the holder's option. The generated `chacha20/chacha20_arm.s` and
`poly1305/poly1305_arm.s` inherit that dual license and carry the
full BSD-3-Clause text in their file headers (the CryptoGAMS license
requires the copyright notice to travel with source distributions).

Files written by us (`regen/plan9-xlate.pl`, `regen/neon_encode.pl`,
`regen/regen.sh`, `regen/arm_arch.h` (a minimal stub), the Go
wrappers) are BSD-3-Clause without the dual-license option.

The upstream `.pl` files are NOT vendored. `regen.sh` fetches them
from a Tailscale-hosted mirror of the CryptoGAMS distribution at a
pinned commit SHA, with a SHA256 check on each file. Updating
upstream is a SHA bump in `regen.sh` plus re-running it.

## Layout

```
regen/
  plan9-xlate.pl                       our GAS -> Plan 9 translator
  neon_encode.pl                       pure-Perl NEON instruction encoders
  neon_encode_test.pl                  dev tool: cross-check vs arm-as
  regen.sh                             pipeline driver, fetches upstream
  regen_test.go                        TestRegenReproducible
  arm_arch.h                           minimal stub (we don't want upstream's)
  .cache/                              gitignored; populated by regen.sh
chacha20/      Go wrapper + generated .s + tests for ChaCha20
poly1305/      same for Poly1305
chacha20poly1305/   AEAD glue + shared compat tests
```

The Go wrappers in `chacha20/` and `poly1305/` are tiny: arg
marshalling, `cpu.ARM.HasNEON` dispatch, and a fall-through to the
scalar entry point for any leftover bytes the NEON entry point can't
handle (see "Cross-function branches" below).

## Regenerate

    ./tsasm/arm/regen/regen.sh

(or `go generate ./tsasm/arm/...`).

Prerequisites: `perl`, `cc` (gcc or clang; we invoke `cc -E -P -x
assembler-with-cpp` rather than `cpp` directly so the pipeline is
deterministic across macOS's clang `cpp` wrapper and Linux GNU
`cpp`), `sh`, `curl`, `sha256sum`. Override with `CC=...` if you
need a specific compiler. The pipeline is pure Perl past the
upstream-fetch step -- no cross-assembler or `objcopy` needed.

`regen.sh` downloads the upstream CryptoGAMS .pl scripts on first run
and caches them in a gitignored `.cache/` directory. Each fetch is
verified against a SHA256 recorded in `regen.sh`.

`TestRegenReproducible` (`regen/regen_test.go`) runs the whole
pipeline and diffs against the committed `.s` files; if the diff is
non-empty it prints the first 30 differing lines so a stale
checked-in `.s` is self-explanatory.

`TestNEONEncoderAgainstGAS` (`regen/neon_encode_test.go`) extracts
every unique NEON line from the cached upstream `.S` files and
cross-checks the pure-Perl encoder against `arm-linux-gnueabihf-as`,
failing on any mismatch or skipped line. This is the validator that
keeps `neon_encode.pl` honest.

Both tests are gated: by default they skip. Pass `--run-regen-tests`
or set `CI=true` to opt in. Under `CI=true`, a missing dependency
fails the test rather than silently skipping (so CI images that
forget to install something break loudly). The full Debian/Ubuntu
package list to run everything:

    apt-get install perl gcc curl coreutils dash \
                    binutils-arm-linux-gnueabihf

## What `plan9-xlate.pl` actually has to do

Most of the GAS-to-Plan-9 mapping is mechanical (operand order
swap, register name changes, condition-code suffixes, etc.).
The non-obvious parts:

### Plan 9 frame layout vs upstream's view of SP (`sp_shift`)

Plan 9 ARM auto-saves LR at `0(SP)` and decrements SP by
`framesize+4` at function entry. Upstream GAS code thinks of SP as
already pointing at its first local. So every `[sp, #N]` in the body
must become `[R13, #N+4]` in our output. `plan9-xlate.pl` calls
this `sp_shift` and applies it to:

- Memory operands (`xlate_mem`)
- `add rD, sp, #N` immediates
- `mov rD, sp` (becomes `ADD $sp_shift, R13, RD`, not a bare reg
  copy)

NEON ops with a bare `[sp]` (no immediate slot to bump) get a
scratch-register dance: spill R12, set `R12 = SP + sp_shift`, run
the op against `[r12]`, reload R12. The ABI-callee-saved
`vldmia sp, {d8-d15}` in the chacha NEON epilogue is dropped -- the
Go ARM ABI doesn't require us to preserve d8-d15.

### R10 = g

Plan 9's R10 is the goroutine pointer; clobbering it segfaults at
the next async preemption. Upstream uses r10 as a regular scratch
in tight loops, so `plan9-xlate.pl` shadows upstream's r10 to a
frame slot, using R14 as the transient. R14's own value gets parked
in a dedicated `r14_save` slot during r10 ops. Consecutive r10 uses
in a straight-line block coalesce so we don't redundantly save and
reload R14.

Writeback forms (`ldr rD, [r10], #imm` post-incr; `[r10, #imm]!`
pre-incr) treat r10 as both src and dst: the post-incremented value
must flush back to the shadow slot so the next iteration sees the
new pointer.

### Frame size from prologue scan

CryptoGAMS layers its prologue: outer `stmdb sp!, {regs}`, optional
`vstmdb sp!, {d8-d15}` for the NEON ABI, an inner `stmdb`, and a
final `sub sp, #N`. `plan9-xlate.pl` walks the function body
linearly tracking the SP delta and uses the low-water mark as the
upstream framesize. Functions with multiple exit paths (chacha NEON
has a "switch frame" branch we replace with UDF, see below) don't
balance under linear simulation -- we trust the low-water and warn.

### NEON instructions

Go's ARM assembler rejects every NEON mnemonic, so each one becomes
a raw `WORD $0x...`. `neon_encode.pl` is a pure-Perl encoder for
the ARMv7-A NEON subset CryptoGAMS uses: `vadd.iSZ`, `veor`,
`vshl/vshr`, `vsli/vsri`, `vmlal`, `vmull`, `vrev32`, `vext.8`,
`vmov` (register + immediate forms), `vstr/vldr`, `vstmdb/vldmia`,
`vld1/vst1` (multi-element and single-element-to-lane),
`vld4/vst4` (multi-element and single-element-to-lane),
`vaddl`, and more. Each `enc_v*` sub cites the ARM-ARM section it
implements. A missing encoder is a fatal regen error (in
`batch_encode_neon`), not a shell-out to `gas` -- the regen
pipeline is hermetic past the `curl` step.

### Cross-function branches

Upstream chacha NEON has a `b .Loop` from the NEON entry into the
inner loop of the scalar function. Useful when both live in one C
.text section, unrepresentable in Plan 9 where each function has
its own TEXT directive. We replace those branches with `UDF`
(illegal-instruction trap) and have the Go-side wrapper avoid the
lengths that would hit them. Specifically chacha20 NEON only stays
inside its own function for `length` in 0..256, exact multiples of
256, or `256*K + R` with R in 129..255; XORKeyStream trims to a
safe length and sends any 1..128-byte tail through
`ChaCha20_ctr32`.

### Adjacent data labels (sigma + one + rot8)

CryptoGAMS chacha20 stores three constants in three contiguous
`.L*` labels and loads them with a single `adr` followed by
post-increment `vld1!` writebacks that march past 16 bytes at a
time. Plan 9's `name<>(SB)` symbols have no inter-symbol contiguity
guarantee from the linker, so naively emitting one GLOBL per label
would have the writebacks land on whatever else the linker placed
after the head. `scan_data_labels` folds adjacent label + `.long`
blocks into a single GLOBL named after the head label, with the
later labels recorded as no-emit aliases.
