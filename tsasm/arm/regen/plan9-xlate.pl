#! /usr/bin/env perl
# SPDX-License-Identifier: BSD-3-Clause
#
# plan9-xlate.pl: post-processor that translates linux32 GAS ARMv4
# assembly emitted by CryptoGAMS scripts (chacha-armv4.pl,
# poly1305-armv4.pl, post-processed by arm-xlate.pl) into Go's Plan 9
# ARM assembler syntax.
#
# Pipeline:
#
#     perl chacha-armv4.pl linux32 chacha-armv4.S       # upstream GAS
#     cpp -P -I. -D__ARM_ARCH__=6 chacha-armv4.S \
#       | perl plan9-xlate.pl > chacha20_arm.s
#
# Input grammar: anything chacha-armv4.pl + poly1305-armv4.pl emit when
# fed to arm-xlate.pl with flavour=linux32, plus a small set of GAS
# directives (.globl, .type, .size, .align, .text, .long, .word, label
# definitions, comments).
#
# The upstream .pl scripts are NOT vendored: regen.sh fetches them
# at a pinned commit SHA into .cache/ and verifies sha256. Do NOT
# edit anything in .cache/; if you need the regenerator to behave
# differently, change plan9-xlate.pl or neon_encode.pl here.

use strict;
use warnings;
use Getopt::Long;
use FindBin;

# Pure-Perl NEON instruction encoders. See neon_encode.pl.
require "$FindBin::Bin/neon_encode.pl";

# Command-line flags.
#   --only=<regex>   only emit functions whose name matches this regex
#                    (used to extract just the NEON entry points from
#                    a __ARM_MAX_ARCH__=7 build that contains both
#                    scalar and NEON code).
my $opt_only;
GetOptions("only=s" => \$opt_only) or die "bad arguments";

# Shared state used by the per-function passes. Defined at file scope
# so xlate_mem (which runs early in the call chain) can read it.
our $cur_func;       # name of function currently being emitted (or undef)
our $cur_funcsize;   # framesize for current function
our $sp_shift;       # bytes to add to body [sp,#N] references inside a
                     # function (= 4 to skip Plan 9's saved-LR slot, +
                     # any extra-locals contribution baked into our
                     # frame layout).
our $shadow_r10_off; # frame offset of the spill slot used as a stand-in
                     # for upstream's r10 register. We don't keep r10
                     # in the actual R10 (Plan 9 maps R10 to g, the
                     # goroutine pointer; clobbering it breaks signal-
                     # based async preemption) -- instead, every body
                     # instruction that mentions r10 is rewritten to
                     # use R14 as a scratch and load/store this slot
                     # around the use.
our $r14_save_off;   # extra frame slot used to preserve R14 across
                     # the r10 spill machinery, since R14 is also
                     # used by upstream as a scratch (lr holding the
                     # input pointer or temporary arithmetic results)
                     # and we mustn't clobber it.
our $r14_holds_shadow; # within a straight-line code window, true if
                       # R14 currently holds shadow_r10's value
                       # (loaded by a prior r10 spill and not yet
                       # overwritten). Used to coalesce consecutive
                       # r10 spills: when this is set we can skip
                       # the R14-save / shadow-load pair at the next
                       # r10 use. Reset on every label and branch
                       # because we can't track across control flow.

# Cache of NEON GAS lines to their encoded 32-bit words. Plan 9's
# arm assembler accepts no NEON mnemonics, so each one becomes a
# raw `WORD $0x...`. We assemble all unique NEON lines through
# arm-linux-gnueabihf-as in a single batch (see batch_encode_neon)
# and look the result up here.
our %NEON_ENC;

################################################################
# Function signatures.
#
# Plan 9 ARM uses FP-relative argument access (e.g. arg+0(FP)). The
# upstream GAS code accesses arguments via R0..R3 already in registers
# at function entry (standard EABI). The translator needs to know each
# function's Go-side signature so it can emit a TEXT directive with the
# right argsize and (eventually) name FP-relative loads.
#
# Format: name => {
#     args     => [[name, off, size], ...]  describing each arg slot,
#     argsize  => total size in bytes,
# }
my %SIGS = (
    poly1305_init => {
        args    => [["ctx", 0, 4], ["key", 4, 4]],
        argsize => 8,
    },
    poly1305_blocks => {
        args    => [["ctx", 0, 4], ["inp", 4, 4], ["len", 8, 4], ["padbit", 12, 4]],
        argsize => 16,
    },
    poly1305_emit => {
        args    => [["ctx", 0, 4], ["mac", 4, 4], ["nonce", 8, 4]],
        argsize => 12,
    },
    ChaCha20_ctr32 => {
        args    => [["out", 0, 4], ["inp", 4, 4], ["len", 8, 4],
                    ["key", 12, 4], ["ctr_nonce", 16, 4]],
        argsize => 20,
    },
    ChaCha20_neon => {
        args    => [["out", 0, 4], ["inp", 4, 4], ["len", 8, 4],
                    ["key", 12, 4], ["ctr_nonce", 16, 4]],
        argsize => 20,
    },
    poly1305_init_neon => {
        args    => [["ctx", 0, 4], ["key", 4, 4]],
        argsize => 8,
    },
    poly1305_blocks_neon => {
        args    => [["ctx", 0, 4], ["inp", 4, 4], ["len", 8, 4], ["padbit", 12, 4]],
        argsize => 16,
    },
    poly1305_emit_neon => {
        args    => [["ctx", 0, 4], ["mac", 4, 4], ["nonce", 8, 4]],
        argsize => 12,
    },
);

################################################################
# Operand translation (single token).

# xlate_reg maps a GAS-style register name to its Plan 9 spelling.
# Plan 9's R10 is the goroutine pointer (g) and is reserved by Go's
# runtime for signal-based async preemption. We never let upstream
# r10 land on the physical R10; the per-instruction wrapper around
# xlate_insn rewrites all `r10` operands to `r14` (with stack
# load/store on each side), so xlate_reg should never actually see
# `r10` from the wrapped path.
sub xlate_reg {
    my $r = shift;
    return "R13" if $r eq "sp";
    return "R14" if $r eq "lr";
    return "R15" if $r eq "pc";
    return "R12" if $r eq "ip";
    if ($r =~ /^r(\d+)$/) {
        return "R$1";
    }
    return undef;
}

# xlate_imm maps a GAS-style immediate (#NN) to its Plan 9 spelling.
sub xlate_imm {
    my $imm = shift;
    if ($imm =~ /^#(.*)$/) {
        return "\$$1";
    }
    return undef;
}

# xlate_shifted_reg maps a GAS-style shifted/rotated register operand
# (e.g. "r2, lsl#3" or "r2, ror#13") to its Plan 9 spelling
# ("R2<<3", "R2@>13"). Returns undef if not a shifted register.
sub xlate_shifted_reg {
    my $s = shift;
    if ($s =~ /^(r\d+|sp|lr|pc|ip),\s*(lsl|lsr|asr|ror)\s*#(\d+)$/) {
        my ($r, $op, $n) = ($1, $2, $3);
        my $R = xlate_reg($r);
        return "${R}<<$n"  if $op eq "lsl";
        return "${R}>>$n"  if $op eq "lsr";
        return "${R}->$n"  if $op eq "asr";
        return "${R}\@>$n" if $op eq "ror";
    }
    return undef;
}

# eval_const evaluates a small subset of GAS constant expressions made
# up of integer literals (decimal or 0x... hex), parens, and the
# operators + - * /. Returns the integer result. CryptoGAMS uses these
# in offset arithmetic like 4*(16+10) for stack slot indexing.
sub eval_const {
    my $s = shift;
    return undef unless defined $s;
    # Sanitize. Disallow anything outside the small grammar (decimal
    # digits, parens, +-*/ operators, and hex literals with a-f).
    return undef unless $s =~ m{^[\s\d+\-*/()xa-fA-F]+$};
    # Convert 0xN hex to a form Perl eval understands.
    $s =~ s/0x([0-9a-fA-F]+)/hex("0x$1")/ge;
    my $v = eval $s;
    return undef if $@;
    return int($v);
}

# adjust_sp_offset adds the current $sp_shift to a memory offset when
# the base register is sp. Plan 9's auto-prologue reserves 0(SP) for
# the saved LR, so upstream `[sp, #N]` references must be shifted up by
# 4 bytes to match the layout we emit for the local frame.
sub adjust_sp_offset {
    my ($base, $imm) = @_;
    my $n = eval_const($imm);
    $n //= ($imm =~ /^-?\d+$/) ? int($imm) : 0;
    return $n unless defined($sp_shift) && $base eq "sp";
    return $n + $sp_shift;
}

# adjust_neon_sp_offsets rewrites any [sp, #expr] memory operand in
# a NEON GAS line, evaluating the expression and adding the current
# sp_shift. Used before passing the line to encode_neon so that
# upstream offsets get the same +4 bump xlate_mem applies elsewhere.
sub adjust_neon_sp_offsets {
    my ($line, $shift) = @_;
    $line =~ s{\[sp\s*,\s*#([^\]]+)\]}{
        my $expr = $1;
        my $v    = eval_const($expr);
        $v       = int($expr) if !defined($v) && $expr =~ /^-?\d+$/;
        defined($v) ? "[sp, #" . ($v + $shift) . "]" : "[sp, #$expr]";
    }ge;
    return $line;
}

# xlate_mem maps a GAS-style memory operand to its Plan 9 spelling.
# Returns (operand_text, suffix) where suffix is "" / ".W" (pre-incr
# writeback) / ".P" (post-incr).
sub xlate_mem {
    my $m = shift;
    # Plain "[rN]".
    if ($m =~ /^\[(r\d+|sp|lr|pc|ip)\]$/) {
        my $base = $1;
        # If sp_shift is active and base is sp, an offset-less form
        # implicitly references offset 0; emit "shift(R13)" instead.
        if (defined($sp_shift) && $base eq "sp") {
            return ("$sp_shift(R13)", "");
        }
        return ("(" . xlate_reg($base) . ")", "");
    }
    # "[rN, #imm]" -- no writeback. The immediate may be a constant
    # expression like 4*(16+10).
    if ($m =~ /^\[(r\d+|sp|lr|pc|ip),\s*#([-+\s\d*\/()x]+)\]$/) {
        my $imm = adjust_sp_offset($1, $2);
        return ("$imm(" . xlate_reg($1) . ")", "");
    }
    # "[rN, #imm]!" -- pre-increment with writeback.
    if ($m =~ /^\[(r\d+|sp|lr|pc|ip),\s*#([-+\s\d*\/()x]+)\]!$/) {
        my $imm = adjust_sp_offset($1, $2);
        return ("$imm(" . xlate_reg($1) . ")", ".W");
    }
    # "[rN], #imm" -- post-increment.
    if ($m =~ /^\[(r\d+|sp|lr|pc|ip)\],\s*#([-+\s\d*\/()x]+)$/) {
        my $n = eval_const($2);
        $n //= int($2);
        return ("$n(" . xlate_reg($1) . ")", ".P");
    }
    return (undef, "");
}

# xlate_op translates a single GAS operand token to Plan 9.
# Memory operands return only the address part; any writeback suffix
# (.W/.P) is dropped here since instruction-level translators consume
# those via xlate_mem directly.
sub xlate_op {
    my $op = shift;
    $op =~ s/^\s+|\s+$//g;
    if (defined(my $r = xlate_reg($op)))         { return $r; }
    if (defined(my $i = xlate_imm($op)))         { return $i; }
    if (defined(my $s = xlate_shifted_reg($op))) { return $s; }
    my ($m, $sfx) = xlate_mem($op);
    return $m if defined $m;
    return $op;
}

################################################################
# Register-list translation (for ldmia / stmdb).
#
# Input: comma-separated list inside braces, e.g. "r3,r4,r5,r6,r7" or
# "r4-r11,lr". Output: Plan 9 list "[R3-R7]" or "[R4-R11, R14]".
sub xlate_reglist {
    my $s = shift;
    $s =~ s/^\s*\{//;
    $s =~ s/\}\s*$//;
    my @parts = split /\s*,\s*/, $s;
    my @out;
    for my $p (@parts) {
        if ($p =~ /^(r\d+|sp|lr|pc)-(r\d+|sp|lr|pc)$/) {
            push @out, xlate_reg($1) . "-" . xlate_reg($2);
        } else {
            push @out, xlate_reg($p);
        }
    }
    return "[" . join(", ", @out) . "]";
}

# parse_reglist takes a "{r0,r1,r2,r4-r11,lr}" style list and returns a
# reference to an array of register numbers in stmdb-store order
# (lowest reg# first), or undef if the list contains anything we don't
# understand. lr -> 14, pc -> 15.
sub parse_reglist {
    my $s = shift;
    $s =~ s/^\s*\{//;
    $s =~ s/\}\s*$//;
    my @nums;
    for my $tok (split /\s*,\s*/, $s) {
        if ($tok =~ /^r(\d+)-r(\d+)$/) {
            push @nums, ($1..$2);
        } elsif ($tok eq "lr") {
            push @nums, 14;
        } elsif ($tok eq "pc") {
            push @nums, 15;
        } elsif ($tok =~ /^r(\d+)$/) {
            push @nums, $1;
        } else {
            return undef;
        }
    }
    return [sort { $a <=> $b } @nums];
}

################################################################
# Mnemonic translation.
#
# Returns a Plan 9 instruction line (without trailing newline) given a
# GAS mnemonic and its argument string. Returns undef for things we
# don't yet know how to translate; the caller emits a comment.

# Map GAS conditional suffix to Plan 9 .COND suffix.
my %CONDS = (
    eq => ".EQ", ne => ".NE", cs => ".CS", hs => ".HS",
    cc => ".CC", lo => ".LO", mi => ".MI", pl => ".PL",
    vs => ".VS", vc => ".VC", hi => ".HI", ls => ".LS",
    ge => ".GE", lt => ".LT", gt => ".GT", le => ".LE",
);

# split_mnemonic splits something like "addne" or "movne" into
# (base, ".NE"), or "adds" into ("add", ".S") -- except for special
# cases like "adcs" (which is "adc" + S).
sub split_mnemonic {
    my $m = shift;
    # Memory ops can carry the condition between the op and the size
    # qualifier: "ldrne", "ldrneb", "strhsb", etc. Recognize this
    # structure first so the size suffix isn't mistaken for a flag.
    if ($m =~ /^(ldr|str)([a-z]{2})(b|h|sb|sh)?$/i) {
        my ($op, $cond, $size) = ($1, lc($2), $3 // "");
        if (exists $CONDS{$cond}) {
            return (lc($op) . lc($size), $CONDS{$cond});
        }
    }
    # Try .S suffix first (ADD.S etc.).
    if ($m =~ /^(.+?)s$/i && $m !~ /^(eor|sub|abs|tst|teq|push|pls|cls)$/i) {
        my $base = $1;
        if (length($base) >= 2 && exists $CONDS{lc(substr($base, -2))}) {
            my $cond = substr($base, -2);
            my $bb = substr($base, 0, length($base)-2);
            return ($bb, $CONDS{$cond} . ".S");
        }
        return ($base, ".S") if $base =~ /^(add|adc|sub|sbc|rsb|rsc|and|orr|eor|bic|mov|mvn|asr|lsl|lsr|ror|mul|mla)$/;
    }
    # Conditional suffix.
    if (length($m) >= 2) {
        my $tail = lc(substr($m, -2));
        if (exists $CONDS{$tail}) {
            return (substr($m, 0, length($m)-2), $CONDS{$tail});
        }
    }
    return ($m, "");
}

# arith_3op handles 3-operand arith like "add r0, r1, r2" -> ADD R2, R1, R0.
# Also handles 2-operand forms "add r0, r1" -> ADD R1, R0.
sub arith_3op {
    my ($op, $cond, $args) = @_;
    my @a = split /\s*,\s*/, $args, 3;
    if (@a == 3) {
        my $dst = xlate_op($a[0]);
        my $src1 = xlate_op($a[1]);
        my $src2 = xlate_op($a[2]);
        return "\t$op$cond\t$src2, $src1, $dst";
    } elsif (@a == 2) {
        my $dst = xlate_op($a[0]);
        my $src = xlate_op($a[1]);
        return "\t$op$cond\t$src, $dst";
    }
    return undef;
}

# xlate_insn translates a GAS instruction line into Plan 9.
sub xlate_insn {
    my ($mnemonic, $args) = @_;
    my ($base, $cond) = split_mnemonic($mnemonic);
    $base = lc $base;

    # Branch.
    if ($base eq "b") {
        return "\tB$cond\t$args";
    }
    if ($base eq "bne" || $base eq "beq" || $base =~ /^b[a-z]{2}$/) {
        # Already handled by split_mnemonic? bne -> b + .NE.
        return "\tB$cond\t$args";
    }
    if ($base eq "bx") {
        # bx lr -> RET (caller handles as part of epilogue normally).
        if ($args =~ /^\s*lr\s*$/i) {
            return "\tRET";
        }
        return "\tB$cond\t($args)"; # rough fallback
    }

    # `add rD, sp, #imm` / `sub rD, sp, #imm` compute an address
    # within upstream's frame. Our R13 is shifted +4 from upstream's
    # SP (Plan 9 reserves 0(R13) for the auto-saved LR), so the
    # immediate must be adjusted by sp_shift to land on the right
    # slot.
    if (($base eq "add" || $base eq "sub") && defined $sp_shift) {
        my @a = split /\s*,\s*/, $args, 3;
        if (@a == 3 && $a[1] eq "sp" && $a[2] =~ /^#(.+)$/) {
            my $n = eval_const($1);
            if (defined $n) {
                my $adj = ($base eq "add") ? $n + $sp_shift : $n - $sp_shift;
                my $dst = xlate_op($a[0]);
                if ($adj >= 0) {
                    return "\t" . uc($base) . "$cond\t\$$adj, R13, $dst";
                } else {
                    my $abs = -$adj;
                    my $opp = ($base eq "add") ? "SUB" : "ADD";
                    return "\t$opp$cond\t\$$abs, R13, $dst";
                }
            }
        }
    }

    # AND with a negative immediate cannot be encoded as an ARM
    # rotated-8-bit immediate. Plan 9's assembler will synthesize it
    # with R11 (REGTMP) as scratch, which clobbers any state we have
    # in R11. Convert to BIC with the bitwise-complement immediate
    # (which is small and encodes directly): `and rd, rn, #-K` becomes
    # `bic rd, rn, #(K-1)`.
    if ($base eq "and") {
        my @a = split /\s*,\s*/, $args, 3;
        if (@a == 3 && $a[2] =~ /^#(-\d+)$/) {
            my $neg = int($1);
            my $bic_imm = ~$neg & 0xFFFFFFFF;
            if ($bic_imm < 256) {
                my $dst  = xlate_op($a[0]);
                my $src1 = xlate_op($a[1]);
                return "\tBIC$cond\t\$$bic_imm, $src1, $dst";
            }
        }
        return arith_3op("AND", $cond, $args);
    }

    # Arithmetic / logical (3-op or 2-op).
    if ($base =~ /^(add|adc|sub|sbc|rsb|rsc|orr|eor|bic|mul)$/) {
        return arith_3op(uc($base), $cond, $args);
    }

    # Long unsigned multiply / multiply-accumulate.
    #   umull rlo, rhi, rn, rm    -> MULLU  Rn, Rm, (Rhi, Rlo)
    #   umlal rlo, rhi, rn, rm    -> MULALU Rn, Rm, (Rhi, Rlo)
    if ($base eq "umull" || $base eq "umlal") {
        my @a = split /\s*,\s*/, $args, 4;
        return undef unless @a == 4;
        my $rlo = xlate_op($a[0]);
        my $rhi = xlate_op($a[1]);
        my $rn  = xlate_op($a[2]);
        my $rm  = xlate_op($a[3]);
        my $op  = ($base eq "umull") ? "MULLU" : "MULALU";
        return "\t$op$cond\t$rn, $rm, ($rhi, $rlo)";
    }
    # mla ra, rb, rc, rd  ->  ra = rb*rc + rd  ->  MULA Rb, Rc, Rd, Ra
    if ($base eq "mla") {
        my @a = split /\s*,\s*/, $args, 4;
        return undef unless @a == 4;
        my $ra = xlate_op($a[0]);
        my $rb = xlate_op($a[1]);
        my $rc = xlate_op($a[2]);
        my $rd = xlate_op($a[3]);
        return "\tMULA$cond\t$rb, $rc, $rd, $ra";
    }

    # MOV: "mov dst, src" or "mov dst, src, lsr#N" (3rd part is shift).
    if ($base eq "mov") {
        # If the args have 3 comma-separated tokens, the third is
        # a shift suffix that combines with the source: "mov rD, rS, lsr#N"
        # -> Plan 9 "MOVW rS>>N, rD".
        my @a = split /\s*,\s*/, $args, 3;
        if (@a == 3) {
            my $dst = xlate_op($a[0]);
            # Reassemble "rS, lsr#N" into a shifted-reg token.
            my $shifted = xlate_shifted_reg("$a[1], $a[2]");
            return undef unless defined $shifted;
            return "\tMOVW$cond\t$shifted, $dst";
        }
        if (@a == 2) {
            my $dst = xlate_op($a[0]);
            # `mov rD, sp` copies the upstream view of the stack
            # pointer. Plan 9's R13 sits sp_shift bytes lower (for
            # the auto-saved LR), so emit ADD instead of a bare
            # MOVW to land on upstream's sp+0.
            if (defined($sp_shift) && $a[1] =~ /^\s*sp\s*$/) {
                return "\tADD$cond\t\$$sp_shift, R13, $dst";
            }
            my $src = xlate_op($a[1]);
            return "\tMOVW$cond\t$src, $dst";
        }
        return undef;
    }
    if ($base eq "mvn") {
        my @a = split /\s*,\s*/, $args, 2;
        return undef unless @a == 2;
        my $dst = xlate_op($a[0]);
        my $src = xlate_op($a[1]);
        return "\tMVN$cond\t$src, $dst";
    }

    # CMP / TST / TEQ: "tst r0, #4" -> TST $4, R0.
    if ($base =~ /^(cmp|tst|teq|cmn)$/) {
        my @a = split /\s*,\s*/, $args, 2;
        return undef unless @a == 2;
        my $a0 = xlate_op($a[0]);
        my $a1 = xlate_op($a[1]);
        return "\t" . uc($base) . "$cond\t$a1, $a0";
    }

    # LDR / STR / LDRB / STRB. Memory may have pre/post-increment
    # writeback. The whole memory operand may include a comma after
    # the bracket close ("[rN], #imm"), so split on the first comma
    # outside brackets.
    if ($base =~ /^(ldr|str|ldrb|strb)$/) {
        my ($reg, $mem);
        if ($args =~ /^\s*([^,\[]+)\s*,\s*(\[.*)$/) {
            ($reg, $mem) = ($1, $2);
        }
        return undef unless defined $reg;
        my $RD = xlate_op($reg);
        my ($M, $sfx) = xlate_mem($mem);
        return undef unless defined $M;
        my $op_p9;
        if    ($base eq "ldr")  { $op_p9 = "MOVW"; }
        elsif ($base eq "str")  { $op_p9 = "MOVW"; }
        elsif ($base eq "ldrb") { $op_p9 = "MOVBU"; }
        elsif ($base eq "strb") { $op_p9 = "MOVB"; }
        if ($base =~ /^ld/) {
            return "\t$op_p9$sfx$cond\t$M, $RD";
        } else {
            return "\t$op_p9$sfx$cond\t$RD, $M";
        }
    }

    # LDMIA / STMDB: "ldmia rN, {regs}" or "ldmia rN!, {regs}" / "stmdb sp!, {regs}".
    # Caller usually intercepts the prologue/epilogue forms; this handles
    # body uses like "ldmia r0, {r3-r7}".
    if ($base eq "ldmia" || $base eq "stmdb" || $base eq "stmia" || $base eq "ldmdb") {
        if ($args =~ /^\s*(r\d+|sp|lr)(\!?)\s*,\s*(\{.*\})\s*$/) {
            my ($base_reg, $bang, $list) = ($1, $2, $3);
            my $R = xlate_reg($base_reg);
            my $L = xlate_reglist($list);
            my $mode_suffix;
            if    ($base eq "ldmia") { $mode_suffix = ".IA"; }
            elsif ($base eq "ldmdb") { $mode_suffix = ".DB"; }
            elsif ($base eq "stmia") { $mode_suffix = ".IA"; }
            elsif ($base eq "stmdb") { $mode_suffix = ".DB"; }
            $mode_suffix .= ".W" if $bang eq "!";
            if ($base =~ /^ldm/) {
                return "\tMOVM$mode_suffix$cond\t($R), $L";
            } else {
                return "\tMOVM$mode_suffix$cond\t$L, ($R)";
            }
        }
        return undef;
    }

    return undef;
}

################################################################
# Main driver.

my $skip_size_line; # next .size directive should be eaten

# Map of recognized data labels: ".Lsigma" => { name => "sigma",
# words => [0x61707865, ...] }. Populated by the pre-pass; consumed
# by emit_data_sections at end-of-file. Also used during instruction
# translation: any operand reference to ".Lsigma" becomes
# "sigma<>(SB)".
our %DATA_LABELS;

sub emit_header {
    print <<'HDR';
// Code generated by plan9-xlate.pl from CryptoGAMS Perl. DO NOT EDIT.
//
// Run `go generate ./tsasm/arm/...` (or tsasm/arm/regen/regen.sh) to
// regenerate. The upstream chacha-armv4.pl / poly1305-armv4.pl are
// fetched at a pinned commit by regen.sh; see that script for the
// upstream URL and SHA. Translation is by tsasm/arm/regen/plan9-xlate.pl.
//
// The original CryptoGAMS code this was derived from is dual-licensed
// under the BSD-3-Clause and OpenSSL licenses, at the holder's option.
// The CryptoGAMS BSD-3-Clause text is reproduced below; that license
// requires the copyright notice to travel with the source. Files in
// tsasm/arm/regen/ that are not derived from CryptoGAMS (plan9-xlate.pl
// and friends) are BSD-3-Clause without the dual-license option.
//
// ----------------------------------------------------------------
// Copyright (c) 2006, CRYPTOGAMS by <appro@openssl.org>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//       * Redistributions of source code must retain copyright
//         notices, this list of conditions and the following
//         disclaimer.
//
//       * Redistributions in binary form must reproduce the above
//         copyright notice, this list of conditions and the following
//         disclaimer in the documentation and/or other materials
//         provided with the distribution.
//
//       * Neither the name of the CRYPTOGAMS nor the names of its
//         copyright holder and contributors may be used to endorse or
//         promote products derived from this software without specific
//         prior written permission.
//
// ALTERNATIVELY, provided that this notice is retained in full, this
// product may be distributed under the terms of the GNU General Public
// License (GPL), in which case the provisions of the GPL apply INSTEAD
// OF those given above.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
// ----------------------------------------------------------------

#include "textflag.h"
#include "funcdata.h"

HDR
}

# is_neon_mnemonic returns true if the mnemonic looks like a NEON
# instruction (starts with 'v') as opposed to a regular ARM
# instruction. The lookup is intentionally broad: anything starting
# with 'v' goes through the NEON encoder.
sub is_neon_mnemonic {
    my $m = shift;
    return $m =~ /^v[a-z]/i;
}

# neon_dreg_count counts how many D registers a NEON list refers to.
# `{d8,d9,d10,d11}` -> 4. `{d8-d15}` -> 8. Q registers (q0..q15) each
# count as 2 D registers; S registers count as 1 (32-bit lanes).
sub neon_dreg_count {
    my $s = shift;
    my $total = 0;
    for my $tok (split /\s*,\s*/, $s) {
        if ($tok =~ /^([dqs])(\d+)-\1(\d+)$/) {
            my ($k, $a, $b) = ($1, $2, $3);
            my $n = ($b - $a + 1);
            if    ($k eq "q") { $n *= 2; }
            elsif ($k eq "s") { $n  = ($n + 1) >> 1; }
            $total += $n;
        } elsif ($tok =~ /^([dqs])(\d+)$/) {
            my $k = $1;
            my $n = 1;
            $n = 2 if $k eq "q";
            $total += $n;
        }
    }
    return $total;
}

# batch_encode_neon populates %NEON_ENC by running every unique NEON
# line through the pure-Perl encoder in neon_encode.pl. If any line
# isn't recognized, fail loudly: pure-Perl coverage is the only path
# now, and a missing encoder is something to fix in neon_encode.pl
# rather than paper over.
sub batch_encode_neon {
    my @lines = @_;
    my @missing;
    for my $l (@lines) {
        my $word = eval { encode_neon($l) };
        if ($@) {
            push @missing, [$l, $@];
        } else {
            $NEON_ENC{$l} = $word;
        }
    }
    return unless @missing;
    my $msg = "plan9-xlate.pl: " . scalar(@missing)
        . " NEON line(s) have no pure-Perl encoder (add to neon_encode.pl):\n";
    for my $m (@missing) {
        $msg .= "  $m->[0]\n";
        my $err = $m->[1];
        $err =~ s/\n.*$//s;
        $msg .= "    -> $err\n" if length $err;
    }
    die $msg;
}

# scan_neon_lines walks the input and returns the list of unique
# NEON GAS lines (already cleaned of leading whitespace and trailing
# @-comments) that we need to encode.
sub scan_neon_lines {
    my $lines = shift;
    my %seen;
    my @uniq;
    for my $line (@$lines) {
        my $clean = $line;
        $clean =~ s/\s*\@.*$//;
        $clean =~ s/^\s+//;
        $clean =~ s/\s+$//;
        next unless length $clean;
        next if $clean =~ /^[#.\@\/]/;     # directives and comments
        my ($mn) = split /\s+/, $clean, 2;
        next unless defined $mn && is_neon_mnemonic($mn);
        next if $seen{$clean}++;
        push @uniq, $clean;
    }
    return @uniq;
}

# Drop tokens that have no Plan 9 equivalent or are handled by other
# logic.
sub is_drop_directive {
    my $line = shift;
    return 1 if $line =~ /^\s*\.(text|globl|global|type|size|align|p2align|fpu|arch|syntax|code|thumb|arm|cfi_\w+|extern|hidden|comm)\b/;
    return 1 if $line =~ /^\s*\.byte\s/;     # version string at end of file
    return 1 if $line =~ /^\s*\.section\s/;
    return 0;
}

# compute_function_layout walks the function body and simulates SP
# motion to produce a frame layout. The result tells the prologue
# emitter where each upstream-pushed register lands in our Plan 9
# frame, and tells the body translator which lines to drop because
# we already absorbed them into the prologue/epilogue.
#
# The general form: every stmdb sp!, sub sp,sp,#N, add sp,sp,#N, and
# ldmia sp! we encounter is recorded. Total push depth (low water of
# the simulated SP) determines framesize. Each stmdb's individual
# regs are mapped to a Plan 9 offset that mirrors upstream's frame
# layout, so body refs to [sp, #N] still land on the right slot
# after the +4 LR-slot shift.
#
# Robustness: if the function contains any SP-modifying form we
# don't recognize (e.g. mov sp, ...), we die. If the simulated SP
# isn't balanced at the end, we die.
sub compute_function_layout {
    my ($lines, $entry_label_idx, $end_re, $func_name) = @_;

    # Find the body bounds.
    my $body_end = $entry_label_idx + 1;
    while ($body_end < @$lines && $lines->[$body_end] !~ $end_re) {
        $body_end++;
    }

    my %absorbed;
    my %body_emits;       # line_idx -> [ "MOVW ...\n", ... ] (for non-prologue stmdbs)
    my @stmdb_recs;       # each: { regs => [...], sp_after => N, line => idx }
    my @arg_loads;        # each: { reg => N, fp_off => M, line => idx }
    my $virtual_sp = 0;
    my $low_water  = 0;
    my $first_sp_mod_idx;
    my $terminal_ldmia_line;

    for (my $j = $entry_label_idx + 1; $j < $body_end; $j++) {
        my $clean = $lines->[$j];
        $clean =~ s/\s*\@.*$//;
        $clean =~ s/^\s+//;
        $clean =~ s/\s+$//;
        next unless length $clean;

        # stmdb sp!, {regs} -- push.
        if ($clean =~ /^stmdb\s+sp!\s*,\s*(\{[^}]*\})\s*$/) {
            my $regs = parse_reglist($1);
            unless (defined $regs) {
                die "$func_name: cannot parse register list at line $j: $clean\n";
            }
            $virtual_sp -= 4 * scalar @$regs;
            $low_water = $virtual_sp if $virtual_sp < $low_water;
            push @stmdb_recs, {
                regs     => $regs,
                sp_after => $virtual_sp,
                line     => $j,
            };
            $absorbed{$j} = 1;
            $first_sp_mod_idx //= $j;
            next;
        }

        # ldmia sp!, {regs[, pc]} -- pop+optional return. Must be the
        # function's terminal point (we'll emit RET in its place).
        if ($clean =~ /^ldmia\s+sp!\s*,\s*(\{[^}]*\})\s*$/) {
            my $regs = parse_reglist($1);
            unless (defined $regs) {
                die "$func_name: cannot parse register list at line $j: $clean\n";
            }
            $virtual_sp += 4 * scalar @$regs;
            $terminal_ldmia_line = $j;
            # Don't mark absorbed -- main loop's epilogue handler
            # consumes this as the trigger to emit RET.
            $first_sp_mod_idx //= $j;
            next;
        }

        # NEON multi-register pushes/pops via vstmdb sp!, vldmia sp!.
        # Each D register is 8 bytes (vs ARM's 4-byte regs). The
        # CryptoGAMS NEON paths use these to save/restore d8-d15.
        if ($clean =~ /^vstmdb\s+sp!\s*,\s*\{([^}]*)\}\s*$/) {
            my $dregs = $1;
            my $count = neon_dreg_count($dregs);
            $virtual_sp -= 8 * $count;
            $low_water = $virtual_sp if $virtual_sp < $low_water;
            $absorbed{$j} = 1;
            $first_sp_mod_idx //= $j;
            next;
        }
        if ($clean =~ /^vldmia\s+sp!\s*,\s*\{([^}]*)\}\s*$/) {
            my $dregs = $1;
            my $count = neon_dreg_count($dregs);
            $virtual_sp += 8 * $count;
            $absorbed{$j} = 1;
            $first_sp_mod_idx //= $j;
            next;
        }

        # sub sp, sp, #imm -- allocate.
        if ($clean =~ /^sub\s+sp\s*,\s*sp\s*,\s*#(.+)$/) {
            my $amt = eval_const($1);
            unless (defined $amt) {
                die "$func_name: cannot evaluate sub sp,sp,#$1 at line $j\n";
            }
            $virtual_sp -= $amt;
            $low_water = $virtual_sp if $virtual_sp < $low_water;
            $absorbed{$j} = 1;
            $first_sp_mod_idx //= $j;
            next;
        }

        # add sp, sp, #imm -- unconditional cleanup (epilogue prep).
        if ($clean =~ /^add\s+sp\s*,\s*sp\s*,\s*#(.+)$/) {
            my $amt = eval_const($1);
            unless (defined $amt) {
                die "$func_name: cannot evaluate add sp,sp,#$1 at line $j\n";
            }
            $virtual_sp += $amt;
            $absorbed{$j} = 1;
            next;
        }

        # add<cond> sp, sp, #imm -- conditional partial cleanup
        # (early-out idiom). Plan 9's auto-epilogue handles the full
        # unwind regardless of which branch we take, so we just drop
        # this line. Don't update $virtual_sp (the unconditional path
        # is what we track).
        if ($clean =~ /^add(eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)\s+sp\s*,\s*sp\s*,\s*#(.+)$/) {
            $absorbed{$j} = 1;
            next;
        }

        # Caller-frame argument loads happen before the first SP
        # modifier; upstream uses `ldr rN, [sp, #M]` on entry to pull
        # the 5th-and-later args off the caller's stack.
        if (!defined($first_sp_mod_idx)
            && $clean =~ /^ldr\s+(r\d+|sp|lr|ip)\s*,\s*\[sp\s*,\s*#(\d+)\]\s*$/) {
            my $reg_gas = $1;
            my $fp_off = int($2) + 16;  # first 4 args in r0-r3, stack args start at FP+16
            push @arg_loads, { reg_gas => $reg_gas, fp_off => $fp_off, line => $j };
            $absorbed{$j} = 1;
            next;
        }

        # Any other SP write is an unsupported form. We allow uses of
        # SP as a memory base ([sp, ...]) and as a non-write source.
        # A bare write to SP -- `mov sp, ...` etc. -- is rejected.
        if ($clean =~ /^(mov|mvn|ldr|str)\w*\s+sp\b/) {
            die "$func_name: unsupported SP write at line $j: $clean\n";
        }
    }

    # We do a linear walk of the function, not a proper CFG; functions
    # with multiple exit paths (e.g. CryptoGAMS's chacha NEON, which
    # has a "switch frame" branch into the scalar loop's epilogue and
    # a separate NEON-tail epilogue) won't balance under linear
    # simulation. We trust the low-water mark (= deepest SP relative
    # to entry) as the frame depth in that case. The note printed
    # here is a heads-up, not an error -- it's expected for the
    # multi-exit chacha NEON.
    if ($virtual_sp != 0) {
        print STDERR "$func_name: multi-exit function (linear SP scan ends at +$virtual_sp, low_water $low_water); using low_water as framesize\n";
    }

    # framesize_upstream is the byte size of the user data area in
    # upstream's view of the frame. The first stmdb's lr push is
    # auto-handled by Plan 9's prologue (LR at 0(R13)) and so is
    # excluded here -- but only when we actually saw such a push.
    # Functions that don't push at all (NEON helpers like
    # poly1305_init_neon) get framesize 0.
    my $pushed_lr = 0;
    if (@stmdb_recs) {
        for my $n (@{$stmdb_recs[0]->{regs}}) {
            $pushed_lr = 1 if $n == 14;
        }
    }
    my $framesize_upstream = -$low_water - ($pushed_lr ? 4 : 0);
    if ($framesize_upstream < 0) {
        die "$func_name: computed negative framesize ($framesize_upstream)\n";
    }

    # Compute Plan 9 offsets for each stmdb's regs.
    # In body-view, upstream sp = $low_water (= -accum_total). For each
    # stmdb with sp_after = X, the regs sit at upstream sp[X..X+4*count-1]
    # in CPU memory; in body-view (offset from final sp), they're at
    # (X - $low_water) to (X - $low_water + 4*count - 1). +4 for the
    # Plan 9 LR-slot shift.
    my $accum_total = -$low_water;
    for my $rec (@stmdb_recs) {
        my $base = $rec->{sp_after} + $accum_total + 4;
        my @reg_offs;
        for (my $i = 0; $i < scalar @{$rec->{regs}}; $i++) {
            push @reg_offs, [$rec->{regs}[$i], $base + 4 * $i];
        }
        $rec->{reg_offs} = \@reg_offs;
    }

    # Locate shadow_r10. r10 reuses the Plan 9 slot the *first*
    # stmdb's r10-save would have occupied (the only stmdb-save we
    # actually emit at function entry; later stmdbs save r10 values
    # computed in the body, so they spill via the shadow slot too).
    my $shadow_off;
    if (@stmdb_recs) {
        for my $reg_off (@{$stmdb_recs[0]->{reg_offs}}) {
            my ($n, $off) = @$reg_off;
            if ($n == 10) { $shadow_off = $off; last; }
        }
    }

    my $framesize_p9 = $framesize_upstream;
    my $r14_save_o;
    if (defined $shadow_off) {
        $framesize_p9 += 4;
        $r14_save_o = $framesize_p9;
    }

    # For each stmdb beyond the first, queue MOVWs to emit at the
    # original line position. Those stmdbs save values produced in
    # the body (data loaded via ldmia r3 / ldmia r12 / ldmia r14),
    # so the prologue can't fold them in.
    for (my $i = 1; $i < @stmdb_recs; $i++) {
        my $rec = $stmdb_recs[$i];
        my @lines_to_emit;
        for my $reg_off (@{$rec->{reg_offs}}) {
            my ($n, $off) = @$reg_off;
            next if $n == 14;                        # lr -- auto-saved at 0(R13)
            if ($n == 10) {
                # The value normally in upstream's r10 register lives
                # in our shadow slot. To "save it" to the upstream-
                # equivalent slot, copy via R14, preserving R14
                # itself across the bounce.
                push @lines_to_emit,
                    "\tMOVW\tR14, $r14_save_o(R13)\n",
                    "\tMOVW\t$shadow_off(R13), R14\n",
                    "\tMOVW\tR14, $off(R13)\n",
                    "\tMOVW\t$r14_save_o(R13), R14\n";
            } else {
                push @lines_to_emit, "\tMOVW\tR$n, $off(R13)\n";
            }
        }
        $body_emits{$rec->{line}} = \@lines_to_emit;
        $absorbed{$rec->{line}} = 1;
    }

    return {
        framesize_p9      => $framesize_p9,
        framesize_upstream => $framesize_upstream,
        stmdb_recs        => \@stmdb_recs,
        absorbed          => \%absorbed,
        body_emits        => \%body_emits,
        arg_loads         => \@arg_loads,
        shadow_r10_off    => $shadow_off,
        r14_save_off      => $r14_save_o,
        terminal_ldmia    => $terminal_ldmia_line,
    };
}

# emit_function_prologue is called when we enter a function whose
# body has been pre-scanned by compute_function_layout. It emits the
# TEXT directive and explicit MOVWs that mirror what upstream's
# stmdb sequence would have stored, populating each reg into the
# Plan 9 slot whose offset matches upstream's view of the frame.
sub emit_function_prologue {
    my ($func, $layout) = @_;
    my $sig = $SIGS{$func};
    unless ($sig) {
        die "plan9-xlate.pl: no signature for function $func\n";
    }

    $cur_funcsize     = $layout->{framesize_p9};
    $sp_shift         = 4;
    $shadow_r10_off   = $layout->{shadow_r10_off};
    $r14_save_off     = $layout->{r14_save_off};
    $r14_holds_shadow = 0;

    print "\n";
    print "// func $func(",
          join(", ", map { $_->[0] . " uintptr" } @{$sig->{args}}),
          ")\n";
    print "TEXT \xc2\xb7$func(SB), NOSPLIT, \$$cur_funcsize-$sig->{argsize}\n";

    # Mark the entire function as unsafe for async preemption (defense
    # in depth -- we no longer clobber g, but the marker also keeps
    # the runtime from poking at our hand-rolled frame).
    print "\tPCDATA\t\$PCDATA_UnsafePoint, \$-2\n";
    print "\tNO_LOCAL_POINTERS\n";

    # FP-relative arg loads into R0..R3 (CryptoGAMS expects EABI
    # register passing on entry).
    for my $a (@{$sig->{args}}) {
        my ($name, $off, $sz) = @$a;
        my $reg = "R" . int($off / 4);
        next if int($off / 4) > 3;
        print "\tMOVW\t$name+$off(FP), $reg\n";
    }

    # Caller-frame argument loads (e.g. ChaCha20_ctr32's 5th arg
    # pulled via "ldr r12, [sp, #0]" before its first stmdb).
    for my $al (@{$layout->{arg_loads}}) {
        my $r_p9 = xlate_reg($al->{reg_gas});
        unless (defined $r_p9) {
            die "plan9-xlate.pl: cannot translate arg-load reg $al->{reg_gas}\n";
        }
        my $arg_name = arg_name_for_offset($sig, $al->{fp_off});
        unless (defined $arg_name) {
            die "plan9-xlate.pl: $func has no arg at FP+$al->{fp_off}\n";
        }
        print "\tMOVW\t$arg_name+$al->{fp_off}(FP), $r_p9\n";
    }

    # Only the first stmdb captures register values present at
    # function entry (args from FP into R0..R3 and the EABI-callee-
    # saved R4..R11). Emit MOVWs for those into the upstream-
    # equivalent slots. Subsequent stmdbs save values that the body
    # produces (ldmia of key/nonce/sigma into r4..r11); those are
    # emitted in place during body translation, see body_emits.
    if (@{$layout->{stmdb_recs}}) {
        my $first = $layout->{stmdb_recs}[0];
        for my $reg_off (@{$first->{reg_offs}}) {
            my ($n, $off) = @$reg_off;
            next if $n == 14;             # lr -- auto-saved
            next if $n == 10;             # slot reserved as shadow_r10
            print "\tMOVW\tR$n, $off(R13)\n";
        }
    }
}

# arg_name_for_offset returns the named-arg label for a given
# FP-relative offset, or undef if no arg matches.
sub arg_name_for_offset {
    my ($sig, $off) = @_;
    for my $a (@{$sig->{args}}) {
        return $a->[0] if $a->[1] == $off;
    }
    return undef;
}

# emit_function_epilogue is called when we recognize the "ldmia sp!,
# {r4-r11,...}" epilogue. It restores the saved regs and emits RET.
sub emit_function_epilogue {
    my ($reglist) = @_;
    my $list_str = $reglist;
    $list_str =~ s/^\{//; $list_str =~ s/\}$//;
    my @reg_nums;
    for my $tok (split /\s*,\s*/, $list_str) {
        if ($tok =~ /^r(\d+)-r(\d+)$/) {
            push @reg_nums, ($1..$2);
        } elsif ($tok eq "pc" || $tok eq "lr") {
            next;
        } elsif ($tok =~ /^r(\d+)$/) {
            push @reg_nums, $1;
        }
    }
    # Skip r10 -- we never saved it (we use the slot it would have
    # occupied as the shadow-r10 spill instead). Reload others.
    my $extra_locals = $cur_funcsize - 4 * scalar @reg_nums;
    my $off = 4 + $extra_locals;
    for my $n (@reg_nums) {
        if ($n != 10) {
            print "\tMOVW\t$off(R13), R$n\n";
        }
        $off += 4;
    }
    print "\tRET\n";
}

# scan_data_labels finds ".LFoo:" lines that are immediately followed
# by .long or .word data and records them as data sections. Each one
# becomes a Plan 9 DATA/GLOBL block at the end of the output. The
# original label and data lines are skipped during the main pass.
#
# A data label is identified by being followed by at least one
# .long/.word line; .L labels followed by code (i.e. branch targets)
# are unaffected.
sub scan_data_labels {
    my $lines = shift;
    my $i = 0;
    while ($i < @$lines) {
        my $line = $lines->[$i];
        if ($line =~ /^(\.L\w+)\s*:\s*$/) {
            my $label = $1;            # ".Lsigma"
            my $short = lc($label);
            $short =~ s/^\.l//;        # ".Lsigma" -> "sigma"
            my @words;
            my @aliases;               # other labels merged into this block
            my $j = $i + 1;
            # Walk the data block. The block ends at the first non-
            # data, non-data-label line. Subsequent contiguous
            # ".LFoo:" labels with their own .long lines are folded
            # into the SAME block so they end up at predictable
            # offsets in memory: upstream code uses a single `adr`
            # to grab the head label and walks via [Rn]! writebacks
            # through the rest (e.g. .Lsigma -> .Lone -> .Lrot8).
            # Plan 9 emits a separate GLOBL per `name<>(SB)` symbol
            # and the linker has no obligation to keep them adjacent,
            # so without folding the writebacks would land in
            # whatever else the linker placed after the head.
            my $hit_unevaluable = 0;
            while ($j < @$lines) {
                my $nxt = $lines->[$j];
                if ($nxt =~ /^\s*\.(long|word)\s+(.*?)(?:\s*\@.*)?\s*$/) {
                    my $list = $2;
                    my @parsed;
                    for my $w (split /\s*,\s*/, $list) {
                        $w =~ s/^\s+|\s+$//g;
                        my $v = eval_const($w);
                        $v //= int($w) if $w =~ /^-?\d+$/;
                        push @parsed, $v;
                    }
                    if (grep { !defined $_ } @parsed) {
                        # The next .word/.long line involves a label-
                        # arithmetic expression we can't evaluate at
                        # scan time (e.g. CryptoGAMS uses the form
                        # `OPENSSL_armcap_P-.LFoo` to record a
                        # PC-relative offset for feature dispatch).
                        # That marker doesn't belong with the head
                        # data block, so end the block here.
                        $hit_unevaluable = 1;
                        last;
                    }
                    push @words, @parsed;
                    $j++;
                    next;
                }
                if ($nxt =~ /^(\.L\w+)\s*:\s*$/) {
                    my $alias_name = $1;
                    if ($j + 1 < @$lines
                        && $lines->[$j + 1] =~ /^\s*\.(long|word)\s+/) {
                        # Adjacent label + data: treat as part of
                        # the current data block (skip the label
                        # line and keep accumulating .long words).
                        # If the following words turn out to be
                        # unevaluable, the next iteration will bail
                        # out and we'll keep this label as an alias
                        # without contributing words.
                        push @aliases, $alias_name;
                        $j++;
                        next;
                    }
                }
                last;
            }
            # If the block ended on an unevaluable .word, the alias
            # we pushed for the immediately preceding label is bogus
            # -- that label belongs to the unevaluable data, not to
            # this block. Drop it.
            if ($hit_unevaluable && @aliases) {
                pop @aliases;
            }
            if (@words) {
                # If any word couldn't be evaluated to a literal
                # (e.g. .Lopenssl_armcap holding a label-arithmetic
                # expression), skip the section. We don't reference
                # those symbols in the generated output anyway.
                my $has_undef = grep { !defined $_ } @words;
                if (!$has_undef) {
                    $DATA_LABELS{$label} = { name => $short, words => \@words };
                    # Mark each aliased label as part of the head's
                    # block so the main pass skips emitting it as a
                    # branch target. We only flag presence; aliases
                    # don't get their own GLOBL or `name => $short`
                    # name lookup.
                    for my $a (@aliases) {
                        $DATA_LABELS{$a} = { alias_of => $label };
                    }
                }
                $i = $j;
                next;
            }
        }
        $i++;
    }
}

sub emit_data_sections {
    for my $label (sort keys %DATA_LABELS) {
        my $entry = $DATA_LABELS{$label};
        next if $entry->{alias_of};   # folded into another block
        my $name  = $entry->{name};
        my @words = @{$entry->{words}};
        my $size  = 4 * scalar @words;
        print "\n";
        for my $i (0..$#words) {
            my $off = 4 * $i;
            my $val = $words[$i] & 0xFFFFFFFF;
            printf "DATA %s<>+0x%02x(SB)/4, \$0x%08x\n", $name, $off, $val;
        }
        print "GLOBL ${name}<>(SB), RODATA, \$$size\n";
    }
}

sub main {
    emit_header();

    # Normalize incoming lines: strip CR (for any source that crept
    # in via Windows line endings) and trailing whitespace, so the
    # generated .s output stays reproducible across preprocessors
    # (GNU cpp vs clang cpp emit different trailing whitespace).
    my @lines;
    while (my $line = <>) {
        $line =~ s/\r?\n$//;
        $line =~ s/[ \t]+$//;
        push @lines, $line;
    }

    scan_data_labels(\@lines);

    # Pre-encode all NEON instructions (the Plan 9 arm assembler
    # rejects every NEON mnemonic, so each one becomes a raw
    # WORD $0x...). Doing this in a single batch keeps us to one
    # arm-as invocation per regen.
    my @neon = scan_neon_lines(\@lines);
    if (@neon) {
        batch_encode_neon(@neon);
    }

    my %is_func;  # name -> 1 if known function
    for my $line (@lines) {
        if ($line =~ /^\s*\.type\s+(\w+),\s*%function\b/) {
            $is_func{$1} = 1;
        }
    }

    # Per-function layout, computed at function entry and consulted
    # during body translation to know which lines have already been
    # absorbed into the prologue.
    my $cur_layout;

    my $i = 0;
    while ($i < @lines) {
        my $line = $lines[$i];
        my $orig_idx = $i;
        $i++;

        # Strip a trailing GAS @-comment for translation purposes; we
        # preserve it as a Plan 9 // comment.
        my $tail_comment = "";
        if ($line =~ s/\s*\@\s*(.*)$//) {
            $tail_comment = $1;
        }

        # Blank lines from the preprocessor are not load-bearing; they
        # come and go between GNU cpp and clang -P. Drop them
        # entirely so the output is byte-deterministic. Structural
        # blanks in the .s file are inserted explicitly by
        # emit_header and emit_function_prologue. A blank line that
        # had a trailing GAS @-comment is preserved as a comment.
        if ($line =~ /^\s*$/) {
            print "\t// $tail_comment\n" if $tail_comment;
            next;
        }

        # Drop directives we ignore.
        if (is_drop_directive($line)) { next; }

        # Drop CPP residue and #-comments.
        if ($line =~ /^\s*#/) { next; }

        # If this line was absorbed by the prologue/epilogue
        # accumulation, either emit its precomputed body MOVWs
        # (e.g. a non-prologue stmdb stashing key material into
        # the upstream-equivalent stack slots) or just drop it.
        if ($cur_layout && $cur_layout->{absorbed}{$orig_idx}) {
            if (my $emit = $cur_layout->{body_emits}{$orig_idx}) {
                # body_emits use R14/r14_save_off too; flush our
                # in-progress r10 spill before them.
                if ($r14_holds_shadow) {
                    print "\tMOVW\t$r14_save_off(R13), R14\n";
                    $r14_holds_shadow = 0;
                }
                print @$emit;
            }
            next;
        }

        # Function entry label: "Foo:" where Foo is in is_func.
        if ($line =~ /^(\w+)\s*:\s*$/ && $is_func{$1}) {
            my $name = $1;
            my $end_re = qr/^\s*\.size\s+\Q$name\E\b/;
            # If --only was given, skip functions that don't match by
            # advancing past their .size marker. The body still gets
            # consumed (so we don't leak instructions into the next
            # function), but nothing is emitted.
            if (defined($opt_only) && $name !~ /$opt_only/) {
                while ($i < @lines && $lines[$i] !~ $end_re) {
                    $i++;
                }
                $i++ if $i < @lines;   # consume the .size line itself
                next;
            }
            $cur_func = $name;
            $cur_layout = compute_function_layout(\@lines, $orig_idx, $end_re, $cur_func);
            emit_function_prologue($cur_func, $cur_layout);
            next;
        }

        # Drop .long / .word data lines; if they belong to a recognized
        # data label, scan_data_labels has already collected them.
        if ($line =~ /^\s*\.(long|word)\b/) {
            next;
        }

        # Local label ".Lfoo:". If it names a recognized data section,
        # drop it (we emit DATA/GLOBL at end). Otherwise rename to
        # "lb_Lfoo:" so it doesn't collide with global function names.
        # Either way the label is a control-flow merge point: anything
        # joining at this label can't rely on R14 still holding a
        # shadow_r10 value, so flush our dirty state first.
        if ($line =~ /^(\.L\w+)\s*:\s*$/) {
            my $label = $1;
            next if exists $DATA_LABELS{$label};
            if ($r14_holds_shadow) {
                print "\tMOVW\t$r14_save_off(R13), R14\n";
                $r14_holds_shadow = 0;
            }
            (my $renamed = $label) =~ s/^\.//;
            print "lb_$renamed:\n";
            next;
        }

        # Plain label inside a function (no .L prefix); keep as-is.
        # Same flush as above for control-flow merge.
        if ($line =~ /^(\w+)\s*:\s*$/) {
            if ($r14_holds_shadow) {
                print "\tMOVW\t$r14_save_off(R13), R14\n";
                $r14_holds_shadow = 0;
            }
            print "$1:\n";
            next;
        }

        # Instruction or directive starting with a mnemonic. Trim
        # leading whitespace and split.
        my $stripped = $line;
        $stripped =~ s/^\s+//;
        $stripped =~ s/\s+$//;
        my ($mnemonic, $argstr) = split /\s+/, $stripped, 2;
        $argstr //= "";

        # NEON instructions: emit as raw WORD using the encoding from
        # batch_encode_neon. NEON memory operands that reference sp
        # (e.g. `vldr d24, [sp, #4*(16+0)]`) need the same +4 offset
        # bump that xlate_mem applies for non-NEON loads/stores --
        # Plan 9 reserves 0(R13) for the auto-saved LR, so upstream's
        # sp+N maps to our R13+N+sp_shift. Re-adjust the line, encode
        # on demand, and cache the adjusted form.
        if (is_neon_mnemonic($mnemonic)) {
            my $key = $stripped;
            if (defined($sp_shift) && $stripped =~ /\[sp\b/) {
                $key = adjust_neon_sp_offsets($stripped, $sp_shift);
            }

            # Plain `[sp]` (no offset) and `vldmia sp,{...}` /
            # `vstmdb sp!,{...}` body forms have no immediate slot
            # we can bump by sp_shift. Plan 9 reserves 0(R13) for
            # the auto-saved LR, so a literal-sp NEON store would
            # clobber it. Spill R12, set R12 = sp+sp_shift, encode
            # against R12, then restore R12.
            #
            # Special case: the epilogue's `vldmia sp,{d8..d15}`
            # restores callee-saved NEON regs for the AAPCS C ABI.
            # Go's ARM ABI doesn't require us to preserve d8-d15,
            # so we drop the instruction entirely.
            if (defined($sp_shift) && $cur_func &&
                ($key =~ /\[\s*sp\s*\]/
                 || $key =~ /^vld[ms]ia\s+sp\b/
                 || $key =~ /^vstm[di]b\s+sp!/)) {
                if ($key =~ /^vldmia\s+sp\s*,\s*\{d8\b/) {
                    print "\t// dropped: $stripped (Go ABI: d8-d15 not preserved)\n";
                    next;
                }
                # Pick R12 as the scratch register: it's caller-
                # saved in the C ABI and the upstream code uses it
                # in ways we can preserve via spill/reload. The
                # spill slot (148(R13) = upstream sp+144) lives in
                # the d-register save area, which the body never
                # reads or writes (we drop the d-reg vldmia above).
                my $rewritten = $key;
                $rewritten =~ s/\[\s*sp\s*\]/[r12]/g;
                $rewritten =~ s/(^vld[ms]ia\s+)sp\b/$1r12/;
                $rewritten =~ s/(^vstm[di]b\s+)sp!/$1r12/;
                unless (exists $NEON_ENC{$rewritten}) {
                    my $w = eval { encode_neon($rewritten) };
                    if ($@) {
                        die "plan9-xlate.pl: no NEON encoding for: $rewritten\n  $@";
                    }
                    $NEON_ENC{$rewritten} = $w;
                }
                my $w = $NEON_ENC{$rewritten};
                my $slot = 148;
                print "\tMOVW\tR12, $slot(R13)\t// scratch save (sp-base NEON)\n";
                print "\tADD\t\$$sp_shift, R13, R12\n";
                printf "\tWORD\t\$0x%08x\t// %s\n", $w, $stripped;
                print "\tMOVW\t$slot(R13), R12\n";
                next;
            }

            unless (exists $NEON_ENC{$key}) {
                my $word = eval { encode_neon($key) };
                if ($@) {
                    die "plan9-xlate.pl: no NEON encoding for: $key\n  $@";
                }
                $NEON_ENC{$key} = $word;
            }
            my $word = $NEON_ENC{$key};
            printf "\tWORD\t\$0x%08x\t// %s\n", $word, $stripped;
            next;
        }

        # NEON-flavour PC-relative: "adr rN, .Llabel" loads the address
        # of a recognized data label into rN. Translate to
        # MOVW $label<>(SB), rN.
        if ($cur_func && $mnemonic eq "adr"
            && $argstr =~ /^\s*(r\d+|sp|lr|pc)\s*,\s*(\.L\w+)\s*$/
            && exists $DATA_LABELS{$2}) {
            my ($reg_gas, $label) = ($1, $2);
            my $reg = xlate_op($reg_gas);
            my $name = $DATA_LABELS{$label}{name};
            print "\tMOVW\t\$${name}<>(SB), $reg\n";
            next;
        }

        # IT (if-then) blocks are Thumb-2 conditional-execution
        # hints. The ARM assembler treats them as a no-op, and Plan 9
        # doesn't recognize them at all, so drop them.
        if ($mnemonic =~ /^itt?t?t?$/) {
            next;
        }

        # bl to a local function-helper label (e.g. CryptoGAMS NEON's
        # `bl .Lpoly1305_init_neon`) -- the local-label form names the
        # same address as the global function symbol of the same name.
        # Translate to a Plan 9 BL of the global symbol.
        if ($mnemonic =~ /^bl([a-z]{2})?$/i) {
            my $cond_suf = $1 // "";
            if ($argstr =~ /^\s*\.L(\w+)\s*$/) {
                my $name = $1;
                if (exists $SIGS{$name}) {
                    my $cs = $cond_suf ? $CONDS{lc $cond_suf} : "";
                    print "\tBL$cs\t\xc2\xb7$name(SB)\n";
                    next;
                }
            }
        }

        # blo .Lscalar_fallback -- CryptoGAMS NEON's "if len < N, fall
        # back to the scalar function" idiom. We can't emit a Plan 9
        # branch into the middle of another function, but the Go-side
        # wrapper gates this case anyway, so drop the line.
        if ($mnemonic =~ /^blo$/i
            && $argstr =~ /^\s*\.L(poly1305_blocks|ChaCha20_ctr32)\s*$/) {
            next;
        }

        # CryptoGAMS's runtime-armcap dispatch in ChaCha20_ctr32 reads
        # OPENSSL_armcap_P and branches to ChaCha20_neon. Go selects
        # the path itself via golang.org/x/sys/cpu, so drop these.
        if ($line =~ /OPENSSL_armcap|\bARMV7_NEON\b/) {
            next;
        }
        if ($mnemonic =~ /^bne$/i
            && $argstr =~ /^\s*\.LChaCha20_neon\s*$/) {
            next;
        }

        # `b .Loop @ go integer-only` -- chacha20 NEON's tail handler
        # branches into the middle of the scalar function for the
        # 64..191-byte residue after the main 3-block-at-a-time loop.
        # We can't represent that in Plan 9 syntax, so emit a UDF
        # (0xe7f000f0, the ARM "permanently undefined" encoding,
        # A8.6.247) as a tripwire. The Go-side wrapper gates the
        # NEON entry on len being a multiple of 192, so this point
        # is unreachable at runtime; if the gate ever breaks, we
        # crash here instead of corrupting data.
        if ($cur_func && $cur_func eq "ChaCha20_neon"
            && $mnemonic =~ /^b$/i
            && $argstr =~ /^\s*\.(?:Loop|LChaCha20_ctr32)\s*$/) {
            print "\tWORD\t\$0xe7f000f0\t// UDF (chacha NEON tail expects Go to gate by 192 bytes)\n";
            next;
        }

        # CryptoGAMS reaches its read-only constants via two PC-rel
        # subs: "sub rN, pc, #M @ funcname" gets the function's own
        # address into rN, and a later "sub rN, rN, #K @ .Llabel"
        # adjusts that to the data label. In Plan 9 we use SB-relative
        # addressing instead. Drop the first sub entirely; rewrite the
        # second to "MOVW $label<>(SB), rN".
        if ($cur_func && $mnemonic eq "sub"
            && $argstr =~ /^(r\d+|sp|lr|pc)\s*,\s*pc\s*,\s*#\d+\s*$/) {
            next;
        }
        if ($cur_func && $mnemonic eq "sub"
            && $argstr =~ /^(r\d+|sp|lr|pc)\s*,\s*\1\s*,\s*#\d+\s*$/
            && $tail_comment =~ /^(\.L\w+)$/
            && exists $DATA_LABELS{$1}) {
            my $label = $1;     # snapshot before xlate_op clobbers $1
            my $reg_gas = $argstr;
            $reg_gas =~ s/\s*,.*//;
            my $reg = xlate_op($reg_gas);
            my $name = $DATA_LABELS{$label}{name};
            print "\tMOVW\t\$${name}<>(SB), $reg\n";
            next;
        }

        # Function-end epilogue: terminal "ldmia sp!, {regs[, pc]}" from
        # the layout. We emit RET (Plan 9's auto-epilogue handles the
        # frame unwind and LR restore; callee-saved regs aren't a thing
        # in Go's ARM ABI). Any trailing "bx lr" gets eaten too.
        if ($cur_func
            && defined($cur_layout)
            && defined($cur_layout->{terminal_ldmia})
            && $cur_layout->{terminal_ldmia} == $orig_idx)
        {
            # No need to restore R14 -- RET unwinds via 0(R13).
            $r14_holds_shadow = 0;
            print "\tRET\n";
            if ($i < @lines) {
                my $pk = $lines[$i];
                $pk =~ s/^\s+//; $pk =~ s/\s+$//; $pk =~ s/\s*\@.*$//;
                if ($pk =~ /^bx\s+lr$/i) { $i++; }
            }
            $cur_func   = undef;
            $cur_layout = undef;
            $sp_shift   = undef;
            next;
        }

        # Drop "bx lr" that wasn't already absorbed.
        if ($mnemonic eq "bx" && $argstr =~ /^\s*lr\s*$/i) {
            print "\tRET\n";
            next;
        }

        # ldmia/stmdb that we must decompose into individual MOVWs:
        #   - r10 in the register list (hardware bitmask is positional,
        #     so we can't simply substitute R14 for R10 within MOVM).
        #   - base register is sp without writeback (Plan 9's MOVM
        #     starts at the base directly, but our SP is offset 4
        #     bytes past upstream's SP because of the auto-saved-LR
        #     slot, so we need explicit (N+4)(R13) accesses).
        my ($_base_reg, $_bang, $_list);
        if (($mnemonic eq "ldmia" || $mnemonic eq "stmdb"
                || $mnemonic eq "stmia" || $mnemonic eq "ldmdb")
            && $argstr =~ /^\s*(r\d+|sp|lr)(\!?)\s*,\s*\{(.*)\}\s*$/
            && do { ($_base_reg, $_bang, $_list) = ($1, $2, $3); 1 }
            && ($argstr =~ /\br10\b/
                || ($_base_reg eq "sp" && $_bang ne "!")))
        {
            my ($base_reg, $bang, $list) = ($_base_reg, $_bang, $_list);
            # Decomposition uses R14 too; flush any in-progress
            # r10 spill before it.
            if ($r14_holds_shadow) {
                print "\tMOVW\t$r14_save_off(R13), R14\n";
                $r14_holds_shadow = 0;
            }
            my @reg_nums;
            for my $tok (split /\s*,\s*/, $list) {
                if ($tok =~ /^r(\d+)-r(\d+)$/) {
                    push @reg_nums, ($1..$2);
                } elsif ($tok eq "lr") {
                    push @reg_nums, 14;
                } elsif ($tok eq "pc") {
                    push @reg_nums, 15;
                } elsif ($tok =~ /^r(\d+)$/) {
                    push @reg_nums, $1;
                }
            }
            my $is_load = ($mnemonic =~ /^ldm/);
            my $is_decr = ($mnemonic =~ /db$/);
            my $base_p9 = xlate_reg($base_reg);
            my $writeback = ($bang eq "!");
            my $count = scalar @reg_nums;
            my $size  = 4 * $count;
            my $start = $is_decr ? -$size : 0;
            # When the base is sp, our R13 is shifted +4 from
            # upstream's sp because of the auto-saved-LR slot at
            # 0(R13). Apply the shift to all offsets.
            if ($base_reg eq "sp" && defined $sp_shift) {
                $start += $sp_shift;
            }
            if ($base_reg eq "lr") {
                die "$cur_func: ldmia/stmdb with lr base + r10 in list is not supported\n";
            }
            # If the base register is in the load list, we must
            # access [base, #N] for all entries before overwriting
            # the base. Build an ordered list of (reg_num, mem_off)
            # pairs with the base placed last for ldm.
            my $base_num;
            if ($base_reg =~ /^r(\d+)$/) { $base_num = $1; }
            my @ordered;
            my $offs = $start;
            for my $n (@reg_nums) {
                push @ordered, [$n, $offs];
                $offs += 4;
            }
            if ($is_load && defined($base_num)) {
                my @nonbase = grep { $_->[0] != $base_num } @ordered;
                my @base    = grep { $_->[0] == $base_num } @ordered;
                @ordered = (@nonbase, @base);
            }
            # We use R14 as the staging register for the r10 element.
            # R14 may already hold a live value (e.g. a base address
            # set up by an earlier instruction); save and restore it
            # via the dedicated r14_save slot.
            print "\tMOVW\tR14, $r14_save_off(R13)\n";
            for my $pair (@ordered) {
                my ($n, $off) = @$pair;
                if ($n == 10) {
                    if ($is_load) {
                        print "\tMOVW\t$off($base_p9), R14\n";
                        print "\tMOVW\tR14, $shadow_r10_off(R13)\n";
                    } else {
                        print "\tMOVW\t$shadow_r10_off(R13), R14\n";
                        print "\tMOVW\tR14, $off($base_p9)\n";
                    }
                } else {
                    if ($is_load) {
                        print "\tMOVW\t$off($base_p9), R$n\n";
                    } else {
                        print "\tMOVW\tR$n, $off($base_p9)\n";
                    }
                }
            }
            print "\tMOVW\t$r14_save_off(R13), R14\n";
            if ($writeback) {
                if ($is_decr) {
                    print "\tSUB\t\$$size, $base_p9, $base_p9\n";
                } else {
                    print "\tADD\t\$$size, $base_p9, $base_p9\n";
                }
            }
            next;
        }

        # General instruction. If r10 appears in any operand,
        # substitute r14 + bracket with shadow-slot load/store. We
        # coalesce consecutive r10 uses within a straight-line code
        # window: $r14_holds_shadow tracks whether R14 already holds
        # the shadow value from a prior r10 spill, in which case we
        # can skip the redundant R14-save / shadow-load. Conversely,
        # when R14's saved value is needed by an upstream instruction
        # (any non-r10 read or write of R14/lr), we must restore it
        # first.
        my ($prefix, $suffix) = ("", "");
        my $rewritten_args = $argstr;
        my $is_r10_use = ($rewritten_args =~ /\br10\b/);
        my $touches_r14 = (!$is_r10_use && (
            $rewritten_args =~ /\b(?:r14|lr)\b/
        ));

        # Branches are control-flow exits: their target may have been
        # entered with R14 in any state, so we must flush before
        # leaving (restore R14's saved value if we'd dirtied it for
        # an r10 spill).
        my $is_branch = ($mnemonic =~ /^(b|bl|bx)([a-z]{2})?s?$/);
        if ($is_branch && $r14_holds_shadow) {
            $prefix = "\tMOVW\t$r14_save_off(R13), R14\n";
            $r14_holds_shadow = 0;
        }

        if ($is_r10_use) {
            unless (defined $shadow_r10_off) {
                die "plan9-xlate.pl: r10 used in $cur_func but no shadow slot\n";
            }
            my ($dst_role, $src_role) = r10_roles($mnemonic, $argstr);
            if ($r14_holds_shadow) {
                # R14 already has shadow_r10's value; skip the save
                # (R14's prior meaningful value is still safe in
                # r14_save_off from the first spill in this window)
                # and skip the load (R14 already has what we'd load).
                $prefix .= "";
            } else {
                $prefix .= "\tMOVW\tR14, $r14_save_off(R13)\n";
                $prefix .= "\tMOVW\t$shadow_r10_off(R13), R14\n" if $src_role;
            }
            $suffix  = "";
            $suffix .= "\tMOVW\tR14, $shadow_r10_off(R13)\n" if $dst_role;
            $r14_holds_shadow = 1;
            $rewritten_args =~ s/\br10\b/r14/g;
        } elsif ($touches_r14 && $r14_holds_shadow) {
            # Upstream wants R14's "real" value back; restore from
            # the saved slot before letting upstream's instruction
            # proceed.
            $prefix .= "\tMOVW\t$r14_save_off(R13), R14\n";
            $r14_holds_shadow = 0;
        }

        my $out = xlate_insn($mnemonic, $rewritten_args);
        if (defined $out) {
            # Rename .Lfoo references to lb_Lfoo so they match the
            # local-label rename above. Use a negative lookbehind
            # to avoid matching condition-code suffixes that happen
            # to start with L (.LO, .LS, .LE, .LT -- those are
            # preceded by an alphabetic mnemonic letter).
            $out =~ s/(?<![A-Za-z])\.(L\w+)/lb_$1/g;
            print $prefix if $prefix;
            if ($tail_comment) {
                print "$out\t// $tail_comment\n";
            } else {
                print "$out\n";
            }
            print $suffix if $suffix;
        } else {
            print "\t// TODO: untranslated: $line\n";
        }
    }

    emit_data_sections();
}

# r10_roles classifies whether r10 is used as a destination, a source,
# or both for a given instruction. CryptoGAMS uses r10 as a regular
# scratch register, so we replace it with R14 and bracket each use
# with shadow-slot load (if r10 is read) and store (if r10 is written).
#
# The classification is per-mnemonic and matches GAS conventions:
#   - ldr  rD, [...]                  -> rD is dest only
#   - str  rS, [...]                  -> rS is src only
#   - ldrb rD, [...]                  -> rD is dest only
#   - strb rS, [...]                  -> rS is src only
#   - mov  rD, rS                     -> rD dest, rS src
#   - add/sub/.../mul rD, rN, rM      -> rD dest, rN/rM src
#   - umull rDlo, rDhi, rN, rM        -> rDlo/rDhi dest, rN/rM src
#   - umlal rDlo, rDhi, rN, rM        -> rDlo/rDhi dest+src (accumulating)
#   - cmp/tst/teq/cmn  r1, op2        -> both src, no dest
#   - b/bl/bx ...                     -> no register dest
sub r10_roles {
    my ($m, $args) = @_;
    my @toks = split /\s*,\s*/, $args;
    my ($base, $cond) = split_mnemonic($m);
    $base = lc $base;

    # tok_has_r10($i): true iff token at index $i mentions r10.
    my $hasr10 = sub {
        my $i = shift;
        return 0 unless $i < @toks;
        return $toks[$i] =~ /\br10\b/;
    };
    my $dst = 0;
    my $src = 0;

    if ($base =~ /^(add|adc|sub|sbc|rsb|rsc|and|orr|eor|bic|mul)$/) {
        # 3-op (or 2-op): dst at 0, srcs at 1+.
        $dst = 1 if $hasr10->(0);
        $src = 1 if $hasr10->(1) || $hasr10->(2);
    } elsif ($base eq "mov" || $base eq "mvn") {
        $dst = 1 if $hasr10->(0);
        # mov rD, rS (, shift) -- srcs are positions 1+.
        $src = 1 if $hasr10->(1) || $hasr10->(2);
    } elsif ($base eq "ldr" || $base eq "ldrb" || $base eq "ldrh"
          || $base eq "ldrsb" || $base eq "ldrsh") {
        $dst = 1 if $hasr10->(0);
        # The address may also reference r10 (e.g. "[r10, #4]"),
        # which would be a src.
        $src = 1 if grep { $_ =~ /\br10\b/ } @toks[1..$#toks];
        # Post-increment ([r10], #imm) and pre-increment with
        # writeback ([r10, #imm]!) both modify r10 in place, so r10
        # is also a dst in those forms.
        $dst = 1 if $args =~ /\[\s*r10\s*\]\s*,/
                 || $args =~ /\[\s*r10\b[^\]]*\]\s*!/;
    } elsif ($base eq "str" || $base eq "strb" || $base eq "strh") {
        # str rS, [...] -- rS is src; address may also use r10 as src.
        $src = 1 if $args =~ /\br10\b/;
        # Same writeback-as-dst rule as for loads.
        $dst = 1 if $args =~ /\[\s*r10\s*\]\s*,/
                 || $args =~ /\[\s*r10\b[^\]]*\]\s*!/;
    } elsif ($base eq "umull") {
        # umull rLo, rHi, rN, rM; rLo/rHi are write-only dests.
        $dst = 1 if $hasr10->(0) || $hasr10->(1);
        $src = 1 if $hasr10->(2) || $hasr10->(3);
    } elsif ($base eq "umlal") {
        # umlal rLo, rHi, rN, rM; rLo/rHi are read-modify-write.
        if ($hasr10->(0) || $hasr10->(1)) { $dst = 1; $src = 1; }
        $src = 1 if $hasr10->(2) || $hasr10->(3);
    } elsif ($base eq "mla") {
        # mla rA, rB, rC, rD; rA = rB*rC + rD. rA is write-only dest.
        $dst = 1 if $hasr10->(0);
        $src = 1 if $hasr10->(1) || $hasr10->(2) || $hasr10->(3);
    } elsif ($base =~ /^(cmp|tst|teq|cmn)$/) {
        $src = 1 if $args =~ /\br10\b/;
    } elsif ($base eq "b" || $base eq "bl" || $base eq "bx") {
        # Branches don't reference r10 in our codebase.
    } else {
        # Conservative fallback -- be safe and load+store.
        $dst = 1 if $hasr10->(0);
        $src = 1 if $args =~ /\br10\b/;
    }
    return ($dst, $src);
}

main();
