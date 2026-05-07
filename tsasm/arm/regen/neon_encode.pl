#! /usr/bin/env perl
# SPDX-License-Identifier: BSD-3-Clause
#
# Pure-Perl ARMv7 NEON instruction encoder. Handles the subset of
# NEON used by CryptoGAMS chacha-armv4.pl and poly1305-armv4.pl.
#
# Each per-mnemonic encoder takes the GAS-style operand string (e.g.
# "q0,q0,q12" for `vadd.i32 q0,q0,q12`) and returns the 32-bit ARM
# encoding as a Perl integer.
#
# The dispatcher `encode_neon($line)` parses the mnemonic from
# `$line`, looks up the per-mnemonic encoder, calls it, and returns
# the encoded word. It dies loudly when given a mnemonic or operand
# shape it doesn't recognize, so the regenerator never silently
# emits a wrong instruction.
#
# References (operand bit positions, Vd/Vn/Vm split into 4-bit
# low + 1-bit high, etc.) come from the ARMv7-A ARM, sections
# A8.6.* (NEON). Each encoder includes a comment with the manual
# section it implements, so a reviewer can cross-check.

use strict;
use warnings;

################################################################
# Operand parsing helpers.

# parse_dq parses a "d12" or "q3" operand and returns
# (kind, regnum, dnum) where kind is "d" or "q", regnum is the
# register's own number (0-31 for D, 0-15 for Q), and dnum is the
# 5-bit "D-register equivalent" used by the encoding (qN -> 2*N).
sub parse_dq {
    my $s = shift;
    if ($s =~ /^d(\d+)$/i) {
        my $n = $1 + 0;
        die "neon_encode: D register out of range: d$n\n" if $n > 31;
        return ("d", $n, $n);
    }
    if ($s =~ /^q(\d+)$/i) {
        my $n = $1 + 0;
        die "neon_encode: Q register out of range: q$n\n" if $n > 15;
        return ("q", $n, 2 * $n);
    }
    die "neon_encode: unrecognized D/Q operand: '$s'\n";
}

# parse_dn_lane parses a NEON scalar reference like "d0[0]" returning
# (regnum, lane, lane_bits) where lane_bits is what to put in the
# lane field of the encoding. Only used for instructions that
# reference a single lane.
sub parse_dn_lane {
    my $s = shift;
    return undef unless $s =~ /^d(\d+)\[(\d+)\]$/i;
    return ($1 + 0, $2 + 0);
}

# parse_arm_reg parses "rN" / "lr" / "sp" and returns the register
# number (0..15).
sub parse_arm_reg {
    my $s = shift;
    return 13 if $s eq "sp";
    return 14 if $s eq "lr";
    return 15 if $s eq "pc";
    if ($s =~ /^r(\d+)$/i) { return $1 + 0; }
    die "neon_encode: unrecognized ARM register: '$s'\n";
}

# enc_dn_split takes a 5-bit D-register number and returns its 4-bit
# low part and 1-bit high part packed for the Vd/Vn/Vm fields.
# Each return value is "($low_4bit, $hi_1bit)".
sub enc_dn_split {
    my $n = shift;
    return ($n & 0xF, ($n >> 4) & 0x1);
}

# size_bits_for maps a "i32"/"u32"/"32" type suffix to the 2-bit
# size encoding (00=8, 01=16, 10=32, 11=64). Dies on unknown sizes.
sub size_bits_for {
    my $s = shift;
    return 0b00 if $s =~ /^[iuf]?8$/;
    return 0b01 if $s =~ /^[iuf]?16$/;
    return 0b10 if $s =~ /^[iuf]?32$/;
    return 0b11 if $s =~ /^[iuf]?64$/;
    die "neon_encode: unknown size suffix '$s'\n";
}

################################################################
# Encoders for individual mnemonics.
#
# Each encoder receives the full mnemonic (e.g. "vadd.i32") and the
# argument string (e.g. "q0,q0,q12") and returns a 32-bit integer
# encoding.

# VADD (integer) -- ARMv7-A ARM A8.6.359.
# Encoding A1: 1111 001U 0Dss Vnnn Vddd 1000 N Q M 0 Vmmm
# where U=0 for VADD (signed/unsigned doesn't matter for add),
# size = ss (00=8, 01=16, 10=32, 11=64).
sub enc_vadd_i {
    my ($mn, $args) = @_;
    my $size = $mn;
    $size =~ s/^vadd\.i//;
    my $sz = size_bits_for("i$size");
    my @a = split /\s*,\s*/, $args;
    @a == 3 or die "neon_encode: vadd needs 3 operands: $args\n";
    my ($kind, undef, $dd) = parse_dq($a[0]);
    my (undef, undef, $dn) = parse_dq($a[1]);
    my (undef, undef, $dm) = parse_dq($a[2]);
    my $Q = ($kind eq "q") ? 1 : 0;
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vn_lo, $Vn_hi) = enc_dn_split($dn);
    my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);
    return (0b1111 << 28)
         | (0b0010 << 24)
         | ($Vd_hi << 22)
         | ($sz    << 20)
         | ($Vn_lo << 16)
         | ($Vd_lo << 12)
         | (0b1000 << 8)
         | ($Vn_hi << 7)
         | ($Q     << 6)
         | ($Vm_hi << 5)
         | (0      << 4)
         | $Vm_lo;
}

# VEOR -- ARMv7-A ARM A8.6.371.
# Encoding A1: 1111 0011 0D00 Vnnn Vddd 0001 N Q M 1 Vmmm
sub enc_veor {
    my ($mn, $args) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 3 or die "neon_encode: veor needs 3 operands: $args\n";
    my ($kind, undef, $dd) = parse_dq($a[0]);
    my (undef,  undef, $dn) = parse_dq($a[1]);
    my (undef,  undef, $dm) = parse_dq($a[2]);
    my $Q = ($kind eq "q") ? 1 : 0;
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vn_lo, $Vn_hi) = enc_dn_split($dn);
    my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);
    return (0b1111 << 28)
         | (0b0011 << 24)
         | ($Vd_hi << 22)
         | (0b00   << 20)
         | ($Vn_lo << 16)
         | ($Vd_lo << 12)
         | (0b0001 << 8)
         | ($Vn_hi << 7)
         | ($Q     << 6)
         | ($Vm_hi << 5)
         | (1      << 4)
         | $Vm_lo;
}

# VMUL/VMLA long form (signed/unsigned, integer) -- A8.6.443 (VMLAL),
# A8.6.444 (VMLSL), A8.6.469 (VMULL).  Vd is a Q register, Vn/Vm are
# D registers; output is 2x input width.
#
# Encoding A1 (vector form): 1111 001 U 1 D ss Vn Vd 10 op 0 N 0 M 0 Vm
# where op = 0 for VMLAL, 1 for VMLSL, and the bit-pattern for VMULL
# uses the same shape with bits[11:8]=1100 (op2 differs).
#
# The "by scalar" form (A8.6.451 etc.): 1111 001 U 1 D ss Vn Vd 10 op 1 N 1 M 0 Vm
# with the scalar D-register restricted to d0..d15 and a lane bit.
sub _enc_long_mac {
    my ($mn, $args, $opbits, $opbits_scalar, $base27_24) = @_;
    # $opbits        = bits[11:8] for the vector form.
    # $opbits_scalar = bits[11:8] for the by-scalar form.
    # $base27_24     = bits[27:24] of the encoding (e.g. 0b0011 for U=1).
    my @a = split /\s*,\s*/, $args;
    @a == 3 or die "neon_encode: long-mac needs 3 operands: $args\n";
    my ($kind_d, undef, $dd) = parse_dq($a[0]);
    $kind_d eq "q" or die "neon_encode: $mn destination must be Q register: $args\n";
    my ($kind_n, undef, $dn) = parse_dq($a[1]);
    $kind_n eq "d" or die "neon_encode: $mn second operand must be D register: $args\n";

    my $size = $mn;
    $size =~ s/^v(?:mlal|mlsl|mull|mla|mls)\.[us]//;
    my $sz = size_bits_for($size);

    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vn_lo, $Vn_hi) = enc_dn_split($dn);

    # Third operand: either dM (vector form) or dM[lane] (scalar form).
    my ($scalar, $dm, $lane) = (0, 0, 0);
    if ($a[2] =~ /^d(\d+)\[(\d+)\]$/i) {
        ($dm, $lane) = ($1 + 0, $2 + 0);
        $scalar = 1;
    } elsif ($a[2] =~ /^d(\d+)$/i) {
        $dm = $1 + 0;
    } else {
        die "neon_encode: $mn third operand must be dN or dN[lane]: $args\n";
    }

    if (!$scalar) {
        # Vector form: opbits[11:8] as given; bits[7,6,5,4] = N 0 M 0.
        my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);
        return (0b1111     << 28)
             | ($base27_24 << 24)
             | ($Vd_hi     << 22)
             | (1          << 23)
             | ($sz        << 20)
             | ($Vn_lo     << 16)
             | ($Vd_lo     << 12)
             | ($opbits    << 8)
             | ($Vn_hi     << 7)
             | (0          << 6)
             | ($Vm_hi     << 5)
             | (0          << 4)
             | $Vm_lo;
    } else {
        my $sc_opbits = $opbits_scalar;
        # Lane encoding for size=32: M = lane (0 or 1). Vm[3:0] = dM
        # (must be in 0..15).
        my ($lane_bit, $vm_field);
        if ($sz == 0b10) {
            die "scalar dM must be d0..d15: d$dm\n" if $dm > 15;
            die "lane out of range: d$dm\[$lane\]\n" if $lane > 1;
            $lane_bit = $lane;
            $vm_field = $dm;
        } elsif ($sz == 0b01) {
            die "scalar dM must be d0..d7 for 16-bit: d$dm\n" if $dm > 7;
            die "lane out of range\n" if $lane > 3;
            $lane_bit = ($lane >> 1) & 1;
            $vm_field = $dm | (($lane & 1) << 3);
        } else {
            die "by-scalar size $size not supported\n";
        }
        return (0b1111     << 28)
             | ($base27_24 << 24)
             | ($Vd_hi     << 22)
             | (1          << 23)
             | ($sz        << 20)
             | ($Vn_lo     << 16)
             | ($Vd_lo     << 12)
             | ($sc_opbits << 8)
             | ($Vn_hi     << 7)
             | (1          << 6)
             | ($lane_bit  << 5)
             | (0          << 4)
             | $vm_field;
    }
}

sub enc_vmlal_u { _enc_long_mac(@_, 0b1000, 0b0010, 0b0011); }
sub enc_vmlal_s { _enc_long_mac(@_, 0b1000, 0b0010, 0b0010); }
sub enc_vmull_u { _enc_long_mac(@_, 0b1100, 0b1010, 0b0011); }
sub enc_vmull_s { _enc_long_mac(@_, 0b1100, 0b1010, 0b0010); }

# Shift-by-immediate helper. The (L:imm6) field jointly encodes the
# element size and the shift amount per ARMv7-A ARM A7.4 (Modified
# immediate constants in advanced SIMD instructions).
#
# For "left-shift by N":
#   size  8: imm6 = 8+N  (N=0..7),    L=0
#   size 16: imm6 = 16+N (N=0..15),   L=0
#   size 32: imm6 = 32+N (N=0..31),   L=0
#   size 64: imm6 = N    (N=0..63),   L=1
#
# For "right-shift by N", the encoding is (size - N) instead of N:
#   size  8: imm6 = 16-N  (N=1..8),    L=0
#   size 16: imm6 = 32-N  (N=1..16),   L=0
#   size 32: imm6 = 64-N  (N=1..32),   L=0
#   size 64: imm6 = 64-N  (N=1..64),   L=1
sub _shift_imm6_L_left {
    my ($size, $shift) = @_;
    return (8  + $shift, 0) if $size == 8  && $shift >= 0 && $shift <= 7;
    return (16 + $shift, 0) if $size == 16 && $shift >= 0 && $shift <= 15;
    return (32 + $shift, 0) if $size == 32 && $shift >= 0 && $shift <= 31;
    return ($shift,      1) if $size == 64 && $shift >= 0 && $shift <= 63;
    die "shift left by $shift on size $size out of range\n";
}
sub _shift_imm6_L_right {
    my ($size, $shift) = @_;
    return (16 - $shift, 0) if $size == 8  && $shift >= 1 && $shift <= 8;
    return (32 - $shift, 0) if $size == 16 && $shift >= 1 && $shift <= 16;
    return (64 - $shift, 0) if $size == 32 && $shift >= 1 && $shift <= 32;
    return (64 - $shift, 1) if $size == 64 && $shift >= 1 && $shift <= 64;
    die "shift right by $shift on size $size out of range\n";
}

# Common encoder for VSHL/VSHR/VSLI/VSRI (immediate). $base27_24 is
# the bits[27:24] of the encoding (encodes U for shr/shl) and
# $opbits is bits[11:8] (the opcode). $is_left selects the
# left/right shift-amount convention. Operands: qD/dD, qM/dM, #imm.
sub _enc_shift_imm {
    my ($mn, $args, $base27_24, $opbits, $is_left) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 3 or die "neon_encode: $mn needs 3 operands: $args\n";
    my ($kind, undef, $dd) = parse_dq($a[0]);
    my (undef,  undef, $dm) = parse_dq($a[1]);
    my $Q = ($kind eq "q") ? 1 : 0;

    my $size = $mn;
    $size =~ s/^v(?:shl|shr|sli|sri|sra|qshl|qshr|qrshr|qrshl)\.[ius]?//;
    my $sz = size_bits_for("i$size");
    my $size_v = $size;
    $size_v =~ s/^[us]?//;

    my $imm;
    if ($a[2] =~ /^#(.+)$/) {
        my $val = $1;
        $val =~ s/^\s+|\s+$//g;
        if ($val =~ /^\d+$/)        { $imm = int($val); }
        elsif ($val =~ /^0x[0-9a-fA-F]+$/) { $imm = hex($val); }
        else { die "neon_encode: bad shift immediate '$val'\n"; }
    } else {
        die "neon_encode: $mn needs immediate as 3rd operand: $args\n";
    }

    my ($imm6, $L) = $is_left
        ? _shift_imm6_L_left($size_v, $imm)
        : _shift_imm6_L_right($size_v, $imm);

    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);

    return (0b1111     << 28)
         | ($base27_24 << 24)
         | ($Vd_hi     << 22)
         | (1          << 23)
         | ($imm6      << 16)
         | ($Vd_lo     << 12)
         | ($opbits    << 8)
         | ($L         << 7)
         | ($Q         << 6)
         | ($Vm_hi     << 5)
         | (1          << 4)
         | $Vm_lo;
}

# Shift-by-immediate variants. The two per-mnemonic things that
# vary are bits[27:24] (U field) and bits[11:8] (opcode):
#   VSHL.i*  (U=0): 0010 / 0101 / left
#   VSHR.s*  (U=0): 0010 / 0000 / right
#   VSHR.u*  (U=1): 0011 / 0000 / right
#   VSLI.*   (U=1): 0011 / 0101 / left   (bit[24]=1 distinguishes from VSHL)
#   VSRI.*   (U=1): 0011 / 0100 / right
#   VSRA.u*  (U=1): 0011 / 0001 / right (accumulate)
# VSHL by immediate is bit-identical for signed and unsigned input
# (the shift doesn't care), so vshl.u* and vshl.i* both encode with
# bit[24]=0.
sub enc_vshl_i { _enc_shift_imm(@_, 0b0010, 0b0101, 1); }
sub enc_vshl_u { _enc_shift_imm(@_, 0b0010, 0b0101, 1); }
sub enc_vshr_s { _enc_shift_imm(@_, 0b0010, 0b0000, 0); }
sub enc_vshr_u { _enc_shift_imm(@_, 0b0011, 0b0000, 0); }
sub enc_vsli   { _enc_shift_imm(@_, 0b0011, 0b0101, 1); }
sub enc_vsri   { _enc_shift_imm(@_, 0b0011, 0b0100, 0); }
sub enc_vsra_u { _enc_shift_imm(@_, 0b0011, 0b0001, 0); }
sub enc_vsra_s { _enc_shift_imm(@_, 0b0010, 0b0001, 0); }

# 3-register same length, bits[27:24]=0010, bits[11:8]=0001.
# bits[21:20] selects: 00=VAND, 01=VBIC, 10=VORR, 11=VORN.
# `vmov vD, vM` in GAS is encoded as `vorr vD, vM, vM` so the
# register-to-register move falls through to enc_vorr_reg.
sub _enc_logical_3reg {
    my ($args, $sel) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 3 or die "neon_encode: logical needs 3 operands: $args\n";
    my ($kind, undef, $dd) = parse_dq($a[0]);
    my (undef,  undef, $dn) = parse_dq($a[1]);
    my (undef,  undef, $dm) = parse_dq($a[2]);
    my $Q = ($kind eq "q") ? 1 : 0;
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vn_lo, $Vn_hi) = enc_dn_split($dn);
    my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);
    return (0b1111 << 28)
         | (0b0010 << 24)
         | ($Vd_hi << 22)
         | ($sel   << 20)
         | ($Vn_lo << 16)
         | ($Vd_lo << 12)
         | (0b0001 << 8)
         | ($Vn_hi << 7)
         | ($Q     << 6)
         | ($Vm_hi << 5)
         | (1      << 4)
         | $Vm_lo;
}

# 2-register vmov (D-D or Q-Q) is just VORR with both source operands
# the same. GAS allows it as a separate mnemonic.
sub enc_vmov_reg {
    my ($mn, $args) = @_;
    return undef if $args =~ /\#/;            # not register form
    my @a = split /\s*,\s*/, $args;
    @a == 2 or die "neon_encode: vmov reg-form needs 2 operands: $args\n";
    return _enc_logical_3reg("$a[0],$a[1],$a[1]", 0b10);  # VORR
}

sub enc_vand_3reg { _enc_logical_3reg($_[1], 0b00); }
sub enc_vbic_3reg { _enc_logical_3reg($_[1], 0b01); }
sub enc_vorr_3reg { _enc_logical_3reg($_[1], 0b10); }
sub enc_vorn_3reg { _enc_logical_3reg($_[1], 0b11); }

# VAND/VBIC also have an immediate form when the second operand is
# `#imm`. The `.iSZ` suffix on vbic.i32 etc. signals the immediate
# form. Encoding A1 (VBIC immediate, A8.6.367):
#   1111 001 i 1 D 000 imm3 Vd cmode 0 Q 1 1 imm4
# where (cmode, op) selects the immediate byte-replication pattern
# per A7.4.6.
sub enc_vand_or_vbic_imm {
    my ($mn, $args, $is_bic) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 2 or die "neon_encode: $mn imm needs 2 operands: $args\n";
    my ($kind, undef, $dd) = parse_dq($a[0]);
    my $Q = ($kind eq "q") ? 1 : 0;
    my $imm;
    if ($a[1] =~ /^#(.+)$/) {
        my $v = $1;
        $imm = $v =~ /^0x/ ? hex($v) : int($v);
    } else {
        die "neon_encode: $mn imm needs '#imm': $args\n";
    }

    # For .i32 VBIC, the constant is replicated/encoded by cmode.
    # Patterns: 0x000000ff, 0x0000ff00, 0x00ff0000, 0xff000000 use
    # cmode bits[3:2] = 00,01,10,11 (and bit[1:0]=01 for .i32).
    # 0xffff0000 / 0x0000ffff (16-bit forms) use cmode bits[3:2]=10,11
    # with bit[1:0]=10 ... actually 16-bit uses different cmode.
    #
    # We only need .i32 here; identify which byte the constant occupies.
    my $size = $mn;
    $size =~ s/^v(?:bic|and)\.i//;
    if ($size != 32 && $size != 16) {
        die "neon_encode: $mn imm only .i16/.i32 supported: $mn\n";
    }
    # cmode for VORR/VBIC (immediate) = 0xx1 (per A7.4.6); the
    # corresponding VMOV/VMVN family uses cmode 0xx0 with the same
    # byte-position bits in [3:1].
    my ($cmode, $imm8);
    if ($size == 32) {
        if    (($imm & ~0x000000FF) == 0) { $cmode = 0b0001; $imm8 = $imm        & 0xFF; }
        elsif (($imm & ~0x0000FF00) == 0) { $cmode = 0b0011; $imm8 = ($imm >> 8) & 0xFF; }
        elsif (($imm & ~0x00FF0000) == 0) { $cmode = 0b0101; $imm8 = ($imm >>16) & 0xFF; }
        elsif (($imm & ~0xFF000000) == 0) { $cmode = 0b0111; $imm8 = ($imm >>24) & 0xFF; }
        else {
            die sprintf("neon_encode: %s .i32 immediate 0x%x not encodable\n", $mn, $imm);
        }
    } else {                  # .i16
        if    (($imm & ~0x00FF) == 0) { $cmode = 0b1001; $imm8 = $imm       & 0xFF; }
        elsif (($imm & ~0xFF00) == 0) { $cmode = 0b1011; $imm8 = ($imm >>8) & 0xFF; }
        else {
            die sprintf("neon_encode: %s .i16 immediate 0x%x not encodable\n", $mn, $imm);
        }
    }

    # For VBIC immediate the op bit (bit 5 of cmode in the encoded
    # field, but that's bits[6] of the instruction's cmode... actually
    # there's a bit "op" alongside cmode that selects bitwise OR
    # (VORR.imm) vs AND-NOT (VBIC.imm).
    # Encoding bit positions:
    #   bit[24]   = i
    #   bit[22]   = D
    #   bits[21:19] = 1 1 1 (always for these forms)
    #   bits[18:16] = imm3 (high 3 bits of imm8)
    #   bits[15:12] = Vd_lo
    #   bits[11:8]  = cmode (4 bits)
    #   bit[7]      = 0
    #   bit[6]      = Q
    #   bit[5]      = op  (0 = VORR-imm or VMOV-imm; 1 = VBIC/VMVN-imm)
    #   bit[4]      = 1
    #   bits[3:0]   = imm4 (low 4 bits of imm8)
    my $i    = ($imm8 >> 7) & 0x1;
    my $imm3 = ($imm8 >> 4) & 0x7;
    my $imm4 =  $imm8       & 0xF;
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my $op_bit = $is_bic ? 1 : 0;

    return (0b1111 << 28)
         | (0b0010 << 24)
         | ($i     << 24) # bit[24] = i (high bit of imm8)
         | (1      << 23)
         | ($Vd_hi << 22)
         | (0b000  << 19)
         | ($imm3  << 16)
         | ($Vd_lo << 12)
         | ($cmode << 8)
         | (0      << 7)
         | ($Q     << 6)
         | ($op_bit<< 5)
         | (1      << 4)
         | $imm4;
}

# VEXT.8 vD, vN, vM, #imm -- A8.6.380.
# 1111 0010 1011 Vn Vd imm4 N Q M 0 Vm
sub enc_vext_8 {
    my ($mn, $args) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 4 or die "neon_encode: vext.8 needs 4 operands: $args\n";
    my ($kind, undef, $dd) = parse_dq($a[0]);
    my (undef,  undef, $dn) = parse_dq($a[1]);
    my (undef,  undef, $dm) = parse_dq($a[2]);
    my $Q = ($kind eq "q") ? 1 : 0;
    my $imm;
    if ($a[3] =~ /^#(\d+)$/) { $imm = int($1); }
    else { die "vext.8 needs '#imm' as 4th operand: $args\n"; }
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vn_lo, $Vn_hi) = enc_dn_split($dn);
    my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);
    return (0b1111 << 28) | (0b0010 << 24)
         | ($Vd_hi << 22) | (1 << 23)
         | (0b11 << 20) | ($Vn_lo << 16)
         | ($Vd_lo << 12) | ($imm << 8)
         | ($Vn_hi << 7)  | ($Q << 6) | ($Vm_hi << 5) | (0 << 4) | $Vm_lo;
}

# VDUP (ARM core register) -- A8.6.376.
# Encoding A1: 1110 1110 1 B Q 0 Vd Rt 1011 D 0 E 1 0000
# Or VDUP (scalar) -- A8.6.302 -- 1111 0011 1 D 11 imm4 Vd 1100 0 Q M 0 Vm
# We only see "vdup.32 dD, rN" form here (ARM core source, .32).
sub enc_vdup_32 {
    my ($mn, $args) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 2 or die "neon_encode: vdup needs 2 operands: $args\n";
    my ($kind, $regnum, $dd) = parse_dq($a[0]);
    my $rt = parse_arm_reg($a[1]);
    my $Q = ($kind eq "q") ? 1 : 0;
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my $size = $mn;
    $size =~ s/^vdup\.//;
    my ($B, $E);
    if    ($size eq "8")  { ($B, $E) = (1, 0); }
    elsif ($size eq "16") { ($B, $E) = (0, 1); }
    elsif ($size eq "32") { ($B, $E) = (0, 0); }
    else  { die "neon_encode: vdup.$size unsupported\n"; }
    return (0b1110 << 28)
         | (0b1110 << 24)
         | (1 << 23)
         | ($B << 22)
         | ($Q << 21)
         | (0 << 20)
         | ($Vd_lo << 16)
         | ($rt << 12)
         | (0b1011 << 8)
         | ($Vd_hi << 7)
         | (0 << 6)
         | ($E << 5)
         | (1 << 4)
         | 0;
}

# VMOV (ARM core register to NEON scalar) -- A8.6.298.
# vmov.32 dD[lane], rN
# Encoding: 1110 1110 0 0 opc1 0 Vd Rt 1011 D opc2 1 0000
# For .32 lane: opc1[1]=1, opc2=00, lane bit in opc1[0].
sub enc_vmov_32 {
    my ($mn, $args) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 2 or die "neon_encode: vmov.32 needs 2 operands: $args\n";

    # Two forms: vmov.32 dD[lane], rN  (ARM->NEON)
    #           vmov.32 rN, dD[lane]   (NEON->ARM)
    my ($dst, $src) = @a;
    my ($to_neon, $dD, $lane, $rt);
    if ($dst =~ /^d(\d+)\[(\d+)\]$/i) {
        $to_neon = 1;
        $dD = $1 + 0; $lane = $2 + 0;
        $rt = parse_arm_reg($src);
    } elsif ($src =~ /^d(\d+)\[(\d+)\]$/i) {
        $to_neon = 0;
        $dD = $1 + 0; $lane = $2 + 0;
        $rt = parse_arm_reg($dst);
    } else {
        die "neon_encode: vmov.32 needs dN[lane],rN or rN,dN[lane]: $args\n";
    }
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dD);
    # Per A8.6.298 (VMOV ARM-to-scalar) for .32:
    #   bit[22]=0, bit[21]=lane, bit[6:5]=00.
    # The L bit at bit[20] is 0 for ARM-to-NEON, 1 for NEON-to-ARM.
    my $L = $to_neon ? 0 : 1;
    return (0b1110 << 28)
         | (0b1110 << 24)
         | (0 << 23) | (0 << 22)
         | ($lane << 21)
         | ($L << 20)
         | ($Vd_lo << 16)
         | ($rt << 12)
         | (0b1011 << 8)
         | ($Vd_hi << 7)
         | (0 << 5)
         | (1 << 4)
         | 0;
}

# VREV32 -- A8.6.354. Reverses (8/16-bit) elements within each 32-bit
# word of the source vector. The size suffix is the *element* size,
# not the lane size: `.8` reverses 4 bytes per 32-bit word; `.16`
# reverses 2 halfwords per 32-bit word. Encoding A1:
#
#   1111 0011 1D11 size 00 Vd 0000 1 Q M 0 Vm
#
# Bits[8:7] = 01 are constant for VREV32 (00 = VREV64, 10 = VREV16);
# the element-size suffix lives in size (bits[19:18]).
sub enc_vrev32 {
    my ($mn, $args) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 2 or die "neon_encode: vrev32 needs 2 operands: $args\n";
    my ($kind, undef, $dd) = parse_dq($a[0]);
    my (undef,  undef, $dm) = parse_dq($a[1]);
    my $Q = ($kind eq "q") ? 1 : 0;
    my $size = $mn;
    $size =~ s/^vrev32\.//;
    my $sz = size_bits_for("i$size");
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);
    return (0b1111 << 28) | (0b0011 << 24)
         | (1 << 23) | ($Vd_hi << 22)
         | (0b11 << 20) | ($sz << 18)
         | (0b00 << 16) | ($Vd_lo << 12)
         | (0b0000 << 8) | (1 << 7)
         | ($Q << 6) | ($Vm_hi << 5) | (0 << 4) | $Vm_lo;
}

# VTRN -- A8.6.413. Transpose pairs of elements between two vectors.
# 1111 0011 1D11 ss 10 Vd 0000 1 Q M 0 Vm
sub enc_vtrn {
    my ($mn, $args) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 2 or die "neon_encode: vtrn needs 2 operands: $args\n";
    my ($kind, undef, $dd) = parse_dq($a[0]);
    my (undef,  undef, $dm) = parse_dq($a[1]);
    my $Q = ($kind eq "q") ? 1 : 0;
    my $size = $mn; $size =~ s/^vtrn\.//;
    my $sz = size_bits_for("i$size");
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);
    return (0b1111 << 28) | (0b0011 << 24)
         | (1 << 23) | ($Vd_hi << 22)
         | (0b11 << 20) | ($sz << 18) | (0b10 << 16)
         | ($Vd_lo << 12) | (0b0000 << 8)
         | (1 << 7) | ($Q << 6) | ($Vm_hi << 5) | (0 << 4) | $Vm_lo;
}

# VMOVN.iSZ dD, qM -- A8.6.317. Narrow each element by half (32->16 etc).
# 1111 0011 1D11 ss 10 Vd 0010 0 0 M 0 Vm
sub enc_vmovn_i {
    my ($mn, $args) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 2 or die "neon_encode: vmovn needs 2 operands: $args\n";
    my (undef,  undef, $dd) = parse_dq($a[0]);
    my (undef,  undef, $dm) = parse_dq($a[1]);
    my $size = $mn; $size =~ s/^vmovn\.i//;
    # The ss field encodes the SIZE OF THE NARROWED ELEMENT. So
    # vmovn.i64 narrows 64-bit -> 32-bit, ss = size_bits_for(32).
    my $narrowed = $size / 2;
    my $sz = size_bits_for("i$narrowed");
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);
    return (0b1111 << 28) | (0b0011 << 24)
         | (1 << 23) | ($Vd_hi << 22)
         | (0b11 << 20) | ($sz << 18) | (0b10 << 16)
         | ($Vd_lo << 12) | (0b0010 << 8)
         | (0 << 7) | (0 << 6) | ($Vm_hi << 5) | (0 << 4) | $Vm_lo;
}

# VSHRN.iSZ dD, qM, #imm -- A8.6.398. Narrow + right shift.
# 1111 001 0 1 D imm6 Vd 1000 0 0 M 1 Vm
sub enc_vshrn_i_or_u {
    my ($mn, $args) = @_;
    my @a = split /\s*,\s*/, $args;
    @a == 3 or die "neon_encode: vshrn needs 3 operands: $args\n";
    my (undef,  undef, $dd) = parse_dq($a[0]);
    my (undef,  undef, $dm) = parse_dq($a[1]);
    my $imm;
    if ($a[2] =~ /^#(\d+)$/) { $imm = int($1); }
    else { die "vshrn needs '#imm': $args\n"; }
    my $size = $mn; $size =~ s/^vshrn\.[iu]//;
    # imm6 = source_size - shift, with L=0 always (A8.6.398). The
    # source size is the full element size (16/32/64); the result
    # is half. shift must be in 1..source_size/2.
    die "vshrn shift out of range: $imm on size $size\n"
        if $imm < 1 || $imm > $size / 2;
    my $imm6 = $size - $imm;
    my $L = 0;
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);
    return (0b1111 << 28) | (0b0010 << 24)
         | (1 << 23) | ($Vd_hi << 22)
         | ($imm6 << 16) | ($Vd_lo << 12)
         | (0b1000 << 8) | ($L << 7) | (0 << 6) | ($Vm_hi << 5) | (1 << 4) | $Vm_lo;
}

# parse_neon_reglist parses "{q0}", "{q0,q1}", "{d0}", "{d0,d1,d2,d3}".
# Returns (start_d, count_d) where count_d is the total number of
# consecutive D registers covered. Q registers count as 2 D regs.
sub parse_neon_reglist {
    my $s = shift;
    $s =~ s/^\{//; $s =~ s/\}$//;
    my @parts = split /\s*,\s*/, $s;
    my @dregs;
    for my $p (@parts) {
        if ($p =~ /^d(\d+)-d(\d+)$/i) {
            for ($1..$2) { push @dregs, $_; }
        } elsif ($p =~ /^q(\d+)-q(\d+)$/i) {
            for my $q ($1..$2) { push @dregs, 2*$q, 2*$q + 1; }
        } elsif ($p =~ /^d(\d+)\[(\d+)\]$/i) {
            push @dregs, [$1+0, $2+0];   # marked as scalar
        } elsif ($p =~ /^d(\d+)$/i) {
            push @dregs, $1 + 0;
        } elsif ($p =~ /^q(\d+)$/i) {
            push @dregs, 2*$1, 2*$1 + 1;
        } else {
            die "neon_encode: bad reglist token '$p'\n";
        }
    }
    return @dregs;
}

# parse_mem_addr parses [rN], [rN]!, [rN, #imm], [rN, #imm]!, [rN, rM]
# Returns (rn_num, mode) where mode is one of:
#   ("noinc")       -- no writeback
#   ("postinc_w")   -- post-increment by element-width
#   ("postinc_imm", $imm) -- pre-decrement by literal (after VLDR/VSTR)
#   ("postinc_rm",  $rm)  -- post-increment by register
#   ("imm",  $imm)        -- immediate offset (VLDR/VSTR)
#   ("imm_w",$imm)        -- pre-incremented immediate with writeback
# Evaluate a constant expression that may contain decimal/hex
# integers, parens, +-*/ -- same shape as plan9-xlate.pl's eval_const.
sub _eval_int_expr {
    my $s = shift;
    return undef unless defined $s;
    # Allow shift operators (<<, >>) in addition to the basic
    # arithmetic, so an immediate like "1<<24" evaluates.
    return undef unless $s =~ m{^[\s\d+\-*/()<>xa-fA-F]+$};
    $s =~ s/0x([0-9a-fA-F]+)/hex("0x$1")/ge;
    my $v = eval $s;
    return undef if $@;
    return int($v);
}

sub parse_mem_addr {
    my $s = shift;
    $s =~ s/^\s+|\s+$//g;
    if ($s =~ /^\[(r\d+|sp|lr|pc)\]\s*!\s*$/i) {
        return (parse_arm_reg($1), "postinc_w");
    }
    if ($s =~ /^\[(r\d+|sp|lr|pc)\]\s*,\s*(r\d+|sp|lr|pc)\s*$/i) {
        return (parse_arm_reg($1), "postinc_rm", parse_arm_reg($2));
    }
    if ($s =~ /^\[(r\d+|sp|lr|pc)\]\s*$/i) {
        return (parse_arm_reg($1), "noinc");
    }
    if ($s =~ /^\[(r\d+|sp|lr|pc)\s*,\s*#([^\]]+)\]\s*!\s*$/i) {
        my $v = _eval_int_expr($2);
        defined $v or die "neon_encode: bad memory immediate '$2'\n";
        return (parse_arm_reg($1), "imm_w", $v);
    }
    if ($s =~ /^\[(r\d+|sp|lr|pc)\s*,\s*#([^\]]+)\]\s*$/i) {
        my $v = _eval_int_expr($2);
        defined $v or die "neon_encode: bad memory immediate '$2'\n";
        return (parse_arm_reg($1), "imm", $v);
    }
    die "neon_encode: cannot parse memory operand '$s'\n";
}

# parse_align_mem extends parse_mem_addr with the GAS "[rN, :Nbits]"
# alignment hint used by single-/multi-element VLD1/VST1/VLDn/VSTn.
# Returns (rn, align_bits, mode, ...) where align_bits is the integer
# after the colon (e.g. 32 for ":32") or 0 if no hint. The
# instruction-specific encoder maps that to the actual align field.
sub parse_align_mem {
    my $s = shift;
    $s =~ s/^\s+|\s+$//g;
    if ($s =~ /^\[(r\d+|sp|lr|pc)\s*,\s*:(\d+)\]\s*!\s*$/i) {
        return (parse_arm_reg($1), int($2), "postinc_w");
    }
    if ($s =~ /^\[(r\d+|sp|lr|pc)\s*,\s*:(\d+)\]\s*,\s*(r\d+|sp|lr|pc)\s*$/i) {
        return (parse_arm_reg($1), int($2), "postinc_rm", parse_arm_reg($3));
    }
    if ($s =~ /^\[(r\d+|sp|lr|pc)\s*,\s*:(\d+)\]\s*$/i) {
        return (parse_arm_reg($1), int($2), "noinc");
    }
    my @r = parse_mem_addr($s);
    return ($r[0], 0, @r[1..$#r]);
}

# _rm_for_mode maps a parse_mem_addr / parse_align_mem mode to the
# Rm encoding used by VLD1/VST1/VLDn/VSTn single-/multi-element ops:
#   noinc       -> 0b1111  (no writeback)
#   postinc_w   -> 0b1101  (writeback by element-width)
#   postinc_rm  -> Rm      (post-increment by register)
sub _rm_for_mode {
    my ($mode, @rest) = @_;
    return 0b1111      if $mode eq "noinc";
    return 0b1101      if $mode eq "postinc_w";
    return $rest[0]    if $mode eq "postinc_rm";
    die "neon_encode: unsupported memory mode '$mode'\n";
}

# Encode VLD1 / VST1 (multiple single elements). A8.6.391/A8.6.392.
# Encoding A1: 1111 0100 0 D L 0 Rn Vd type size align Rm
# where L=1 for VLD1, L=0 for VST1.
sub _enc_vld1_vst1 {
    my ($mn, $args, $is_load) = @_;
    # mnemonic suffix may be .8/.16/.32/.64 (no signedness for vld1).
    my $size = $mn;
    $size =~ s/^v(?:ld|st)1\.//;
    my $sz = size_bits_for("i$size");

    # args is "{regs}, [mem]"  optionally with writeback or post-incr.
    my ($reglist_str, $mem_str);
    if ($args =~ /^\s*(\{[^}]*\})\s*,\s*(.*)$/) {
        ($reglist_str, $mem_str) = ($1, $2);
    } else {
        die "neon_encode: $mn malformed args: $args\n";
    }
    my @dregs = parse_neon_reglist($reglist_str);
    my $count = scalar @dregs;
    my $vd = $dregs[0];
    # Reject single-element forms (e.g. `vst1.32 {d18[0]}, [r0]`):
    # those are a different encoding (vst1 single element to one
    # lane) which this multiple-element encoder doesn't handle.
    # Falling through silently would produce garbage because $vd
    # is an array ref instead of a scalar reg number.
    if (ref($dregs[0])) {
        die "neon_encode: $mn single-element form not supported: $reglist_str\n";
    }
    # Validate that the d-register sequence is contiguous.
    for (my $i = 1; $i < @dregs; $i++) {
        if (ref($dregs[$i]) || $dregs[$i] != $dregs[$i-1] + 1) {
            die "neon_encode: $mn requires contiguous regs: $reglist_str\n";
        }
    }

    my %type_for = (1 => 0b0111, 2 => 0b1010, 3 => 0b0110, 4 => 0b0010);
    my $type = $type_for{$count};
    die "neon_encode: $mn count $count not supported\n" unless defined $type;

    my @addr = parse_mem_addr($mem_str);
    my ($rn, $mode, @rest) = @addr;
    my $rm;
    if    ($mode eq "noinc")       { $rm = 0b1111; }
    elsif ($mode eq "postinc_w")   { $rm = 0b1101; }
    elsif ($mode eq "postinc_rm")  { $rm = $rest[0]; }
    else { die "neon_encode: $mn does not support address mode '$mode'\n"; }

    my ($Vd_lo, $Vd_hi) = enc_dn_split($vd);
    my $align = 0;     # default no-alignment hint
    return (0b1111 << 28)
         | (0b0100 << 24)
         | (0 << 23)
         | ($Vd_hi << 22)
         | (($is_load ? 1 : 0) << 21)
         | (0 << 20)
         | ($rn << 16)
         | ($Vd_lo << 12)
         | ($type << 8)
         | ($sz << 6)
         | ($align << 4)
         | $rm;
}

sub enc_vld1 { _enc_vld1_vst1(@_, 1); }
sub enc_vst1 { _enc_vld1_vst1(@_, 0); }

# VLDR / VSTR for D registers -- A8.6.275 / A8.6.401.
# Encoding A1: 1110 110 P U D W 1 Rn Vd 1011 imm8
#   where for VLDR/VSTR (single D-reg, no writeback): P=1, W=0
#   U=1 if positive offset, 0 if negative; imm8 = abs(offset)/4.
sub _enc_vldr_vstr {
    my ($mn, $args, $is_load) = @_;
    my @a = split /\s*,\s*/, $args, 2;
    @a == 2 or die "neon_encode: $mn needs 2 operands: $args\n";
    my ($kind, undef, $dD) = parse_dq($a[0]);
    $kind eq "d" or die "neon_encode: $mn requires D register: $args\n";
    my @addr = parse_mem_addr($a[1]);
    my ($rn, $mode, @rest) = @addr;
    my ($U, $imm8) = (1, 0);
    if ($mode eq "noinc") {
        # [rN] = offset 0
    } elsif ($mode eq "imm") {
        my $off = $rest[0];
        $U = $off >= 0 ? 1 : 0;
        my $abs = $off >= 0 ? $off : -$off;
        die "neon_encode: $mn offset must be word-multiple: $off\n" if $abs & 3;
        die "neon_encode: $mn offset out of range: $off\n" if $abs > 1020;
        $imm8 = $abs >> 2;
    } else {
        die "neon_encode: $mn unsupported mode '$mode'\n";
    }
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dD);
    return (0b1110 << 28)
         | (0b110 << 25)
         | (1 << 24)         # P=1 (offset addressing)
         | ($U << 23)
         | ($Vd_hi << 22)
         | (0 << 21)         # W=0 (no writeback)
         | (($is_load ? 1 : 0) << 20)
         | ($rn << 16)
         | ($Vd_lo << 12)
         | (0b1011 << 8)
         | $imm8;
}
sub enc_vldr { _enc_vldr_vstr(@_, 1); }
sub enc_vstr { _enc_vldr_vstr(@_, 0); }

# VLDM / VSTM (multiple D registers) -- A8.6.273 / A8.6.398.
# Encoding A1: 1110 110 P U D W L Rn Vd 1011 imm8
# imm8 = 2*number_of_dregs (each D-reg occupies 2 imm8 units in the
# T2 encoding, where the lsb of imm8 indicates a pair vs single).
# For vldmia rN, {dN-dM}: P=0, U=1, W=0, L=1.
# For vstmdb rN!, {dN-dM}: P=1, U=0, W=1, L=0.
sub _enc_vldm_vstm {
    my ($mn, $args, $P, $U, $W, $L) = @_;
    my @a = split /\s*,\s*/, $args, 2;
    @a == 2 or die "neon_encode: $mn needs 2 operands: $args\n";
    my $base = $a[0];
    my $bang = ($base =~ s/!\s*$//) ? 1 : 0;
    my $rn = parse_arm_reg($base);
    if ($bang && !$W) {
        die "neon_encode: $mn writeback '!' but encoding W=0\n";
    }
    my @dregs = parse_neon_reglist($a[1]);
    my $count = scalar @dregs;
    my $vd = $dregs[0];
    for (my $i = 1; $i < @dregs; $i++) {
        if (ref($dregs[$i]) || $dregs[$i] != $dregs[$i-1] + 1) {
            die "neon_encode: $mn requires contiguous D regs: $a[1]\n";
        }
    }
    my ($Vd_lo, $Vd_hi) = enc_dn_split($vd);
    my $imm8 = 2 * $count;
    return (0b1110 << 28)
         | (0b110 << 25)
         | ($P << 24)
         | ($U << 23)
         | ($Vd_hi << 22)
         | ($W << 21)
         | ($L << 20)
         | ($rn << 16)
         | ($Vd_lo << 12)
         | (0b1011 << 8)
         | $imm8;
}

sub enc_vldmia    { _enc_vldm_vstm($_[0], $_[1], 0, 1, 0, 1); }
sub enc_vldmia_w  { _enc_vldm_vstm($_[0], $_[1], 0, 1, 1, 1); }
sub enc_vstmia    { _enc_vldm_vstm($_[0], $_[1], 0, 1, 0, 0); }
sub enc_vstmdb    { _enc_vldm_vstm($_[0], $_[1], 1, 0, 1, 0); }

# Dispatcher entry for vldmia / vstmdb that handles writeback ('!')
# at the base register.
sub enc_vldmia_disp {
    my ($mn, $args) = @_;
    my @a = split /\s*,\s*/, $args, 2;
    return enc_vldmia_w($mn, $args) if $a[0] =~ /!\s*$/;
    return enc_vldmia($mn, $args);
}

################################################################
# VLD1 / VST1 single element to/from one lane. A8.6.394 / A8.6.395.
#
# Encoding A1:
#   1111 0100 1 D L 0 Rn Vd ssXX index_align Rm
# where L=1 for VLD1, L=0 for VST1, ss = size, and index_align
# encodes the lane index plus an optional alignment hint:
#   size 8:  index_align[3:1] = index (0..7), index_align[0] = 0
#   size 16: index_align[3:2] = index (0..3), [1] = a (a=1 for :16), [0] = 0
#   size 32: index_align[3]   = index (0..1), [2:0] = 011 if :32 else 000
sub _enc_vld1_vst1_lane {
    my ($mn, $args, $is_load) = @_;
    my $size = $mn;
    $size =~ s/^v(?:ld|st)1\.//;
    my $sz = size_bits_for("i$size");

    # Operand form 1: "{dN[lane]}, mem"  (with braces)
    # Operand form 2: "dN[lane], mem"    (no braces, GAS accepts both)
    my ($lane_str, $mem_str);
    if ($args =~ /^\s*\{([^}]*)\}\s*,\s*(.*)$/) {
        ($lane_str, $mem_str) = ($1, $2);
    } elsif ($args =~ /^\s*(d\d+\[\d+\])\s*,\s*(.*)$/i) {
        ($lane_str, $mem_str) = ($1, $2);
    } else {
        die "neon_encode: $mn malformed args: $args\n";
    }
    my @dregs = parse_neon_reglist("{$lane_str}");
    @dregs == 1 && ref($dregs[0])
        or die "neon_encode: $mn expects {dN[lane]}: $args\n";
    my ($vd, $lane) = @{$dregs[0]};

    my ($rn, $align_bits, $mode, @rest) = parse_align_mem($mem_str);
    my $rm = _rm_for_mode($mode, @rest);

    # Build index_align field per ARM ARM table.
    my $idx_align;
    if    ($sz == 0b00) { # size 8
        $align_bits == 0 or die "neon_encode: $mn .8 lane has no alignment hint\n";
        $idx_align = ($lane & 0x7) << 1;
    } elsif ($sz == 0b01) { # size 16
        my $a = 0;
        if    ($align_bits == 0)  { $a = 0; }
        elsif ($align_bits == 16) { $a = 1; }
        else { die "neon_encode: $mn .16 lane bad align :$align_bits\n"; }
        $idx_align = (($lane & 0x3) << 2) | ($a << 1);
    } elsif ($sz == 0b10) { # size 32
        my $low3 = 0;
        if    ($align_bits == 0)  { $low3 = 0b000; }
        elsif ($align_bits == 32) { $low3 = 0b011; }
        else { die "neon_encode: $mn .32 lane bad align :$align_bits\n"; }
        $idx_align = (($lane & 0x1) << 3) | $low3;
    } else {
        die "neon_encode: $mn size 64 not valid for single-element form\n";
    }

    my ($Vd_lo, $Vd_hi) = enc_dn_split($vd);
    return (0b1111 << 28)
         | (0b0100 << 24)
         | (1 << 23)
         | ($Vd_hi << 22)
         | (($is_load ? 1 : 0) << 21)
         | (0 << 20)
         | ($rn << 16)
         | ($Vd_lo << 12)
         | ($sz << 10)
         | (0b00 << 8)
         | ($idx_align << 4)
         | $rm;
}

################################################################
# VLD4 / VST4 (multiple 4-element structures). A8.6.317 / A8.6.418.
#
# Encoding A1:
#   1111 0100 0 D L 0 Rn Vd type size align Rm
# where L=1 for VLD4, L=0 for VST4. type encodes the stride between
# adjacent d-regs in the structure: 0000=stride 1, 0001=stride 2.
sub _enc_vld4_vst4_multi {
    my ($mn, $args, $is_load) = @_;
    my $size = $mn;
    $size =~ s/^v(?:ld|st)4\.//;
    my $sz = size_bits_for("i$size");

    my ($reglist_str, $mem_str);
    if ($args =~ /^\s*(\{[^}]*\})\s*,\s*(.*)$/) {
        ($reglist_str, $mem_str) = ($1, $2);
    } else {
        die "neon_encode: $mn malformed args: $args\n";
    }
    my @dregs = parse_neon_reglist($reglist_str);
    @dregs == 4 or die "neon_encode: $mn expects 4 d-regs: $reglist_str\n";
    for my $r (@dregs) {
        ref($r) and die "neon_encode: $mn (multi) got lane operand: $reglist_str\n";
    }

    # Stride between adjacent d-regs: 1 or 2.
    my $stride = $dregs[1] - $dregs[0];
    $stride == 1 || $stride == 2
        or die "neon_encode: $mn stride must be 1 or 2: $reglist_str\n";
    for (my $i = 1; $i < 4; $i++) {
        $dregs[$i] == $dregs[0] + $i * $stride
            or die "neon_encode: $mn d-regs not in regular stride: $reglist_str\n";
    }
    my $type = ($stride == 1) ? 0b0000 : 0b0001;

    my ($rn, $align_bits, $mode, @rest) = parse_align_mem($mem_str);
    my $rm = _rm_for_mode($mode, @rest);
    # Alignment hint encoding for VLD4/VST4 multi: 00=none, 01=:64,
    # 10=:128, 11=:256. We only need :none for now.
    my $align = 0;
    if    ($align_bits == 0)   { $align = 0b00; }
    elsif ($align_bits == 64)  { $align = 0b01; }
    elsif ($align_bits == 128) { $align = 0b10; }
    elsif ($align_bits == 256) { $align = 0b11; }
    else { die "neon_encode: $mn unsupported align :$align_bits\n"; }

    my ($Vd_lo, $Vd_hi) = enc_dn_split($dregs[0]);
    return (0b1111 << 28)
         | (0b0100 << 24)
         | (0 << 23)
         | ($Vd_hi << 22)
         | (($is_load ? 1 : 0) << 21)
         | (0 << 20)
         | ($rn << 16)
         | ($Vd_lo << 12)
         | ($type << 8)
         | ($sz << 6)
         | ($align << 4)
         | $rm;
}

################################################################
# VLD4 / VST4 single 4-element structure to/from one lane.
# A8.6.320 / A8.6.421.
#
# Encoding A1:
#   1111 0100 1 D L 0 Rn Vd ss 11 index_align Rm
# size=32 is the only one CryptoGAMS uses. index_align:
#   [3] = lane index (0..1 for .32)
#   [2] = stride select (0 = stride 1, 1 = stride 2)
#   [1:0] = alignment bits (00=none, others = specific sizes per ARM ARM)
sub _enc_vld4_vst4_lane {
    my ($mn, $args, $is_load) = @_;
    my $size = $mn;
    $size =~ s/^v(?:ld|st)4\.//;
    my $sz = size_bits_for("i$size");

    my ($reglist_str, $mem_str);
    if ($args =~ /^\s*(\{[^}]*\})\s*,\s*(.*)$/) {
        ($reglist_str, $mem_str) = ($1, $2);
    } else {
        die "neon_encode: $mn malformed args: $args\n";
    }
    my @dregs = parse_neon_reglist($reglist_str);
    @dregs == 4 or die "neon_encode: $mn expects 4 lane operands: $reglist_str\n";
    for my $r (@dregs) {
        ref($r) or die "neon_encode: $mn (single) wants {dN[lane]}: $reglist_str\n";
    }
    my $lane = $dregs[0]->[1];
    for my $r (@dregs) {
        $r->[1] == $lane or die "neon_encode: $mn lane must match across regs: $reglist_str\n";
    }
    my $stride = $dregs[1]->[0] - $dregs[0]->[0];
    $stride == 1 || $stride == 2
        or die "neon_encode: $mn stride must be 1 or 2: $reglist_str\n";
    for (my $i = 1; $i < 4; $i++) {
        $dregs[$i]->[0] == $dregs[0]->[0] + $i * $stride
            or die "neon_encode: $mn d-regs not in regular stride: $reglist_str\n";
    }

    my ($rn, $align_bits, $mode, @rest) = parse_align_mem($mem_str);
    my $rm = _rm_for_mode($mode, @rest);

    # index_align: lane in [3], stride bit in [2], align in [1:0].
    # For size 32 with no alignment hint, [1:0] = 00.
    my $align_low2 = 0;
    if    ($align_bits == 0)   { $align_low2 = 0b00; }
    # ARM ARM specifies other alignment values per size; we don't
    # use them and don't need to encode them yet.
    else { die "neon_encode: $mn unsupported align :$align_bits\n"; }
    my $T = ($stride == 2) ? 1 : 0;
    my $idx_align = (($lane & 0x1) << 3) | ($T << 2) | $align_low2;

    my ($Vd_lo, $Vd_hi) = enc_dn_split($dregs[0]->[0]);
    return (0b1111 << 28)
         | (0b0100 << 24)
         | (1 << 23)
         | ($Vd_hi << 22)
         | (($is_load ? 1 : 0) << 21)
         | (0 << 20)
         | ($rn << 16)
         | ($Vd_lo << 12)
         | ($sz << 10)
         | (0b11 << 8)
         | ($idx_align << 4)
         | $rm;
}

sub enc_vld1_lane { _enc_vld1_vst1_lane(@_, 1); }
sub enc_vst1_lane { _enc_vld1_vst1_lane(@_, 0); }
sub enc_vld4_multi { _enc_vld4_vst4_multi(@_, 1); }
sub enc_vst4_multi { _enc_vld4_vst4_multi(@_, 0); }
sub enc_vld4_lane  { _enc_vld4_vst4_lane(@_, 1); }
sub enc_vst4_lane  { _enc_vld4_vst4_lane(@_, 0); }

# Dispatch vld4./vst4. between the multi-register and single-element-
# to-lane forms based on whether the reglist tokens carry a "[lane]"
# index.
sub enc_vld4 {
    my ($mn, $args) = @_;
    return ($args =~ /\[\d+\]/) ? enc_vld4_lane($mn, $args)
                                : enc_vld4_multi($mn, $args);
}
sub enc_vst4 {
    my ($mn, $args) = @_;
    return ($args =~ /\[\d+\]/) ? enc_vst4_lane($mn, $args)
                                : enc_vst4_multi($mn, $args);
}

################################################################
# VADDL (signed/unsigned vector add long). A8.6.355.
#
# Encoding A1:
#   1111 001U 1 D ss Vn Vd 0000 N 0 M 0 Vm
# Dest is a Q register starting at d{Vd}; sources are D registers.
sub _enc_vaddl {
    my ($mn, $args, $U) = @_;
    my $size = $mn;
    $size =~ s/^vaddl\.[us]//;
    my $sz = size_bits_for("i$size");

    my @a = split /\s*,\s*/, $args;
    @a == 3 or die "neon_encode: $mn needs 3 operands: $args\n";
    my ($kind_d, undef, $dd) = parse_dq($a[0]);
    $kind_d eq "q" or die "neon_encode: $mn dest must be Q: $args\n";
    my ($kind_n, undef, $dn) = parse_dq($a[1]);
    $kind_n eq "d" or die "neon_encode: $mn Vn must be D: $args\n";
    my ($kind_m, undef, $dm) = parse_dq($a[2]);
    $kind_m eq "d" or die "neon_encode: $mn Vm must be D: $args\n";

    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my ($Vn_lo, $Vn_hi) = enc_dn_split($dn);
    my ($Vm_lo, $Vm_hi) = enc_dn_split($dm);
    return (0b1111 << 28)
         | (0b001 << 25)
         | ($U << 24)
         | (1 << 23)
         | ($Vd_hi << 22)
         | ($sz << 20)
         | ($Vn_lo << 16)
         | ($Vd_lo << 12)
         | (0b0000 << 8)
         | ($Vn_hi << 7)
         | (0 << 6)
         | ($Vm_hi << 5)
         | (0 << 4)
         | $Vm_lo;
}
sub enc_vaddl_u { _enc_vaddl(@_, 1); }
sub enc_vaddl_s { _enc_vaddl(@_, 0); }

################################################################
# VMOV (immediate). A8.6.298.
#
# Encoding A1:
#   1111 0010 1 D 0 0 0 imm3 Vd cmode 0 Q op 1 imm4
# where imm8 = imm3:imm4. We handle .i32 with optional shift-by-8/16/24,
# which is what CryptoGAMS uses ("vmov.i32 q14, #1<<24"). cmode selects
# the shift family per the ARM ARM cmode table:
#   0000: i32, imm8         | 0010: i32, imm8 << 8
#   0100: i32, imm8 << 16   | 0110: i32, imm8 << 24
sub enc_vmov_imm32 {
    my ($mn, $args) = @_;
    my @a = split /\s*,\s*/, $args, 2;
    @a == 2 or die "neon_encode: $mn needs 2 operands: $args\n";
    my ($kind, undef, $dd) = parse_dq($a[0]);

    my $imm_str = $a[1];
    $imm_str =~ s/^\s*#//;
    my $imm_val = _eval_int_expr($imm_str);
    defined $imm_val or die "neon_encode: $mn cannot evaluate immediate '$imm_str'\n";
    $imm_val &= 0xFFFFFFFF;

    # Find which 8-bit-shifted-by-Nx8 form matches.
    my $cmode;
    my $imm8;
    if    (($imm_val & 0xFFFFFF00) == 0)                 { $cmode = 0b0000; $imm8 = $imm_val & 0xFF; }
    elsif (($imm_val & 0xFFFF00FF) == 0 && $imm_val>=0)  { $cmode = 0b0010; $imm8 = ($imm_val >> 8)  & 0xFF; }
    elsif (($imm_val & 0xFF00FFFF) == 0)                 { $cmode = 0b0100; $imm8 = ($imm_val >> 16) & 0xFF; }
    elsif (($imm_val & 0x00FFFFFF) == 0)                 { $cmode = 0b0110; $imm8 = ($imm_val >> 24) & 0xFF; }
    else {
        die sprintf("neon_encode: %s immediate 0x%08x doesn't fit i32 shift-by-8 form\n",
                    $mn, $imm_val);
    }

    my $Q = ($kind eq "q") ? 1 : 0;
    my ($Vd_lo, $Vd_hi) = enc_dn_split($dd);
    my $imm3 = ($imm8 >> 4) & 0x7;
    my $imm4 = $imm8 & 0xF;
    return (0b1111 << 28)
         | (0b0010 << 24)
         | (1 << 23)
         | ($Vd_hi << 22)
         | (0b000 << 19)
         | ($imm3 << 16)
         | ($Vd_lo << 12)
         | ($cmode << 8)
         | (0 << 7)
         | ($Q << 6)
         | (0 << 5)
         | (1 << 4)
         | $imm4;
}

################################################################
# Dispatcher.

# Map mnemonic (or mnemonic prefix with size suffix) to encoder.
my %ENCODERS = (
    "veor"   => \&enc_veor,
    "vmov"   => \&enc_vmov_reg,
    "vand"   => \&enc_vand_3reg,
    "vorr"   => \&enc_vorr_3reg,
    "vorn"   => \&enc_vorn_3reg,
    "vbic"   => \&enc_vbic_3reg,
    "vldr"   => \&enc_vldr,
    "vstr"   => \&enc_vstr,
    "vldmia" => \&enc_vldmia_disp,
    "vstmdb" => \&enc_vstmdb,
);

# Encoders that key on the size-less prefix. The dispatcher falls
# back to checking these when the full mnemonic isn't found, so
# vadd.i32, vadd.i16, etc. all route through enc_vadd_i.
my %PREFIX_ENCODERS = (
    "vadd.i"   => \&enc_vadd_i,
    "vmlal.u"  => \&enc_vmlal_u,
    "vmlal.s"  => \&enc_vmlal_s,
    "vmull.u"  => \&enc_vmull_u,
    "vmull.s"  => \&enc_vmull_s,
    "vshl.i"   => \&enc_vshl_i,
    "vshl.u"   => \&enc_vshl_u,
    "vshr.s"   => \&enc_vshr_s,
    "vshr.u"   => \&enc_vshr_u,
    "vsli."    => \&enc_vsli,
    "vsri."    => \&enc_vsri,
    "vsri.u"   => \&enc_vsri,
    "vsra.u"   => \&enc_vsra_u,
    "vsra.s"   => \&enc_vsra_s,
    "vbic.i"   => sub { enc_vand_or_vbic_imm($_[0], $_[1], 1); },
    "vext.8"   => \&enc_vext_8,
    "vdup."    => \&enc_vdup_32,
    "vmov.32"  => \&enc_vmov_32,
    "vrev32."  => \&enc_vrev32,
    "vtrn."    => \&enc_vtrn,
    "vmovn.i"  => \&enc_vmovn_i,
    "vshrn.i"  => \&enc_vshrn_i_or_u,
    "vshrn.u"  => \&enc_vshrn_i_or_u,
);

# vand.iSZ: only `.i32`/`.i16` are immediate forms; `vand.i64` is
# really the vec-vec form (logical AND of two 64-bit values).
$PREFIX_ENCODERS{"vand.i64"} = sub { enc_vand_3reg($_[0], $_[1]); };
$PREFIX_ENCODERS{"vand.i"}   = sub { enc_vand_or_vbic_imm($_[0], $_[1], 0); };

# vld1 / vst1 with various size suffixes. enc_vld1/enc_vst1 dispatch
# between the multiple-element and single-element-to-lane forms based
# on whether the reglist token contains a "[lane]" index.
$PREFIX_ENCODERS{"vld1."} = sub {
    return ($_[1] =~ /\[\d+\]/) ? enc_vld1_lane(@_) : enc_vld1(@_);
};
$PREFIX_ENCODERS{"vst1."} = sub {
    return ($_[1] =~ /\[\d+\]/) ? enc_vst1_lane(@_) : enc_vst1(@_);
};
$PREFIX_ENCODERS{"vld4."} = \&enc_vld4;
$PREFIX_ENCODERS{"vst4."} = \&enc_vst4;
$PREFIX_ENCODERS{"vaddl.u"} = \&enc_vaddl_u;
$PREFIX_ENCODERS{"vaddl.s"} = \&enc_vaddl_s;
$PREFIX_ENCODERS{"vmov.i32"} = \&enc_vmov_imm32;

sub encode_neon {
    my $line = shift;
    $line =~ s/\s*\@.*$//;          # strip GAS comment
    $line =~ s/^\s+|\s+$//g;
    my ($mn, $args) = split /\s+/, $line, 2;
    $args //= "";

    if (my $fn = $ENCODERS{$mn}) {
        return $fn->($mn, $args);
    }
    # Try the longest matching prefix first so e.g. "vand.i64" hits
    # its dedicated entry before the generic "vand.i" immediate-form
    # encoder.
    for my $prefix (sort { length($b) <=> length($a) } keys %PREFIX_ENCODERS) {
        if (substr($mn, 0, length $prefix) eq $prefix) {
            return $PREFIX_ENCODERS{$prefix}->($mn, $args);
        }
    }
    die "neon_encode: no encoder for mnemonic '$mn' (line: $line)\n";
}

1;
