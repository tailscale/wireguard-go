#! /usr/bin/env perl
# SPDX-License-Identifier: BSD-3-Clause
#
# Cross-checks the Perl NEON encoders in neon_encode.pl against
# arm-linux-gnueabihf-as. Reads NEON GAS lines on stdin (one per
# line); for each, computes the Perl encoding and the arm-as
# encoding and reports any mismatch.
#
# Usage:
#   perl neon_encode_test.pl <neon_lines.txt
#
# A typical run (use the Go wrapper for an end-to-end automated
# version, see TestNEONEncoderAgainstGAS in neon_encode_test.go):
#   perl neon_encode_test.pl < unique_neon_lines.txt
#
# Exits 0 only if every input line matched and the Perl encoder
# recognized every line (no skips). A skip means there's a missing
# encoder in neon_encode.pl, which the regen pipeline now treats as
# a hard error (batch_encode_neon dies rather than falling back to
# arm-as), so we want the same strict behavior here.

use strict;
use warnings;
use File::Temp qw/tempfile/;
use FindBin;
require "$FindBin::Bin/neon_encode.pl";

sub asm_encode_batch {
    my @lines = @_;
    my ($sf, $sp) = tempfile("nv-XXXX", SUFFIX => ".s", TMPDIR => 1);
    my ($of, $op) = tempfile("nv-XXXX", SUFFIX => ".o", TMPDIR => 1);
    my ($bf, $bp) = tempfile("nv-XXXX", SUFFIX => ".bin", TMPDIR => 1);
    close $of; close $bf;
    print $sf ".syntax unified\n.arch armv7-a\n.fpu neon\n.code 32\n";
    for my $l (@lines) { print $sf "$l\n"; }
    close $sf;
    system("arm-linux-gnueabihf-as", "-mfpu=neon", "-march=armv7-a",
           "-o", $op, $sp) == 0
        or die "arm-as failed; input at $sp\n";
    system("arm-linux-gnueabihf-objcopy", "-O", "binary",
           "--only-section=.text", $op, $bp) == 0
        or die "objcopy failed\n";
    open my $fh, "<:raw", $bp or die;
    my $buf;
    read $fh, $buf, -s $bp;
    close $fh;
    unlink $sp, $op, $bp;
    my @words = unpack("V*", $buf);
    return @words;
}

my @lines;
while (my $l = <STDIN>) {
    chomp $l;
    $l =~ s/^\s+|\s+$//g;
    next unless length $l;
    next if $l =~ /^[#@\.]/;
    push @lines, $l;
}

my @asm = asm_encode_batch(@lines);
if (@asm != @lines) {
    die sprintf("arm-as produced %d words for %d lines\n",
                scalar @asm, scalar @lines);
}

my $ok       = 0;
my $mismatch = 0;
my @skipped;
for (my $i = 0; $i < @lines; $i++) {
    my $line = $lines[$i];
    my $want = $asm[$i];
    my $got  = eval { encode_neon($line) };
    if ($@) {
        push @skipped, $line;
        next;
    }
    if ($got == $want) {
        $ok++;
    } else {
        $mismatch++;
        printf STDERR "MISMATCH: %-40s perl=0x%08x asm=0x%08x\n",
            $line, $got, $want;
    }
}

printf "ok=%d  mismatch=%d  skipped(no encoder)=%d\n",
    $ok, $mismatch, scalar @skipped;
for my $l (@skipped) {
    print STDERR "SKIPPED: $l\n";
}
exit(1) if $mismatch || @skipped;
exit(0);
