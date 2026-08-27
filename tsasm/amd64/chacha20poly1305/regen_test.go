//go:build amd64 && gc && !purego

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package chacha20poly1305

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var runRegenTests = flag.Bool("run-regen-tests", false,
	"regenerate assembly (may download the pinned x/crypto module); always on when CI=true")

func TestRegenReproducible(t *testing.T) {
	if !*runRegenTests && os.Getenv("CI") != "true" {
		t.Skip("regen test is gated: pass --run-regen-tests or set CI=true")
	}
	want, err := os.ReadFile("chacha20poly1305_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "chacha20poly1305_amd64.s")
	cmd := exec.Command("go", "run", ".", "-out", out)
	cmd.Dir = "_asm"
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("regenerating: %v\n%s", err, b)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("checked-in assembly is stale: generated %d bytes, want %d", len(got), len(want))
	}
}

func TestGeneratedAssemblyContainsOnlySSE(t *testing.T) {
	b, err := os.ReadFile("chacha20poly1305_amd64.s")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"TEXT ·chacha20Poly1305Open(SB)", "openSSE128:", "TEXT ·chacha20Poly1305Seal(SB)", "sealSSETail:"} {
		if !strings.Contains(s, want) {
			t.Errorf("generated assembly is missing %q", want)
		}
	}
	for _, unwanted := range []string{"AVX2", " Y0", " Y1", "VPERM", "VPXOR", "VZEROUPPER", "·useAVX2"} {
		if strings.Contains(s, unwanted) {
			t.Errorf("generated assembly contains dormant AVX2 marker %q", unwanted)
		}
	}
}
