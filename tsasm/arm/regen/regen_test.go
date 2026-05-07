// SPDX-License-Identifier: BSD-3-Clause

// Package regen is a placeholder so the regenerator integration test
// can run from this directory tree. It contains no Go production
// code; the real artifacts here are plan9-xlate.pl, neon_encode.pl,
// regen.sh, and the .cache/ directory regen.sh populates from
// upstream CryptoGAMS at the pinned commit recorded in regen.sh.
package regen

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var runRegenTests = flag.Bool("run-regen-tests", false,
	"run regenerator integration tests (which fetch upstream Perl from "+
		"the network on first run); always on when CI=true")

// skipIfNotCI reports the formatted message as a t.Skip locally and
// t.Fatal under CI=true. Use for "this test needs a tool/condition
// the dev box may lack but CI must satisfy" -- a silent skip in CI
// would let a missing dependency hide a real regression.
func skipIfNotCI(t testing.TB, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") == "true" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// requireTool fails (or skips, locally) if tool isn't in PATH.
func requireTool(t *testing.T, tool, aptPkg string) {
	t.Helper()
	if _, err := exec.LookPath(tool); err != nil {
		skipIfNotCI(t, "%s not in PATH (Debian/Ubuntu: apt-get install %s)",
			tool, aptPkg)
	}
}

// TestRegenReproducible verifies that running tsasm/arm/regen/regen.sh
// produces the .s files already checked in.
//
// The test is skipped by default because it has a network dependency
// on first run (regen.sh fetches the upstream CryptoGAMS .pl files
// from a pinned GitHub URL into a gitignored .cache/ directory).
// Pass --run-regen-tests to opt in, or set CI=true (where we always
// want it to run; in CI any missing tool is a hard failure rather
// than a silent skip).
func TestRegenReproducible(t *testing.T) {
	if !*runRegenTests && os.Getenv("CI") != "true" {
		t.Skip("regen integration test is gated: pass --run-regen-tests or set CI=true")
	}
	if runtime.GOOS == "windows" {
		t.Skip("regen pipeline assumes a Unix shell")
	}
	requireTool(t, "perl", "perl")
	requireTool(t, "cc", "gcc")
	requireTool(t, "curl", "curl")
	requireTool(t, "sh", "dash") // usually present already
	requireTool(t, "sha256sum", "coreutils")

	regenDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	// Snapshot the current committed copies, run regen.sh, diff,
	// then restore. Doing it in-place is the simplest way to avoid
	// having to thread a destination directory through regen.sh.
	committed := []string{
		filepath.Join(regenDir, "..", "poly1305", "poly1305_arm.s"),
		filepath.Join(regenDir, "..", "chacha20", "chacha20_arm.s"),
	}
	saved := make([][]byte, len(committed))
	for i, p := range committed {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		saved[i] = b
	}
	t.Cleanup(func() {
		for i, p := range committed {
			_ = os.WriteFile(p, saved[i], 0o644)
		}
	})

	cmd := exec.Command("sh", filepath.Join(regenDir, "regen.sh"))
	cmd.Dir = regenDir
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("regen.sh failed: %v", err)
	}

	for i, p := range committed {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read regenerated %s: %v", p, err)
		}
		if !bytes.Equal(got, saved[i]) {
			t.Errorf("%s differs from regen.sh output (the committed copy is stale).\nFirst differences:\n%s",
				p, firstDiffs(saved[i], got, 30))
		}
	}
}

// firstDiffs returns a unified-diff-style summary of the first
// `limit` differing lines between two byte slices. Used by
// TestRegenReproducible to make stale-.s failures self-explanatory
// without an external diff invocation.
func firstDiffs(want, got []byte, limit int) string {
	wantLines := strings.Split(string(want), "\n")
	gotLines := strings.Split(string(got), "\n")
	var b strings.Builder
	shown := 0
	n := max(len(wantLines), len(gotLines))
	for i := 0; i < n && shown < limit; i++ {
		var w, g string
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w == g {
			continue
		}
		fmt.Fprintf(&b, "  line %d:\n    -want: %q\n    +got:  %q\n", i+1, w, g)
		shown++
	}
	if shown == limit {
		fmt.Fprintf(&b, "  ... (more differences suppressed)\n")
	}
	return b.String()
}
