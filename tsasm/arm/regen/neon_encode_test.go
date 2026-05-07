// SPDX-License-Identifier: BSD-3-Clause

package regen

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// TestNEONEncoderAgainstGAS extracts every unique NEON GAS line from
// the cached upstream .S files and feeds them through
// neon_encode_test.pl, which encodes each line with both our pure-Perl
// encoder and arm-linux-gnueabihf-as and exits non-zero on any
// mismatch or unrecognized line. Together with TestRegenReproducible
// this gives end-to-end coverage of the regen pipeline.
//
// Gated identically to TestRegenReproducible: skipped by default,
// runs under CI=true or --run-regen-tests. Additionally needs
// arm-linux-gnueabihf-as / arm-linux-gnueabihf-objcopy (the cross-as
// is only used by this validator; the production regen pipeline no
// longer touches it).
func TestNEONEncoderAgainstGAS(t *testing.T) {
	if !*runRegenTests && os.Getenv("CI") != "true" {
		t.Skip("regen integration test is gated: pass --run-regen-tests or set CI=true")
	}
	if runtime.GOOS == "windows" {
		t.Skip("test pipeline assumes a Unix shell")
	}
	requireTool(t, "perl", "perl")
	requireTool(t, "arm-linux-gnueabihf-as", "binutils-arm-linux-gnueabihf")
	requireTool(t, "arm-linux-gnueabihf-objcopy", "binutils-arm-linux-gnueabihf")

	regenDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	// Make sure the .cache/ has the upstream .S files. Easiest way is
	// to run regen.sh once; on first run that fetches the upstream .pl
	// from the network. Subsequent runs use the cache.
	if _, err := os.Stat(filepath.Join(regenDir, ".cache", "chacha-armv4.S")); err != nil {
		cmd := exec.Command("sh", filepath.Join(regenDir, "regen.sh"))
		cmd.Dir = regenDir
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("priming regen.sh: %v", err)
		}
	}

	lines, err := uniqueNEONLines(
		filepath.Join(regenDir, ".cache", "chacha-armv4.S"),
		filepath.Join(regenDir, ".cache", "poly1305-armv4.S"),
	)
	if err != nil {
		t.Fatalf("extracting NEON lines: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("no NEON lines found in cached .S files")
	}
	t.Logf("checking %d unique NEON instruction forms", len(lines))

	cmd := exec.Command("perl", filepath.Join(regenDir, "neon_encode_test.pl"))
	cmd.Dir = regenDir
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("neon_encode_test.pl failed:\n%s", out.String())
	}
	t.Logf("neon_encode_test.pl: %s", strings.TrimSpace(out.String()))
}

// uniqueNEONLines returns the sorted, deduplicated set of NEON GAS
// lines (those starting with "v[a-z]") across the given .S files.
func uniqueNEONLines(paths ...string) ([]string, error) {
	neonRE := regexp.MustCompile(`^v[a-z][a-z0-9.]*`)
	seen := map[string]bool{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", p, err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if i := strings.Index(line, "@"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if !neonRE.MatchString(line) {
				continue
			}
			seen[line] = true
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	sort.Strings(out)
	return out, nil
}
