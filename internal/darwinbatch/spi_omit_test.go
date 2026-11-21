//go:build darwin

package darwinbatch

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOmitBuildHasNoSPITrace builds the module root with and without ts_omit_darwin_spi for amd64 and arm64, and checks the import table and raw bytes: only the default build may mention sendmsg_x or recvmsg_x.
//
// It builds the root rather than this package because call sites in other packages can also carry the names.
func TestOmitBuildHasNoSPITrace(t *testing.T) {
	if _, err := exec.LookPath("nm"); err != nil {
		t.Skip("nm not available")
	}
	dir := t.TempDir()
	for _, arch := range []string{"amd64", "arm64"} {
		for _, omit := range []bool{false, true} {
			name := "with-spi-" + arch
			if omit {
				name = "omit-spi-" + arch
			}
			bin := filepath.Join(dir, name)
			args := []string{"build", "-o", bin}
			if omit {
				args = append(args, "-tags", "ts_omit_darwin_spi")
			}
			args = append(args, "../..") // the module root
			cmd := exec.Command("go", args...)
			cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH="+arch, "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: build failed: %v\n%s", name, err, out)
			}
			raw, err := os.ReadFile(bin)
			if err != nil {
				t.Fatal(err)
			}
			hasString := strings.Contains(string(raw), "sendmsg_x") || strings.Contains(string(raw), "recvmsg_x")
			nmOut, _ := exec.Command("nm", "-u", bin).Output()
			hasImport := strings.Contains(string(nmOut), "_sendmsg_x") || strings.Contains(string(nmOut), "_recvmsg_x")
			if omit && (hasString || hasImport) {
				t.Errorf("%s: omit build still references the SPI (string=%v import=%v)", name, hasString, hasImport)
			}
			if !omit && !(hasString && hasImport) {
				t.Errorf("%s: default build does not reference the SPI (string=%v import=%v), so it is not compiled in and this test would pass vacuously", name, hasString, hasImport)
			}
			t.Logf("%-18s string=%-5v import=%v", name, hasString, hasImport)
		}
	}
}

// In an omit build Supported must be false, so every caller takes the unbatched fallback.
func TestSupportedFollowsBuildTag(t *testing.T) {
	if spiAvailable != Supported() && !spiAvailable {
		t.Fatal("omit build must report Supported() == false")
	}
	t.Logf("spiAvailable=%v Supported()=%v", spiAvailable, Supported())
}
