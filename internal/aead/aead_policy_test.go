// SPDX-License-Identifier: MIT

package aead

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestEscapeHatch(t *testing.T) {
	t.Setenv("TS_WG_ASM", "0")
	key := make([]byte, chacha20poly1305.KeySize)
	got, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	want, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.TypeOf(got) != reflect.TypeOf(want) {
		t.Fatalf("TS_WG_ASM=0 returned %T, want %T", got, want)
	}
}

func TestFIPSPolicy(t *testing.T) {
	if os.Getenv("WG_AEAD_POLICY_HELPER") == "1" {
		if _, err := New(make([]byte, chacha20poly1305.KeySize)); err == nil {
			t.Fatal("constructor bypassed fips140=only")
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFIPSPolicy$")
	cmd.Env = subprocessEnv(map[string]string{
		"WG_AEAD_POLICY_HELPER": "1",
		"GODEBUG":               "fips140=only",
		"TS_WG_ASM":             "1",
	})
	if out, err := cmd.CombinedOutput(); err != nil {
		// Go rejects FIPS mode during initialization in purego builds, before
		// the constructor can run. That rejection also enforces the policy.
		if strings.Contains(string(out), "fips140: FIPS 140-3 mode is incompatible with the purego build tag") {
			return
		}
		t.Fatalf("subprocess: %v\n%s", err, out)
	}
}

// subprocessEnv replaces rather than appends, since a duplicate GODEBUG entry is ambiguous.
func subprocessEnv(overrides map[string]string) []string {
	env := os.Environ()
	for key, value := range overrides {
		prefix := key + "="
		filtered := env[:0]
		for _, entry := range env {
			if !strings.HasPrefix(entry, prefix) {
				filtered = append(filtered, entry)
			}
		}
		env = append(filtered, prefix+value)
	}
	return env
}
