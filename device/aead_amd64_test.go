//go:build amd64 && gc && !purego

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/cpu"

	asmAEAD "github.com/tailscale/wireguard-go/tsasm/amd64/chacha20poly1305"
)

func TestShouldUseTSAsm(t *testing.T) {
	for bits := 0; bits < 8; bits++ {
		ssse3, avx2, bmi2 := bits&1 != 0, bits&2 != 0, bits&4 != 0
		want := ssse3 && !(avx2 && bmi2)
		t.Run(fmt.Sprintf("ssse3=%t/avx2=%t/bmi2=%t", ssse3, avx2, bmi2), func(t *testing.T) {
			if got := shouldUseTSAsm(ssse3, avx2, bmi2); got != want {
				t.Fatalf("shouldUseTSAsm = %t, want %t", got, want)
			}
		})
	}
}

// TestAEADDispatchSubprocess starts fresh processes because x/sys/cpu reads
// GODEBUG only during process initialization. Disabling features is supported
// on every host, unlike pretending unsupported instructions are available.
func TestAEADDispatchSubprocess(t *testing.T) {
	if os.Getenv("WG_AEAD_DISPATCH_HELPER") == "1" {
		testAEADDispatchHelper(t)
		return
	}

	cases := []struct {
		name, godebug, want string
	}{
		{"fallback-no-ssse3", "cpu.ssse3=off,cpu.avx2=off,cpu.bmi2=off", "xcrypto"},
	}
	// This case executes the restored kernel, so only request it when CPUID says
	// the real hardware supports SSSE3. GODEBUG never enables an absent feature.
	if cpu.X86.HasSSSE3 {
		cases = append(cases, struct{ name, godebug, want string }{
			"sse-with-newer-kernel-disabled", "cpu.avx2=off,cpu.bmi2=off", "tsasm",
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestAEADDispatchSubprocess$")
			cmd.Env = subprocessEnv(map[string]string{
				"WG_AEAD_DISPATCH_HELPER": "1",
				"WG_AEAD_WANT":            tc.want,
				"GODEBUG":                 tc.godebug,
				"TS_WG_ASM":               "1",
			})
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("subprocess: %v\n%s", err, out)
			}
		})
	}
}

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

func testAEADDispatchHelper(t *testing.T) {
	wantAsm := os.Getenv("WG_AEAD_WANT") == "tsasm"
	if useTSAsm != wantAsm {
		t.Fatalf("SSSE3=%t AVX2=%t BMI2=%t: useTSAsm=%t, want %t",
			cpu.X86.HasSSSE3, cpu.X86.HasAVX2, cpu.X86.HasBMI2, useTSAsm, wantAsm)
	}
	aead, err := chacha20poly1305New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	typ := reflect.TypeOf(aead)
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	isAsm := typ.PkgPath() == "github.com/tailscale/wireguard-go/tsasm/amd64/chacha20poly1305"
	if isAsm != wantAsm {
		t.Fatalf("constructor returned %T; assembly=%t, want %t", aead, isAsm, wantAsm)
	}

	nonce := make([]byte, aead.NonceSize())
	sealed := aead.Seal(nil, nonce, []byte("dispatch test"), nil)
	if got, err := aead.Open(nil, nonce, sealed, nil); err != nil || string(got) != "dispatch test" {
		t.Fatalf("AEAD round trip = %q, %v", got, err)
	}
}

func TestAEADEscapeHatch(t *testing.T) {
	if !useTSAsm {
		t.Skip("this CPU does not use tsasm")
	}
	asm, err := asmAEAD.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TS_WG_ASM", "0")
	got, err := chacha20poly1305New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%T", got) == fmt.Sprintf("%T", asm) {
		t.Fatalf("TS_WG_ASM=0 returned assembly implementation %T", got)
	}
}
