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

/*
TestAEADDispatch asserts the two properties the dispatch has to get right: a CPU with SSSE3 but no AVX2 must reach tsasm, and a CPU with AVX2 must not. The second half is the important one, since routing AVX2 machines here would silently replace x/crypto's maintained kernel for most amd64 users.
*/
func TestAEADDispatch(t *testing.T) {
	hasAVX2 := cpu.X86.HasAVX2 && cpu.X86.HasBMI2
	t.Logf("SSSE3=%v AVX2=%v BMI2=%v -> useTSAsm=%v",
		cpu.X86.HasSSSE3, cpu.X86.HasAVX2, cpu.X86.HasBMI2, useTSAsm)

	switch {
	case hasAVX2 && useTSAsm:
		t.Error("CPU has AVX2+BMI2 but dispatch chose tsasm; x/crypto's AVX2 kernel must win")
	case cpu.X86.HasSSSE3 && !hasAVX2 && !useTSAsm:
		t.Error("CPU has SSSE3 and no AVX2 but dispatch did not choose tsasm")
	case !cpu.X86.HasSSSE3 && useTSAsm:
		t.Error("CPU lacks SSSE3 but dispatch chose tsasm; the kernel would SIGILL")
	}

	/*
		Assert on the AEAD the constructor actually returns, not on the flag. Re-deriving useTSAsm from its own definition cannot fail whatever the dispatch does. Comparing dynamic types can: it catches the constructor ignoring the flag, and the flag being right while the routing is wrong.
	*/
	asmInst, err := asmAEAD.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	asmType := fmt.Sprintf("%T", asmInst)
	dispatched, err := chacha20poly1305New(make([]byte, 32))
	if err != nil {
		t.Fatalf("chacha20poly1305New: %v", err)
	}
	if gotType := fmt.Sprintf("%T", dispatched); (gotType == asmType) != useTSAsm {
		t.Errorf("dispatch returned %s but useTSAsm = %v; the two disagree", gotType, useTSAsm)
	}

	// Whatever the CPU, the constructor has to produce a working AEAD.
	aead, err := chacha20poly1305New(make([]byte, 32))
	if err != nil {
		t.Fatalf("chacha20poly1305New: %v", err)
	}
	if got := aead.NonceSize(); got != 12 {
		t.Errorf("NonceSize = %d, want 12", got)
	}
	if got := aead.Overhead(); got != 16 {
		t.Errorf("Overhead = %d, want 16", got)
	}
}

// TestAEADEscapeHatch checks that TS_WG_ASM=0 forces x/crypto even on a CPU
// the dispatch would otherwise send to tsasm.
func TestAEADEscapeHatch(t *testing.T) {
	if !useTSAsm {
		t.Skip("this CPU does not use tsasm, so there is nothing to override")
	}
	asmAEADInst, err := asmAEAD.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	asmType := fmt.Sprintf("%T", asmAEADInst)

	if got, err := chacha20poly1305New(make([]byte, 32)); err != nil {
		t.Fatal(err)
	} else if fmt.Sprintf("%T", got) != asmType {
		t.Fatalf("without the override, got %T, want the tsasm type %s", got, asmType)
	}

	t.Setenv("TS_WG_ASM", "0")
	got, err := chacha20poly1305New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%T", got) == asmType {
		t.Errorf("TS_WG_ASM=0 still returned the tsasm implementation %T", got)
	}
}

// TestShouldUseTSAsm exhausts the dispatch predicate over all eight feature combinations.
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

/*
TestAEADDispatchSubprocess covers both dispatch outcomes on one host. x/sys/cpu reads GODEBUG only at process start, so features have to be masked before the process runs, and GODEBUG can only disable a feature. Without this the assembly path is never dispatched in CI, whose runners all have AVX2.
*/
func TestAEADDispatchSubprocess(t *testing.T) {
	if os.Getenv("WG_AEAD_DISPATCH_HELPER") == "1" {
		testAEADDispatchHelper(t)
		return
	}

	cases := []struct{ name, godebug, want string }{
		{"fallback-no-ssse3", "cpu.ssse3=off,cpu.avx2=off,cpu.bmi2=off", "xcrypto"},
	}
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

/*
TestAEADFIPSPolicy checks that the assembly path cannot be used to get around x/crypto's policy on ChaCha20-Poly1305 under fips140=only. GODEBUG is read at process start, so it needs a subprocess, and that subprocess disables AVX2 so the constructor actually reaches the assembly kernel. Without that the dispatch sends any AVX2 machine straight to x/crypto and the test passes without exercising the code it is meant to cover.
*/
func TestAEADFIPSPolicy(t *testing.T) {
	if os.Getenv("WG_AEAD_FIPS_HELPER") == "1" {
		if !useTSAsm {
			t.Fatalf("subprocess did not reach the assembly path: SSSE3=%t AVX2=%t BMI2=%t",
				cpu.X86.HasSSSE3, cpu.X86.HasAVX2, cpu.X86.HasBMI2)
		}
		if _, err := chacha20poly1305New(make([]byte, 32)); err == nil {
			t.Fatal("constructor succeeded under fips140=only; the policy check was bypassed")
		}
		return
	}
	if !asmAEAD.Available() {
		t.Skip("no SSSE3, cannot reach the assembly path")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAEADFIPSPolicy$")
	cmd.Env = subprocessEnv(map[string]string{
		"WG_AEAD_FIPS_HELPER": "1",
		"GODEBUG":             "cpu.avx2=off,cpu.bmi2=off,fips140=only",
	})
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subprocess: %v\n%s", err, out)
	}
}
