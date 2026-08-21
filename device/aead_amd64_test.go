//go:build amd64 && gc && !purego

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"fmt"
	"testing"

	"golang.org/x/sys/cpu"

	asmAEAD "github.com/tailscale/wireguard-go/tsasm/amd64/chacha20poly1305"
)

// TestAEADDispatch asserts the two properties the dispatch has to get right:
// a CPU with SSSE3 but no AVX2 must reach tsasm, and a CPU with AVX2 must not.
// The second half is the important one, since routing AVX2 machines here would
// silently replace x/crypto's maintained kernel for most amd64 users.
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

	// Assert on the AEAD the constructor actually returns, not on the flag.
	// Re-deriving useTSAsm from its own definition cannot fail whatever the
	// dispatch does. Comparing dynamic types can: it catches the constructor
	// ignoring the flag, and the flag being right while the routing is wrong.
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
