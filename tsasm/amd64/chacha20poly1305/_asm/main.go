/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

// Command asmgen extracts the pre-AVX2 ChaCha20-Poly1305 implementation from
// the last x/crypto release that shipped it. It intentionally transforms the
// generated assembly rather than carrying x/crypto's much larger avo source.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const cryptoVersion = "v0.51.0"

//go:generate go run .
func main() {
	out := flag.String("out", "../chacha20poly1305_amd64.s", "output assembly file")
	flag.Parse()

	dir, err := moduleDir("golang.org/x/crypto@" + cryptoVersion)
	if err != nil {
		fatal(err)
	}
	in := filepath.Join(dir, "chacha20poly1305", "chacha20poly1305_amd64.s")
	src, err := os.ReadFile(in)
	if err != nil {
		fatal(fmt.Errorf("read %s: %w", in, err))
	}
	generated, err := extractSSE(src)
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, generated, 0o644); err != nil {
		fatal(err)
	}
}

func moduleDir(module string) (string, error) {
	// go mod download is the supported way to populate and locate an exact
	// module version in the module cache; it also handles escaped cache paths.
	cmd := exec.Command("go", "mod", "download", "-json", module)
	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("locate %s with go mod download: %w", module, err)
	}
	var result struct {
		Dir   string
		Error string
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return "", fmt.Errorf("decode go mod download output: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("download %s: %s", module, result.Error)
	}
	if result.Dir == "" {
		return "", fmt.Errorf("go mod download returned no directory for %s", module)
	}
	return result.Dir, nil
}

func extractSSE(src []byte) ([]byte, error) {
	// The upstream generated file consists of a shared Poly1305 helper, Open's
	// SSE implementation, Open's AVX2 implementation, data, Seal's SSE
	// implementation, and Seal's AVX2 implementation, in that order. Keep only
	// the named ranges and the data referenced by the SSE code.
	poly := rangeBefore(src, "// func polyHashADInternal<>()", "// func chacha20Poly1305Open(")
	open := rangeBefore(src, "// func chacha20Poly1305Open(", "chacha20Poly1305Open_AVX2:")
	data := rangeBefore(src, "DATA ·chacha20Constants<>", "DATA ·avx2InitMask<>")
	rol := rangeBefore(src, "DATA ·rol16<>", "DATA ·avx2IncMask<>")
	seal := rangeBefore(src, "// func chacha20Poly1305Seal(", "chacha20Poly1305Seal_AVX2:")
	if poly == nil || open == nil || data == nil || rol == nil || seal == nil {
		return nil, fmt.Errorf("x/crypto %s assembly layout changed", cryptoVersion)
	}

	open = bytes.Replace(open, []byte("\t// Check for AVX2 support\n\tCMPB ·useAVX2+0(SB), $0x01\n\tJE   chacha20Poly1305Open_AVX2\n\n"), nil, 1)
	seal = bytes.Replace(seal, []byte("\tCMPB ·useAVX2+0(SB), $0x01\n\tJE   chacha20Poly1305Seal_AVX2\n\n"), nil, 1)
	for _, unwanted := range [][]byte{
		[]byte("·useAVX2"),
		[]byte("chacha20Poly1305Open_AVX2"),
		[]byte("chacha20Poly1305Seal_AVX2"),
	} {
		if bytes.Contains(open, unwanted) || bytes.Contains(seal, unwanted) {
			return nil, fmt.Errorf("failed to remove AVX2 dispatch marker %q", unwanted)
		}
	}

	var out bytes.Buffer
	fmt.Fprintf(&out, "// Code generated from golang.org/x/crypto@%s by go generate; DO NOT EDIT.\n\n", cryptoVersion)
	out.WriteString("//go:build amd64 && gc && !purego\n\n#include \"textflag.h\"\n\n")
	out.Write(poly)
	out.Write(open)
	out.Write(data)
	out.Write(rol)
	out.Write(seal)
	generated := bytes.ReplaceAll(out.Bytes(),
		[]byte("// Requires: AVX, AVX2, BMI2, CMOV, SSE2"),
		[]byte("// Requires: SSSE3, CMOV, SSE2"))
	return append(bytes.TrimRight(generated, "\n"), '\n'), nil
}

func rangeBefore(src []byte, start, end string) []byte {
	i := bytes.Index(src, []byte(start))
	if i < 0 {
		return nil
	}
	j := bytes.Index(src[i:], []byte(end))
	if j < 0 {
		return nil
	}
	return append([]byte(nil), src[i:i+j]...)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
