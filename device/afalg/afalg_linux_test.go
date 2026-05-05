/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package afalg

import (
	"errors"
	"testing"
)

// TestSelfTest exercises the runtime kernel-availability probe used
// by device/aead_linux_arm.go to gate the AF_ALG-vs-Go fallback.
//
// It only fails the test when the kernel claimed to support the
// algorithm but produced wrong output. Environmental absences
// (missing module, blacklisted kernel module, LSM/seccomp denial,
// kernels built without CONFIG_CRYPTO_USER_API_AEAD, etc.) are
// reported via t.Logf and treated as a pass: the production code's
// runtime gate handles those by falling back to software crypto.
func TestSelfTest(t *testing.T) {
	err := SelfTest()
	switch {
	case err == nil:
		// kernel supports it and got the right answer.
	case errors.Is(err, ErrUnavailable):
		t.Logf("AF_ALG ChaCha20-Poly1305 not usable in this environment: %v", err)
	default:
		t.Fatalf("AF_ALG ChaCha20-Poly1305 produced wrong output: %v", err)
	}
}
