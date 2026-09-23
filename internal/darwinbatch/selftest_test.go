//go:build darwin

package darwinbatch

import "testing"

func TestSelfTest(t *testing.T) {
	if !spiAvailable {
		if Supported() || SelfTestErr() == nil {
			t.Fatal("an omit build must report unsupported, with a reason")
		}
		return
	}
	if err := selfTest(); err != nil {
		t.Fatalf("self-test failed on this kernel: %v", err)
	}
	if !Supported() {
		t.Fatalf("Supported() = false after a passing self-test: %v", SelfTestErr())
	}
}
