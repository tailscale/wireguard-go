//go:build unix && !aix && !solaris && !illumos

package conn

import "testing"

// The check must pass on supported kernels; if it fails, ConnectedSockets is silently off.
func TestConnectedDeliveryCheck(t *testing.T) {
	if err := ConnectedDeliveryCheck(); err != nil {
		t.Fatalf("ConnectedDeliveryCheck: %v", err)
	}
}
