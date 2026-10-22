//go:build !darwin

package conn

import (
	"errors"
	"net"

	"golang.org/x/net/ipv6"
)

var errBatchIOUnsupported = errors.New("batched I/O on an unconnected socket is only implemented for darwin")

// UnconnectedBatch is only implemented on darwin.
type UnconnectedBatch struct{}

// BatchIOSupported returns an error except on darwin.
func BatchIOSupported() error { return errBatchIOUnsupported }

// NewUnconnectedBatch returns an error except on darwin.
func NewUnconnectedBatch(*net.UDPConn) (*UnconnectedBatch, error) { return nil, errBatchIOUnsupported }

func (*UnconnectedBatch) ReadBatch([]ipv6.Message, int) (int, error) { return 0, errBatchIOUnsupported }
func (*UnconnectedBatch) WriteBatch([]ipv6.Message, int) (int, error) {
	return 0, errBatchIOUnsupported
}
