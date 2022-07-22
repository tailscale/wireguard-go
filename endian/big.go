//go:build mips || mips64 || ppc64 || s390x

package endian

import "encoding/binary"

// Native is the platform's native byte order.
var Native = binary.LittleEndian
