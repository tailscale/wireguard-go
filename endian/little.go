//go:build 386 || amd64 || arm || arm64 || mips64le || mipsle || ppc64le || riscv64 || wasm || loong64

package endian

import "encoding/binary"

// Native is the platform's native byte order.
var Native = binary.LittleEndian
