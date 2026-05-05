/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

// Package afalg provides a crypto/cipher.AEAD backed by the Linux
// kernel's AF_ALG socket interface.
//
// The motivation is platforms where Go's pure-Go ChaCha20-Poly1305
// fallback is much slower than the kernel's NEON-assisted version
// (notably 32-bit ARM, where golang.org/x/crypto/chacha20poly1305
// ships no assembly).
//
// On modern amd64/arm64 with optimized assembly in x/crypto, the per-
// packet syscall overhead of AF_ALG is likely to make this slower than
// the Go implementation. Benchmark before assuming a win, using
// BenchmarkAEAD_Seal / BenchmarkAEAD_Open in device/aead_compat_test.go.
//
// Run those benchmarks on real hardware. CPU emulators (qemu-user and
// qemu-system-arm) produce misleading numbers in opposite directions:
// qemu-user passes AF_ALG syscalls through to the host kernel (so
// AF_ALG appears artificially fast running on host-native crypto while
// the Go side runs interpreted), and qemu-system-arm emulates the
// kernel too (so each syscall costs ~1ms of TCG overhead and AF_ALG
// looks artificially terrible). Neither resembles a real ARM device.
//
// See https://github.com/tailscale/wireguard-go/pull/57 for example
// benchmark numbers across amd64, arm64, ARMv6, and ARMv7+NEON.
package afalg

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ErrUnavailable is returned (wrapped) by SelfTest when the kernel does
// not advertise a usable AF_ALG ChaCha20-Poly1305 implementation in this
// environment: PF_ALG missing, the chacha20poly1305 module not loaded
// or blacklisted, an LSM/seccomp policy denying the socket, etc.
//
// SelfTest returns a non-ErrUnavailable error only when the kernel
// accepted the operation but produced cryptographically wrong output
// (a real bug in the kernel or in this package's wire encoding).
// Callers should treat ErrUnavailable as "use the software AEAD" and
// non-ErrUnavailable failures as alarming.
var ErrUnavailable = errors.New("afalg: ChaCha20-Poly1305 unavailable")

const (
	chachaKeySize   = 32
	chachaNonceSize = 12
	chachaTagSize   = 16

	algType = "aead"
	algName = "rfc7539(chacha20,poly1305)"
)

// New returns a cipher.AEAD that performs ChaCha20-Poly1305 (RFC 8439)
// via the Linux kernel's AF_ALG socket interface.
//
// The returned AEAD is safe for concurrent use by multiple goroutines:
// each Seal/Open call leases an op-socket from an internal pool.
//
// Each instance owns one bound AF_ALG socket plus a pool of accepted
// op-sockets. Close-on-GC is wired via runtime.SetFinalizer; callers
// that want deterministic cleanup should let the *Keypair go out of
// scope (the GC will then close the fds) or extend this API.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != chachaKeySize {
		return nil, fmt.Errorf("afalg: chacha20-poly1305 requires a %d-byte key, got %d", chachaKeySize, len(key))
	}
	bindFD, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("afalg: socket(AF_ALG): %w", err)
	}
	if err := unix.Bind(bindFD, &unix.SockaddrALG{Type: algType, Name: algName}); err != nil {
		unix.Close(bindFD)
		return nil, fmt.Errorf("afalg: bind %s/%s: %w", algType, algName, err)
	}
	if err := unix.SetsockoptString(bindFD, unix.SOL_ALG, unix.ALG_SET_KEY, string(key)); err != nil {
		unix.Close(bindFD)
		return nil, fmt.Errorf("afalg: ALG_SET_KEY: %w", err)
	}
	// ALG_SET_AEAD_AUTHSIZE is a quirky setsockopt: the kernel reads
	// only optlen and ignores optval, so we pass a dummy 16-byte
	// buffer to encode the authsize. accept() returns ECONNABORTED
	// on AEAD sockets if this has not been set before the accept.
	authSizeDummy := make([]byte, chachaTagSize)
	if err := unix.SetsockoptString(bindFD, unix.SOL_ALG, unix.ALG_SET_AEAD_AUTHSIZE, string(authSizeDummy)); err != nil {
		unix.Close(bindFD)
		return nil, fmt.Errorf("afalg: ALG_SET_AEAD_AUTHSIZE: %w", err)
	}

	a := &aead{bindFD: bindFD}
	a.opPool.New = func() any {
		opfd, err := acceptNull(a.bindFD)
		if err != nil {
			return &opEntry{err: fmt.Errorf("afalg: accept: %w", err)}
		}
		return &opEntry{fd: opfd}
	}
	runtime.SetFinalizer(a, (*aead).finalize)
	return a, nil
}

// opEntry is what we cache in the op-fd sync.Pool: either a usable
// op-fd or an accept() error to surface lazily on first use. We hand
// out *opEntry rather than the value so that sync.Pool.Put doesn't
// allocate to box the int field into an interface{}.
type opEntry struct {
	fd  int
	err error
}

type aead struct {
	bindFD int
	opPool sync.Pool // of *opEntry
}

// cmsgBufSize is the fixed control-message buffer size for one AEAD
// op: ALG_SET_OP (u32) + ALG_SET_IV (af_alg_iv: u32 ivlen + 12-byte
// nonce) + ALG_SET_AEAD_ASSOCLEN (u32). All three cmsgs are always
// sent so the kernel can reset op-fd state across pool reuse.
var cmsgBufSize = unix.CmsgSpace(4) + unix.CmsgSpace(4+chachaNonceSize) + unix.CmsgSpace(4)

// cmsgPool reuses the small fixed-size cmsg buffer across ops. We
// pool a *[]byte (rather than a []byte) so Put doesn't allocate to
// box a slice header into an interface{}.
var cmsgPool = sync.Pool{
	New: func() any {
		b := make([]byte, cmsgBufSize)
		return &b
	},
}

// recvPool reuses the recv buffer across ops. The buffer grows to fit
// the largest payload seen on a given pool slot; for steady-state
// WireGuard traffic this stabilizes at the link MTU.
var recvPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 2048)
		return &b
	},
}

func (a *aead) NonceSize() int { return chachaNonceSize }
func (a *aead) Overhead() int  { return chachaTagSize }

// Close closes the bound AF_ALG socket. Pooled op-fds are not drained;
// they leak until process exit. This is acceptable for the test/probe
// path that calls Close explicitly and for long-lived data-path
// instances that live for the lifetime of a Keypair.
func (a *aead) close() error {
	if a.bindFD < 0 {
		return nil
	}
	err := unix.Close(a.bindFD)
	a.bindFD = -1
	return err
}

func (a *aead) finalize() { _ = a.close() }

// SelfTest constructs an AF_ALG ChaCha20-Poly1305 instance and runs
// the RFC 8439 §2.8.2 known-answer vector through it (both encrypt
// and decrypt). It returns:
//
//   - nil on success;
//   - an error wrapping ErrUnavailable if the kernel rejected the
//     setup or operation (missing module, LSM denial, etc.);
//   - a plain error if the kernel accepted the operation but
//     produced wrong cryptographic output.
//
// Callers can use errors.Is(err, ErrUnavailable) to distinguish
// "fall back to software" from "kernel ChaCha20-Poly1305 is broken".
func SelfTest() error {
	key, _ := hex.DecodeString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce, _ := hex.DecodeString("070000004041424344454647")
	aad, _ := hex.DecodeString("50515253c0c1c2c3c4c5c6c7")
	plaintext := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	wantHex := "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
	want, _ := hex.DecodeString(wantHex)

	a, err := New(key)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	impl := a.(*aead)
	defer impl.close()

	// Drive the kernel directly via op() rather than Seal/Open so
	// that runtime kernel errors (e.g. EPERM under an LSM, or
	// EAFNOSUPPORT after delayed-init failure) come back as
	// returnable errors instead of panics.
	got, err := impl.op(nil, unix.ALG_OP_ENCRYPT, nonce, aad, plaintext, len(plaintext)+chachaTagSize)
	if err != nil {
		return fmt.Errorf("%w: encrypt: %w", ErrUnavailable, err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("afalg: encrypt output mismatch:\n got: %x\nwant: %x", got, want)
	}
	gotPT, err := impl.op(nil, unix.ALG_OP_DECRYPT, nonce, aad, want, len(want)-chachaTagSize)
	if err != nil {
		return fmt.Errorf("%w: decrypt: %w", ErrUnavailable, err)
	}
	if !bytes.Equal(gotPT, plaintext) {
		return fmt.Errorf("afalg: decrypt output mismatch")
	}
	return nil
}

func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != chachaNonceSize {
		panic("afalg: incorrect nonce length")
	}
	out, err := a.op(dst, unix.ALG_OP_ENCRYPT, nonce, additionalData, plaintext, len(plaintext)+chachaTagSize)
	if err != nil {
		// Match the contract of crypto/cipher AEADs, which panic on
		// programmer error rather than returning an encryption error.
		panic(fmt.Sprintf("afalg: Seal: %v", err))
	}
	return out
}

func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != chachaNonceSize {
		return nil, fmt.Errorf("afalg: incorrect nonce length")
	}
	if len(ciphertext) < chachaTagSize {
		return nil, fmt.Errorf("afalg: ciphertext too short")
	}
	return a.op(dst, unix.ALG_OP_DECRYPT, nonce, additionalData, ciphertext, len(ciphertext)-chachaTagSize)
}

// op runs a single AEAD operation through the kernel and appends the
// result to dst.
//
// Wire format (matching <linux/if_alg.h>):
//   - sendmsg control message carries: ALG_SET_OP (encrypt/decrypt),
//     ALG_SET_IV (struct af_alg_iv: u32 ivlen + iv bytes),
//     and ALG_SET_AEAD_ASSOCLEN (u32) when there is AAD.
//   - sendmsg payload is AAD || data.
//   - recv buffer comes back as AAD || result, where result is
//     ciphertext+tag for encrypt or plaintext for decrypt.
//
// The caller must not retain references to internal scratch buffers
// beyond op's return: the recv pool is replenished from a defer, so
// any non-appended view into the recv buffer would race with
// concurrent ops on another goroutine.
func (a *aead) op(dst []byte, opCode uint32, iv, aad, in []byte, outLen int) ([]byte, error) {
	e := a.opPool.Get().(*opEntry)
	if e.err != nil {
		return nil, e.err
	}
	opfd := e.fd
	// Op-fds are reusable: kernel docs say accept() returns a fd
	// "which can be used for several operations", so we recycle.
	defer a.opPool.Put(e)

	cbufPtr := cmsgPool.Get().(*[]byte)
	defer cmsgPool.Put(cbufPtr)
	cbuf := writeControl(*cbufPtr, opCode, iv, len(aad))

	// Concatenate AAD || in. The kernel requires them in one logical
	// buffer; the pure data-path (no AAD) path is alloc-free.
	var sendBuf []byte
	if len(aad) == 0 {
		sendBuf = in
	} else {
		sendBuf = make([]byte, len(aad)+len(in))
		copy(sendBuf, aad)
		copy(sendBuf[len(aad):], in)
	}

	if _, err := sendmsgRaw(opfd, sendBuf, cbuf); err != nil {
		return nil, fmt.Errorf("afalg: sendmsg: %w", err)
	}

	recvLen := len(aad) + outLen
	// AF_ALG's recvmsg short-circuits when the user buffer has zero
	// bytes (its `while (msg_data_left(msg))` loop never runs), which
	// leaves the queued ciphertext unprocessed and the op-socket
	// stuck in the "init" state. Subsequent sendmsg on the same fd
	// then fails with EINVAL. Always read at least one byte so the
	// kernel actually drives the AEAD op to completion.
	bufLen := recvLen
	if bufLen == 0 {
		bufLen = 1
	}
	recvPtr := recvPool.Get().(*[]byte)
	defer recvPool.Put(recvPtr)
	if cap(*recvPtr) < bufLen {
		*recvPtr = make([]byte, bufLen)
	} else {
		*recvPtr = (*recvPtr)[:bufLen]
	}
	recvBuf := *recvPtr

	n, err := unix.Read(opfd, recvBuf)
	if err != nil {
		// Auth failure on Open surfaces here (typically EBADMSG).
		return nil, err
	}
	if n != recvLen {
		return nil, fmt.Errorf("afalg: short read: got %d, want %d", n, recvLen)
	}
	// Append the operation result to the caller's dst before the
	// defer returns the recv buffer to the pool.
	return append(dst, recvBuf[len(aad):recvLen]...), nil
}

// writeControl writes the cmsg buffer for one AEAD op into buf and
// returns the populated subslice. buf must have cap >= cmsgBufSize.
func writeControl(buf []byte, opCode uint32, iv []byte, aadLen int) []byte {
	const ivHdrSize = 4 // u32 ivlen prefix on struct af_alg_iv
	ivPayload := ivHdrSize + len(iv)

	total := unix.CmsgSpace(4) + unix.CmsgSpace(ivPayload) + unix.CmsgSpace(4)
	cbuf := buf[:total]

	off := 0

	// ALG_SET_OP: u32 op (encrypt/decrypt).
	off += writeCmsg(cbuf[off:], unix.ALG_SET_OP, 4, func(data []byte) {
		binary.NativeEndian.PutUint32(data, opCode)
	})

	// ALG_SET_IV: struct af_alg_iv { u32 ivlen; u8 iv[]; }.
	off += writeCmsg(cbuf[off:], unix.ALG_SET_IV, ivPayload, func(data []byte) {
		binary.NativeEndian.PutUint32(data, uint32(len(iv)))
		copy(data[ivHdrSize:], iv)
	})

	// ALG_SET_AEAD_ASSOCLEN: u32 aadlen. We always send this even
	// when aadLen == 0: the kernel keeps the previous op's assoclen
	// on a reused op-socket, so omitting it can leave a stale value
	// that mismatches the payload and yields EINVAL on sendmsg.
	writeCmsg(cbuf[off:], unix.ALG_SET_AEAD_ASSOCLEN, 4, func(data []byte) {
		binary.NativeEndian.PutUint32(data, uint32(aadLen))
	})

	return cbuf
}

// sendmsgRaw invokes sendmsg(2) without the dummy-iov injection that
// x/sys/unix.SendmsgN performs when the payload is empty. AF_ALG
// requires the iov layout to match the declared assoclen byte-for-byte,
// so a stray dummy byte produces EINVAL or a corrupted op.
func sendmsgRaw(fd int, p, oob []byte) (int, error) {
	var iov unix.Iovec
	var msg unix.Msghdr
	if len(p) > 0 {
		iov.Base = &p[0]
		iov.SetLen(len(p))
		msg.Iov = &iov
		msg.SetIovlen(1)
	}
	if len(oob) > 0 {
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	n, _, errno := syscall.Syscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), 0)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

// acceptNull invokes accept4(fd, NULL, NULL, 0). The standard
// unix.Accept helper supplies a non-NULL sockaddr buffer, which makes
// the kernel call sock_ops->getname() on the new AF_ALG socket. AF_ALG
// has no getname op, and __sys_accept4 translates that failure into
// ECONNABORTED before the new fd is ever returned to userspace.
// Bypassing the buffer avoids the lookup entirely.
func acceptNull(fd int) (int, error) {
	nfd, _, errno := syscall.Syscall6(unix.SYS_ACCEPT4, uintptr(fd), 0, 0, 0, 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(nfd), nil
}

// writeCmsg writes one cmsg of payloadLen bytes into buf at offset 0,
// invoking fill on the data region. It returns the aligned number of
// bytes consumed (CMSG_SPACE(payloadLen)) so the caller can advance.
func writeCmsg(buf []byte, cmsgType, payloadLen int, fill func(data []byte)) int {
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&buf[0]))
	hdr.SetLen(unix.CmsgLen(payloadLen))
	hdr.Level = unix.SOL_ALG
	hdr.Type = int32(cmsgType)
	dataOff := unix.CmsgLen(0)
	fill(buf[dataOff : dataOff+payloadLen])
	return unix.CmsgSpace(payloadLen)
}
