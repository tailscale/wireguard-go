//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"expvar"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/ipc"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
	ENV_WG_DEBUG_ADDR         = "WG_DEBUG_ADDR"
)

// deviceMetrics returns the [device.Metrics] to instrument the [device.Device]
// with, backed by expvars. They are readable at /debug/vars when
// WG_DEBUG_ADDR is set.
func deviceMetrics() device.Metrics {
	return device.Metrics{
		TransportRXReplayDropped: expvar.NewInt("wireguard_rx_replay_dropped"),
	}
}

func setenv(env []string, key, value string) []string {
	prefix := key + "="
	var filtered []string
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return append(filtered, prefix+value)
}

func printUsage() {
	fmt.Printf("Usage: %s [-f/--foreground] INTERFACE-NAME\n", os.Args[0])
}

func warning() {
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd":
		if os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1" {
			return
		}
	default:
		return
	}

	fmt.Fprintln(os.Stderr, "┌──────────────────────────────────────────────────────┐")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "│   Running wireguard-go is not required because this  │")
	fmt.Fprintln(os.Stderr, "│   kernel has first class support for WireGuard. For  │")
	fmt.Fprintln(os.Stderr, "│   information on installing the kernel module,       │")
	fmt.Fprintln(os.Stderr, "│   please visit:                                      │")
	fmt.Fprintln(os.Stderr, "│         https://www.wireguard.com/install/           │")
	fmt.Fprintln(os.Stderr, "│                                                      │")
	fmt.Fprintln(os.Stderr, "└──────────────────────────────────────────────────────┘")
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("wireguard-go v%s\n\nUserspace WireGuard daemon for %s-%s.\nInformation available at https://www.wireguard.com.\nCopyright (C) Jason A. Donenfeld <Jason@zx2c4.com>.\n", Version, runtime.GOOS, runtime.GOARCH)
		return
	}

	warning()

	var foreground bool
	var interfaceName string
	if len(os.Args) < 2 || len(os.Args) > 3 {
		printUsage()
		return
	}

	switch os.Args[1] {

	case "-f", "--foreground":
		foreground = true
		if len(os.Args) != 3 {
			printUsage()
			return
		}
		interfaceName = os.Args[2]

	default:
		foreground = false
		if len(os.Args) != 2 {
			printUsage()
			return
		}
		interfaceName = os.Args[1]
	}

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}

	// get log level (default: info)

	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "verbose", "debug":
			return device.LogLevelVerbose
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelError
	}()

	// open TUN device (or use supplied fd)

	tunQueuesCount := 1
	if v := os.Getenv("WG_TUN_QUEUES"); v != "" {
		var err error
		tunQueuesCount, err = strconv.Atoi(v)
		if err != nil || tunQueuesCount < 1 {
			fmt.Fprintf(os.Stderr, "Invalid WG_TUN_QUEUES %q: must be a positive integer\n", v)
			os.Exit(ExitSetupFailed)
		}
	}
	tdev, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, device.DefaultMTU, tun.WithQueues(tunQueuesCount))
		}
		fields := strings.Split(tunFdStr, ",")
		files := make([]*os.File, 0, len(fields))
		var fds []int
		for _, field := range fields {
			fd, err := strconv.ParseUint(strings.TrimSpace(field), 10, 32)
			if err != nil {
				for _, f := range files {
					f.Close()
				}
				return nil, fmt.Errorf("invalid %s %q: %w", ENV_WG_TUN_FD, tunFdStr, err)
			}
			fds = append(fds, int(fd))
		}
		var dupes []int
		set := map[int]struct{}{}
		for _, v := range fds {
			if _, dup := set[v]; dup {
				dupes = append(dupes, v)
				continue
			}
			set[v] = struct{}{}
		}
		if len(dupes) != 0 {
			for fd := range set {
				unix.Close(fd)
			}
			return nil, fmt.Errorf("passed duplicate file descriptors: %v", dupes)
		}
		for _, fd := range fds {
			// construct tun device from supplied fds
			if err := unix.SetNonblock(fd, true); err != nil {
				for _, f := range files {
					f.Close()
				}
				return nil, err
			}

			files = append(files, os.NewFile(uintptr(fd), ""))
		}
		return tun.CreateTUNFromFiles(files, device.DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Verbosef("Starting wireguard-go version %s", Version)

	if err != nil {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	tunQueues := tun.QueuesOf(tdev)
	if len(tunQueues) != tunQueuesCount {
		logger.Errorf("WG_TUN_QUEUES=%d requested but the TUN device has %d queue(s)", tunQueuesCount, len(tunQueues))
	}
	logger.Verbosef("TUN device has %d queue(s)", len(tunQueues))

	// Per-peer queue depth. Using the old default as a cap, applied to both
	// inbound and outbound direction.
	// TODO: make cgroup-aware with runtime.GOMAXPROCS(0).
	queueSize := min(device.DefaultQueueInboundSize, runtime.NumCPU())
	if v := os.Getenv("WG_QUEUE_SIZE"); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 1 {
			fmt.Fprintf(os.Stderr, "Invalid WG_QUEUE_SIZE %q: must be a positive integer\n", v)
			os.Exit(ExitSetupFailed)
		}
		queueSize = n
	}
	logger.Verbosef("Per-peer queue size is %d", queueSize)

	// open UAPI file (or use supplied fd)

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()
	if err != nil {
		logger.Errorf("UAPI listen error: %v", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// daemonize the process

	if !foreground {
		var procFiles []*os.File
		stdin, _ := os.Open(os.DevNull)
		procFiles = append(procFiles, stdin)
		if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
			procFiles = append(procFiles, os.Stdout, os.Stderr)
		} else {
			stdout, _ := os.Open(os.DevNull)
			stderr, _ := os.Open(os.DevNull)
			procFiles = append(procFiles, stdout, stderr)
		}

		uapiFD := len(procFiles)
		procFiles = append(procFiles, fileUAPI)

		tunFDs := make([]string, 0, tunQueuesCount)
		for i, q := range tunQueues {
			f := q.File()
			if f == nil {
				logger.Errorf("Failed to daemonize: TUN queue %d has no file descriptor", i)
				os.Exit(ExitSetupFailed)
			}
			tunFDs = append(tunFDs, strconv.Itoa(len(procFiles)))
			procFiles = append(procFiles, f)
		}

		env := os.Environ()
		env = setenv(env, ENV_WG_TUN_FD, strings.Join(tunFDs, ","))
		env = setenv(env, ENV_WG_UAPI_FD, strconv.Itoa(uapiFD))
		env = setenv(env, ENV_WG_PROCESS_FOREGROUND, "1")
		attr := &os.ProcAttr{
			Files: procFiles,
			Dir:   ".",
			Env:   env,
		}

		path, err := os.Executable()
		if err != nil {
			logger.Errorf("Failed to determine executable: %v", err)
			os.Exit(ExitSetupFailed)
		}

		process, err := os.StartProcess(
			path,
			os.Args,
			attr,
		)
		if err != nil {
			logger.Errorf("Failed to daemonize: %v", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	device := device.NewDevice(tdev, conn.NewDefaultBind(), logger,
		device.WithQueueInboundSize(queueSize),
		device.WithQueueOutboundSize(queueSize),
		device.WithMetrics(deviceMetrics()))

	logger.Verbosef("Device started")

	if debugAddr := os.Getenv(ENV_WG_DEBUG_ADDR); debugAddr != "" {
		logger.Verbosef("Serving expvars at http://%s/debug/vars", debugAddr)
		go func() {
			// Importing expvar registers /debug/vars on the default mux.
			if err := http.ListenAndServe(debugAddr, nil); err != nil {
				logger.Errorf("Debug listener on %s stopped: %v", debugAddr, err)
			}
		}()
	}

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Errorf("Failed to listen on uapi socket: %v", err)
		os.Exit(ExitSetupFailed)
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	logger.Verbosef("UAPI listener started")

	// wait for program to terminate

	signal.Notify(term, unix.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Verbosef("Shutting down")
}
