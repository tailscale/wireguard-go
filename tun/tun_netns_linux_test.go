/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// waitTimeout bounds how long tests wait for an expected condition. It is
// long because CI machines can be very slow, and it only costs time when the
// condition never comes true. Tests never wait for something not to happen.
const waitTimeout = 30 * time.Second

// requireIPCommand skips the test if the iproute2 "ip" command is missing.
func requireIPCommand(tb testing.TB) {
	tb.Helper()
	if _, err := exec.LookPath("ip"); err != nil {
		tb.Skip("needs the ip command")
	}
}

func runIP(tb testing.TB, args ...string) {
	tb.Helper()
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		tb.Fatalf("ip %v: %v\n%s", args, err, out)
	}
}

// waitFor polls cond until it returns true, failing the test if that takes
// longer than waitTimeout.
func waitFor(tb testing.TB, what string, cond func() bool) {
	tb.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			tb.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// initialEvent returns the startup link state event of a newly created dev.
// It is queued before the constructor returns, so there is no waiting.
func initialEvent(tb testing.TB, dev Device) Event {
	tb.Helper()
	select {
	case ev := <-dev.Events():
		return ev
	default:
		tb.Fatal("no initial event queued")
		return 0
	}
}

// eventRecorder consumes a device's events, recording Up/Down state.
type eventRecorder struct {
	last   atomic.Int32 // last EventUp or EventDown seen, or 0
	ups    atomic.Int32 // number of EventUp seen
	closed chan struct{}
}

func recordEvents(dev Device) *eventRecorder {
	r := &eventRecorder{closed: make(chan struct{})}
	go func() {
		defer close(r.closed)
		for ev := range dev.Events() {
			if ev&EventUp != 0 {
				r.ups.Add(1)
			}
			if ev &= EventUp | EventDown; ev != 0 {
				r.last.Store(int32(ev))
			}
		}
	}()
	return r
}

// waitState waits for the last Up/Down event to be want. Callers must make
// sure that the state changes with each action they wait on, as netlink
// repeats the current state on every link change.
func (r *eventRecorder) waitState(tb testing.TB, want Event, what string) {
	tb.Helper()
	waitFor(tb, fmt.Sprintf("%v after %s", want, what), func() bool {
		return Event(r.last.Load()) == want
	})
}

// waitClosed waits for the device's events channel to be closed.
func (r *eventRecorder) waitClosed(tb testing.TB) {
	tb.Helper()
	select {
	case <-r.closed:
	case <-time.After(waitTimeout):
		tb.Fatal("events channel not closed after Close")
	}
}

// netnsIno returns the inode of the network namespace file at path.
func netnsIno(tb testing.TB, path string) uint64 {
	tb.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		tb.Fatal(err)
	}
	return st.Ino
}

// listenerNetnsIno returns the inode of the network namespace of tun's
// current netlink socket, or 0 if there is none.
func listenerNetnsIno(tb testing.TB, tun *NativeTun) uint64 {
	tb.Helper()
	tun.nlMu.Lock()
	defer tun.nlMu.Unlock()
	if tun.nl == nil {
		return 0
	}
	nsFD, err := unix.IoctlRetInt(tun.nl.sock, unix.SIOCGSKNS)
	if err != nil {
		tb.Fatalf("SIOCGSKNS: %v", err)
	}
	defer unix.Close(nsFD)
	var st unix.Stat_t
	if err := unix.Fstat(nsFD, &st); err != nil {
		tb.Fatal(err)
	}
	return st.Ino
}

// threadNetnsInos returns the set of network namespace inodes that the
// process's threads are in.
func threadNetnsInos(tb testing.TB) map[uint64]bool {
	tb.Helper()
	tids, err := os.ReadDir("/proc/self/task")
	if err != nil {
		tb.Fatal(err)
	}
	inos := map[uint64]bool{}
	for _, tid := range tids {
		var st unix.Stat_t
		if err := unix.Stat("/proc/self/task/"+tid.Name()+"/ns/net", &st); err != nil {
			continue // thread exited
		}
		inos[st.Ino] = true
	}
	return inos
}

func TestInitialLinkStateEvent(t *testing.T) {
	requireNetAdmin(t)
	requireIPCommand(t)

	// Bring the interface up before handing it over, and keep its default
	// MTU so that setMTU doesn't trigger a netlink event. Only the startup
	// probe can then report it as up.
	files := openQueueFiles(t, 1)
	name, err := tunNameOf(files[0])
	if err != nil {
		t.Fatal(err)
	}
	runIP(t, "link", "set", name, "up")
	dev, err := CreateTUNFromFiles(files, 1500)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	if got := initialEvent(t, dev); got != EventUp {
		t.Fatalf("initial event = %v, want EventUp", got)
	}
}

// TestNetlinkReportsDown checks that EventDown is reported once netlink has
// reported EventUp, even when they arrive in separate netlink reads.
func TestNetlinkReportsDown(t *testing.T) {
	requireNetAdmin(t)
	requireIPCommand(t)

	name := testTUNName(t)
	dev, err := CreateTUN(name, testMTU)
	if err != nil {
		t.Fatal(err)
	}
	initialEvent(t, dev)
	r := recordEvents(dev)

	// The interface has never been up, so any EventUp is from this.
	runIP(t, "link", "set", name, "up")
	waitFor(t, "EventUp after link up", func() bool { return r.ups.Load() > 0 })
	runIP(t, "link", "set", name, "down")
	r.waitState(t, EventDown, "link down")

	dev.Close()
	r.waitClosed(t)
}

func TestFollowNetns(t *testing.T) {
	requireNetAdmin(t)
	requireIPCommand(t)

	ns := fmt.Sprintf("wgtest%d", os.Getpid())
	runIP(t, "netns", "add", ns)
	t.Cleanup(func() { exec.Command("ip", "netns", "del", ns).Run() })
	nsIno := netnsIno(t, "/run/netns/"+ns)
	hostIno := netnsIno(t, "/proc/1/ns/net") // "netns 1" below means PID 1's
	if inos := threadNetnsInos(t); len(inos) != 1 || !inos[hostIno] {
		t.Fatalf("threads not all in PID 1's netns %d at start: %v", hostIno, inos)
	}
	// Following must not leave any of our threads in another namespace.
	defer func() {
		if inos := threadNetnsInos(t); len(inos) != 1 || !inos[hostIno] {
			t.Errorf("threads in netns %v after following, want only %d", inos, hostIno)
		}
	}()

	name := testTUNName(t)
	dev, err := CreateTUN(name, testMTU)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close() // before the netns cleanup, which would destroy it
	nt := dev.(*NativeTun)
	initialEvent(t, dev)
	r := recordEvents(dev)

	waitFollowed := func(ino uint64, where string) {
		t.Helper()
		waitFor(t, "listener to follow interface "+where, func() bool {
			return listenerNetnsIno(t, nt) == ino
		})
	}
	expectMTU := func(want int) {
		t.Helper()
		if got, err := nt.MTU(); err != nil || got != want {
			t.Fatalf("MTU() = %v, %v; want %v", got, err, want)
		}
	}

	// Each step below flips the link state, so that waitState can't be
	// satisfied by an event from an earlier step. The interface has never
	// been up yet.
	runIP(t, "link", "set", name, "netns", ns)
	waitFollowed(nsIno, "into netns")
	runIP(t, "-n", ns, "link", "set", name, "up")
	r.waitState(t, EventUp, "up in netns")
	runIP(t, "-n", ns, "link", "set", name, "mtu", "1300")
	expectMTU(1300)
	runIP(t, "-n", ns, "link", "set", name, "down")
	r.waitState(t, EventDown, "down in netns")

	runIP(t, "-n", ns, "link", "set", name, "netns", "1")
	waitFollowed(hostIno, "back to host")
	runIP(t, "link", "set", name, "up")
	r.waitState(t, EventUp, "up in host")
	expectMTU(1300)
	runIP(t, "link", "set", name, "mtu", "1280")
	expectMTU(1280)
	runIP(t, "link", "set", name, "down")
	r.waitState(t, EventDown, "down in host")

	runIP(t, "link", "set", name, "netns", ns)
	waitFollowed(nsIno, "into netns again")
	runIP(t, "-n", ns, "link", "set", name, "up")
	r.waitState(t, EventUp, "up in netns again")

	// Close shuts down the listener while it is following the interface.
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	r.waitClosed(t)
}

// TestDeleteWhileListening checks that deleting the interface, which looks
// like a move to the netlink listener, doesn't wedge it.
func TestDeleteWhileListening(t *testing.T) {
	requireNetAdmin(t)
	requireIPCommand(t)

	handled := make(chan struct{})
	var once sync.Once
	testHookDelLink = func() { once.Do(func() { close(handled) }) }
	defer func() { testHookDelLink = nil }()

	name := testTUNName(t)
	dev, err := CreateTUN(name, testMTU)
	if err != nil {
		t.Fatal(err)
	}
	initialEvent(t, dev)
	r := recordEvents(dev)

	runIP(t, "link", "del", name)
	select {
	case <-handled:
	case <-time.After(waitTimeout):
		t.Fatal("listener never handled RTM_DELLINK")
	}
	if err := dev.Close(); err != nil {
		t.Fatal(err)
	}
	r.waitClosed(t) // the hook's listener has exited before resetting it
}
