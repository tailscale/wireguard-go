// Package main implements a static lock-order checker for the device package.
package main

// LockID is the canonical name of a lock class, e.g. "Device.staticIdentity".
// All instances of the same struct share the same LockID.
type LockID string

// LockKind distinguishes exclusive (Lock) from shared (RLock).
type LockKind int

const (
	Exclusive LockKind = iota // Lock()
	Shared                    // RLock()
)

func (k LockKind) String() string {
	if k == Shared {
		return "RLock"
	}
	return "Lock"
}

// MutexKind distinguishes Mutex from RWMutex.
type MutexKind int

const (
	PlainMutex     MutexKind = iota // sync.Mutex — only Lock/Unlock
	ReadWriteMutex                  // sync.RWMutex — Lock/Unlock/RLock/RUnlock
)

// TrackedLock describes one lock class we want to track.
//
// (OwnerType, FieldPath) is the access-path key: it matches the selector
// chain that callers write at the lock site, e.g. `device.staticIdentity`
// or `peer.handshake.mutex`. (DefType, DefPath) identifies the struct and
// field where the mutex is actually declared, which is what the inventory
// check uses to match against the package's struct types. The two pairs
// differ when a lock lives on a sub-type accessed through a parent — for
// example, `Device.allowedips.mu` is owned via Device but defined on the
// AllowedIPs type as field `mu`.
type TrackedLock struct {
	ID        LockID
	OwnerType string // "Device" or "Peer" — the struct containing this lock
	FieldPath string // dot-separated field path from owner, e.g. "handshake.mutex"
	Kind      MutexKind
	DefType   string // struct type that declares the mutex field
	DefPath   string // path within DefType to the mutex; "" if directly embedded

	// InstanceLocal indicates that the lock is per-instance and that
	// each instance is owned by exactly one goroutine at a time
	// (typically because instances flow through a channel). Static cycle
	// detection cannot distinguish instances of a lock class, so an
	// instance-local lock would otherwise produce false-positive cycles
	// when two different goroutines hold two different instances. Cycle
	// and reentrance detection skip any cycle that contains an
	// instance-local lock; the lock is still tracked for inventory and
	// edge listing.
	InstanceLocal bool
}

// trackedLocks is the registry of every lock in the device package.
// Adding a new sync.Mutex or sync.RWMutex anywhere in the package
// without registering it here causes the inventory check to fail.
//
// FieldPath is matched against the selector chain from the receiver
// variable up to (but not including) the Lock/Unlock method call. For
// directly-embedded mutexes (FieldPath: "") the registry key has a
// trailing dot, e.g. "Keypairs." — see buildRegistry.
//
// Lock ordering is determined topologically from the lock-after edges
// the analyzer observes. There are no level numbers in the data: a
// lock with no outgoing edges is a leaf in the partial order; a cycle
// involving any pair of locks is a violation regardless of how
// "isolated" the participants might seem.
var trackedLocks = []TrackedLock{
	{ID: "Device.state", OwnerType: "Device", FieldPath: "state", Kind: PlainMutex, DefType: "Device", DefPath: "state"},
	{ID: "Device.ipcMutex", OwnerType: "Device", FieldPath: "ipcMutex", Kind: ReadWriteMutex, DefType: "Device", DefPath: "ipcMutex"},
	{ID: "Device.net", OwnerType: "Device", FieldPath: "net", Kind: ReadWriteMutex, DefType: "Device", DefPath: "net"},
	{ID: "Device.staticIdentity", OwnerType: "Device", FieldPath: "staticIdentity", Kind: ReadWriteMutex, DefType: "Device", DefPath: "staticIdentity"},
	{ID: "Device.peers", OwnerType: "Device", FieldPath: "peers", Kind: ReadWriteMutex, DefType: "Device", DefPath: "peers"},
	{ID: "Device.sessionState", OwnerType: "Device", FieldPath: "sessionState", Kind: PlainMutex, DefType: "Device", DefPath: "sessionState"},
	{ID: "Device.allowedips.mu", OwnerType: "Device", FieldPath: "allowedips.mu", Kind: ReadWriteMutex, DefType: "AllowedIPs", DefPath: "mu"},
	{ID: "Device.indexTable", OwnerType: "Device", FieldPath: "indexTable", Kind: ReadWriteMutex, DefType: "IndexTable", DefPath: ""},
	{ID: "Device.cookieChecker", OwnerType: "Device", FieldPath: "cookieChecker", Kind: ReadWriteMutex, DefType: "CookieChecker", DefPath: ""},
	{ID: "Peer.state", OwnerType: "Peer", FieldPath: "state", Kind: PlainMutex, DefType: "Peer", DefPath: "state"},
	{ID: "Peer.handshake.mutex", OwnerType: "Peer", FieldPath: "handshake.mutex", Kind: ReadWriteMutex, DefType: "Handshake", DefPath: "mutex"},
	{ID: "Peer.keypairs", OwnerType: "Peer", FieldPath: "keypairs", Kind: ReadWriteMutex, DefType: "Keypairs", DefPath: ""},
	{ID: "Peer.endpoint", OwnerType: "Peer", FieldPath: "endpoint", Kind: PlainMutex, DefType: "Peer", DefPath: "endpoint"},
	{ID: "Peer.cookieGenerator", OwnerType: "Peer", FieldPath: "cookieGenerator", Kind: ReadWriteMutex, DefType: "CookieGenerator", DefPath: ""},
	{ID: "Timer.modifyingLock", OwnerType: "Timer", FieldPath: "modifyingLock", Kind: ReadWriteMutex, DefType: "Timer", DefPath: "modifyingLock"},
	{ID: "Timer.runningLock", OwnerType: "Timer", FieldPath: "runningLock", Kind: PlainMutex, DefType: "Timer", DefPath: "runningLock"},
	{ID: "WaitPool.lock", OwnerType: "WaitPool", FieldPath: "lock", Kind: PlainMutex, DefType: "WaitPool", DefPath: "lock"},
}

// instanceLocalLocks is the set of LockIDs marked InstanceLocal in
// trackedLocks; used by cycle detection to skip false positives caused
// by treating per-instance locks as a single class.
func instanceLocalLocks() map[LockID]bool {
	m := map[LockID]bool{}
	for _, tl := range trackedLocks {
		if tl.InstanceLocal {
			m[tl.ID] = true
		}
	}
	return m
}

// alternateResolutions maps (TypeName.fieldPath) to the canonical LockID
// for cases where a lock is accessed through an intermediate type rather
// than the top-level owner. For example, handshake.mutex where handshake
// is *Handshake (obtained from the index table) rather than
// peer.handshake.mutex. Keys for directly-embedded mutexes have a
// trailing dot — see buildRegistry.
var alternateResolutions = map[string]LockID{
	"Handshake.mutex":  "Peer.handshake.mutex",
	"Keypairs.":        "Peer.keypairs",        // keypairs.Lock() inside *Keypairs methods
	"CookieChecker.":   "Device.cookieChecker", // st.Lock() inside *CookieChecker methods
	"CookieGenerator.": "Peer.cookieGenerator", // st.Lock() inside *CookieGenerator methods
}

// buildRegistry creates a lookup map from (ownerType.fieldPath) → LockID.
func buildRegistry() map[string]LockID {
	m := make(map[string]LockID, len(trackedLocks)+len(alternateResolutions))
	for _, tl := range trackedLocks {
		key := tl.OwnerType + "." + tl.FieldPath
		m[key] = tl.ID
	}
	for key, id := range alternateResolutions {
		m[key] = id
	}
	return m
}
