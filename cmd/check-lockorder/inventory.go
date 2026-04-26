package main

import (
	"go/types"
	"sort"
)

// lockSite identifies a sync.Mutex or sync.RWMutex field declared in
// the device package. DefType is the named struct type that declares
// the field. FieldPath is the dot-separated path from a value of that
// type to the mutex, or "" if the mutex is directly embedded on the
// struct.
//
// Examples:
//
//	{DefType: "Device",     FieldPath: "ipcMutex"}  // device.ipcMutex (named field)
//	{DefType: "Device",     FieldPath: "state"}     // device.state.{Mutex} (anon-struct field embeds sync.Mutex)
//	{DefType: "Handshake",  FieldPath: "mutex"}     // handshake.mutex (named field)
//	{DefType: "Keypairs",   FieldPath: ""}          // keypairs.{RWMutex} (embedded directly on Keypairs)
type lockSite struct {
	DefType   string
	FieldPath string
}

func (s lockSite) String() string {
	if s.FieldPath == "" {
		return s.DefType
	}
	return s.DefType + "." + s.FieldPath
}

// findLockSites walks every named struct type in pkg and returns all
// sync.Mutex/sync.RWMutex fields reachable without crossing into
// another named type. Anonymous (inline) struct fields are descended
// into; named struct fields are not (they are inventoried separately
// when they appear at the top level of pkg).
func findLockSites(pkg *types.Package) []lockSite {
	var sites []lockSite
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		tn, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		walkStructForLocks(name, st, "", &sites)
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].DefType != sites[j].DefType {
			return sites[i].DefType < sites[j].DefType
		}
		return sites[i].FieldPath < sites[j].FieldPath
	})
	return sites
}

func walkStructForLocks(defType string, st *types.Struct, prefix string, out *[]lockSite) {
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if isMutexType(f.Type()) {
			path := prefix
			if !f.Anonymous() {
				path = joinPath(prefix, f.Name())
			}
			*out = append(*out, lockSite{DefType: defType, FieldPath: path})
			continue
		}
		// Descend only into anonymous (inline) struct types. Named
		// types — including pointers and other struct types defined
		// elsewhere — are inventoried at the top level on their own
		// (or are out-of-scope, e.g. *time.Timer).
		if _, ok := f.Type().(*types.Named); ok {
			continue
		}
		anon, ok := f.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		sub := prefix
		if !f.Anonymous() {
			sub = joinPath(prefix, f.Name())
		}
		walkStructForLocks(defType, anon, sub, out)
	}
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func isMutexType(t types.Type) bool {
	n, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := n.Obj()
	if obj.Pkg() == nil || obj.Pkg().Path() != "sync" {
		return false
	}
	return obj.Name() == "Mutex" || obj.Name() == "RWMutex"
}

// checkInventory returns the sync.Mutex/sync.RWMutex sites in pkg that
// are not registered in trackedLocks. An empty result means every
// mutex in the package is part of the lock-ordering analysis.
func checkInventory(pkg *types.Package) []lockSite {
	sites := findLockSites(pkg)
	known := make(map[lockSite]bool, len(trackedLocks))
	for _, tl := range trackedLocks {
		known[lockSite{DefType: tl.DefType, FieldPath: tl.DefPath}] = true
	}
	var unknown []lockSite
	for _, s := range sites {
		if !known[s] {
			unknown = append(unknown, s)
		}
	}
	return unknown
}
