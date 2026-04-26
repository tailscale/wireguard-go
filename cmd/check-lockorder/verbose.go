package main

import (
	"fmt"
	"go/token"
	"io"
	"sort"
)

// printVerbose writes the full lock inventory and every observed lock-after
// edge to w. Edges are deduplicated by (from, fromKind, to, toKind); for
// each unique pair the shortest attribution chain is shown.
func printVerbose(w io.Writer, edges []Edge, fset *token.FileSet) {
	fmt.Fprintf(w, "== Lock inventory (%d) ==\n", len(trackedLocks))
	for _, tl := range trackedLocks {
		kind := "Mutex"
		if tl.Kind == ReadWriteMutex {
			kind = "RWMutex"
		}
		def := tl.DefType
		if tl.DefPath != "" {
			def += "." + tl.DefPath
		}
		note := ""
		if tl.InstanceLocal {
			note = "  [instance-local; cycles not checked]"
		}
		fmt.Fprintf(w, "  %-32s %-7s  defined at %s%s\n", tl.ID, kind, def, note)
	}
	fmt.Fprintln(w)

	type edgeKey struct {
		from, to         LockID
		fromKind, toKind LockKind
	}
	best := map[edgeKey]Edge{}
	for _, e := range edges {
		k := edgeKey{e.From, e.To, e.FromKind, e.ToKind}
		if cur, ok := best[k]; !ok || len(e.Chain) < len(cur.Chain) {
			best[k] = e
		}
	}

	keys := make([]edgeKey, 0, len(best))
	for k := range best {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].from != keys[j].from {
			return keys[i].from < keys[j].from
		}
		if keys[i].fromKind != keys[j].fromKind {
			return keys[i].fromKind < keys[j].fromKind
		}
		if keys[i].to != keys[j].to {
			return keys[i].to < keys[j].to
		}
		return keys[i].toKind < keys[j].toKind
	})

	fmt.Fprintf(w, "== Lock-after edges (%d unique pairs from %d observations) ==\n",
		len(best), len(edges))
	for _, k := range keys {
		e := best[k]
		fmt.Fprintf(w, "\n%s.%s -> %s.%s\n",
			k.from, k.fromKind, k.to, k.toKind)
		fmt.Fprintln(w, formatChain(e.Chain, fset))
	}
}
