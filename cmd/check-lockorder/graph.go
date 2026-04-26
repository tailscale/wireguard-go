package main

import (
	"fmt"
	"go/token"
	"sort"
	"strings"
)

// Violation is a problem found by the analysis.
type Violation struct {
	Kind    string // "cycle" or "reentrant-rlock"
	Message string
	Detail  string // multi-line detail with file:line references
}

// findViolations examines the collected edges for cycles and reentrant RLock.
// Cycles or reentrance involving an InstanceLocal lock are not reported:
// per-instance locks where each instance is owned by exactly one goroutine
// can't deadlock with themselves under static cycle analysis (different
// holders are different instances).
func findViolations(edges []Edge, fset *token.FileSet) []Violation {
	var violations []Violation
	instLocal := instanceLocalLocks()

	// Deduplicate edges into an adjacency list with attribution.
	type edgeKey struct {
		from, to         LockID
		fromKind, toKind LockKind
	}
	best := make(map[edgeKey]Edge)
	for _, e := range edges {
		k := edgeKey{e.From, e.To, e.FromKind, e.ToKind}
		if _, ok := best[k]; !ok {
			best[k] = e
		}
	}

	// 1. Detect reentrant RLock (self-loops). Skip instance-local locks
	// since each instance is owned by a single goroutine.
	for k, e := range best {
		if k.from == k.to {
			if instLocal[k.from] {
				continue
			}
			desc := "REENTRANT "
			if k.fromKind == Shared && k.toKind == Shared {
				desc += "RLOCK"
			} else {
				desc += "LOCK"
			}
			violations = append(violations, Violation{
				Kind:    "reentrant-rlock",
				Message: fmt.Sprintf("%s on %s", desc, k.from),
				Detail:  formatChain(e.Chain, fset),
			})
		}
	}

	// 2. Detect ordering cycles.
	// Build adjacency list (excluding self-loops, already reported above,
	// and edges touching instance-local locks).
	adj := make(map[LockID]map[LockID]bool)
	edgeFor := make(map[edgeKey]Edge)
	for k, e := range best {
		if k.from == k.to {
			continue
		}
		if instLocal[k.from] || instLocal[k.to] {
			continue
		}
		if adj[k.from] == nil {
			adj[k.from] = make(map[LockID]bool)
		}
		adj[k.from][k.to] = true
		edgeFor[edgeKey{k.from, k.to, k.fromKind, k.toKind}] = e
	}

	// Find all 2-cycles (A→B and B→A).
	// This is the most common deadlock pattern.
	reported := make(map[[2]LockID]bool)
	for k, e := range best {
		if k.from == k.to {
			continue
		}
		if instLocal[k.from] || instLocal[k.to] {
			continue
		}
		// Check if the reverse edge exists
		if adj[k.to] != nil && adj[k.to][k.from] {
			pair := [2]LockID{k.from, k.to}
			if k.from > k.to {
				pair = [2]LockID{k.to, k.from}
			}
			if reported[pair] {
				continue
			}
			reported[pair] = true

			// Find the reverse edge for the detail
			var reverseEdge Edge
			for rk, re := range best {
				if rk.from == k.to && rk.to == k.from {
					reverseEdge = re
					break
				}
			}

			violations = append(violations, Violation{
				Kind: "cycle",
				Message: fmt.Sprintf("LOCK ORDERING CYCLE: %s <-> %s",
					pair[0], pair[1]),
				Detail: fmt.Sprintf(
					"  Path A (%s -> %s):\n%s\n  Path B (%s -> %s):\n%s",
					e.From, e.To,
					formatChain(e.Chain, fset),
					reverseEdge.From, reverseEdge.To,
					formatChain(reverseEdge.Chain, fset),
				),
			})
		}
	}

	// Also find longer cycles using DFS.
	longerCycles := findLongerCycles(adj)
	for _, cycle := range longerCycles {
		if len(cycle) == 2 {
			continue // already reported as a 2-cycle above
		}
		// Check if this is just a combination of known 2-cycles.
		// If all adjacent pairs are already reported 2-cycles, skip.
		allPairsKnown := true
		for i := 0; i < len(cycle); i++ {
			a := cycle[i]
			b := cycle[(i+1)%len(cycle)]
			pair := [2]LockID{a, b}
			if a > b {
				pair = [2]LockID{b, a}
			}
			if !reported[pair] {
				allPairsKnown = false
				break
			}
		}
		if allPairsKnown {
			continue
		}
		violations = append(violations, Violation{
			Kind:    "cycle",
			Message: fmt.Sprintf("LOCK ORDERING CYCLE: %s", formatCycle(cycle)),
			Detail:  fmt.Sprintf("  Cycle: %s", formatCycle(cycle)),
		})
	}

	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Kind != violations[j].Kind {
			return violations[i].Kind < violations[j].Kind
		}
		return violations[i].Message < violations[j].Message
	})

	return violations
}

// findLongerCycles finds all elementary cycles in the directed graph.
// Returns unique cycles (each as a slice of LockIDs).
func findLongerCycles(adj map[LockID]map[LockID]bool) [][](LockID) {
	var cycles [][]LockID

	// Standard DFS-based cycle detection
	color := make(map[LockID]int) // 0=white, 1=gray, 2=black
	parent := make(map[LockID][]LockID)

	var dfs func(node LockID, path []LockID)
	dfs = func(node LockID, path []LockID) {
		color[node] = 1
		path = append(path, node)

		for next := range adj[node] {
			if color[next] == 1 {
				// Found a cycle — extract it
				start := -1
				for i, n := range path {
					if n == next {
						start = i
						break
					}
				}
				if start >= 0 {
					cycle := make([]LockID, len(path)-start)
					copy(cycle, path[start:])
					if len(cycle) > 2 {
						cycles = append(cycles, cycle)
					}
				}
			} else if color[next] == 0 {
				parent[next] = path
				dfs(next, path)
			}
		}

		color[node] = 2
	}

	// Get sorted nodes for deterministic output
	var nodes []LockID
	for n := range adj {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i] < nodes[j]
	})

	for _, n := range nodes {
		if color[n] == 0 {
			dfs(n, nil)
		}
	}

	return cycles
}

func formatChain(chain []CallFrame, fset *token.FileSet) string {
	if len(chain) == 0 {
		return "    (no attribution)"
	}
	var b strings.Builder
	for _, frame := range chain {
		pos := fset.Position(frame.Pos)
		// Strip to just filename:line
		file := pos.Filename
		if idx := strings.LastIndex(file, "/"); idx >= 0 {
			file = file[idx+1:]
		}
		fmt.Fprintf(&b, "    %s:%d  %s\n", file, pos.Line, shortName(frame.FuncName))
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatCycle(cycle []LockID) string {
	parts := make([]string, len(cycle))
	for i, c := range cycle {
		parts[i] = string(c)
	}
	return strings.Join(parts, " -> ") + " -> " + parts[0]
}

// shortName strips the package path from a function name.
//
//	"(*github.com/tailscale/wireguard-go/device.Device).SetPrivateKey" → "(*Device).SetPrivateKey"
//	"(github.com/tailscale/wireguard-go/device.Peer).Foo"              → "(Peer).Foo"
//	"github.com/tailscale/wireguard-go/device.SomeFunc"                → "SomeFunc"
func shortName(fullName string) string {
	leading := ""
	s := fullName
	switch {
	case strings.HasPrefix(s, "(*"):
		leading, s = "(*", s[2:]
	case strings.HasPrefix(s, "("):
		leading, s = "(", s[1:]
	}
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		s = s[idx+1:]
	}
	if dot := strings.Index(s, "."); dot >= 0 {
		s = s[dot+1:]
	}
	return leading + s
}
