// check-lockorder statically analyzes the device package for lock-ordering
// deadlocks. It builds a lock-after directed graph and reports cycles
// (potential deadlocks) and reentrant RLock (deadlock with pending writer).
//
// Exit code 0 means no violations found; 1 means violations were found.
//
// Usage:
//
//	go run ./cmd/check-lockorder [-v]
//
// With -v, print the full lock inventory and every observed lock-after edge.
package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/tools/go/packages"
)

const targetPkg = "github.com/tailscale/wireguard-go/device"

func main() {
	verbose := flag.Bool("v", false, "list the lock inventory and all observed lock-after edges")
	flag.Parse()

	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedSyntax |
			packages.NeedTypes |
			packages.NeedTypesInfo,
	}
	pkgs, err := packages.Load(cfg, targetPkg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load package: %v\n", err)
		os.Exit(2)
	}
	if len(pkgs) == 0 {
		fmt.Fprintf(os.Stderr, "package %s not found\n", targetPkg)
		os.Exit(2)
	}
	pkg := pkgs[0]
	if len(pkg.Errors) > 0 {
		for _, e := range pkg.Errors {
			fmt.Fprintf(os.Stderr, "package error: %v\n", e)
		}
		os.Exit(2)
	}

	if unknown := checkInventory(pkg.Types); len(unknown) > 0 {
		fmt.Fprintf(os.Stderr, "found %d unregistered sync.Mutex/sync.RWMutex field(s) in %s:\n",
			len(unknown), targetPkg)
		for _, s := range unknown {
			fmt.Fprintf(os.Stderr, "  %s\n", s)
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Every mutex in the device package must be registered in trackedLocks")
		fmt.Fprintln(os.Stderr, "(cmd/check-lockorder/registry.go). The analyzer will treat the new lock")
		fmt.Fprintln(os.Stderr, "as part of the partial order and fail on any cycle it participates in.")
		os.Exit(1)
	}

	registry := buildRegistry()
	a := newAnalyzer(pkg.Fset, pkg.TypesInfo, pkg.Types, registry)

	for _, file := range pkg.Syntax {
		a.addFile(file)
	}

	edges := a.analyze()

	fmt.Fprintf(os.Stderr, "analyzed %d functions, found %d lock-after edges\n",
		len(a.funcs), len(edges))

	if *verbose {
		printVerbose(os.Stdout, edges, pkg.Fset)
		fmt.Fprintln(os.Stdout)
	}

	violations := findViolations(edges, pkg.Fset)

	if len(violations) == 0 {
		fmt.Println("no lock-ordering violations found")
		return
	}

	fmt.Printf("found %d lock-ordering violation(s):\n\n", len(violations))
	for i, v := range violations {
		fmt.Printf("%d. %s\n%s\n\n", i+1, v.Message, v.Detail)
	}
	os.Exit(1)
}
