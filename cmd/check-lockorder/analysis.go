package main

import (
	"go/ast"
	"go/token"
	"go/types"
)

// HeldLock is one lock in the "currently held" set.
type HeldLock struct {
	Lock LockID
	Kind LockKind
	Pos  token.Pos
}

// CallFrame is one step in a call chain for edge attribution.
type CallFrame struct {
	FuncName string
	Pos      token.Pos
}

// Edge represents a lock-after relationship: Target was acquired while Source was held.
type Edge struct {
	From     LockID
	FromKind LockKind
	To       LockID
	ToKind   LockKind
	Chain    []CallFrame // how we got here
}

// LockAcq records a lock that a function (transitively) acquires.
type LockAcq struct {
	Lock  LockID
	Kind  LockKind
	Chain []CallFrame
}

// analyzer performs per-function held-set analysis and inter-procedural expansion.
type analyzer struct {
	fset     *token.FileSet
	info     *types.Info
	pkg      *types.Package
	registry map[string]LockID
	resolver *resolver

	funcs    map[string]*FuncInfo // funcFullName → FuncInfo
	funcDecl map[string]*ast.FuncDecl
	edges    []Edge

	// Transitive lock acquisitions per function, computed during expansion.
	transitive map[string][]LockAcq // funcFullName → transitive locks
	expanding  map[string]bool      // cycle detection during expansion
}

func newAnalyzer(fset *token.FileSet, info *types.Info, pkg *types.Package, registry map[string]LockID) *analyzer {
	return &analyzer{
		fset:       fset,
		info:       info,
		pkg:        pkg,
		registry:   registry,
		resolver:   newResolver(fset, info, pkg, registry),
		funcs:      make(map[string]*FuncInfo),
		funcDecl:   make(map[string]*ast.FuncDecl),
		transitive: make(map[string][]LockAcq),
		expanding:  make(map[string]bool),
	}
}

// addFile processes all function declarations in a file.
func (a *analyzer) addFile(file *ast.File) {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		fi := a.resolver.extractFuncInfo(fn)
		if fi == nil {
			continue
		}
		a.funcs[fi.Name] = fi
		a.funcDecl[fi.Name] = fn
	}
}

// analyze runs the full analysis: held-set computation, transitive expansion,
// and edge collection.
func (a *analyzer) analyze() []Edge {
	// Phase 1: Compute held-sets and direct edges for each function.
	for _, fi := range a.funcs {
		a.computeHeldSets(fi)
	}

	// Phase 2: Transitive expansion — for each call under lock,
	// expand the callee's transitive lock acquisitions and add edges.
	for _, fi := range a.funcs {
		a.expandCalls(fi)
	}

	return a.edges
}

// computeHeldSets walks a function's lock ops and calls in order,
// maintaining the set of currently-held locks. It records direct edges
// (lock acquired while another is held) and annotates calls with held sets.
func (a *analyzer) computeHeldSets(fi *FuncInfo) {
	if fi.Decl == nil || fi.Decl.Body == nil {
		return
	}

	held := make(map[LockID]HeldLock)
	a.walkBody(fi.Decl.Body.List, held, fi)
}

// walkBody processes statements in order, tracking the held-lock set.
func (a *analyzer) walkBody(stmts []ast.Stmt, held map[LockID]HeldLock, fi *FuncInfo) {
	for _, stmt := range stmts {
		a.walkStmtForHeld(stmt, held, fi, false)
	}
}

func (a *analyzer) walkStmtForHeld(stmt ast.Stmt, held map[LockID]HeldLock, fi *FuncInfo, inDefer bool) {
	switch s := stmt.(type) {
	case *ast.ExprStmt:
		a.processExprForHeld(s.X, held, fi, inDefer)
	case *ast.AssignStmt:
		for _, expr := range s.Rhs {
			a.processExprForHeld(expr, held, fi, inDefer)
		}
	case *ast.DeferStmt:
		a.processExprForHeld(s.Call, held, fi, true)
	case *ast.GoStmt:
		// New goroutine — don't track through
	case *ast.BlockStmt:
		a.walkBody(s.List, held, fi)
	case *ast.IfStmt:
		if s.Init != nil {
			a.walkStmtForHeld(s.Init, held, fi, inDefer)
		}
		a.walkBody(s.Body.List, held, fi)
		if s.Else != nil {
			a.walkStmtForHeld(s.Else, held, fi, inDefer)
		}
	case *ast.ForStmt:
		a.walkBody(s.Body.List, held, fi)
	case *ast.RangeStmt:
		a.walkBody(s.Body.List, held, fi)
	case *ast.SwitchStmt:
		if s.Init != nil {
			a.walkStmtForHeld(s.Init, held, fi, inDefer)
		}
		a.walkBody(s.Body.List, held, fi)
	case *ast.TypeSwitchStmt:
		a.walkBody(s.Body.List, held, fi)
	case *ast.CaseClause:
		a.walkBody(s.Body, held, fi)
	case *ast.SelectStmt:
		a.walkBody(s.Body.List, held, fi)
	case *ast.CommClause:
		a.walkBody(s.Body, held, fi)
	}
}

func (a *analyzer) processExprForHeld(expr ast.Expr, held map[LockID]HeldLock, fi *FuncInfo, inDefer bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return
	}

	// Immediately-invoked function literal: func() { ... }()
	// The closure inherits the caller's held locks but its deferred unlocks
	// fire when the closure returns, not when the outer function returns.
	// We analyze the closure body with a copy of the held set so that
	// deferred unlocks inside the closure don't leak into the outer scope.
	if funcLit, ok := call.Fun.(*ast.FuncLit); ok {
		closureHeld := make(map[LockID]HeldLock, len(held))
		for k, v := range held {
			closureHeld[k] = v
		}
		a.walkBody(funcLit.Body.List, closureHeld, fi)
		return
	}

	sel, isSel := call.Fun.(*ast.SelectorExpr)

	// Check for lock/unlock operations
	if isSel && isLockMethod(sel.Sel.Name) {
		lockID, kind := a.resolver.identifyLock(sel.X, sel.Sel.Name)
		if lockID != "" {
			isUnlock := sel.Sel.Name == "Unlock" || sel.Sel.Name == "RUnlock"
			if isUnlock && !inDefer {
				// Explicit (non-deferred) unlock: remove from held set
				delete(held, lockID)
			} else if !isUnlock {
				// Lock acquisition: record edges from all currently held locks
				for _, h := range held {
					a.edges = append(a.edges, Edge{
						From:     h.Lock,
						FromKind: h.Kind,
						To:       lockID,
						ToKind:   kind,
						Chain: []CallFrame{{
							FuncName: fi.Name,
							Pos:      call.Pos(),
						}},
					})
				}
				// Also check for reentrant acquisition
				if existing, ok := held[lockID]; ok {
					_ = existing // The edge above captures the self-loop
				}
				held[lockID] = HeldLock{
					Lock: lockID,
					Kind: kind,
					Pos:  call.Pos(),
				}
			}
			// Deferred unlock: lock stays in held set (released at function return)
			return
		}
	}

	// Non-lock function call: record as a call under lock if we hold any locks.
	if len(held) == 0 {
		return
	}

	var calleeFunc *types.Func
	if isSel {
		obj := a.info.ObjectOf(sel.Sel)
		if fn, ok := obj.(*types.Func); ok && fn.Pkg() == a.pkg {
			calleeFunc = fn
		}
	} else if ident, ok := call.Fun.(*ast.Ident); ok {
		obj := a.info.ObjectOf(ident)
		if fn, ok := obj.(*types.Func); ok && fn.Pkg() == a.pkg {
			calleeFunc = fn
		}
	}

	if calleeFunc == nil {
		return
	}

	// Record edges: each held lock → each lock the callee transitively acquires
	calleeName := calleeFunc.FullName()
	transLocks := a.getTransitiveLocks(calleeName)
	for _, h := range held {
		for _, tl := range transLocks {
			chain := []CallFrame{{
				FuncName: fi.Name,
				Pos:      call.Pos(),
			}}
			chain = append(chain, tl.Chain...)
			a.edges = append(a.edges, Edge{
				From:     h.Lock,
				FromKind: h.Kind,
				To:       tl.Lock,
				ToKind:   tl.Kind,
				Chain:    chain,
			})
		}
	}
}

// expandCalls is a no-op now — transitive expansion happens lazily in getTransitiveLocks.
func (a *analyzer) expandCalls(fi *FuncInfo) {}

// getTransitiveLocks returns all locks that a function may acquire, directly
// or through callees. Results are memoized.
func (a *analyzer) getTransitiveLocks(funcName string) []LockAcq {
	if cached, ok := a.transitive[funcName]; ok {
		return cached
	}

	// Cycle detection
	if a.expanding[funcName] {
		return nil
	}
	a.expanding[funcName] = true
	defer func() { delete(a.expanding, funcName) }()

	fi, ok := a.funcs[funcName]
	if !ok {
		return nil
	}

	var result []LockAcq
	seen := make(map[LockID]bool)

	// Direct lock acquisitions
	for _, op := range fi.LockOps {
		if !op.IsUnlock && !seen[op.Lock] {
			seen[op.Lock] = true
			result = append(result, LockAcq{
				Lock: op.Lock,
				Kind: op.Kind,
				Chain: []CallFrame{{
					FuncName: funcName,
					Pos:      op.Pos,
				}},
			})
		}
	}

	// Transitive through callees
	for _, c := range fi.Calls {
		calleeName := c.Callee.FullName()
		for _, tl := range a.getTransitiveLocks(calleeName) {
			if !seen[tl.Lock] {
				seen[tl.Lock] = true
				chain := []CallFrame{{
					FuncName: funcName,
					Pos:      c.Pos,
				}}
				chain = append(chain, tl.Chain...)
				result = append(result, LockAcq{
					Lock:  tl.Lock,
					Kind:  tl.Kind,
					Chain: chain,
				})
			}
		}
	}

	a.transitive[funcName] = result
	return result
}
