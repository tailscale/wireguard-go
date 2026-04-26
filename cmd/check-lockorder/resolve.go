package main

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

// LockOp represents a single lock or unlock operation found in source.
type LockOp struct {
	Lock     LockID
	Kind     LockKind // Exclusive or Shared
	IsUnlock bool
	IsDefer  bool
	Pos      token.Pos
}

// CallUnderLock records a function call made while locks are held.
// The held set is filled in later during analysis.
type CallUnderLock struct {
	Callee   *types.Func
	CalleeFn *ast.FuncDecl // nil for non-local callees
	Pos      token.Pos
}

// FuncInfo holds the raw extracted information about a single function.
type FuncInfo struct {
	Name      string
	Obj       *types.Func
	Decl      *ast.FuncDecl
	LockOps   []LockOp
	Calls     []CallUnderLock
	BodyStmts []ast.Stmt // the function body statements
}

// resolver extracts lock operations, variable aliases, and call sites from functions.
type resolver struct {
	fset     *token.FileSet
	info     *types.Info
	registry map[string]LockID // (OwnerType.fieldPath) → LockID
	pkg      *types.Package

	// Per-function state
	aliases map[string]string // localVar → resolved receiver expression string
}

func newResolver(fset *token.FileSet, info *types.Info, pkg *types.Package, registry map[string]LockID) *resolver {
	return &resolver{
		fset:     fset,
		info:     info,
		registry: registry,
		pkg:      pkg,
	}
}

// extractFuncInfo analyzes a single function declaration.
func (r *resolver) extractFuncInfo(fn *ast.FuncDecl) *FuncInfo {
	if fn.Body == nil {
		return nil
	}

	obj := r.info.ObjectOf(fn.Name)
	if obj == nil {
		return nil
	}
	funcObj, ok := obj.(*types.Func)
	if !ok {
		return nil
	}

	fi := &FuncInfo{
		Name:      funcObj.FullName(),
		Obj:       funcObj,
		Decl:      fn,
		BodyStmts: fn.Body.List,
	}

	r.aliases = make(map[string]string)
	r.walkStmtList(fn.Body.List, fi)
	return fi
}

// walkStmtList processes a list of statements, extracting lock ops and calls.
func (r *resolver) walkStmtList(stmts []ast.Stmt, fi *FuncInfo) {
	for _, stmt := range stmts {
		r.walkStmt(stmt, fi, false)
	}
}

func (r *resolver) walkStmt(stmt ast.Stmt, fi *FuncInfo, inDefer bool) {
	switch s := stmt.(type) {
	case *ast.ExprStmt:
		r.walkExpr(s.X, fi, inDefer)
	case *ast.AssignStmt:
		// Check for alias patterns: x := &y.field
		r.checkAlias(s)
		// Also check for lock ops in RHS
		for _, expr := range s.Rhs {
			r.walkExpr(expr, fi, inDefer)
		}
	case *ast.DeferStmt:
		r.walkExpr(s.Call, fi, true)
	case *ast.GoStmt:
		// Goroutine launches start fresh — don't track through them
	case *ast.BlockStmt:
		r.walkStmtList(s.List, fi)
	case *ast.IfStmt:
		if s.Init != nil {
			r.walkStmt(s.Init, fi, inDefer)
		}
		r.walkStmtList(s.Body.List, fi)
		if s.Else != nil {
			r.walkStmt(s.Else, fi, inDefer)
		}
	case *ast.ForStmt:
		r.walkStmtList(s.Body.List, fi)
	case *ast.RangeStmt:
		r.walkStmtList(s.Body.List, fi)
	case *ast.SwitchStmt:
		if s.Init != nil {
			r.walkStmt(s.Init, fi, inDefer)
		}
		r.walkStmtList(s.Body.List, fi)
	case *ast.TypeSwitchStmt:
		r.walkStmtList(s.Body.List, fi)
	case *ast.CaseClause:
		r.walkStmtList(s.Body, fi)
	case *ast.SelectStmt:
		r.walkStmtList(s.Body.List, fi)
	case *ast.CommClause:
		r.walkStmtList(s.Body, fi)
	case *ast.ReturnStmt:
		// nothing to track
	}
}

func (r *resolver) walkExpr(expr ast.Expr, fi *FuncInfo, inDefer bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return
	}

	// Check for immediately-invoked function literals: func() { ... }()
	if funcLit, ok := call.Fun.(*ast.FuncLit); ok {
		r.walkStmtList(funcLit.Body.List, fi)
		return
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		// Non-selector call: could be a package-level function
		if ident, ok := call.Fun.(*ast.Ident); ok {
			obj := r.info.ObjectOf(ident)
			if fn, ok := obj.(*types.Func); ok && fn.Pkg() == r.pkg {
				fi.Calls = append(fi.Calls, CallUnderLock{
					Callee: fn,
					Pos:    call.Pos(),
				})
			}
		}
		return
	}

	methodName := sel.Sel.Name

	// Is this a lock/unlock operation?
	if isLockMethod(methodName) {
		if lockID, kind := r.identifyLock(sel.X, methodName); lockID != "" {
			fi.LockOps = append(fi.LockOps, LockOp{
				Lock:     lockID,
				Kind:     kind,
				IsUnlock: methodName == "Unlock" || methodName == "RUnlock",
				IsDefer:  inDefer,
				Pos:      call.Pos(),
			})
			return
		}
	}

	// Otherwise, it's a method call — track as a potential callee
	selObj := r.info.ObjectOf(sel.Sel)
	if fn, ok := selObj.(*types.Func); ok && fn.Pkg() == r.pkg {
		fi.Calls = append(fi.Calls, CallUnderLock{
			Callee: fn,
			Pos:    call.Pos(),
		})
	}
}

// isLockMethod returns true for sync.Mutex/RWMutex method names.
func isLockMethod(name string) bool {
	return name == "Lock" || name == "Unlock" || name == "RLock" || name == "RUnlock"
}

// identifyLock resolves the receiver expression of a lock method call to a LockID.
// Returns ("", 0) if the lock is not in our tracked set.
func (r *resolver) identifyLock(receiver ast.Expr, methodName string) (LockID, LockKind) {
	// Build the field path from the receiver expression.
	// We walk the selector chain, resolving aliases, until we reach
	// a variable whose type is *Device, *Peer, Device, or Peer.
	ownerType, fieldPath := r.resolveReceiver(receiver)
	if ownerType == "" {
		return "", 0
	}

	key := ownerType + "." + fieldPath
	lockID, ok := r.registry[key]
	if !ok {
		return "", 0
	}

	var kind LockKind
	if methodName == "RLock" || methodName == "RUnlock" {
		kind = Shared
	} else {
		kind = Exclusive
	}
	return lockID, kind
}

// resolveReceiver walks a selector expression chain to extract (ownerType, fieldPath).
// For example, device.staticIdentity → ("Device", "staticIdentity")
// For peer.handshake.mutex → ("Peer", "handshake.mutex")
func (r *resolver) resolveReceiver(expr ast.Expr) (ownerType string, fieldPath string) {
	var fields []string
	cur := expr

	for {
		switch e := cur.(type) {
		case *ast.SelectorExpr:
			fields = append(fields, e.Sel.Name)
			cur = e.X
		case *ast.Ident:
			// Check if this ident has an alias
			if resolved, ok := r.aliases[e.Name]; ok {
				// The alias is a string like "Peer.handshake".
				// Parse it: the first component is the type, the rest are fields.
				parts := strings.SplitN(resolved, ".", 2)
				ownerType = parts[0]
				if len(parts) > 1 {
					// Prepend the alias fields before our accumulated fields
					aliasFields := strings.Split(parts[1], ".")
					fields = append(fields, aliasFields...)
				}
				// Reverse fields (we collected them inner→outer, need outer→inner)
				reverse(fields)
				return ownerType, strings.Join(fields, ".")
			}

			// Not an alias — check the variable's type
			ownerType = r.typeName(e)
			if ownerType == "" {
				return "", ""
			}
			reverse(fields)
			return ownerType, strings.Join(fields, ".")
		case *ast.ParenExpr:
			cur = e.X
		case *ast.StarExpr:
			cur = e.X
		default:
			return "", ""
		}
	}
}

// typeName returns "Device" or "Peer" if the ident's type is *Device/*Peer/Device/Peer.
// Returns "" otherwise.
func (r *resolver) typeName(ident *ast.Ident) string {
	obj := r.info.ObjectOf(ident)
	if obj == nil {
		return ""
	}
	t := obj.Type()
	// Dereference pointer
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		name := named.Obj().Name()
		switch name {
		case "Device", "Peer", "AllowedIPs", "IndexTable",
			"Handshake", "Keypairs",
			"CookieChecker", "CookieGenerator",
			"Timer", "WaitPool":
			return name
		}
	}
	return ""
}

// checkAlias records simple variable alias patterns:
//
//	x := &y.field     →  aliases[x] = resolved(y.field)
//	x := y            →  aliases[x] = resolved(y) if y is a pointer to a tracked type
func (r *resolver) checkAlias(assign *ast.AssignStmt) {
	if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return
	}
	lhs, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return
	}

	rhs := assign.Rhs[0]

	// Pattern: x := &y.field
	if unary, ok := rhs.(*ast.UnaryExpr); ok && unary.Op.String() == "&" {
		ownerType, fieldPath := r.resolveReceiver(unary.X)
		if ownerType != "" {
			if fieldPath != "" {
				r.aliases[lhs.Name] = ownerType + "." + fieldPath
			} else {
				r.aliases[lhs.Name] = ownerType
			}
		}
		return
	}

	// Pattern: x := y.field (direct field access without &)
	if sel, ok := rhs.(*ast.SelectorExpr); ok {
		ownerType, fieldPath := r.resolveReceiver(sel.X)
		if ownerType != "" {
			path := fieldPath
			if path != "" {
				path += "."
			}
			path += sel.Sel.Name
			r.aliases[lhs.Name] = ownerType + "." + path
		}
	}
}

func reverse(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
