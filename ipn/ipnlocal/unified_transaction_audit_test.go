package ipnlocal

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// A route commit may release b.mu only while every competing writer waits
// before capturing state. Walk the direct LocalBackend call graph, including
// closures and platform-specific sources, to prevent silently adding an
// unguarded writer entry. This is a source-level guard, not a substitute for
// integration/race testing or an analysis of indirect/interface calls.
func TestUnifiedPrefsTransactionWriterCoverage(t *testing.T) {
	type method struct {
		decl   *ast.FuncDecl
		calls  []string
		writer bool
	}
	fs := token.NewFileSet()
	methods := map[string][]*method{}
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	readOnly := map[string]bool{
		"CurrentPrefs": true, "CurrentProfile": true, "CurrentUserID": true,
		"Profiles": true, "ProfileIDForName": true, "requiresBackfill": true,
		"Store": true,
	}
	// These mutate the policy fence or install previously committed prefs.
	fenced := map[string]bool{
		"setNetMapLocked": true, "UpdateNetmapDelta": true,
		"reconfigAppConnectorLocked": true, "installCommittedRoutePrefsLocked": true,
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fs, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Body == nil {
				continue
			}
			r := fd.Recv.List[0]
			ptr, ok := r.Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			typ, ok := ptr.X.(*ast.Ident)
			if !ok || typ.Name != "LocalBackend" {
				continue
			}
			if len(r.Names) == 0 {
				continue
			}
			if r.Names[0].Name != "b" {
				t.Fatalf("audit needs receiver support: %s", fs.Position(fd.Pos()))
			}
			m := &method{decl: fd, writer: fenced[fd.Name.Name]}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				s, ok := c.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := s.X.(*ast.Ident); ok && id.Name == "b" {
					m.calls = append(m.calls, s.Sel.Name)
				}
				if x, ok := s.X.(*ast.SelectorExpr); ok && x.Sel.Name == "pm" {
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "b" && !readOnly[s.Sel.Name] {
						m.writer = true
					}
				}
				return true
			})
			methods[fd.Name.Name] = append(methods[fd.Name.Name], m)
		}
	}
	for changed := true; changed; {
		changed = false
		for _, group := range methods {
			for _, m := range group {
				for _, name := range m.calls {
					for _, callee := range methods[name] {
						if callee.writer && !m.writer {
							m.writer = true
							changed = true
						}
					}
				}
			}
		}
	}
	callName := func(st ast.Stmt) string {
		expr, ok := st.(*ast.ExprStmt)
		if !ok {
			return ""
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			return ""
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == "b" {
			return sel.Sel.Name
		}
		if x, ok := sel.X.(*ast.SelectorExpr); ok && x.Sel.Name == "mu" {
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "b" {
				return "mu." + sel.Sel.Name
			}
		}
		return ""
	}
	for name, group := range methods {
		for _, m := range group {
			if !m.writer {
				continue
			}
			locks := 0
			ast.Inspect(m.decl.Body, func(n ast.Node) bool {
				block, ok := n.(*ast.BlockStmt)
				if !ok {
					return true
				}
				for i, st := range block.List {
					if callName(st) != "mu.Lock" {
						continue
					}
					locks++
					// This transaction owns the pending channel when reacquiring
					// after I/O; waiting on itself would deadlock.
					if name == "connectorTransactionCached" && locks > 1 || name == "clearUnifiedAutomatic" && locks == 4 || name == "recoverUnifiedClear" && locks == 2 || name == "applyUnifiedRoutes" && locks == 2 || name == "applyUnifiedOwnerLocked" && locks <= 2 {
						continue
					}
					// Only this exact straight-line projection is exempt. Unknown
					// fields, calls, reads of authoritative state, or control flow
					// still require the transaction barrier.
					if observationalLeaseProjection(block.List[i+1:]) {
						continue
					}
					if i+1 >= len(block.List) || callName(block.List[i+1]) != "waitUnifiedPrefsTransactionLocked" {
						t.Errorf("unguarded writer %s at %s", name, fs.Position(st.Pos()))
					}
				}
				return true
			})
		}
	}
}

// observationalLeaseProjection recognizes sampled values already computed outside
// b.mu. These three fields are diagnostic only: they neither publish a fence nor
// modify prefs, ownership or the lease controller. Do not exempt whole methods.
func observationalLeaseProjection(stmts []ast.Stmt) bool {
	fields := []string{"LeaseCount", "TimeUncertain", "OldestExpiredLeaseSeconds"}
	values := []string{"count", "uncertain", "age"}
	if len(stmts) < 4 {
		return false
	}
	for i, field := range fields {
		a, ok := stmts[i].(*ast.AssignStmt)
		if !ok || a.Tok != token.ASSIGN || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
			return false
		}
		sel, ok := a.Lhs[0].(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != field {
			return false
		}
		parent, ok := sel.X.(*ast.SelectorExpr)
		if !ok || parent.Sel.Name != "unifiedStatus" {
			return false
		}
		recv, ok := parent.X.(*ast.Ident)
		if !ok || recv.Name != "b" {
			return false
		}
		rhs := a.Rhs[0]
		if i > 0 {
			address, ok := rhs.(*ast.UnaryExpr)
			if !ok || address.Op != token.AND {
				return false
			}
			rhs = address.X
		}
		value, ok := rhs.(*ast.Ident)
		if !ok || value.Name != values[i] {
			return false
		}
	}
	expr, ok := stmts[3].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expr.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Unlock" {
		return false
	}
	mu, ok := sel.X.(*ast.SelectorExpr)
	if !ok || mu.Sel.Name != "mu" {
		return false
	}
	recv, ok := mu.X.(*ast.Ident)
	return ok && recv.Name == "b"
}

func TestUnifiedObservationalProjectionAudit(t *testing.T) {
	good := "b.unifiedStatus.LeaseCount = count; b.unifiedStatus.TimeUncertain = &uncertain; b.unifiedStatus.OldestExpiredLeaseSeconds = &age; b.mu.Unlock()"
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"sample", good, true},
		{"fence", strings.Replace(good, "LeaseCount", "Applied", 1), false},
		{"ledger", strings.Replace(good, "b.unifiedStatus.LeaseCount", "b.unifiedLedger", 1), false},
		{"prefs", strings.Replace(good, "count;", "b.pm.CurrentPrefs();", 1), false},
		{"call", strings.Replace(good, "b.mu.Unlock()", "b.mutate(); b.mu.Unlock()", 1), false},
		{"extra-write", strings.Replace(good, "b.mu.Unlock()", "b.unifiedStatus.Applied = fence; b.mu.Unlock()", 1), false},
		{"missing-unlock", strings.Replace(good, "b.mu.Unlock()", "", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", "package p; func f(){"+tc.body+"}", 0)
			if err != nil {
				t.Fatal(err)
			}
			got := observationalLeaseProjection(f.Decls[0].(*ast.FuncDecl).Body.List)
			if got != tc.want {
				t.Fatalf("projection exemption=%v, want %v", got, tc.want)
			}
		})
	}
}
