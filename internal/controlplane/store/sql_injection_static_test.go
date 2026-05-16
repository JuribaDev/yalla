package store_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// SQL injection — static-analysis defense (BE-0344).
//
// Threat model: an attacker submits a string that, if it ever reaches the
// database server as raw SQL, executes attacker-chosen statements with the
// application's privileges. The control is "every SQL statement is fully
// parameterized; caller input is bound through pgx placeholders ($1, $2, …)
// only, never interpolated into the SQL string." The store package's
// AGENTS.md pins this rule:
//
//   "Never build SQL by concatenating caller input; every statement is fully
//    parameterized."
//
// These tests are the regression backstop. They run without a database and
// fail at build time for any change that breaks the invariant — e.g.
// introducing db.Query(fmt.Sprintf("SELECT … WHERE id = '%s'", userID)) into a
// repository file. They scan every non-test Go source file in this package
// directory; subdirectories (store/migrate) are out of scope (the migration
// runner is a separate package and is exercised by its own tests).
//
// The companion runtime test, sql_injection_test.go, exercises the same
// invariant end-to-end against real Postgres.

// TestSQLArgsAreConstantExpressions walks every non-test .go file in this
// package and verifies the SQL-string argument passed to .Exec / .Query /
// .QueryRow is built only from compile-time-constant pieces: string literals,
// package-level string consts, parenthesised wrappers around those, and
// concatenations of any of those with the + operator. Anything else — a
// fmt.Sprintf result, a string(...) conversion, a method call, a local
// variable — is rejected with the file:line of the offending argument.
func TestSQLArgsAreConstantExpressions(t *testing.T) {
	t.Parallel()
	for _, path := range nonTestStoreSourceFiles(t) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			fset, file := mustParseFile(t, path)
			for _, v := range findUnsafeSQLArgs(fset, file) {
				t.Error(v)
			}
		})
	}
}

// TestSQLNoSprintfBuildsQueryStrings walks every non-test .go file in this
// package and rejects any fmt.Sprintf / fmt.Sprint / fmt.Sprintln call whose
// first argument is a string literal containing SQL keywords. This catches
// the indirect pattern where someone builds a query string with Sprintf and
// then passes the resulting local variable to .Query — TestSQLArgsAreConstant
// would still fire on the .Query call site, but this test fires on the
// Sprintf site too, so the diagnostic points at the actual mistake.
func TestSQLNoSprintfBuildsQueryStrings(t *testing.T) {
	t.Parallel()
	for _, path := range nonTestStoreSourceFiles(t) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			fset, file := mustParseFile(t, path)
			for _, v := range findSprintfSQL(fset, file) {
				t.Error(v)
			}
		})
	}
}

// TestSQLInjectionStaticAnalyzerDetectsRegressions is the self-check for the
// static analyzers above. The acceptance criterion "tests fail when the
// control is removed" is the load-bearing one for this story: a future change
// that re-opens the parameterization invariant must visibly fail a test.
// Here we synthesize a handful of known-bad source snippets — direct
// fmt.Sprintf-in-Query, indirect Sprintf-then-Query, string-concat with a
// non-const variable, a string conversion, a method-call SQL — and assert
// each analyzer reports the violation. If the analyzer is ever weakened, the
// regression detector itself fails to fail and this test catches it.
//
// We parse from a string rather than from disk so the bad code never lives in
// the repository — it cannot be accidentally compiled, imported, or shipped.
func TestSQLInjectionStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		source          string
		wantArgsHits    int // expected violations from findUnsafeSQLArgs
		wantSprintfHits int // expected violations from findSprintfSQL
	}{
		{
			name: "fmt.Sprintf passed directly into Query",
			source: `package badstore
import "fmt"
func leak(db interface{ Query(ctx any, sql string, args ...any) }, userID string) {
	db.Query(nil, fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID))
}`,
			wantArgsHits:    1, // the CallExpr handed to Query is not a constant
			wantSprintfHits: 1, // the Sprintf literal contains SELECT/WHERE/FROM
		},
		{
			name: "Sprintf result stored in a local var, then passed to Exec",
			source: `package badstore
import "fmt"
func leak(db interface{ Exec(ctx any, sql string, args ...any) }, schema string) {
	q := fmt.Sprintf("UPDATE %s SET x = 1", schema)
	db.Exec(nil, q)
}`,
			wantArgsHits:    1, // Ident q is not in the const set
			wantSprintfHits: 1, // Sprintf literal contains UPDATE
		},
		{
			name: "Concatenation with a non-const string variable",
			source: `package badstore
func leak(db interface{ QueryRow(ctx any, sql string, args ...any) }, where string) {
	db.QueryRow(nil, "SELECT * FROM users WHERE " + where)
}`,
			wantArgsHits:    1, // the right-hand side of + is a non-const Ident
			wantSprintfHits: 0,
		},
		{
			name: "string(x) conversion as SQL",
			source: `package badstore
type rawSQL []byte
func leak(db interface{ Query(ctx any, sql string, args ...any) }, b rawSQL) {
	db.Query(nil, string(b))
}`,
			wantArgsHits:    1, // CallExpr (string conversion is parsed as a CallExpr)
			wantSprintfHits: 0,
		},
		{
			name: "method-call result as SQL",
			source: `package badstore
type builder struct{}
func (b builder) Build() string { return "" }
func leak(db interface{ Exec(ctx any, sql string, args ...any) }, b builder) {
	db.Exec(nil, b.Build())
}`,
			wantArgsHits:    1, // CallExpr from method invocation
			wantSprintfHits: 0,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse synthetic source: %v", err)
			}
			gotArgs := findUnsafeSQLArgs(fset, file)
			if len(gotArgs) != tc.wantArgsHits {
				t.Errorf("findUnsafeSQLArgs: got %d hits, want %d. Hits:\n  %s",
					len(gotArgs), tc.wantArgsHits, strings.Join(gotArgs, "\n  "))
			}
			gotSprintf := findSprintfSQL(fset, file)
			if len(gotSprintf) != tc.wantSprintfHits {
				t.Errorf("findSprintfSQL: got %d hits, want %d. Hits:\n  %s",
					len(gotSprintf), tc.wantSprintfHits, strings.Join(gotSprintf, "\n  "))
			}
		})
	}
}

// findUnsafeSQLArgs walks file's AST and returns one diagnostic string per
// .Exec/.Query/.QueryRow call whose SQL argument is not a constant-string
// expression. An empty return means file is clean.
//
// One exemption: the methods on (*Tx) that define the Querier surface
// (`(*Tx).Exec`, `(*Tx).Query`, `(*Tx).QueryRow`) are by design thin
// pass-through wrappers that forward a SQL string parameter to pgx; the SQL
// safety contract is satisfied at the CALLERS of those methods, every one of
// which is itself a repository site this scan visits. Inside the wrapper
// itself, the SQL argument is — and must be — the function parameter named
// `sql`. The exemption is recognised structurally: the enclosing function
// declaration must be a method on `*Tx` whose name matches the call's method
// name. No other shape is exempt.
func findUnsafeSQLArgs(fset *token.FileSet, file *ast.File) []string {
	consts := collectStringConsts(file)
	var out []string

	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		exempt := isTxQuerierPassthrough(fd)
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Exec", "Query", "QueryRow":
			default:
				return true
			}
			// pgx-style signature: <receiver>.Method(ctx, sql, args...). The
			// SQL string is positional argument 1; we ignore any call with
			// fewer than two arguments (defensive — the real surface always
			// has at least the ctx + sql pair).
			if len(call.Args) < 2 {
				return true
			}
			if exempt && fd.Name != nil && fd.Name.Name == sel.Sel.Name {
				return true
			}
			sqlArg := call.Args[1]
			if isSafeSQLExpr(sqlArg, consts) {
				return true
			}
			pos := fset.Position(sqlArg.Pos())
			out = append(out, fmt.Sprintf(
				"%s:%d: %s.%s SQL argument is %s (not a constant string expression). "+
					"Build SQL with parameterized placeholders ($1, $2, …) and pass caller input as args; "+
					"never interpolate caller input into the SQL string.",
				pos.Filename, pos.Line,
				renderExpr(sel.X), sel.Sel.Name,
				describeExprKind(sqlArg)))
			return true
		})
	}
	return out
}

// isTxQuerierPassthrough reports whether fd is one of the three methods that
// define the Querier surface on `*Tx`. Those methods (`Exec`, `Query`,
// `QueryRow`) are pure forwarders: they accept a `sql string` parameter and
// hand it to pgx unchanged. They are the lone place in the store package
// where the SQL argument to a `.Exec`/`.Query`/`.QueryRow` invocation is
// legitimately a string parameter rather than a constant expression.
func isTxQuerierPassthrough(fd *ast.FuncDecl) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := star.X.(*ast.Ident)
	if !ok || id.Name != "Tx" {
		return false
	}
	if fd.Name == nil {
		return false
	}
	switch fd.Name.Name {
	case "Exec", "Query", "QueryRow":
		return true
	}
	return false
}

// findSprintfSQL walks file's AST and returns one diagnostic string per
// fmt.Sprintf / fmt.Sprint / fmt.Sprintln call whose first argument is a
// string literal containing SQL keywords. An empty return means file is clean.
func findSprintfSQL(fset *token.FileSet, file *ast.File) []string {
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "fmt" {
			return true
		}
		switch sel.Sel.Name {
		case "Sprintf", "Sprint", "Sprintln":
		default:
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if !sqlKeywordRe.MatchString(lit.Value) {
			return true
		}
		pos := fset.Position(call.Pos())
		out = append(out, fmt.Sprintf(
			"%s:%d: fmt.%s used to build a SQL string (matched literal %s). "+
				"SQL must be a static constant. Use parameterized placeholders ($1, $2, …) instead.",
			pos.Filename, pos.Line, sel.Sel.Name, lit.Value))
		return true
	})
	return out
}

// mustParseFile parses path with the test-friendly options and fails the
// test on a parse error.
func mustParseFile(t *testing.T, path string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fset, file
}

// isSafeSQLExpr reports whether e is a compile-time-constant string expression
// safe to pass as the SQL argument to a parameterized .Exec/.Query/.QueryRow
// call. The accepted shapes are deliberately narrow:
//
//   - a string literal (`"…"` or “ `…` “)
//   - an identifier referring to a package-level string const (see
//     collectStringConsts) — e.g. apiKeyColumns
//   - a parenthesised wrapper around a safe expression
//   - a binary + concatenation whose every operand is safe
//
// Anything else — fmt.Sprintf, string(x), method calls, variable identifiers
// that did not resolve as a string const, type assertions — is unsafe.
func isSafeSQLExpr(e ast.Expr, consts map[string]bool) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.STRING
	case *ast.Ident:
		return consts[v.Name]
	case *ast.ParenExpr:
		return isSafeSQLExpr(v.X, consts)
	case *ast.BinaryExpr:
		return v.Op == token.ADD &&
			isSafeSQLExpr(v.X, consts) &&
			isSafeSQLExpr(v.Y, consts)
	}
	return false
}

// collectStringConsts returns the set of const identifiers in file whose
// declared value is itself a safe SQL expression. Both package-level const
// declarations and function-local `const` blocks count — the language
// guarantees a `const` binding cannot be reassigned, so a const whose value
// is a compile-time string is a safe ingredient in a SQL expression
// regardless of where it is declared. The collection iterates to a fixed
// point so a const that references another const (e.g. `const a = "foo " + b`)
// resolves once b is known.
//
// `var` declarations are deliberately NOT collected: a `var` is mutable and a
// safe-SQL value today could be reassigned to caller input later, which would
// silently re-open the injection hole. Identifiers other than collected
// consts are unsafe — this catches a function parameter, a method receiver,
// or any other local variable being passed as a SQL string.
func collectStringConsts(file *ast.File) map[string]bool {
	type entry struct {
		name string
		val  ast.Expr
	}
	var pending []entry
	ast.Inspect(file, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			return true
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				pending = append(pending, entry{name.Name, vs.Values[i]})
			}
		}
		return true
	})
	consts := map[string]bool{}
	for {
		progress := false
		for _, e := range pending {
			if consts[e.name] {
				continue
			}
			if isSafeSQLExpr(e.val, consts) {
				consts[e.name] = true
				progress = true
			}
		}
		if !progress {
			return consts
		}
	}
}

// renderExpr pretty-prints an expression node for inclusion in diagnostics.
// Errors from the printer are squashed to a placeholder; this is best-effort.
func renderExpr(e ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, token.NewFileSet(), e); err != nil {
		return "<unprintable>"
	}
	return buf.String()
}

// describeExprKind returns a short, diagnostic-friendly label for an AST
// expression — the node type plus its rendered text. Used only by the failure
// path, so the cost of fmt-style reflection is acceptable.
func describeExprKind(e ast.Expr) string {
	rendered := renderExpr(e)
	if len(rendered) > 80 {
		rendered = rendered[:77] + "…"
	}
	return exprNodeKind(e) + " `" + rendered + "`"
}

// exprNodeKind maps each ast.Expr concrete type to its short name. The list
// covers every shape parser.ParseFile can produce. Anything unrecognised
// collapses to "ast.Expr" — informative enough for a diagnostic.
func exprNodeKind(e ast.Expr) string {
	switch e.(type) {
	case *ast.BadExpr:
		return "BadExpr"
	case *ast.Ident:
		return "Ident"
	case *ast.Ellipsis:
		return "Ellipsis"
	case *ast.BasicLit:
		return "BasicLit"
	case *ast.FuncLit:
		return "FuncLit"
	case *ast.CompositeLit:
		return "CompositeLit"
	case *ast.ParenExpr:
		return "ParenExpr"
	case *ast.SelectorExpr:
		return "SelectorExpr"
	case *ast.IndexExpr:
		return "IndexExpr"
	case *ast.IndexListExpr:
		return "IndexListExpr"
	case *ast.SliceExpr:
		return "SliceExpr"
	case *ast.TypeAssertExpr:
		return "TypeAssertExpr"
	case *ast.CallExpr:
		return "CallExpr"
	case *ast.StarExpr:
		return "StarExpr"
	case *ast.UnaryExpr:
		return "UnaryExpr"
	case *ast.BinaryExpr:
		return "BinaryExpr"
	case *ast.KeyValueExpr:
		return "KeyValueExpr"
	default:
		return "Expr"
	}
}

// sqlKeywordRe matches the bare-word SQL verbs and clauses that signal a
// string literal is being used to assemble a query. The match is whole-word
// and case-SENSITIVE — the codebase writes SQL keywords in uppercase
// (`SELECT`, `INSERT INTO`, `UPDATE …`), so lowercase prose like
// "transition from %s to %s" or "returning the value" is correctly excluded.
// A future regression that introduces lowercase SQL would slip past this
// check; the static-args check above catches it independently because the
// expression still cannot be const.
var sqlKeywordRe = regexp.MustCompile(`\b(SELECT\b|INSERT\s+INTO\b|UPDATE\s+\S|DELETE\s+FROM\b|UNION\b|FROM\s+\S|WHERE\b|JOIN\b|RETURNING\b|VALUES\s*\()`)

// nonTestStoreSourceFiles returns the list of non-test .go source files in
// the package directory in stable order. Subdirectories are skipped — the
// migration runner under store/migrate is a separate package with its own
// tests.
func nonTestStoreSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read store dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		t.Fatalf("no non-test .go files found in the store package — the static SQL injection guard is vacuous")
	}
	return out
}
