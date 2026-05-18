package httpapi

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Request body size limits — static-analysis defense (BE-0345).
//
// Threat model: an unauthenticated or authenticated attacker submits a
// request body of unbounded size (tens of megabytes, gigabytes, or a slow
// loris streaming body) to a JSON-decoding handler. Without a cap on the
// read, the handler will either (a) exhaust process memory and crash the
// API, (b) monopolise a request-handling goroutine for an arbitrary time,
// or (c) trip a panic deep in encoding/json or a downstream parser. The
// control is "every handler that touches `r.Body` either reads it through
// `validate.DecodeJSON` (which caps at `DefaultMaxBodyBytes = 1 MiB` and
// surfaces oversize as a typed `apierr.Invalid`) or through
// `io.LimitReader(r.Body, <cap+1>)` followed by a bounded `io.ReadAll` (the
// shape used by the idempotency middleware to hash the request before
// dispatching the wrapped handler)."
//
// These tests are the regression backstop. They run without a database and
// fail at build time for any change that breaks the invariant — e.g.
// introducing `json.NewDecoder(r.Body).Decode(&req)` or
// `io.ReadAll(r.Body)` (without a `LimitReader` wrap) into a handler. They
// scan every non-test Go source file in the `httpapi` package directory; a
// regression in the idempotency middleware (which legitimately needs a
// pre-decode buffered read) is caught by the structural check on the wrap
// shape itself, not by an opaque allowlist.
//
// The companion runtime test, `body_size_test.go`, exercises the same
// invariant end-to-end through `NewHandler` against a real `POST
// /v1/organizations` request — an oversized body is a stable 400
// `E_VALIDATION` with the canonical "exceeds the maximum allowed size"
// message and the orchestrator is never reached.

// TestRequestBodyAccessIsAlwaysSizeBounded walks every non-test .go file in
// this package and verifies every reference to `r.Body` / `req.Body` /
// `request.Body` sits inside one of the deliberately narrow allowed shapes
// (see `findUnsafeRequestBodyAccesses`). Anything else — a `json.NewDecoder`
// on the body, an unbounded `io.ReadAll`, a `bufio.NewReader` wrap, a raw
// return of the body, a struct field that captures the body, a type
// assertion on the body — is rejected with the file:line of the offending
// selector and a remediation hint.
func TestRequestBodyAccessIsAlwaysSizeBounded(t *testing.T) {
	t.Parallel()
	for _, path := range nonTestHTTPAPISourceFiles(t) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			fset, file := mustParseHTTPAPIFile(t, path)
			for _, v := range findUnsafeRequestBodyAccesses(fset, file) {
				t.Error(v)
			}
		})
	}
}

// TestRequestBodyStaticAnalyzerDetectsRegressions is the self-check for the
// static analyzer above. The acceptance criterion "tests fail when the
// control is removed" is the load-bearing one for this story: a future
// change that re-opens the size-cap invariant must visibly fail a test.
// Here we synthesize a handful of known-bad source snippets — direct
// `json.NewDecoder(r.Body)`, unbounded `io.ReadAll(r.Body)`, `bufio.NewReader`
// wrap, a struct that captures the raw body, a return of the body, a type
// assertion on the body — and assert the analyzer reports each one. If the
// analyzer is ever weakened, the regression detector itself fails to fail
// and this test catches it.
//
// We parse from a string rather than from disk so the bad code never lives
// in the repository — it cannot be accidentally compiled, imported, or
// shipped. Allowed-shape positive cases are also asserted (no violations) so
// a future change that over-tightens the analyzer is caught too.
func TestRequestBodyStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		source   string
		wantHits int
	}{
		{
			name: "json.NewDecoder on r.Body is unsafe",
			source: `package badhandler
import (
	"encoding/json"
	"net/http"
)
func handle(w http.ResponseWriter, r *http.Request) {
	var req struct{ A string }
	_ = json.NewDecoder(r.Body).Decode(&req)
}`,
			wantHits: 1,
		},
		{
			name: "io.ReadAll on r.Body without LimitReader is unsafe",
			source: `package badhandler
import (
	"io"
	"net/http"
)
func handle(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
}`,
			wantHits: 1,
		},
		{
			name: "bufio.NewReader on r.Body is unsafe",
			source: `package badhandler
import (
	"bufio"
	"net/http"
)
func handle(w http.ResponseWriter, r *http.Request) {
	_ = bufio.NewReader(r.Body)
}`,
			wantHits: 1,
		},
		{
			name: "capturing r.Body in a struct literal is unsafe",
			source: `package badhandler
import (
	"io"
	"net/http"
)
type caps struct{ R io.Reader }
func handle(w http.ResponseWriter, r *http.Request) {
	_ = caps{R: r.Body}
}`,
			wantHits: 1,
		},
		{
			name: "returning r.Body up the stack is unsafe",
			source: `package badhandler
import (
	"io"
	"net/http"
)
func handle(r *http.Request) io.ReadCloser { return r.Body }`,
			wantHits: 1,
		},
		{
			name: "rebinding r.Body to a local on the RHS is unsafe",
			source: `package badhandler
import (
	"io"
	"net/http"
)
func handle(w http.ResponseWriter, r *http.Request) {
	body := r.Body
	_, _ = io.ReadAll(body)
}`,
			wantHits: 1, // the r.Body on the RHS — the io.ReadAll(body) takes 'body', not r.Body, so it's not a Body selector itself
		},
		{
			name: "io.Copy from r.Body without a LimitReader is unsafe",
			source: `package badhandler
import (
	"io"
	"net/http"
)
func handle(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
}`,
			wantHits: 1,
		},
		{
			name: "type assertion on r.Body is unsafe",
			source: `package badhandler
import (
	"bytes"
	"net/http"
)
func handle(w http.ResponseWriter, r *http.Request) {
	_, _ = r.Body.(*bytes.Buffer)
}`,
			wantHits: 1,
		},
		{
			name: "validate.DecodeJSON(r.Body, ...) is the canonical allowed shape",
			source: `package goodhandler
import (
	"net/http"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)
func handle(w http.ResponseWriter, r *http.Request) {
	var req struct{ A string }
	_ = validate.DecodeJSON(r.Body, &req, 0)
}`,
			wantHits: 0,
		},
		{
			name: "io.LimitReader(r.Body, cap)+io.ReadAll is the allowed wrap shape (idempotency middleware)",
			source: `package goodhandler
import (
	"bytes"
	"io"
	"net/http"
)
const maxBody = 1 << 20
func handle(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		return
	}
	limited := io.LimitReader(r.Body, maxBody+1)
	buf, _ := io.ReadAll(limited)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf))
}`,
			wantHits: 0,
		},
		{
			name: "nil-compare on r.Body is allowed",
			source: `package goodhandler
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
}`,
			wantHits: 0,
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
			got := findUnsafeRequestBodyAccesses(fset, file)
			if len(got) != tc.wantHits {
				t.Errorf("findUnsafeRequestBodyAccesses: got %d hits, want %d. Hits:\n  %s",
					len(got), tc.wantHits, strings.Join(got, "\n  "))
			}
		})
	}
}

// requestBodyReceiverNames is the closed set of identifier names this package
// uses for the `*http.Request` parameter of a handler. The analyzer ignores
// `<other>.Body` selectors so an unrelated struct field named `Body` (e.g.
// `http.Response.Body`, `mail.Message.Body`) does not produce a spurious
// diagnostic. The codebase convention is uniform — every handler in
// `httpapi` declares the parameter as `r *http.Request` — so the set is
// deliberately tight; the `req`/`request` aliases are reserved for future
// drift and keep the analyzer robust to a rename.
var requestBodyReceiverNames = map[string]bool{
	"r":       true,
	"req":     true,
	"request": true,
}

// findUnsafeRequestBodyAccesses walks file's AST and returns one diagnostic
// per `<r>.Body` / `<req>.Body` / `<request>.Body` selector that is NOT in
// one of the deliberately narrow allowed shapes:
//
//  1. Argument 0 of `validate.DecodeJSON(<r>.Body, &dst, max)` — the
//     canonical body decoder, which caps the read at
//     `validate.DefaultMaxBodyBytes` (1 MiB) and rejects an oversized body
//     as a typed `apierr.Invalid` (E_VALIDATION).
//  2. Argument 0 of `io.LimitReader(<r>.Body, <cap>)` — the explicit
//     bounded-wrap shape the idempotency middleware uses to hash the
//     request body before dispatching the wrapped handler. The subsequent
//     `io.ReadAll` reads from the `LimitReader`, not from `<r>.Body`
//     directly, so the cap is structurally enforced.
//  3. Comparison to `nil`: `<r>.Body == nil` / `<r>.Body != nil` (and the
//     symmetric `nil == <r>.Body` / `nil != <r>.Body`). A handler that
//     decides whether to read at all does not bypass the cap.
//  4. Left-hand side of an assignment: `<r>.Body = <expr>`. The idempotency
//     middleware restores the body after buffering via
//     `r.Body = io.NopCloser(bytes.NewReader(buf))`; the wrapped handler
//     then reads the restored body which is still bounded because `buf`
//     itself is.
//  5. Receiver of a `.Close()` method call: `<r>.Body.Close()` (with zero
//     args). Closing an `io.ReadCloser` is structurally bounded — `Close`
//     does not read.
//
// An empty return means the file is clean. The diagnostics are sorted so
// the output is deterministic across parallel parses.
func findUnsafeRequestBodyAccesses(fset *token.FileSet, file *ast.File) []string {
	// Pass 1: collect every `<receiver>.Body` selector position we care
	// about.
	bodyPositions := map[token.Pos]ast.Expr{}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Body" {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if !requestBodyReceiverNames[id.Name] {
			return true
		}
		bodyPositions[sel.Pos()] = sel
		return true
	})

	// Pass 2: mark every Body position that appears in an allowed shape.
	allowed := map[token.Pos]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			markAllowedInCall(v, bodyPositions, allowed)
		case *ast.BinaryExpr:
			markAllowedInBinaryNilCmp(v, bodyPositions, allowed)
		case *ast.AssignStmt:
			markAllowedInAssignLHS(v, bodyPositions, allowed)
		}
		return true
	})

	// Pass 3: diagnose every remaining Body position.
	var out []string
	for pos, expr := range bodyPositions {
		if allowed[pos] {
			continue
		}
		position := fset.Position(pos)
		out = append(out, fmt.Sprintf(
			"%s:%d: request body access %q is not size-bounded. "+
				"Decode JSON bodies through validate.DecodeJSON (which caps at "+
				"validate.DefaultMaxBodyBytes), or wrap the read in "+
				"io.LimitReader(r.Body, <cap+1>) and io.ReadAll the limited "+
				"reader. An unbounded read lets an attacker OOM the API with a "+
				"single request.",
			position.Filename, position.Line, renderBodyExpr(expr)))
	}
	sort.Strings(out)
	return out
}

// markAllowedInCall marks the `<r>.Body` Body-selector positions allowed by
// a CallExpr whose function selector matches one of the canonical
// size-bounded body APIs.
func markAllowedInCall(call *ast.CallExpr, bodies map[token.Pos]ast.Expr, allowed map[token.Pos]bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}
	// Pattern: `<pkg>.<func>(<r>.Body, ...)` — accepted when (pkg, func)
	// names one of the canonical body APIs.
	if pkg, ok := sel.X.(*ast.Ident); ok && len(call.Args) >= 1 {
		switch {
		case pkg.Name == "validate" && sel.Sel.Name == "DecodeJSON",
			pkg.Name == "io" && sel.Sel.Name == "LimitReader":
			markIfBody(call.Args[0], bodies, allowed)
		}
	}
	// Pattern: `<r>.Body.Close()` — call expression on a Body selector
	// whose method name is Close and which takes no arguments.
	if sel.Sel.Name == "Close" && len(call.Args) == 0 {
		markIfBody(sel.X, bodies, allowed)
	}
}

// markAllowedInBinaryNilCmp marks Body selector positions that appear as one
// side of an `==`/`!=` comparison whose other operand is the predeclared
// `nil`. A handler that decides whether to read at all does not bypass the
// cap.
func markAllowedInBinaryNilCmp(bin *ast.BinaryExpr, bodies map[token.Pos]ast.Expr, allowed map[token.Pos]bool) {
	if bin.Op != token.EQL && bin.Op != token.NEQ {
		return
	}
	if id, ok := bin.Y.(*ast.Ident); ok && id.Name == "nil" {
		markIfBody(bin.X, bodies, allowed)
	}
	if id, ok := bin.X.(*ast.Ident); ok && id.Name == "nil" {
		markIfBody(bin.Y, bodies, allowed)
	}
}

// markAllowedInAssignLHS marks Body selectors that appear on the LHS of an
// assignment. The idempotency middleware restores `r.Body` after buffering
// the request for hashing; the wrapped handler then reads the restored
// body, which is structurally bounded because the bytes themselves are.
func markAllowedInAssignLHS(assn *ast.AssignStmt, bodies map[token.Pos]ast.Expr, allowed map[token.Pos]bool) {
	for _, lhs := range assn.Lhs {
		markIfBody(lhs, bodies, allowed)
	}
}

// markIfBody flips an entry in `allowed` when expr is a Body selector we
// previously recorded.
func markIfBody(expr ast.Expr, bodies map[token.Pos]ast.Expr, allowed map[token.Pos]bool) {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return
	}
	if _, exists := bodies[sel.Pos()]; exists {
		allowed[sel.Pos()] = true
	}
}

// renderBodyExpr renders a `<r>.Body` selector for inclusion in a
// diagnostic; the canonical form `<ident>.Body` reads cleanly in test
// output.
func renderBodyExpr(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "<unknown>"
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "." + sel.Sel.Name
	}
	return id.Name + "." + sel.Sel.Name
}

// mustParseHTTPAPIFile parses path with the test-friendly options and fails
// the test on a parse error.
func mustParseHTTPAPIFile(t *testing.T, path string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fset, file
}

// nonTestHTTPAPISourceFiles returns the non-test .go files in the httpapi
// package directory in stable order. Subdirectories are skipped — the only
// nested package today is the OpenAPI spec generator and it has no HTTP
// handlers.
func nonTestHTTPAPISourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read httpapi dir: %v", err)
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
		t.Fatalf("no non-test .go files found in the httpapi package — the static request-body-size guard is vacuous")
	}
	return out
}
