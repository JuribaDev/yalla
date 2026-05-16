package validate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"testing"
)

// JSON parser hardening — static-analysis defense (BE-0346).
//
// Threat model: `validate.DecodeJSON` is the single canonical entry point
// for decoding an untrusted JSON body into a typed Go value. Every mutating
// HTTP handler in the control plane reads its request through this one
// function (the body-size static analyzer in `httpapi` — BE-0345 — already
// rejects any handler that bypasses it). That centralisation is what makes
// the parser hardening contract enforceable: as long as `DecodeJSON` itself
// keeps its hardenings, every handler inherits them at zero cost.
//
// The hardenings are four AST-shaped, load-bearing invariants:
//
//  1. The reader is wrapped in `&limitedReader{...}` BEFORE being passed
//     to `json.NewDecoder`. An unwrapped reader lets an unbounded stream
//     reach the JSON parser (OOM, slow loris, deep nesting, runaway string).
//
//  2. The decoder calls `DisallowUnknownFields()` before `Decode`. Without
//     it, an attacker can stuff arbitrary keys into the body that silently
//     parse as no-ops — this is the classic schema-confusion vector
//     (mass-assignment, hidden-field smuggling, parameter spoofing under
//     proxies that mutate the payload).
//
//  3. After `Decode` succeeds, the function calls `dec.More()` and rejects
//     trailing data. A handler that accepts `{"a":1}{"a":2}` lets a
//     downstream consumer (a log forwarder, a cache, a WAF) see one value
//     while the API acts on another — classic JSON smuggling.
//
//  4. The error path renders via `decodeError(...)` which produces a
//     `apierr.Invalid` (E_INVALID_INPUT, HTTP 400) with a fixed-string
//     message. Anything else risks echoing the submitted body into the
//     response — a secret pasted into a malformed payload would leak
//     through a verbose `encoding/json` error.
//
// The two-test pattern (BE-0344, BE-0345) applies here verbatim. The static
// half (`TestDecodeJSONKeepsAllHardenings`, this file) parses `json.go`
// and asserts each invariant is present in `DecodeJSON`'s body — a future
// change that deletes the `DisallowUnknownFields` call, drops the trailing
// `dec.More()` check, removes the `&limitedReader{}` wrap, or stops
// routing errors through `decodeError` fails at build time, BEFORE any
// integration test has the chance to mask it. The runtime half lives in
// `validate_test.go::TestDecodeJSON` (an exhaustive table of the documented
// rejection modes) and in `internal/controlplane/httpapi/json_hardening_test.go`
// (end-to-end through `NewHandler` against `POST /v1/organizations`).
//
// Self-check: `TestDecodeJSONHardeningStaticAnalyzerDetectsRegressions`
// feeds known-bad and known-good DecodeJSON-shaped functions to the
// analyser and pins both directions — a regression that over-tightens the
// analyser (false positives) and a regression that under-tightens it
// (silently passes a missing hardening) are both caught.

// TestDecodeJSONKeepsAllHardenings is the load-bearing static guard. It
// parses `json.go` from disk, finds the `DecodeJSON` function declaration,
// and asserts the four hardenings are all syntactically present. Each
// missing hardening produces a single, named diagnostic.
func TestDecodeJSONKeepsAllHardenings(t *testing.T) {
	t.Parallel()
	fset, file := mustParseValidateFile(t, "json.go")
	decl := findFuncDecl(file, "DecodeJSON")
	if decl == nil {
		t.Fatalf("DecodeJSON not found in json.go — the JSON-hardening guard is vacuous")
	}
	missing := missingDecodeJSONHardenings(decl)
	for _, m := range missing {
		pos := fset.Position(decl.Pos())
		t.Errorf("%s:%d: DecodeJSON is missing required hardening: %s",
			pos.Filename, pos.Line, m)
	}
}

// TestDecodeJSONHardeningStaticAnalyzerDetectsRegressions is the
// self-check for the static analyser. It feeds synthetic DecodeJSON-shaped
// functions and asserts the analyser fires on known-bad shapes (one
// missing hardening per case) and stays silent on the known-good shape.
//
// The synthetic sources are parsed from strings rather than written to
// disk so the bad code can never compile, import, or ship.
func TestDecodeJSONHardeningStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	const goodSource = `package validate
import (
	"encoding/json"
	"io"
)
type limitedReader struct{ r io.Reader; remaining int64 }
func decodeError(err error) error { return err }
func DecodeJSON(r io.Reader, dst any, maxBytes int64) error {
	if maxBytes <= 0 { maxBytes = 1 }
	dec := json.NewDecoder(&limitedReader{r: r, remaining: maxBytes + 1})
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil { return decodeError(err) }
	if dec.More() { return decodeError(io.EOF) }
	return nil
}`

	cases := []struct {
		name        string
		source      string
		wantMissing []string
	}{
		{
			name:        "canonical hardened DecodeJSON has no missing hardenings",
			source:      goodSource,
			wantMissing: nil,
		},
		{
			name: "missing limitedReader wrap on the reader",
			source: `package validate
import (
	"encoding/json"
	"io"
)
func decodeError(err error) error { return err }
func DecodeJSON(r io.Reader, dst any, maxBytes int64) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil { return decodeError(err) }
	if dec.More() { return decodeError(io.EOF) }
	return nil
}`,
			wantMissing: []string{
				"reader is not wrapped in `&limitedReader{...}` before `json.NewDecoder` (the body-size cap)",
			},
		},
		{
			name: "missing DisallowUnknownFields call",
			source: `package validate
import (
	"encoding/json"
	"io"
)
type limitedReader struct{ r io.Reader; remaining int64 }
func decodeError(err error) error { return err }
func DecodeJSON(r io.Reader, dst any, maxBytes int64) error {
	dec := json.NewDecoder(&limitedReader{r: r, remaining: maxBytes + 1})
	if err := dec.Decode(dst); err != nil { return decodeError(err) }
	if dec.More() { return decodeError(io.EOF) }
	return nil
}`,
			wantMissing: []string{
				"`DisallowUnknownFields()` is not called on the decoder (mass-assignment / schema-confusion defence)",
			},
		},
		{
			name: "missing dec.More() trailing-data check",
			source: `package validate
import (
	"encoding/json"
	"io"
)
type limitedReader struct{ r io.Reader; remaining int64 }
func decodeError(err error) error { return err }
func DecodeJSON(r io.Reader, dst any, maxBytes int64) error {
	dec := json.NewDecoder(&limitedReader{r: r, remaining: maxBytes + 1})
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil { return decodeError(err) }
	return nil
}`,
			wantMissing: []string{
				"`dec.More()` trailing-data check is not invoked after Decode (JSON-smuggling defence)",
			},
		},
		{
			name: "errors not routed through decodeError",
			source: `package validate
import (
	"encoding/json"
	"io"
)
type limitedReader struct{ r io.Reader; remaining int64 }
func DecodeJSON(r io.Reader, dst any, maxBytes int64) error {
	dec := json.NewDecoder(&limitedReader{r: r, remaining: maxBytes + 1})
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil { return err }
	if dec.More() { return io.EOF }
	return nil
}`,
			wantMissing: []string{
				"error path does not flow through `decodeError(...)` (body-echo / secret-leak defence)",
			},
		},
		{
			name: "all four hardenings missing — every diagnostic fires",
			source: `package validate
import (
	"encoding/json"
	"io"
)
func DecodeJSON(r io.Reader, dst any, maxBytes int64) error {
	dec := json.NewDecoder(r)
	if err := dec.Decode(dst); err != nil { return err }
	return nil
}`,
			wantMissing: []string{
				"`DisallowUnknownFields()` is not called on the decoder (mass-assignment / schema-confusion defence)",
				"`dec.More()` trailing-data check is not invoked after Decode (JSON-smuggling defence)",
				"error path does not flow through `decodeError(...)` (body-echo / secret-leak defence)",
				"reader is not wrapped in `&limitedReader{...}` before `json.NewDecoder` (the body-size cap)",
			},
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
			decl := findFuncDecl(file, "DecodeJSON")
			if decl == nil {
				t.Fatalf("synthetic source has no DecodeJSON function")
			}
			got := missingDecodeJSONHardenings(decl)
			sort.Strings(got)
			want := append([]string(nil), tc.wantMissing...)
			sort.Strings(want)
			if !equalStringSlices(got, want) {
				t.Errorf("missingDecodeJSONHardenings:\n  got:  %v\n  want: %v", got, want)
			}
		})
	}
}

// missingDecodeJSONHardenings inspects the body of a DecodeJSON-shaped
// function declaration and returns one diagnostic per missing hardening.
// The four hardenings are:
//
//  1. `json.NewDecoder(&limitedReader{...})` — the reader is wrapped in
//     the explicit-cap reader BEFORE the decoder sees it.
//  2. `<dec>.DisallowUnknownFields()` — the decoder rejects extra fields.
//  3. `<dec>.More()` — a post-Decode trailing-data check exists.
//  4. `decodeError(<x>)` — the error path is funnelled through the
//     fixed-message renderer that prevents body echo.
//
// The checks are syntactic (AST-shape), not semantic, so they catch the
// shape of the hardening regression without requiring a typechecker. The
// receiver of the `DisallowUnknownFields`/`More` calls is intentionally
// not pinned to the literal name `dec` — a future rename of the local is
// fine, the analyser only requires the method names to be present.
func missingDecodeJSONHardenings(decl *ast.FuncDecl) []string {
	var (
		sawLimitedReaderWrap     bool
		sawDisallowUnknownFields bool
		sawMoreCheck             bool
		sawDecodeErrorCall       bool
	)

	ast.Inspect(decl, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			// Selector-style calls: `json.NewDecoder(...)`,
			// `<dec>.DisallowUnknownFields()`, `<dec>.More()`.
			if pkg, ok := fun.X.(*ast.Ident); ok && pkg.Name == "json" && fun.Sel.Name == "NewDecoder" {
				if len(call.Args) == 1 && isAddressOfLimitedReader(call.Args[0]) {
					sawLimitedReaderWrap = true
				}
			}
			if fun.Sel.Name == "DisallowUnknownFields" && len(call.Args) == 0 {
				sawDisallowUnknownFields = true
			}
			if fun.Sel.Name == "More" && len(call.Args) == 0 {
				sawMoreCheck = true
			}
		case *ast.Ident:
			// Plain-identifier call: `decodeError(err)`.
			if fun.Name == "decodeError" {
				sawDecodeErrorCall = true
			}
		}
		return true
	})

	var out []string
	if !sawDisallowUnknownFields {
		out = append(out, "`DisallowUnknownFields()` is not called on the decoder (mass-assignment / schema-confusion defence)")
	}
	if !sawMoreCheck {
		out = append(out, "`dec.More()` trailing-data check is not invoked after Decode (JSON-smuggling defence)")
	}
	if !sawDecodeErrorCall {
		out = append(out, "error path does not flow through `decodeError(...)` (body-echo / secret-leak defence)")
	}
	if !sawLimitedReaderWrap {
		out = append(out, "reader is not wrapped in `&limitedReader{...}` before `json.NewDecoder` (the body-size cap)")
	}
	sort.Strings(out)
	return out
}

// isAddressOfLimitedReader reports whether expr matches the AST shape
// `&limitedReader{...}`. Wrapping the raw reader in this struct is what
// gives the parser the explicit byte-cap defence; an unwrapped reader
// silently re-opens the OOM surface.
func isAddressOfLimitedReader(expr ast.Expr) bool {
	unary, ok := expr.(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return false
	}
	composite, ok := unary.X.(*ast.CompositeLit)
	if !ok {
		return false
	}
	id, ok := composite.Type.(*ast.Ident)
	if !ok {
		return false
	}
	return id.Name == "limitedReader"
}

// findFuncDecl returns the top-level function declaration named name, or
// nil if not present.
func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name != nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// mustParseValidateFile parses path under the validate package and fails
// the test on a parse error. Mirrors `mustParseHTTPAPIFile` (BE-0345) so
// each security-verification static analyser uses the same shape for
// loading its own package's sources.
func mustParseValidateFile(t *testing.T, path string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fset, file
}

// equalStringSlices is a tiny order-sensitive comparator for the analyser
// self-checks. Both inputs are pre-sorted by the caller, so order
// sensitivity here means content equality. Using a hand-rolled comparator
// keeps this static-test file free of new package dependencies.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
