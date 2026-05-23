package variables_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Environment-variable redaction — static-analysis defense (BE-0360).
//
// Threat model: a customer-supplied environment variable can carry a
// production secret (database password, third-party API key, signing key,
// session token). The variables package is the single place that holds the
// plaintext of every scope's environment variable while it is being merged
// for a Dokploy render. A regression that lets a raw plaintext or sealed
// ciphertext escape the package via a slog record, a customer-facing JSON
// envelope, an error message, or an apierr.FieldViolation reason would land
// the secret in operator logs, customer-facing API responses, or the
// audit ring buffer — all of which are effectively persisted (log shippers,
// on-call dashboards, post-incident transcripts forward the byte).
//
// The control is the package's three structural redaction seams:
//
//   1. (ScopedVariable).LogValue, (Rendered).LogValue, (Resolved).LogValue —
//      the slog.LogValuer hooks that replace plaintext/ciphertext-bearing
//      fields with output.Sentinel before slog reflects the struct.
//   2. (Resolved).Explain — the customer-facing projection whose
//      ExplainedVariable.Value is always output.Sentinel.
//   3. The error / apierr surfaces — no error message, no
//      apierr.FieldViolation reason, no apierr.Internal/apierr.SecretDecryption
//      wrapped error may
//      interpolate a `.Value` or `.SecretCiphertext` selector, nor a local
//      identifier named `plaintext`.
//
// These tests are the regression backstop. They scan every non-test .go
// source file in this package directory and fail at build time for any
// change that breaks one of the seams — e.g. dropping `output.Sentinel`
// from `LogValue`, adding a new `ExplainedVariable{...}` composite literal
// that copies `Value:` from the rendered row, or rewriting a customer-facing
// error to `fmt.Errorf("could not open %q", v.Value)`.
//
// The companion runtime test, env_var_redaction_test.go, exercises the same
// invariant end-to-end with a hostile-value fuzz seed corpus that proves the
// redaction holds for control characters, sentinel-overlap, regex
// metacharacters, and the marker-bracket leak detector borrowed from the
// BE-0359 log-redaction fuzz suite.

// redactingTypes is the closed set of package-local types whose LogValue
// methods are load-bearing for the env-var redaction contract. Adding a new
// type that carries a plaintext or ciphertext column MUST extend this set
// and provide a matching LogValue redaction, otherwise the rule below is
// vacuous for that type.
var redactingTypes = []string{
	"ScopedVariable",
	"Rendered",
	"Resolved",
}

// forbiddenFieldNames is the closed set of selectors that, when fed into a
// string-forming or log-emitting call, would surface a plaintext or
// ciphertext byte. Both the slog-side checks and the error-formatting
// checks consult this list.
var forbiddenFieldNames = map[string]bool{
	"Value":            true,
	"SecretCiphertext": true,
}

// forbiddenIdentNames is the closed set of local identifier names this
// package uses for already-Opened plaintext bytes. A future Sprintf /
// Errorf / errors.New / apierr call MUST NOT pass one of these idents.
var forbiddenIdentNames = map[string]bool{
	"plaintext": true,
}

// errorFormingFuncs is the closed set of (package, function) pairs whose
// arguments are forbidden to carry a `.Value` / `.SecretCiphertext` /
// `plaintext` interpolation. The set is deliberately small: a future
// regression that reaches for a new error-forming helper would either pass
// the static check (if the helper does not produce a customer-visible
// string) or land a new entry here.
var errorFormingFuncs = map[string]map[string]bool{
	"fmt": {
		"Errorf":   true,
		"Sprintf":  true,
		"Sprint":   true,
		"Sprintln": true,
	},
	"errors": {
		"New": true,
	},
	"apierr": {
		"Internal":         true,
		"SecretDecryption": true,
		"InvalidInput":     true,
		"NotFound":         true,
		"Conflict":         true,
	},
}

// errorFormingCompositeLitFields is the set of (struct-type, field-name)
// pairs whose value expression must not carry a forbidden selector. The
// field is one a customer or operator will read in an error envelope.
var errorFormingCompositeLitFields = map[string]map[string]bool{
	"FieldViolation": {
		"Reason": true,
		"Field":  true,
	},
}

// TestRedactionLogValueMethodsReferenceSentinel walks every non-test .go
// file in the variables package and verifies that each of the closed-set
// LogValue methods exists AND mentions output.Sentinel at least once. This
// is rule (1) of the static control: the slog.LogValuer hook is the only
// thing standing between a stray `slog.Info("v", v)` and a plaintext leak,
// so a LogValue body that loses the sentinel reference is a regression.
func TestRedactionLogValueMethodsReferenceSentinel(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for _, path := range nonTestVariablesSourceFiles(t) {
		fset, file := mustParseVariablesFile(t, path)
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name.Name != "LogValue" {
				continue
			}
			recv := receiverTypeName(fd)
			if !contains(redactingTypes, recv) {
				continue
			}
			seen[recv] = true
			if !bodyReferencesSelector(fd.Body, "output", "Sentinel") {
				pos := fset.Position(fd.Pos())
				t.Errorf("%s:%d: (%s).LogValue does not reference output.Sentinel — "+
					"the slog redaction seam has been removed",
					filepath.Base(pos.Filename), pos.Line, recv)
			}
			for _, sel := range bodyForbiddenSelectors(fd.Body, recv, fd) {
				pos := fset.Position(sel.Pos())
				t.Errorf("%s:%d: (%s).LogValue emits forbidden selector %s — "+
					"plaintext/ciphertext must be replaced by output.Sentinel",
					filepath.Base(pos.Filename), pos.Line, recv, renderVariablesExpr(sel))
			}
		}
	}
	for _, want := range redactingTypes {
		if !seen[want] {
			t.Errorf("(%s).LogValue method not found in package source — the redaction "+
				"seam is missing and the static guard is vacuous", want)
		}
	}
}

// TestRedactionExplainedVariableLiteralsRedactValue walks every non-test .go
// file in the variables package and verifies that every
// `ExplainedVariable{...}` composite literal sets `Value:` to
// `output.Sentinel`. This is rule (2) of the static control: the customer-
// facing projection is the only struct in this package that carries a
// per-key value field in a customer-visible JSON envelope, and the test
// pins the contract documented on Resolved.Explain.
func TestRedactionExplainedVariableLiteralsRedactValue(t *testing.T) {
	t.Parallel()

	found := false
	for _, path := range nonTestVariablesSourceFiles(t) {
		fset, file := mustParseVariablesFile(t, path)
		ast.Inspect(file, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if compositeLitTypeName(cl) != "ExplainedVariable" {
				return true
			}
			found = true
			valueExpr, present := compositeLitField(cl, "Value")
			if !present {
				pos := fset.Position(cl.Pos())
				t.Errorf("%s:%d: ExplainedVariable composite literal omits Value — "+
					"the field is required and must be set to output.Sentinel",
					filepath.Base(pos.Filename), pos.Line)
				return true
			}
			if !isOutputSentinelExpr(valueExpr) {
				pos := fset.Position(valueExpr.Pos())
				t.Errorf("%s:%d: ExplainedVariable.Value is %s — must be output.Sentinel",
					filepath.Base(pos.Filename), pos.Line, renderVariablesExpr(valueExpr))
			}
			return true
		})
	}
	if !found {
		t.Fatalf("no ExplainedVariable composite literal found in package source — the " +
			"customer-facing projection has been removed and the static guard is vacuous",
		)
	}
}

// TestRedactionNoPlaintextInErrorSurface walks every non-test .go file in
// the variables package and rejects any call to one of the closed-set
// error-forming helpers (fmt.Sprintf/Errorf/..., errors.New, apierr.*) or
// any composite-literal field marked as a customer-readable reason whose
// argument is a forbidden selector (`<x>.Value` / `<x>.SecretCiphertext`) or
// the local identifier `plaintext`. This is rule (3) of the static control:
// even when LogValue and Explain are intact, a regression that wraps the
// Open failure as `fmt.Errorf("could not open %q", v.Value)` would leak the
// plaintext through the apierr.Internal/apierr.SecretDecryption cause chain
// into operator logs.
func TestRedactionNoPlaintextInErrorSurface(t *testing.T) {
	t.Parallel()

	for _, path := range nonTestVariablesSourceFiles(t) {
		fset, file := mustParseVariablesFile(t, path)
		for _, v := range findPlaintextLeaks(fset, file) {
			t.Error(v)
		}
	}
}

// TestRedactionStaticAnalyzerDetectsRegressions is the self-check for the
// three analyzers above. The acceptance criterion "tests fail when the
// control is removed" is the load-bearing one for this story: a future
// change that re-opens any of the three redaction seams must visibly fail
// a test. Here we synthesize known-bad and known-good source snippets and
// assert each analyzer reports the violation (or, for positive cases,
// remains silent). If an analyzer is ever weakened, the regression
// detector itself fails to fail and this test catches it.
//
// The bad/good source lives in this test file rather than on disk so the
// snippets cannot be accidentally compiled, imported, or shipped.
func TestRedactionStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		source            string
		wantLogValueHits  int // missing-sentinel LogValue methods
		wantForbiddenLog  int // forbidden-selector LogValue methods
		wantExplainedHits int // ExplainedVariable composite-literal violations
		wantLeakHits      int // findPlaintextLeaks violations
	}{
		{
			name: "ScopedVariable.LogValue drops output.Sentinel",
			source: `package variables
import "log/slog"
type ScopedVariable struct{ Value string }
func (v ScopedVariable) LogValue() slog.Value {
	return slog.GroupValue(slog.String("value", v.Value))
}`,
			wantLogValueHits: 1, // missing output.Sentinel
			wantForbiddenLog: 1, // v.Value is a forbidden selector
		},
		{
			name: "Rendered.LogValue keeps sentinel but also emits Value",
			source: `package variables
import "log/slog"
type Rendered struct{ Value string }
const Sentinel = "[REDACTED]"
type outputT struct{}
var output struct{ Sentinel string } = struct{ Sentinel string }{Sentinel: "[REDACTED]"}
func (r Rendered) LogValue() slog.Value {
	return slog.GroupValue(slog.String("value", output.Sentinel), slog.String("leak", r.Value))
}`,
			wantForbiddenLog: 1, // r.Value used alongside Sentinel
		},
		{
			name: "ExplainedVariable composite uses row Value instead of Sentinel",
			source: `package variables
type ExplainedVariable struct{ Value string }
type Rendered struct{ Value string }
func leak(r Rendered) ExplainedVariable {
	return ExplainedVariable{Value: r.Value}
}`,
			wantExplainedHits: 1, // Value: r.Value
			wantLeakHits:      0, // no error-forming call
		},
		{
			name: "ExplainedVariable composite omits Value entirely",
			source: `package variables
type ExplainedVariable struct{ Value string; Key string }
func leak() ExplainedVariable {
	return ExplainedVariable{Key: "API_KEY"}
}`,
			wantExplainedHits: 1, // missing Value field
		},
		{
			name: "fmt.Errorf interpolates raw .Value",
			source: `package variables
import "fmt"
type Rendered struct{ Value string }
func leak(r Rendered) error {
	return fmt.Errorf("could not open %q", r.Value)
}`,
			wantLeakHits: 1,
		},
		{
			name: "errors.New interpolates a plaintext local",
			source: `package variables
import (
	"errors"
	"fmt"
)
func leak(plaintext string) error {
	return errors.New(fmt.Sprintf("decoded value was %q", plaintext))
}`,
			wantLeakHits: 2, // both errors.New (carries the Sprint call as its arg) and Sprintf
		},
		{
			name: "apierr.FieldViolation echoes ciphertext bytes into Reason",
			source: `package variables
import "fmt"
type FieldViolation struct{ Field, Reason string }
type ScopedVariable struct{ SecretCiphertext []byte }
func leak(v ScopedVariable) FieldViolation {
	return FieldViolation{Field: "x", Reason: fmt.Sprintf("seal mismatch %x", v.SecretCiphertext)}
}`,
			// Both rules legitimately fire: the outer FieldViolation.Reason
			// carries the forbidden expression (the wrapping rule catches the
			// leak as it lands on the customer-readable field) AND the inner
			// fmt.Sprintf call also carries it (the call rule catches the
			// leak as it forms the customer-readable string). Two diagnostics
			// at the same source position is the right shape: each rule
			// catches the leak independently, so a regression that softens
			// either rule still fails the other.
			wantLeakHits: 2,
		},
		{
			name: "allowed: LogValue body uses output.Sentinel and no forbidden selector",
			source: `package variables
import "log/slog"
type Rendered struct{ Key string }
var output struct{ Sentinel string } = struct{ Sentinel string }{Sentinel: "[REDACTED]"}
func (r Rendered) LogValue() slog.Value {
	return slog.GroupValue(slog.String("key", r.Key), slog.String("value", output.Sentinel))
}`,
			// All counters zero.
		},
		{
			name: "allowed: ExplainedVariable composite sets Value to output.Sentinel",
			source: `package variables
type ExplainedVariable struct{ Value string }
var output struct{ Sentinel string } = struct{ Sentinel string }{Sentinel: "[REDACTED]"}
func make() ExplainedVariable { return ExplainedVariable{Value: output.Sentinel} }`,
			// All counters zero.
		},
		{
			name: "allowed: fmt.Errorf with a non-forbidden selector",
			source: `package variables
import "fmt"
type ScopedVariable struct{ Key string }
func leak(v ScopedVariable) error { return fmt.Errorf("bad name %q", v.Key) }`,
			// All counters zero.
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

			var (
				missingSentinel int
				forbiddenSel    int
				explainedHits   int
			)
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Recv == nil || fd.Name.Name != "LogValue" {
					continue
				}
				recv := receiverTypeName(fd)
				if !contains(redactingTypes, recv) {
					continue
				}
				if !bodyReferencesSelector(fd.Body, "output", "Sentinel") {
					missingSentinel++
				}
				forbiddenSel += len(bodyForbiddenSelectors(fd.Body, recv, fd))
			}
			if missingSentinel != tc.wantLogValueHits {
				t.Errorf("missing-sentinel: got %d, want %d", missingSentinel, tc.wantLogValueHits)
			}
			if forbiddenSel != tc.wantForbiddenLog {
				t.Errorf("forbidden-LogValue-selector: got %d, want %d", forbiddenSel, tc.wantForbiddenLog)
			}

			ast.Inspect(file, func(n ast.Node) bool {
				cl, ok := n.(*ast.CompositeLit)
				if !ok || compositeLitTypeName(cl) != "ExplainedVariable" {
					return true
				}
				val, present := compositeLitField(cl, "Value")
				if !present {
					explainedHits++
					return true
				}
				if !isOutputSentinelExpr(val) {
					explainedHits++
				}
				return true
			})
			if explainedHits != tc.wantExplainedHits {
				t.Errorf("ExplainedVariable: got %d, want %d", explainedHits, tc.wantExplainedHits)
			}

			leaks := findPlaintextLeaks(fset, file)
			if len(leaks) != tc.wantLeakHits {
				t.Errorf("plaintext-leak: got %d, want %d. hits:\n  %s",
					len(leaks), tc.wantLeakHits, strings.Join(leaks, "\n  "))
			}
		})
	}
}

// findPlaintextLeaks walks file's AST and returns one diagnostic per
// error-forming call or reason-bearing composite literal whose arguments
// reference a forbidden selector or a forbidden identifier.
func findPlaintextLeaks(fset *token.FileSet, file *ast.File) []string {
	var diags []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			pkg, fn, ok := callPkgFunc(node)
			if !ok {
				return true
			}
			fns, recognised := errorFormingFuncs[pkg]
			if !recognised || !fns[fn] {
				return true
			}
			for _, arg := range node.Args {
				if expr := firstForbiddenExpr(arg); expr != nil {
					pos := fset.Position(expr.Pos())
					diags = append(diags, fmt.Sprintf(
						"%s:%d: %s.%s argument carries forbidden expression %s — "+
							"plaintext/ciphertext must not reach an error or log surface",
						filepath.Base(pos.Filename), pos.Line, pkg, fn,
						renderVariablesExpr(expr)))
				}
			}
		case *ast.CompositeLit:
			tname := compositeLitTypeName(node)
			fields, recognised := errorFormingCompositeLitFields[tname]
			if !recognised {
				return true
			}
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				if !fields[key.Name] {
					continue
				}
				if expr := firstForbiddenExpr(kv.Value); expr != nil {
					pos := fset.Position(expr.Pos())
					diags = append(diags, fmt.Sprintf(
						"%s:%d: %s.%s carries forbidden expression %s — "+
							"plaintext/ciphertext must not reach an error or log surface",
						filepath.Base(pos.Filename), pos.Line, tname, key.Name,
						renderVariablesExpr(expr)))
				}
			}
		}
		return true
	})
	return diags
}

// firstForbiddenExpr walks expr depth-first and returns the first
// SelectorExpr whose selector is in forbiddenFieldNames, OR the first
// Ident whose name is in forbiddenIdentNames. Returns nil when expr is
// clean. The traversal descends into nested CallExpr / BinaryExpr /
// ParenExpr / KeyValueExpr / CompositeLit / IndexExpr so a hidden leak
// inside a nested fmt.Sprintf or struct literal is still caught.
func firstForbiddenExpr(expr ast.Expr) ast.Expr {
	var found ast.Expr
	ast.Inspect(expr, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		switch e := n.(type) {
		case *ast.SelectorExpr:
			if forbiddenFieldNames[e.Sel.Name] {
				found = e
				return false
			}
		case *ast.Ident:
			if forbiddenIdentNames[e.Name] {
				found = e
				return false
			}
		}
		return true
	})
	return found
}

// bodyReferencesSelector reports whether body contains a SelectorExpr of
// the form `<pkg>.<sel>` (e.g. output.Sentinel).
func bodyReferencesSelector(body *ast.BlockStmt, pkg, sel string) bool {
	if body == nil {
		return false
	}
	hit := false
	ast.Inspect(body, func(n ast.Node) bool {
		if hit {
			return false
		}
		se, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := se.X.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name == pkg && se.Sel.Name == sel {
			hit = true
			return false
		}
		return true
	})
	return hit
}

// bodyForbiddenSelectors walks body and returns every SelectorExpr whose
// receiver matches one of the LogValue method's parameter names AND whose
// selector field name is in forbiddenFieldNames. The receiver-name match
// ties the diagnostic to the load-bearing variable (e.g. `v.Value` in
// `(v ScopedVariable).LogValue`) and prevents false positives from
// unrelated `<other>.Value` accesses inside the method body.
func bodyForbiddenSelectors(body *ast.BlockStmt, _ string, fd *ast.FuncDecl) []ast.Expr {
	if body == nil || fd == nil || fd.Recv == nil {
		return nil
	}
	receivers := receiverIdentNames(fd)
	if len(receivers) == 0 {
		return nil
	}
	var out []ast.Expr
	ast.Inspect(body, func(n ast.Node) bool {
		se, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !forbiddenFieldNames[se.Sel.Name] {
			return true
		}
		id, ok := se.X.(*ast.Ident)
		if !ok {
			return true
		}
		if !receivers[id.Name] {
			return true
		}
		out = append(out, se)
		return true
	})
	return out
}

// receiverIdentNames returns the set of identifier names declared on a
// method receiver. A `func (v T) M() {}` declaration yields {"v"}; an
// anonymous `func (T) M() {}` declaration yields an empty set.
func receiverIdentNames(fd *ast.FuncDecl) map[string]bool {
	if fd == nil || fd.Recv == nil {
		return nil
	}
	out := map[string]bool{}
	for _, field := range fd.Recv.List {
		for _, name := range field.Names {
			out[name.Name] = true
		}
	}
	return out
}

// receiverTypeName returns the unqualified type name of fd's receiver,
// stripping a leading pointer if present. Returns "" for a non-method
// FuncDecl.
func receiverTypeName(fd *ast.FuncDecl) string {
	if fd == nil || fd.Recv == nil || len(fd.Recv.List) == 0 {
		return ""
	}
	t := fd.Recv.List[0].Type
	if star, ok := t.(*ast.StarExpr); ok {
		t = star.X
	}
	id, ok := t.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

// compositeLitTypeName returns the unqualified type name of a composite
// literal. Returns "" when the literal has no Type (a typed-context
// elided form like a slice element).
func compositeLitTypeName(cl *ast.CompositeLit) string {
	if cl == nil {
		return ""
	}
	switch t := cl.Type.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	default:
		return ""
	}
}

// compositeLitField looks up a named field on a composite literal and
// returns its value expression and a present flag. The flag is false when
// the field name is not present among the literal's KeyValueExpr entries.
func compositeLitField(cl *ast.CompositeLit, name string) (ast.Expr, bool) {
	if cl == nil {
		return nil, false
	}
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != name {
			continue
		}
		return kv.Value, true
	}
	return nil, false
}

// isOutputSentinelExpr reports whether expr is the SelectorExpr
// `output.Sentinel`. This is the only allowed value for
// ExplainedVariable.Value in package source.
func isOutputSentinelExpr(expr ast.Expr) bool {
	se, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := se.X.(*ast.Ident)
	if !ok {
		return false
	}
	return id.Name == "output" && se.Sel.Name == "Sentinel"
}

// callPkgFunc extracts the (pkg, fn) pair from a CallExpr whose Fun is a
// simple SelectorExpr `<pkg>.<fn>`. Returns ok=false for any other call
// shape (method-on-value, function-from-an-expression, etc.).
func callPkgFunc(call *ast.CallExpr) (string, string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	return id.Name, sel.Sel.Name, true
}

// renderVariablesExpr pretty-prints an expression for inclusion in
// diagnostics. Errors from the printer are squashed to a placeholder; this
// is best-effort.
func renderVariablesExpr(e ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, token.NewFileSet(), e); err != nil {
		return "<unprintable>"
	}
	return buf.String()
}

// contains reports whether haystack contains needle. Used for the small
// closed-set lookups above; a map would be heavier than this slice scan.
func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// nonTestVariablesSourceFiles returns the list of non-test .go source files
// in the package directory in stable order. Subdirectories are skipped —
// the package has none today, and the static guard scope is intentionally
// the same as the package's source-of-truth files.
func nonTestVariablesSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read variables dir: %v", err)
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
		t.Fatalf("no non-test .go files found in the variables package — the env-var " +
			"redaction static guard is vacuous")
	}
	return out
}

// mustParseVariablesFile parses path with the test-friendly options and
// fails the test on a parse error.
func mustParseVariablesFile(t *testing.T, path string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fset, file
}
