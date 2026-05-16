package store_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Audit log tamper resistance — application-layer static defence (BE-0353).
//
// Threat model: the audit log is the evidence trail for every
// security-relevant authorization decision. The database layer enforces
// immutability through a BEFORE UPDATE trigger (see
// `internal/controlplane/store/migrate/audit_immutability_static_test.go`
// for the migration-level guard). This file pins the *application*-level
// walls so the runtime trigger never has to fire:
//
//  1. The `AuditRepository` surface exposes exactly two methods —
//     `Append` and `ListByOrganization`. No `Update*`, `Delete*`,
//     `Patch*`, `Replace*`, `Modify*`, `Truncate*`, or `Remove*`
//     method is permitted. Application code structurally cannot reach
//     a mutation path. A new method that names itself anything else
//     (e.g. `Append2`) is also flagged, so a sneaky drift surface is
//     caught at code review.
//  2. The `AuditEvent` struct exposes no mutation timestamp — no
//     `UpdatedAt`, `ModifiedAt`, or `RevisedAt` field. The table has
//     no such column (pinned in the migration guard); the Go type
//     must agree, so a future developer cannot scan the struct and
//     "fill in" a column that doesn't exist on the wire.
//  3. No SQL string literal anywhere in the store package issues a
//     mutating DML statement against `audit_events`. Only the
//     `INSERT INTO audit_events ...` statement inside `audit.go` is
//     permitted; `UPDATE audit_events`, `DELETE FROM audit_events`,
//     `TRUNCATE audit_events`, `ALTER TABLE audit_events`, and
//     `DROP TABLE audit_events` are each flagged with a file:line
//     diagnostic.
//
// The two-test pattern (BE-0344, BE-0345, BE-0346, BE-0347, BE-0348,
// BE-0349, BE-0350, BE-0351, BE-0352) applies here. The static half
// (this file) pins the source-level invariants on the AST without a
// database. The migration-level half lives in
// `internal/controlplane/store/migrate/audit_immutability_static_test.go`.
// The runtime half lives in `internal/controlplane/store/audit_test.go`
// (`TestAuditRepositoryAppendImmutability` and
// `TestAuditUpdateBlockedByDatabaseTriggerWithRestrictViolation`).
// `TestAuditTamperStaticAnalyzerDetectsRegressions` is the self-check:
// every analyser is driven against synthetic known-good and known-bad
// inputs so a future weakening of any matcher is itself caught.

// auditRepositorySurfaceAllowed is the canonical set of method names
// `AuditRepository` may expose. A method that is NOT in this set is a
// regression — the analyser fails the build for any new method,
// including aliases (`Append2`, `AppendEvent`) and the obvious
// mutation surfaces (`Update`, `Delete`, `DeleteByID`).
//
// "Methods on `*AuditRepository`" in the AST sense covers receivers
// of both `*AuditRepository` and `AuditRepository` (pointer and value
// receivers alike).
var auditRepositorySurfaceAllowed = map[string]struct{}{
	"Append":             {},
	"ListByOrganization": {},
}

// auditEventStructForbiddenFields names struct fields that, if added,
// would create a mutation surface. The names are anchored on common
// "mutation timestamp" patterns; a future field that wants to record
// a write timestamp must use a different name AND justify the
// existence in the type's package doc.
var auditEventStructForbiddenFields = []string{
	"UpdatedAt",
	"ModifiedAt",
	"RevisedAt",
	"LastModifiedAt",
}

// auditEventsMutatingSQLPatterns is the closed set of forbidden DML
// shapes against `audit_events`. The analyser flags any SQL-shaped
// string literal in the store package that contains any of these
// substrings (case-insensitive after whitespace normalisation). The
// only allowed shape, `INSERT INTO audit_events ...`, lives in
// `audit.go` and is explicitly carved out — every other shape is a
// regression.
var auditEventsMutatingSQLPatterns = []string{
	"UPDATE audit_events",
	"DELETE FROM audit_events",
	"TRUNCATE audit_events",
	"TRUNCATE TABLE audit_events",
	"ALTER TABLE audit_events",
	"DROP TABLE audit_events",
}

// TestAuditRepositorySurfaceIsAppendOnly walks the AST of `audit.go`
// and asserts the set of methods declared on `AuditRepository` is
// exactly `auditRepositorySurfaceAllowed`. A new method (especially
// an `Update*`, `Delete*`, `Patch*`, `Replace*`, `Modify*`,
// `Truncate*`, or `Remove*` shape) fails the build with a file:line
// diagnostic. A method removed from the allowed set ALSO fails the
// build — that catches the regression "the read surface silently
// disappeared and nobody noticed."
func TestAuditRepositorySurfaceIsAppendOnly(t *testing.T) {
	t.Parallel()

	fset, file := mustParseFile(t, "audit.go")
	got := collectMethodNamesOnReceiver(file, "AuditRepository")
	if len(got) == 0 {
		t.Fatalf("audit.go: no methods declared on AuditRepository — the immutability surface is vacuous")
	}

	gotSet := make(map[string]token.Pos, len(got))
	for _, m := range got {
		gotSet[m.name] = m.pos
	}

	// (1) Every method we found must be in the allowed set, AND must
	// not be a known mutation-surface shape.
	for _, m := range got {
		if _, ok := auditRepositorySurfaceAllowed[m.name]; !ok {
			pos := fset.Position(m.pos)
			t.Errorf("%s:%d: unexpected method (*AuditRepository).%s — the audit log is append-only; "+
				"a new method is a tamper-resistance regression. Allowed methods: %s",
				pos.Filename, pos.Line, m.name, sortedKeys(auditRepositorySurfaceAllowed))
		}
		if isMutationSurfaceMethodName(m.name) {
			pos := fset.Position(m.pos)
			t.Errorf("%s:%d: method (*AuditRepository).%s names a mutation surface — audit records are immutable by contract",
				pos.Filename, pos.Line, m.name)
		}
	}
	// (2) Every method in the allowed set must actually be declared
	// on the type — a silent disappearance is also a regression.
	for name := range auditRepositorySurfaceAllowed {
		if _, ok := gotSet[name]; !ok {
			t.Errorf("audit.go: required method (*AuditRepository).%s is missing — the read or append surface has been removed", name)
		}
	}
}

// TestAuditEventStructHasNoMutationTimestamp parses `audit.go`, finds
// the `AuditEvent` struct declaration, and rejects any field whose
// name is in `auditEventStructForbiddenFields`. The migration guard
// (sibling file) pins the absence of an `updated_at` column on the
// table; this guard pins the absence of a Go field that could carry
// such a value.
func TestAuditEventStructHasNoMutationTimestamp(t *testing.T) {
	t.Parallel()

	fset, file := mustParseFile(t, "audit.go")
	fields, ok := findStructFields(file, "AuditEvent")
	if !ok {
		t.Fatalf("audit.go: type AuditEvent struct {...} declaration not found — the immutability surface is vacuous")
	}
	if len(fields) == 0 {
		t.Fatalf("audit.go: AuditEvent struct is empty — fixture is broken")
	}
	for _, f := range fields {
		for _, forbidden := range auditEventStructForbiddenFields {
			if f.name == forbidden {
				pos := fset.Position(f.pos)
				t.Errorf("%s:%d: AuditEvent.%s is a mutation-timestamp shape — audit records are append-only and carry only OccurredAt and CreatedAt",
					pos.Filename, pos.Line, f.name)
			}
		}
	}
}

// TestNoStoreSourceTargetsAuditEventsWithMutatingDML walks every
// non-test .go file in the store package, finds every string literal,
// and flags any literal that contains a forbidden DML shape against
// `audit_events`. The single allowed shape — `INSERT INTO
// audit_events ...` in `audit.go` — is not in the forbidden set, so
// it passes silently. A new `UPDATE audit_events SET ...` snuck into
// any repository or service file fails the build with a file:line
// diagnostic.
func TestNoStoreSourceTargetsAuditEventsWithMutatingDML(t *testing.T) {
	t.Parallel()

	for _, path := range nonTestStoreSourceFiles(t) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			fset, file := mustParseFile(t, path)
			for _, v := range findAuditEventsMutatingSQL(fset, file) {
				t.Error(v)
			}
		})
	}
}

// TestAuditTamperStaticAnalyzerDetectsRegressions is the self-check
// for the three analysers above. It synthesises Go sources that drive
// each matcher both ways:
//
//   - the allowed `Append` / `ListByOrganization` methods pass
//   - a synthetic `(*AuditRepository).Update` method is flagged
//   - a synthetic `(*AuditRepository).DeleteByID` method is flagged
//   - a synthetic `(*AuditRepository).Append2` alias is flagged
//   - a synthetic `AuditEvent` with `UpdatedAt` is flagged
//   - a synthetic SQL literal `UPDATE audit_events SET ...` is flagged
//   - a synthetic SQL literal `DELETE FROM audit_events ...` is flagged
//   - a synthetic SQL literal `INSERT INTO audit_events ...` passes
//   - a synthetic Go comment containing `UPDATE audit_events` (as a comment, not a literal) is NOT flagged — string-literal scope is intentional
func TestAuditTamperStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	t.Run("repository surface", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name      string
			source    string
			wantNames []string
		}{
			{
				name: "canonical Append + ListByOrganization passes",
				source: `package p
type AuditRepository struct{}
func (r *AuditRepository) Append() {}
func (r *AuditRepository) ListByOrganization() {}
`,
				wantNames: []string{"Append", "ListByOrganization"},
			},
			{
				name: "value-receiver method is captured",
				source: `package p
type AuditRepository struct{}
func (r AuditRepository) ListByOrganization() {}
`,
				wantNames: []string{"ListByOrganization"},
			},
			{
				name: "Update method shows up",
				source: `package p
type AuditRepository struct{}
func (r *AuditRepository) Append() {}
func (r *AuditRepository) Update() {}
`,
				wantNames: []string{"Append", "Update"},
			},
			{
				name: "alias method shows up",
				source: `package p
type AuditRepository struct{}
func (r *AuditRepository) Append() {}
func (r *AuditRepository) Append2() {}
`,
				wantNames: []string{"Append", "Append2"},
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				file := parseSyntheticAuditFile(t, tc.source)
				got := collectMethodNamesOnReceiver(file, "AuditRepository")
				gotNames := make([]string, 0, len(got))
				for _, m := range got {
					gotNames = append(gotNames, m.name)
				}
				sort.Strings(gotNames)
				want := append([]string(nil), tc.wantNames...)
				sort.Strings(want)
				if strings.Join(gotNames, ",") != strings.Join(want, ",") {
					t.Errorf("collectMethodNamesOnReceiver = %v, want %v", gotNames, want)
				}
			})
		}
	})

	t.Run("mutation surface name detector", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name string
			in   string
			want bool
		}{
			{name: "Append passes", in: "Append", want: false},
			{name: "ListByOrganization passes", in: "ListByOrganization", want: false},
			{name: "Update flagged", in: "Update", want: true},
			{name: "UpdateMutable flagged", in: "UpdateMutable", want: true},
			{name: "Delete flagged", in: "Delete", want: true},
			{name: "DeleteByID flagged", in: "DeleteByID", want: true},
			{name: "Patch flagged", in: "Patch", want: true},
			{name: "Replace flagged", in: "Replace", want: true},
			{name: "Modify flagged", in: "Modify", want: true},
			{name: "Truncate flagged", in: "Truncate", want: true},
			{name: "Remove flagged", in: "Remove", want: true},
			{name: "Set is NOT flagged (too broad)", in: "Set", want: false},
			{name: "Get is NOT flagged", in: "Get", want: false},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				if got := isMutationSurfaceMethodName(tc.in); got != tc.want {
					t.Errorf("isMutationSurfaceMethodName(%q) = %v, want %v", tc.in, got, tc.want)
				}
			})
		}
	})

	t.Run("AuditEvent struct fields", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name        string
			source      string
			wantFlagged []string
		}{
			{
				name: "canonical AuditEvent passes",
				source: `package p
import "time"
type AuditEvent struct {
	ID         string
	OccurredAt time.Time
	CreatedAt  time.Time
}
`,
				wantFlagged: nil,
			},
			{
				name: "UpdatedAt flagged",
				source: `package p
import "time"
type AuditEvent struct {
	ID         string
	OccurredAt time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
`,
				wantFlagged: []string{"UpdatedAt"},
			},
			{
				name: "ModifiedAt flagged",
				source: `package p
import "time"
type AuditEvent struct {
	ModifiedAt time.Time
}
`,
				wantFlagged: []string{"ModifiedAt"},
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				file := parseSyntheticAuditFile(t, tc.source)
				fields, ok := findStructFields(file, "AuditEvent")
				if !ok {
					t.Fatalf("AuditEvent struct not found in synthetic source")
				}
				var flagged []string
				for _, f := range fields {
					for _, forbidden := range auditEventStructForbiddenFields {
						if f.name == forbidden {
							flagged = append(flagged, f.name)
						}
					}
				}
				sort.Strings(flagged)
				want := append([]string(nil), tc.wantFlagged...)
				sort.Strings(want)
				if strings.Join(flagged, ",") != strings.Join(want, ",") {
					t.Errorf("flagged fields = %v, want %v", flagged, want)
				}
			})
		}
	})

	t.Run("mutating SQL string-literal scan", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name     string
			source   string
			wantHits int
		}{
			{
				name: "canonical INSERT passes",
				source: `package p
func _() { _ = ` + "`INSERT INTO audit_events (id) VALUES ($1)`" + ` }
`,
				wantHits: 0,
			},
			{
				name: "canonical SELECT passes",
				source: `package p
func _() { _ = ` + "`SELECT id FROM audit_events WHERE organization_id = $1`" + ` }
`,
				wantHits: 0,
			},
			{
				name: "UPDATE flagged",
				source: `package p
func _() { _ = ` + "`UPDATE audit_events SET reason = 'tampered' WHERE id = $1`" + ` }
`,
				wantHits: 1,
			},
			{
				name: "DELETE FROM flagged",
				source: `package p
func _() { _ = ` + "`DELETE FROM audit_events WHERE id = $1`" + ` }
`,
				wantHits: 1,
			},
			{
				name: "TRUNCATE flagged",
				source: `package p
func _() { _ = ` + "`TRUNCATE audit_events`" + ` }
`,
				wantHits: 1,
			},
			{
				name: "TRUNCATE TABLE flagged",
				source: `package p
func _() { _ = ` + "`TRUNCATE TABLE audit_events`" + ` }
`,
				wantHits: 1,
			},
			{
				name: "ALTER TABLE flagged",
				source: `package p
func _() { _ = ` + "`ALTER TABLE audit_events ADD COLUMN x text`" + ` }
`,
				wantHits: 1,
			},
			{
				name: "DROP TABLE flagged",
				source: `package p
func _() { _ = ` + "`DROP TABLE audit_events`" + ` }
`,
				wantHits: 1,
			},
			{
				name: "case-insensitive: lowercase update flagged",
				source: `package p
func _() { _ = ` + "`update audit_events set reason = 'x'`" + ` }
`,
				wantHits: 1,
			},
			{
				name: "whitespace tolerance: multi-line UPDATE flagged",
				source: `package p
func _() { _ = ` + "`UPDATE\n   audit_events\nSET reason = 'x'`" + ` }
`,
				wantHits: 1,
			},
			{
				name: "comment containing UPDATE audit_events is NOT flagged",
				source: `package p
// This comment mentions UPDATE audit_events but is not a string literal.
func _() { _ = ` + "`INSERT INTO audit_events (id) VALUES ($1)`" + ` }
`,
				wantHits: 0,
			},
			{
				name: "string containing only the substring elsewhere is NOT flagged",
				source: `package p
func _() { _ = ` + "`UPDATE projects SET reason = 'x' WHERE audit_events_count = 0`" + ` }
`,
				wantHits: 0,
			},
		}
		for _, tc := range cases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				file := parseSyntheticAuditFile(t, tc.source)
				fset := token.NewFileSet()
				// Re-parse with a real FileSet so positions are concrete.
				file2, err := parser.ParseFile(fset, "synthetic.go", tc.source, parser.SkipObjectResolution|parser.ParseComments)
				if err != nil {
					t.Fatalf("parse synthetic: %v", err)
				}
				_ = file
				got := len(findAuditEventsMutatingSQL(fset, file2))
				if got != tc.wantHits {
					t.Errorf("findAuditEventsMutatingSQL hits = %d, want %d", got, tc.wantHits)
				}
			})
		}
	})
}

// methodOnReceiver is a (name, position) pair captured for a method
// declared on a named receiver type. The position lets the test
// produce a file:line diagnostic.
type methodOnReceiver struct {
	name string
	pos  token.Pos
}

// collectMethodNamesOnReceiver walks file.Decls and returns every
// method declared with a receiver of the named type. Both pointer
// (`*Recv`) and value (`Recv`) receivers are collected.
func collectMethodNamesOnReceiver(file *ast.File, recv string) []methodOnReceiver {
	if file == nil {
		return nil
	}
	var out []methodOnReceiver
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		recvType := fn.Recv.List[0].Type
		if star, ok := recvType.(*ast.StarExpr); ok {
			recvType = star.X
		}
		ident, ok := recvType.(*ast.Ident)
		if !ok || ident.Name != recv {
			continue
		}
		if fn.Name == nil {
			continue
		}
		out = append(out, methodOnReceiver{name: fn.Name.Name, pos: fn.Pos()})
	}
	return out
}

// isMutationSurfaceMethodName reports whether name starts with a
// known mutation-surface verb. The verb set is closed: a future
// "mutation-shape" alias must be added here AND removed from
// `auditRepositorySurfaceAllowed` if it is somehow legitimate.
// "Set" and "Get" are deliberately NOT in the verb set — they are
// far too broad to flag and would generate false positives across
// unrelated repositories.
func isMutationSurfaceMethodName(name string) bool {
	verbs := []string{"Update", "Delete", "Patch", "Replace", "Modify", "Truncate", "Remove"}
	for _, v := range verbs {
		if strings.HasPrefix(name, v) {
			return true
		}
	}
	return false
}

// structField pairs a field name with its source position so the
// analyser can emit a file:line diagnostic.
type structField struct {
	name string
	pos  token.Pos
}

// findStructFields locates the named struct type in file.Decls and
// returns its declared fields. Embedded fields (no Names) are
// skipped — they cannot be mutation timestamps because they carry no
// local name.
func findStructFields(file *ast.File, name string) ([]structField, bool) {
	if file == nil {
		return nil, false
	}
	var out []structField
	var found bool
	for _, d := range file.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name == nil || ts.Name.Name != name {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			found = true
			for _, f := range st.Fields.List {
				for _, n := range f.Names {
					out = append(out, structField{name: n.Name, pos: n.Pos()})
				}
			}
		}
	}
	return out, found
}

// findAuditEventsMutatingSQL walks every string literal in file and
// returns a list of "file:line: SQL=... shape=..." diagnostics for
// each literal whose normalised content contains a forbidden DML
// shape against `audit_events`. Comments are NOT scanned — the rule
// targets executable code paths.
func findAuditEventsMutatingSQL(fset *token.FileSet, file *ast.File) []string {
	if file == nil {
		return nil
	}
	var diags []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		raw, err := unquoteAuditLit(lit.Value)
		if err != nil {
			return true
		}
		// Normalise whitespace so multi-line literals like
		// "UPDATE\n  audit_events\nSET ..." still match.
		norm := strings.ToUpper(collapseAuditWhitespace(raw))
		for _, pattern := range auditEventsMutatingSQLPatterns {
			if strings.Contains(norm, strings.ToUpper(pattern)) {
				pos := fset.Position(lit.Pos())
				diags = append(diags, fmt.Sprintf("%s:%d: forbidden DML against audit_events: %q in literal — audit_events is append-only",
					pos.Filename, pos.Line, pattern))
				// One pattern is enough; don't double-count overlaps.
				return true
			}
		}
		return true
	})
	return diags
}

// unquoteAuditLit unwraps a Go string literal (double-quoted or
// raw-string) into its content. The two-character minimum check
// rejects malformed input without an unwrap.
func unquoteAuditLit(raw string) (string, error) {
	if len(raw) < 2 {
		return raw, fmt.Errorf("literal too short")
	}
	first, last := raw[0], raw[len(raw)-1]
	if first == '`' && last == '`' {
		return raw[1 : len(raw)-1], nil
	}
	if first == '"' && last == '"' {
		return raw[1 : len(raw)-1], nil
	}
	return raw, fmt.Errorf("unsupported delimiter")
}

// collapseAuditWhitespace squashes every run of whitespace to a
// single space so the pattern check is anchored on token boundaries
// rather than exact formatting. The lower-cased comparison is done
// by the caller (uppercase normalisation both ways).
func collapseAuditWhitespace(s string) string {
	out := make([]byte, 0, len(s))
	prevSpace := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if !prevSpace {
				out = append(out, ' ')
				prevSpace = true
			}
			continue
		}
		out = append(out, c)
		prevSpace = false
	}
	return strings.TrimSpace(string(out))
}

// parseSyntheticAuditFile parses a synthetic Go source for the
// self-check tests. Comments are parsed so a future analyser that
// scans them can use the same helper.
func parseSyntheticAuditFile(t *testing.T, src string) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse synthetic: %v\nsrc:\n%s", err, src)
	}
	return file
}

// sortedKeys returns the keys of m in alphabetical order, suitable
// for inclusion in error messages.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
