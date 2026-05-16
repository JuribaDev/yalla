package secrets

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Secret encryption key rotation — static-analysis defence (BE-0351).
//
// Threat model: AES-256-GCM master keys are not forever. A backup tape
// taken offsite, an HSM decommissioning, a former operator's offline
// copy presumed leaked, or the per-key birthday bound near 2^32
// messages all force a key rotation. The mitigation that has to be in
// place BEFORE any of those events is the ability to add a NEW master
// key without invalidating the ciphertext sealed under any existing
// key, to flip which key is ACTIVE without changing the on-disk
// format, to enumerate the rows that still reference a retired key id,
// and to eventually drop the retired key from the accepted set so any
// Open that names it surfaces as a typed `ErrUnknownKey` instead of a
// silent plaintext recovery.
//
// The provider-layer defence is the four-method rotation surface on
// `AESGCM`:
//   - `NewAESGCM(masterKeys [][]byte)` — takes a slice, not a single key,
//     so a rotation window can hold the new active key in position 0 and
//     the retired key in position 1+ at the same time.
//   - `ActiveKeyID()` — names the key id every subsequent Seal will
//     reference so an operator can confirm a rotation took effect.
//   - `KeyIDs()` — enumerates the accepted set in configured order so
//     the rotation worker can diff it against the distinct key ids the
//     `*_variables_secret_routing_idx` partial index surfaces.
//   - `Open(ciphertext, keyID)` — walks the configured `keys` slice
//     and returns `ErrUnknownKey` when the named key is not in the set.
//     The slice-walk is the load-bearing invariant for the rotation
//     window — a refactor that reduces `Open` to "decrypt with the
//     active key" silently breaks the multi-key accept window and
//     re-opens every previously sealed row to a guaranteed decryption
//     failure the next time the master key list rolls.
//
// This is the cryptographic-primitive layer only. The store-layer
// routing index that the rotation worker consumes is pinned by a
// sibling test in
// `internal/controlplane/store/migrate/secret_routing_idx_static_test.go`.
// The runbook lives in this package's AGENTS.md.
//
// The two-test pattern (BE-0344, BE-0345, BE-0346, BE-0349, BE-0350)
// applies here. The static half (this file) parses `aesgcm.go` and
// asserts the four surface methods exist with their documented shape.
// The runtime half lives in `key_rotation_test.go` (the full three-
// phase rotation lifecycle plus the redacted-projection invariant).
// Self-check: `TestAESGCMRotationStaticAnalyzerDetectsRegressions`
// feeds synthetic known-bad and known-good provider shapes to the
// analyser and pins both directions, so a future change that
// over-tightens the analyser (false positives) or silently
// under-tightens it (missing surface goes unflagged) is caught.

// TestAESGCMRotationSurfaceIsExported is the load-bearing static guard.
// It parses `aesgcm.go` and asserts the four rotation-surface methods
// exist with the documented shape. A diagnostic is one short string
// per missing or malformed surface element.
func TestAESGCMRotationSurfaceIsExported(t *testing.T) {
	t.Parallel()
	fset, file := mustParseSecretsFile(t, "aesgcm.go")

	t.Run("NewAESGCM accepts slice of master keys", func(t *testing.T) {
		t.Parallel()
		decl := findFuncDecl(file, "NewAESGCM")
		if decl == nil {
			t.Fatalf("aesgcm.go: NewAESGCM function not found — the rotation surface is vacuous")
		}
		if decl.Type == nil || decl.Type.Params == nil || len(decl.Type.Params.List) != 1 {
			pos := fset.Position(decl.Pos())
			t.Fatalf("%s:%d: NewAESGCM must take exactly one parameter (the master key slice)", pos.Filename, pos.Line)
		}
		param := decl.Type.Params.List[0]
		arr, ok := param.Type.(*ast.ArrayType)
		if !ok {
			pos := fset.Position(decl.Pos())
			t.Fatalf("%s:%d: NewAESGCM parameter must be a slice type so the rotation window can hold the new active key + every retired key simultaneously", pos.Filename, pos.Line)
		}
		inner, ok := arr.Elt.(*ast.ArrayType)
		if !ok {
			pos := fset.Position(decl.Pos())
			t.Fatalf("%s:%d: NewAESGCM parameter element must itself be a byte slice ([]byte), so each entry is a raw AES-256 key", pos.Filename, pos.Line)
		}
		ident, ok := inner.Elt.(*ast.Ident)
		if !ok || ident.Name != "byte" {
			pos := fset.Position(decl.Pos())
			t.Fatalf("%s:%d: NewAESGCM parameter must be [][]byte; got [][]%T", pos.Filename, pos.Line, inner.Elt)
		}
	})

	t.Run("ActiveKeyID surface method exists", func(t *testing.T) {
		t.Parallel()
		decl := findMethodDecl(file, "AESGCM", "ActiveKeyID")
		if decl == nil {
			t.Fatalf("aesgcm.go: (*AESGCM).ActiveKeyID method not found — operators cannot confirm a rotation took effect without sealing a probe value")
		}
	})

	t.Run("KeyIDs surface method exists", func(t *testing.T) {
		t.Parallel()
		decl := findMethodDecl(file, "AESGCM", "KeyIDs")
		if decl == nil {
			t.Fatalf("aesgcm.go: (*AESGCM).KeyIDs method not found — the rotation worker cannot enumerate the accepted set to diff against the routing index")
		}
	})

	t.Run("Open walks the keys slice and surfaces ErrUnknownKey", func(t *testing.T) {
		t.Parallel()
		decl := findMethodDecl(file, "AESGCM", "Open")
		if decl == nil {
			t.Fatalf("aesgcm.go: (*AESGCM).Open method not found — the rotation surface is vacuous")
		}
		if !openIteratesKeys(decl) {
			pos := fset.Position(decl.Pos())
			t.Errorf("%s:%d: (*AESGCM).Open must iterate the receiver's `keys` slice so a ciphertext sealed under any accepted key can decrypt during the rotation window. "+
				"A refactor that reduces Open to a single-key decrypt silently collapses the multi-key accept window — see AGENTS.md \"Key rotation\" for the threat model.",
				pos.Filename, pos.Line)
		}
		if !openReturnsErrUnknownKey(decl) {
			pos := fset.Position(decl.Pos())
			t.Errorf("%s:%d: (*AESGCM).Open must return ErrUnknownKey when the named key id is not in the configured set — that typed signal is the operator's only way to discover a row that the rotation worker missed before the retired key was dropped.",
				pos.Filename, pos.Line)
		}
	})
}

// TestAESGCMRotationStaticAnalyzerDetectsRegressions is the self-check
// for the static analysers used above. It feeds synthetic provider
// shapes to `openIteratesKeys` and `openReturnsErrUnknownKey` and pins
// both directions, so a future change that over-tightens (false
// positives) or silently under-tightens (missing surface goes
// unflagged) is caught.
func TestAESGCMRotationStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	iterCases := []struct {
		name   string
		source string
		want   bool
	}{
		{
			name: "Open that ranges over p.keys is clean",
			source: `package secrets
type AESGCM struct{ keys []int }
func (p *AESGCM) Open(ct []byte, kid string) ([]byte, error) {
	for _, k := range p.keys {
		_ = k
	}
	return nil, nil
}`,
			want: true,
		},
		{
			name: "Open that only touches a single active key is flagged",
			source: `package secrets
type AESGCM struct{ active int }
func (p *AESGCM) Open(ct []byte, kid string) ([]byte, error) {
	_ = p.active
	return nil, nil
}`,
			want: false,
		},
		{
			name: "Open that ranges over an unrelated slice is flagged",
			source: `package secrets
type AESGCM struct{ keys []int; nonces []byte }
func (p *AESGCM) Open(ct []byte, kid string) ([]byte, error) {
	for _, n := range p.nonces {
		_ = n
	}
	return nil, nil
}`,
			want: false,
		},
	}
	for _, tc := range iterCases {
		tc := tc
		t.Run("iter/"+tc.name, func(t *testing.T) {
			t.Parallel()
			decl := mustParseSyntheticMethod(t, tc.source, "AESGCM", "Open")
			if got := openIteratesKeys(decl); got != tc.want {
				t.Errorf("openIteratesKeys = %v, want %v", got, tc.want)
			}
		})
	}

	errCases := []struct {
		name   string
		source string
		want   bool
	}{
		{
			name: "Open that returns ErrUnknownKey is clean",
			source: `package secrets
type AESGCM struct{ keys []int }
func (p *AESGCM) Open(ct []byte, kid string) ([]byte, error) {
	return nil, ErrUnknownKey
}`,
			want: true,
		},
		{
			name: "Open that returns a different sentinel is flagged",
			source: `package secrets
type AESGCM struct{ keys []int }
func (p *AESGCM) Open(ct []byte, kid string) ([]byte, error) {
	return nil, ErrInvalidCiphertext
}`,
			want: false,
		},
		{
			name: "Open that references ErrUnknownKey only in a comment is flagged",
			source: `package secrets
type AESGCM struct{ keys []int }
func (p *AESGCM) Open(ct []byte, kid string) ([]byte, error) {
	// ErrUnknownKey would go here
	return nil, nil
}`,
			want: false,
		},
	}
	for _, tc := range errCases {
		tc := tc
		t.Run("err/"+tc.name, func(t *testing.T) {
			t.Parallel()
			decl := mustParseSyntheticMethod(t, tc.source, "AESGCM", "Open")
			if got := openReturnsErrUnknownKey(decl); got != tc.want {
				t.Errorf("openReturnsErrUnknownKey = %v, want %v", got, tc.want)
			}
		})
	}
}

// openIteratesKeys reports whether the function body of decl contains
// at least one range loop over the receiver's `keys` field — the
// structural signature of a multi-key accept window. The match is
// exact: a renamed slice is treated as missing (intentional — the
// analyser pins the field name so a silent refactor cannot substitute
// a different slice).
func openIteratesKeys(decl *ast.FuncDecl) bool {
	var found bool
	ast.Inspect(decl, func(n ast.Node) bool {
		rng, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		sel, ok := rng.X.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel != nil && sel.Sel.Name == "keys" {
			found = true
			return false
		}
		return true
	})
	return found
}

// openReturnsErrUnknownKey reports whether the function body of decl
// contains at least one return expression that names the package-level
// `ErrUnknownKey` identifier. Comments and string literals are ignored
// — only an AST-visible identifier counts.
func openReturnsErrUnknownKey(decl *ast.FuncDecl) bool {
	const want = "ErrUnknownKey"
	var found bool
	ast.Inspect(decl, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, result := range ret.Results {
			ast.Inspect(result, func(inner ast.Node) bool {
				ident, ok := inner.(*ast.Ident)
				if !ok {
					return true
				}
				if ident.Name == want {
					found = true
					return false
				}
				return true
			})
			if found {
				return false
			}
		}
		return true
	})
	return found
}

// mustParseSecretsFile parses a named file in the current package
// directory and returns its FileSet + ast.File. The file path is
// resolved relative to the test binary's working directory, which is
// always the package directory for `go test`.
func mustParseSecretsFile(t *testing.T, name string) (*token.FileSet, *ast.File) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	path := filepath.Join(wd, name)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fset, file
}

// mustParseSyntheticMethod parses a synthetic source string and returns
// the named method declaration on the named receiver type. It is the
// self-check helper for the iter/err analyzer tests above.
func mustParseSyntheticMethod(t *testing.T, source, recv, name string) *ast.FuncDecl {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse synthetic source: %v", err)
	}
	decl := findMethodDecl(file, recv, name)
	if decl == nil {
		t.Fatalf("synthetic source has no (%s).%s method", recv, name)
	}
	return decl
}

// findFuncDecl returns the top-level (non-method) function declaration
// named `name`, or nil if none exists. Methods are ignored — use
// findMethodDecl for those.
func findFuncDecl(file *ast.File, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Recv != nil {
			continue
		}
		if fn.Name != nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// findMethodDecl returns the method declaration `name` on the receiver
// type `recv` (pointer or value), or nil if none exists. The recv match
// strips a leading `*` so `*AESGCM` and `AESGCM` both match `recv == "AESGCM"`.
func findMethodDecl(file *ast.File, recv, name string) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		if fn.Name == nil || fn.Name.Name != name {
			continue
		}
		got := recvTypeName(fn.Recv.List[0].Type)
		if strings.TrimPrefix(got, "*") == recv {
			return fn
		}
	}
	return nil
}

// recvTypeName renders a receiver type expression as a bare identifier
// (preserving a leading `*` for pointer receivers) so a string compare
// against the wanted type name is unambiguous.
func recvTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return "*" + id.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}
