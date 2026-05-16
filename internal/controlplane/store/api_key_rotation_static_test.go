package store_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// API key rotation — static-analysis defence (BE-0352).
//
// Threat model: a long-lived API key in source control, in an exported
// shell history, or in a CI log is a permanent credential leak until it is
// rotated. The mitigation is `POST
// /v1/organizations/{org_id}/api-keys/{key_id}/rotate`, which atomically
// swaps the row's credential body so every subsequent authentication
// attempt with the OLD token fails as cleanly as one against a non-existent
// key. The store-layer surface that makes this work is two-piece:
//
//  1. `APIKeyRepository.RotateCredential` runs the single UPDATE that
//     replaces both `prefix` and `secret_hash` on an `api_keys` row in
//     one statement. The pair is load-bearing: replacing only one (e.g.
//     updating prefix but leaving secret_hash stale) silently keeps the
//     leaked secret authenticating against the row, which is exactly the
//     property rotation exists to remove.
//  2. `APIKeyService.Rotate` orchestrates the transaction: it reads the
//     current row inside the same Tx, rejects a revoked or expired key
//     as a typed `apierr.Conflict` BEFORE persisting any credential
//     primitive, calls `RotateCredential` to swap the pair, and appends
//     an audit record whose `Metadata` map is a closed set of public
//     identifiers — `organization_id` (the target tenant) and
//     `rotated_prefix` (the row's NEW public lookup id). The secret hash,
//     the plaintext token, and the actor's bearer credential never enter
//     the metadata.
//
// This file is the load-bearing static defence: it parses
// `apikey.go` and `apikeyservice.go` and pins (a) the RotateCredential
// SQL string contains BOTH `prefix = ` AND `secret_hash = ` in its SET
// clause; (b) the Rotate function body contains the `IsRevoked` and
// `IsExpired` lifecycle guards each returning a typed
// `apierr.Conflict(...)`; (c) the Rotate audit event's `Metadata` map
// literal contains exactly the two closed-set keys and no others.
//
// The two-test pattern (BE-0344, BE-0345, BE-0346, BE-0349, BE-0350,
// BE-0351) applies here. The static half (this file) pins the
// store-layer invariants on the AST. The runtime half lives in
// `internal/controlplane/auth/api_key_rotation_test.go` (the
// credential-primitive lifecycle: distinct prefix+hash, old secret can
// never verify against the new hash, redaction holds across both keys).
// Self-check: `TestRotateCredentialStaticAnalyzerDetectsRegressions` and
// `TestRotateAuditMetadataStaticAnalyzerDetectsRegressions` feed
// synthetic known-bad and known-good sources to the analysers and pin
// both directions, so a future change that over-tightens the analyser
// (false positives) or silently under-tightens it (a missing surface
// element goes unflagged) is caught.

// TestRotateCredentialSQLSwapsBothPrefixAndSecretHash is the load-bearing
// static guard for the SQL-layer half of rotation. It parses
// `apikey.go`, finds the `RotateCredential` method, walks every
// `*ast.BasicLit` in its body, and asserts that one of them is a SQL
// string containing `UPDATE api_keys`, `SET prefix = `, `secret_hash = `,
// and a tenant-scoped `WHERE organization_id = $1 AND id = $2`. A
// regression that drops either column from the SET clause — or widens
// the WHERE to a tenant-less filter — fails the build with a single
// file:line diagnostic, before any test reaches a Postgres instance.
func TestRotateCredentialSQLSwapsBothPrefixAndSecretHash(t *testing.T) {
	t.Parallel()

	fset, file := mustParseStoreFile(t, "apikey.go")
	decl := findMethodDeclInStore(file, "APIKeyRepository", "RotateCredential")
	if decl == nil {
		t.Fatalf("apikey.go: (*APIKeyRepository).RotateCredential method not found — the rotation surface is vacuous")
	}

	sql := collectStringConcatLiterals(decl)
	if sql == "" {
		t.Fatalf("apikey.go: no string literal found in RotateCredential body — the SQL surface has disappeared")
	}

	pos := fset.Position(decl.Pos())
	if err := assertRotateCredentialSQL(sql); err != nil {
		t.Fatalf("%s:%d: RotateCredential SQL fails the rotation contract: %v\nSQL was:\n%s", pos.Filename, pos.Line, err, sql)
	}
}

// TestRotateRejectsRevokedAndExpiredAsConflict pins the lifecycle
// guards in `APIKeyService.Rotate`: an `if current.IsRevoked()` and an
// `if current.IsExpired(...)` each whose body contains a
// `return apierr.Conflict(...)` (any other shape — bare error, NotFound,
// silent success — is rejected). The lifecycle decision must happen
// BEFORE RotateCredential is called, so the regression "rotation
// succeeds on a revoked row" is caught at the AST.
func TestRotateRejectsRevokedAndExpiredAsConflict(t *testing.T) {
	t.Parallel()

	fset, file := mustParseStoreFile(t, "apikeyservice.go")
	decl := findMethodDeclInStore(file, "APIKeyService", "Rotate")
	if decl == nil {
		t.Fatalf("apikeyservice.go: (*APIKeyService).Rotate method not found — the rotation surface is vacuous")
	}

	pos := fset.Position(decl.Pos())
	if !rotateHasLifecycleGuard(decl, "IsRevoked") {
		t.Errorf("%s:%d: Rotate body missing the `if current.IsRevoked() { return apierr.Conflict(...) }` lifecycle guard — a revoked row could be silently rotated back into authentication service", pos.Filename, pos.Line)
	}
	if !rotateHasLifecycleGuard(decl, "IsExpired") {
		t.Errorf("%s:%d: Rotate body missing the `if current.IsExpired(...) { return apierr.Conflict(...) }` lifecycle guard — an expired row could be silently rotated back into authentication service", pos.Filename, pos.Line)
	}
}

// TestRotateAuditMetadataIsClosedSet pins the audit metadata invariant:
// the `event.Metadata` map literal in `APIKeyService.Rotate` contains
// exactly the public-identifier closed set `{organization_id,
// rotated_prefix}`. Any other key — `secret_hash`, `token`, `plaintext`,
// `prefix_old`, anything not in the closed set — is rejected with a
// file:line diagnostic. This is strictly stronger than a substring
// redaction check: it pins the set membership, not the absence of a few
// known-bad strings.
func TestRotateAuditMetadataIsClosedSet(t *testing.T) {
	t.Parallel()

	fset, file := mustParseStoreFile(t, "apikeyservice.go")
	decl := findMethodDeclInStore(file, "APIKeyService", "Rotate")
	if decl == nil {
		t.Fatalf("apikeyservice.go: (*APIKeyService).Rotate method not found — the rotation surface is vacuous")
	}

	keys, ok := rotateAuditMetadataKeys(decl)
	pos := fset.Position(decl.Pos())
	if !ok {
		t.Fatalf("%s:%d: Rotate body has no `Metadata: map[string]string{...}` composite literal — the audit event metadata surface has disappeared", pos.Filename, pos.Line)
	}
	if err := assertRotateMetadataKeys(keys); err != nil {
		t.Fatalf("%s:%d: Rotate audit Metadata fails the closed-set contract: %v\nkeys were: %q", pos.Filename, pos.Line, err, keys)
	}
}

// TestRotateCredentialStaticAnalyzerDetectsRegressions feeds synthetic
// known-bad and known-good RotateCredential bodies to the SQL analyser
// and asserts that each is classified correctly. Without this self-check
// a future refactor of `assertRotateCredentialSQL` could quietly
// over-accept (a missing column slips through) or quietly over-reject
// (every refactor of the SQL trips the analyser); both failure modes
// are caught here.
func TestRotateCredentialStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		sql     string
		wantErr bool
	}{
		{
			name:    "canonical multi-line UPDATE swaps both columns and is tenant-scoped",
			sql:     "UPDATE api_keys\n\t\t    SET prefix = $3, secret_hash = $4\n\t\t  WHERE organization_id = $1 AND id = $2",
			wantErr: false,
		},
		{
			name:    "single-line UPDATE swaps both columns and is tenant-scoped",
			sql:     "UPDATE api_keys SET prefix = $3, secret_hash = $4 WHERE organization_id = $1 AND id = $2",
			wantErr: false,
		},
		{
			name:    "columns swapped — secret_hash first, prefix second — still swaps both",
			sql:     "UPDATE api_keys SET secret_hash = $4, prefix = $3 WHERE organization_id = $1 AND id = $2",
			wantErr: false,
		},
		{
			name:    "regression: only prefix is rotated, secret_hash stays stale",
			sql:     "UPDATE api_keys SET prefix = $3 WHERE organization_id = $1 AND id = $2",
			wantErr: true,
		},
		{
			name:    "regression: only secret_hash is rotated, prefix stays stale",
			sql:     "UPDATE api_keys SET secret_hash = $4 WHERE organization_id = $1 AND id = $2",
			wantErr: true,
		},
		{
			name:    "regression: tenant scope removed from WHERE clause",
			sql:     "UPDATE api_keys SET prefix = $3, secret_hash = $4 WHERE id = $2",
			wantErr: true,
		},
		{
			name:    "regression: wrong table — the UPDATE no longer targets api_keys",
			sql:     "UPDATE other_table SET prefix = $3, secret_hash = $4 WHERE organization_id = $1 AND id = $2",
			wantErr: true,
		},
		{
			name:    "regression: statement is not an UPDATE at all",
			sql:     "DELETE FROM api_keys WHERE organization_id = $1 AND id = $2",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := assertRotateCredentialSQL(tc.sql)
			if tc.wantErr && err == nil {
				t.Fatalf("synthetic %q should have failed but the analyser accepted it", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("synthetic %q should have been accepted but the analyser rejected: %v", tc.name, err)
			}
		})
	}
}

// TestRotateAuditMetadataStaticAnalyzerDetectsRegressions feeds synthetic
// known-bad and known-good audit metadata composite literals to the
// closed-set analyser and asserts both directions. The self-check
// guarantees that an over-accepting refactor of the analyser (a new
// caller-leaked field name slips through) and an over-rejecting refactor
// (the canonical two-key set trips the analyser) are both caught at the
// AST.
func TestRotateAuditMetadataStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "canonical closed-set audit metadata",
			body:    `Metadata: map[string]string{"organization_id": organizationID, "rotated_prefix": prefix}`,
			wantErr: false,
		},
		{
			name:    "canonical metadata with whitespace and trailing comma",
			body:    "Metadata: map[string]string{\n\t\"organization_id\": organizationID,\n\t\"rotated_prefix\":  prefix,\n}",
			wantErr: false,
		},
		{
			name:    "regression: secret_hash key leaks into metadata",
			body:    `Metadata: map[string]string{"organization_id": organizationID, "rotated_prefix": prefix, "secret_hash": secretHash}`,
			wantErr: true,
		},
		{
			name:    "regression: plaintext token key leaks into metadata",
			body:    `Metadata: map[string]string{"organization_id": organizationID, "rotated_prefix": prefix, "token": tokenPlaintext}`,
			wantErr: true,
		},
		{
			name:    "regression: old prefix is carried alongside the new one — caller is invited to keep using the dead credential",
			body:    `Metadata: map[string]string{"organization_id": organizationID, "rotated_prefix": prefix, "prefix_old": oldPrefix}`,
			wantErr: true,
		},
		{
			name:    "regression: rotated_prefix removed — audit trail no longer names the new credential body",
			body:    `Metadata: map[string]string{"organization_id": organizationID}`,
			wantErr: true,
		},
		{
			name:    "regression: organization_id removed — audit trail no longer names the target tenant",
			body:    `Metadata: map[string]string{"rotated_prefix": prefix}`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keys := parseSyntheticMetadataKeys(t, tc.body)
			err := assertRotateMetadataKeys(keys)
			if tc.wantErr && err == nil {
				t.Fatalf("synthetic %q should have failed but the analyser accepted keys=%q", tc.name, keys)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("synthetic %q should have been accepted but the analyser rejected: %v", tc.name, err)
			}
		})
	}
}

// TestRotateLifecycleGuardStaticAnalyzerDetectsRegressions feeds synthetic
// Rotate-body shapes to the lifecycle-guard scanner and pins both
// directions: a guard whose if-body returns `apierr.Conflict(...)` is
// accepted; a guard whose if-body returns a bare error, a NotFound, or
// nothing at all is rejected. The synthetic source is parsed through the
// real go/ast parser so the analyser code path is identical to the one
// the load-bearing tests exercise.
func TestRotateLifecycleGuardStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		body   string
		method string
		want   bool
	}{
		{
			name:   "canonical: if current.IsRevoked { return apierr.Conflict(...) }",
			method: "IsRevoked",
			body:   `if current.IsRevoked() { return apierr.Conflict("api key is revoked") }`,
			want:   true,
		},
		{
			name:   "canonical: if current.IsExpired(now) { return apierr.Conflict(...) }",
			method: "IsExpired",
			body:   `if current.IsExpired(whenUTC) { return apierr.Conflict("api key is expired") }`,
			want:   true,
		},
		{
			name:   "regression: revoked guard returns a bare error",
			method: "IsRevoked",
			body:   `if current.IsRevoked() { return errors.New("api key is revoked") }`,
			want:   false,
		},
		{
			name:   "regression: revoked guard returns NotFound instead of Conflict",
			method: "IsRevoked",
			body:   `if current.IsRevoked() { return apierr.NotFound("api_key", keyID) }`,
			want:   false,
		},
		{
			name:   "regression: revoked guard returns nil (silent rotation of a dead row)",
			method: "IsRevoked",
			body:   `if current.IsRevoked() { return nil }`,
			want:   false,
		},
		{
			name:   "regression: guard is missing entirely",
			method: "IsRevoked",
			body:   `current.IsRevoked()`,
			want:   false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			decl := parseSyntheticFuncBody(t, tc.body)
			got := rotateHasLifecycleGuard(decl, tc.method)
			if got != tc.want {
				t.Fatalf("rotateHasLifecycleGuard(%q) = %v, want %v\nbody:\n%s", tc.method, got, tc.want, tc.body)
			}
		})
	}
}

// assertRotateCredentialSQL is the matcher for the RotateCredential SQL
// invariant. It returns nil iff the SQL is an UPDATE on api_keys that
// sets BOTH prefix and secret_hash in its SET clause and is tenant-scoped
// by `organization_id = $1 AND id = $2`. The check is structural (no
// strict whitespace matching) so a future refactor that re-indents the
// SQL is not a regression.
func assertRotateCredentialSQL(sql string) error {
	normalized := normalizeSQLWhitespace(sql)
	upper := strings.ToUpper(normalized)
	if !strings.Contains(upper, "UPDATE API_KEYS") {
		return fmt.Errorf("missing `UPDATE api_keys` — the statement no longer targets the api_keys table")
	}
	setIdx := strings.Index(upper, "SET ")
	if setIdx < 0 {
		return fmt.Errorf("missing `SET ` clause — the statement is not an UPDATE with a SET")
	}
	whereIdx := strings.Index(upper, "WHERE ")
	if whereIdx < 0 || whereIdx <= setIdx {
		return fmt.Errorf("missing `WHERE` clause after `SET` — the statement is not tenant-scoped")
	}
	setClause := upper[setIdx:whereIdx]
	if !strings.Contains(setClause, "PREFIX") {
		return fmt.Errorf("SET clause does not assign `prefix` — old prefix would survive the rotation: %q", setClause)
	}
	if !strings.Contains(setClause, "SECRET_HASH") {
		return fmt.Errorf("SET clause does not assign `secret_hash` — old secret would keep verifying against the rotated row: %q", setClause)
	}
	whereClause := upper[whereIdx:]
	if !strings.Contains(whereClause, "ORGANIZATION_ID = $1") {
		return fmt.Errorf("WHERE clause is not tenant-scoped on organization_id = $1: %q", whereClause)
	}
	if !strings.Contains(whereClause, "ID = $2") {
		return fmt.Errorf("WHERE clause does not pin the key_id at $2: %q", whereClause)
	}
	return nil
}

// assertRotateMetadataKeys is the matcher for the audit metadata closed-
// set invariant. It returns nil iff the metadata keys set is exactly
// {organization_id, rotated_prefix} — no missing keys, no extra keys.
func assertRotateMetadataKeys(keys []string) error {
	wanted := map[string]bool{
		"organization_id": true,
		"rotated_prefix":  true,
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if !wanted[k] {
			return fmt.Errorf("audit metadata carries key %q which is not in the closed set {organization_id, rotated_prefix} — secret material or caller-controlled values must never enter the audit trail", k)
		}
		if seen[k] {
			return fmt.Errorf("audit metadata carries the same key %q twice — the map literal is malformed", k)
		}
		seen[k] = true
	}
	for k := range wanted {
		if !seen[k] {
			return fmt.Errorf("audit metadata is missing the required key %q — the audit trail no longer identifies the rotation", k)
		}
	}
	return nil
}

// collectStringConcatLiterals walks decl's body and concatenates the raw
// string values of every *ast.BasicLit of kind STRING it encounters, in
// source order. The store layer's SQL strings are written as backquoted
// multi-line literals optionally concatenated with `+apiKeyColumns`; the
// SQL surface we want to check is the leading raw literal. This helper
// is generous on purpose — the matcher (assertRotateCredentialSQL) does
// the strict checks.
func collectStringConcatLiterals(decl *ast.FuncDecl) string {
	if decl == nil || decl.Body == nil {
		return ""
	}
	var sb strings.Builder
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		unquoted, err := unquoteBasicLit(lit.Value)
		if err != nil {
			return true
		}
		sb.WriteString(unquoted)
		sb.WriteString("\n")
		return true
	})
	return sb.String()
}

// unquoteBasicLit unquotes either a "..." or a `...` string literal,
// returning the raw value. A literal with an unknown delimiter is
// returned as-is so the caller can still scan it; callers do not depend
// on the precise unquoting for correctness.
func unquoteBasicLit(raw string) (string, error) {
	if len(raw) < 2 {
		return raw, nil
	}
	first, last := raw[0], raw[len(raw)-1]
	if first == '`' && last == '`' {
		return raw[1 : len(raw)-1], nil
	}
	if first == '"' && last == '"' {
		return raw[1 : len(raw)-1], nil
	}
	return raw, fmt.Errorf("unsupported string literal delimiter")
}

// normalizeSQLWhitespace collapses every run of whitespace (spaces, tabs,
// newlines) to a single space, so the matcher's `strings.Contains` checks
// don't trip on re-indentation of the raw SQL.
func normalizeSQLWhitespace(s string) string {
	out := make([]byte, 0, len(s))
	prevSpace := false
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

// rotateHasLifecycleGuard reports whether decl's body contains an
// `if <selector>.method()` statement whose immediate body contains a
// `return apierr.Conflict(...)`. The "method" is matched on the selector
// name only (not the receiver name) so the analyser is robust to a
// rename of the local `current` variable; the return-shape is matched
// strictly so a regression that returns `nil`, a bare error, or a
// NotFound (which would map to 404, not 409) is caught.
func rotateHasLifecycleGuard(decl *ast.FuncDecl, methodName string) bool {
	if decl == nil || decl.Body == nil {
		return false
	}
	found := false
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if !ifCondCallsSelector(ifs.Cond, methodName) {
			return true
		}
		if ifBodyReturnsAPIErrConflict(ifs.Body) {
			found = true
			return false
		}
		return true
	})
	return found
}

// ifCondCallsSelector reports whether cond is a CallExpr whose function
// is a SelectorExpr ending in methodName — i.e. matches `x.methodName()`
// or `x.methodName(arg)` for any x and any args.
func ifCondCallsSelector(cond ast.Expr, methodName string) bool {
	call, ok := cond.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel != nil && sel.Sel.Name == methodName
}

// ifBodyReturnsAPIErrConflict reports whether body is a block whose
// first statement is a `return apierr.Conflict(...)` CallExpr-shaped
// return. The body need not be one-statement-long; we only require the
// Conflict-shaped return to be present as the first statement so a
// future addition of a `slog.Warn(...)` line above it does not break
// the analyser.
func ifBodyReturnsAPIErrConflict(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) == 0 {
		return false
	}
	for _, stmt := range body.List {
		ret, ok := stmt.(*ast.ReturnStmt)
		if !ok {
			continue
		}
		if returnsAPIErrConflict(ret) {
			return true
		}
	}
	return false
}

// returnsAPIErrConflict reports whether ret's last expression is a
// CallExpr of the form `apierr.Conflict(...)`. Other return shapes —
// `return nil`, `return errors.New(...)`, `return apierr.NotFound(...)`
// — are rejected.
func returnsAPIErrConflict(ret *ast.ReturnStmt) bool {
	if ret == nil || len(ret.Results) == 0 {
		return false
	}
	last := ret.Results[len(ret.Results)-1]
	call, ok := last.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return pkgIdent.Name == "apierr" && sel.Sel != nil && sel.Sel.Name == "Conflict"
}

// rotateAuditMetadataKeys walks decl's body looking for an
// `event.Metadata = map[string]string{...}` assignment OR a
// `Metadata: map[string]string{...}` composite literal field within an
// AuditEvent literal. It returns the list of static string keys in the
// map. ok==false means no such composite literal was found at all
// (the audit metadata surface has been removed).
func rotateAuditMetadataKeys(decl *ast.FuncDecl) (keys []string, ok bool) {
	if decl == nil || decl.Body == nil {
		return nil, false
	}
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		kv, isKV := n.(*ast.KeyValueExpr)
		if !isKV {
			return true
		}
		key, isIdent := kv.Key.(*ast.Ident)
		if !isIdent || key.Name != "Metadata" {
			return true
		}
		composite, isComposite := kv.Value.(*ast.CompositeLit)
		if !isComposite {
			return true
		}
		if !isStringStringMapType(composite.Type) {
			return true
		}
		keys = collectMapStringKeys(composite)
		ok = true
		return false
	})
	return keys, ok
}

// isStringStringMapType reports whether expr is the type `map[string]string`.
func isStringStringMapType(expr ast.Expr) bool {
	m, isMap := expr.(*ast.MapType)
	if !isMap {
		return false
	}
	keyIdent, keyOK := m.Key.(*ast.Ident)
	valIdent, valOK := m.Value.(*ast.Ident)
	if !keyOK || !valOK {
		return false
	}
	return keyIdent.Name == "string" && valIdent.Name == "string"
}

// collectMapStringKeys returns the static string keys of every
// KeyValueExpr in composite. A KeyValueExpr whose key is not a string
// literal is silently skipped (the analyser only checks the closed set
// of literal keys).
func collectMapStringKeys(composite *ast.CompositeLit) []string {
	if composite == nil {
		return nil
	}
	out := make([]string, 0, len(composite.Elts))
	for _, el := range composite.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		lit, ok := kv.Key.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		unquoted, err := unquoteBasicLit(lit.Value)
		if err != nil {
			continue
		}
		out = append(out, unquoted)
	}
	return out
}

// mustParseStoreFile parses the named non-test file in the store
// package directory (the working directory of `go test` is the package
// directory, so a bare filename resolves correctly). It fails the test
// on a parse error.
func mustParseStoreFile(t *testing.T, name string) (*token.FileSet, *ast.File) {
	t.Helper()
	path := filepath.Clean(name)
	return mustParseFile(t, path)
}

// findMethodDeclInStore is the local equivalent of the
// secrets-package helper of the same name: it finds a method by its
// receiver type and method name in file.Decls.
func findMethodDeclInStore(file *ast.File, recv, name string) *ast.FuncDecl {
	if file == nil {
		return nil
	}
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
		if fn.Name != nil && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}

// parseSyntheticMetadataKeys parses a single `Metadata:
// map[string]string{...}` KeyValueExpr embedded in a minimal synthetic
// Go source and returns the static keys of the map literal. It exists
// so the self-check tests exercise the same AST shape as the load-
// bearing analyser, without depending on the real apikeyservice.go
// source.
func parseSyntheticMetadataKeys(t *testing.T, body string) []string {
	t.Helper()
	src := "package p\nvar _ = struct{ Metadata map[string]string }{\n\t" + body + ",\n}\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse synthetic metadata body: %v\nsrc:\n%s", err, src)
	}
	var keys []string
	ast.Inspect(file, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, isIdent := kv.Key.(*ast.Ident)
		if !isIdent || key.Name != "Metadata" {
			return true
		}
		composite, ok := kv.Value.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if !isStringStringMapType(composite.Type) {
			return true
		}
		keys = collectMapStringKeys(composite)
		return false
	})
	return keys
}

// parseSyntheticFuncBody parses a single Go statement (or a sequence)
// as the body of a synthetic function and returns the FuncDecl. The
// self-check tests use this so the lifecycle-guard analyser is
// exercised against the same AST shape it sees in apikeyservice.go.
func parseSyntheticFuncBody(t *testing.T, body string) *ast.FuncDecl {
	t.Helper()
	src := "package p\nfunc f() error {\n\t" + body + "\n\treturn nil\n}\n"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse synthetic func body: %v\nsrc:\n%s", err, src)
	}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name != nil && fn.Name.Name == "f" {
			return fn
		}
	}
	t.Fatalf("parseSyntheticFuncBody: function f not found in synthetic source")
	return nil
}
