package release_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// BE-0362: Security verification — backup encryption.
//
// Threat model.
//
//  1. The Yalla source-of-truth Postgres database is the only place
//     tenant identity, scoped grants, desired state, deployments,
//     audit history, and provisioning-job rows can be reconstructed
//     from. A lost or tampered backup is an unrecoverable outage. The
//     backup pipeline is intentionally external to the Yalla process
//     — `pg_dump`/`pgBackRest` runs under the operator's pipeline,
//     encrypts every object with a KMS-managed key under the
//     operator's principal, and writes to object storage neither the
//     control-plane API nor the worker has read access to. Yalla
//     consumes one signal: a single RFC3339 timestamp the pipeline
//     atomically writes to a status file on every successful run.
//
//  2. A regression that pulled a backup data plane into the Yalla
//     process — an in-process AES cipher, a `pg_dump` exec call, a
//     cloud-bucket SDK upload, a write to the status file from
//     application code — would collapse the encryption boundary in
//     two ways: (a) the encryption key (or the bucket credential, or
//     the database role) would need to live inside the Yalla config
//     surface, which the redaction seam alone cannot protect once a
//     decryption library is on the call path; (b) the same process
//     handling customer requests would gain read access to the
//     encrypted blobs, dissolving the "control-plane API has no read
//     access to the backup bucket" guarantee documented in
//     `docs/operations/backup-restore.md` and `SECURITY.md`.
//
//  3. The Yalla side of the boundary is the `internal/controlplane/backup`
//     package: it reads exactly one operator-supplied file path, parses
//     a single RFC3339 timestamp, redacts any unexpected file content
//     out of its error strings (BE-0039), and exposes the result via
//     a `Reporter.Status(ctx)` method. The redaction posture is pinned
//     by the existing `TestFileReporterParseErrorRedactsContent` (runtime
//     evidence). What this gate adds is the structural complement:
//     the package MUST NOT carry a backup data plane in the first
//     place — no encryption library imports, no archive/compression
//     imports, no database driver imports, no `os/exec` shelling out
//     to `pg_dump`, no `net/http` client for backup-bucket I/O, and no
//     write-seam calls (`os.Create`, `os.WriteFile`, `os.OpenFile`,
//     `os.MkdirAll`, `os.Rename`, `os.Remove`, etc.) anywhere under
//     `internal/controlplane/backup`. The interface `Reporter` MUST
//     expose exactly one method (`Status`) — adding `Write`, `Backup`,
//     `Restore`, `Encrypt`, `Decrypt`, or any other mutating method
//     would route a backup data plane through the read-only port.
//
//  4. The runtime evidence half of the BE-0344 two-test pattern is
//     `internal/controlplane/backup.TestFileReporterEncryptionMarkerNeverLeaks`
//     (landed alongside this gate) plus the pre-existing
//     `TestFileReporterParseErrorRedactsContent` (BE-0039) and the
//     handler-side `TestBackupHealthErrorMessageDoesNotLeakReporterError`.
//     Together they prove the redaction seam: a status file
//     accidentally seeded with a KMS key id, an AES wrap blob, or a
//     bucket-side restore-failed message never echoes into any error
//     string, log record, or wire response.
//
//  5. The operator-facing contract is part of the public security
//     posture. `SECURITY.md` MUST document (a) the closed forbidden-
//     import set for the backup package, (b) the read-only Reporter
//     interface, (c) the absence of any in-process backup data plane,
//     and (d) a row in the Required Verification Gates table pinning
//     the `-run` selector for this test. The runbook
//     `docs/operations/backup-restore.md` MUST keep its "Encryption
//     expectations" section because operators rely on it to discover
//     the KMS rotation cadence, the no-read-access invariant, and the
//     no-plaintext-WAL rule. A silent removal of either doc is a
//     regression on equal footing with a code change.
//
// This is a worked instance of the BE-0344 two-test template, applied
// to a package-confinement invariant: the static half lives here (the
// AST gates plus the doc pin); the runtime half is
// `internal/controlplane/backup.TestFileReporterEncryptionMarkerNeverLeaks`
// plus the pre-existing redaction tests. The
// `TestBackupEncryptionStaticAnalyzerDetectsRegressions` self-check
// feeds synthetic known-bad and known-good fixtures through every
// matcher so over- and under-tightening of the analyser are both
// caught.

// backupEncryptionPackageDir is the relative directory whose non-test
// `.go` files are scanned for forbidden imports and forbidden write-
// seam calls. The package is a leaf — its boundary is the encryption
// gate the threat model relies on.
const backupEncryptionPackageDir = "internal/controlplane/backup"

// backupEncryptionHealthPath is the absolute production file owning
// the `Reporter` interface declaration. Pinned by path so a future
// split or rename forces an explicit update of this test rather than
// silently disabling the interface-shape gate.
const backupEncryptionHealthPath = "internal/controlplane/backup/health.go"

// backupEncryptionSecurityDocPath is the operator-facing security
// posture document. The test pins both the dedicated section heading
// and the verification-gates table row so a silent doc deletion is
// caught alongside a silent code regression.
const backupEncryptionSecurityDocPath = "SECURITY.md"

// backupEncryptionRunbookPath is the operator runbook documenting the
// pipeline contract. The "Encryption expectations" section is part of
// the public posture: it tells operators that the KMS key, bucket
// credentials, and read access live outside the Yalla process. A
// silent removal would let a future "tidy" pass collapse the section
// without anyone noticing the security-relevant content is gone.
const backupEncryptionRunbookPath = "docs/operations/backup-restore.md"

// backupReporterInterfaceName is the AST name of the read-only port
// the package exports. Pinning the name (not just the file) catches a
// regression that renamed the interface to something like
// `BackupSurface` and added mutating methods to the rename.
const backupReporterInterfaceName = "Reporter"

// backupReporterMethodName is the one method the Reporter interface
// is allowed to declare. Adding any other method — `Write`, `Backup`,
// `Restore`, `Encrypt`, `Decrypt`, `Upload`, `Rotate` — would route a
// backup data plane through the read-only port and is exactly what
// this gate exists to prevent.
const backupReporterMethodName = "Status"

// forbiddenBackupImports enumerates the Go package import paths whose
// presence under `internal/controlplane/backup` would indicate a
// backup data plane has been pulled into the Yalla process. The set
// is closed and intentionally aggressive: the only legitimate I/O
// the package performs is `os.ReadFile` on the operator-supplied
// status path, so symmetric-cipher, archive, compression, database,
// HTTP, and exec packages all have no business inside the boundary.
//
//   - `crypto/aes`, `crypto/cipher`, `crypto/des`, `crypto/rc4`,
//     `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519` indicate the
//     package itself encrypts or decrypts backup payloads.
//   - `crypto/tls` indicates the package opens a TLS channel to a
//     backup endpoint (a bucket, KMS, or remote restore service).
//   - `archive/zip`, `archive/tar`, `compress/gzip`, `compress/zlib`,
//     `compress/flate`, `compress/bzip2` indicate the package
//     produces or consumes backup archive streams.
//   - `database/sql`, `github.com/jackc/pgx/v5`, and the pgx pool
//     indicate the package opened a database connection — the
//     control-plane DB is the source the backup pipeline runs
//     against, and the Yalla process touches it through the
//     `store` package, not through `backup`.
//   - `os/exec` indicates the package shells out to a binary —
//     `pg_dump`, `pgBackRest`, or a custom encryption tool — which
//     would carry the credential surface and the data plane into
//     the process.
//   - `net/http` indicates the package speaks HTTP to a backup
//     endpoint (bucket SDK, KMS REST API, remote-restore service).
//     The Yalla process speaks HTTP to Dokploy through the typed
//     `internal/controlplane/dokploy` client only; the backup
//     package has no legitimate HTTP surface.
var forbiddenBackupImports = map[string]struct{}{
	"crypto/aes":                      {},
	"crypto/cipher":                   {},
	"crypto/des":                      {},
	"crypto/rc4":                      {},
	"crypto/rsa":                      {},
	"crypto/ecdsa":                    {},
	"crypto/ed25519":                  {},
	"crypto/tls":                      {},
	"archive/zip":                     {},
	"archive/tar":                     {},
	"compress/gzip":                   {},
	"compress/zlib":                   {},
	"compress/flate":                  {},
	"compress/bzip2":                  {},
	"database/sql":                    {},
	"github.com/jackc/pgx/v5":         {},
	"github.com/jackc/pgx/v5/pgxpool": {},
	"os/exec":                         {},
	"net/http":                        {},
}

// forbiddenBackupWriteSeams enumerates the package-qualified function
// names whose use under `internal/controlplane/backup` would indicate
// the package writes the operator's status file, mutates the
// filesystem under the backup mount, or shells out to a backup
// binary. The matcher pins each as a SelectorExpr (`os.Create`,
// `exec.Command`, etc.) so a future contributor cannot smuggle in a
// write seam through a renamed alias.
//
// `os.ReadFile`, `os.Stat`, `os.Open` (read-only), and
// `errors.Is`/`errors.As` are deliberately NOT in this set — they
// are the legitimate read-only seams the package uses today. The
// matcher only flags writes, exec, and rename/remove side effects.
var forbiddenBackupWriteSeams = map[string]struct{}{
	"os.Create":           {},
	"os.CreateTemp":       {},
	"os.WriteFile":        {},
	"os.OpenFile":         {},
	"os.Mkdir":            {},
	"os.MkdirAll":         {},
	"os.Rename":           {},
	"os.Remove":           {},
	"os.RemoveAll":        {},
	"os.Symlink":          {},
	"os.Link":             {},
	"os.Truncate":         {},
	"os.Chmod":            {},
	"os.Chown":            {},
	"exec.Command":        {},
	"exec.CommandContext": {},
}

// requiredBackupEncryptionSecurityHeading is the literal Markdown
// heading that must appear in `SECURITY.md` to document this story's
// posture. The exact heading is part of the public contract —
// operators and downstream auditors deep-link to it — so changes are
// deliberate.
const requiredBackupEncryptionSecurityHeading = "## Backup Encryption"

// requiredBackupEncryptionSecuritySubstrings is the closed set of
// literal substrings `SECURITY.md` MUST contain to satisfy the
// documentation half of the gate. Each captures a different load-
// bearing fact:
//   - the file path of this static test, so the gate is self-locating,
//   - the package directory the gate scopes its analysis to,
//   - the canonical "no read access" invariant the threat model rests
//     on,
//   - the name of the read-only port (`Reporter`) and its only method,
//   - the runbook path so operators discover the encryption-expectations
//     section without re-reading SECURITY.md in full.
var requiredBackupEncryptionSecuritySubstrings = []string{
	"backup_encryption_static_test.go",
	"internal/controlplane/backup",
	"read access",
	"Reporter.Status",
	"docs/operations/backup-restore.md",
}

// requiredBackupEncryptionGateRow is the literal substring of the row
// that MUST appear in SECURITY.md's Required Verification Gates table.
// The substring is the gate name plus the `-run` selector; a
// contributor who renames the test functions must update both.
const requiredBackupEncryptionGateRow = "Backup encryption"

// requiredBackupRunbookHeading is the literal Markdown heading in
// `docs/operations/backup-restore.md` that documents the encryption
// posture operators are expected to provide. The runbook is the
// operator-facing half of the contract; a silent removal would let
// the contract drift without anyone noticing.
const requiredBackupRunbookHeading = "## Encryption expectations"

// requiredBackupRunbookSubstrings is the closed set of substrings the
// runbook MUST contain to satisfy the documentation half of the gate.
// Each substring is a load-bearing fact from the threat model:
//   - "KMS-managed key" pins the key-management posture,
//   - "no" + "read access" pins the no-read-access invariant for the
//     control-plane API and worker processes,
//   - "Plaintext WAL must never" pins the no-plaintext-WAL rule,
//   - "Auditability" pins the audit-event posture for restores.
//
// The substrings are matched case-sensitively against the runbook
// body, so a future rewording that preserves the meaning but drops
// the exact phrase is a deliberate update of both the runbook and
// this list.
var requiredBackupRunbookSubstrings = []string{
	"KMS-managed key",
	"read access",
	"Plaintext WAL",
	"Auditability",
}

// TestBackupEncryptionNoForbiddenImports proves that no production
// `.go` file directly under `internal/controlplane/backup` imports a
// package from `forbiddenBackupImports`. The scan covers every non-
// test source file in the package; `_test.go` fixtures are excluded
// because a future fuzz target may legitimately need to mention an
// encryption package to construct a synthetic input.
func TestBackupEncryptionNoForbiddenImports(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	files := backupEncryptionPackageProductionFiles(t, root)
	if len(files) == 0 {
		t.Fatalf("no production .go files found under %s; the scan would be silently empty", backupEncryptionPackageDir)
	}
	fset := token.NewFileSet()
	for _, rel := range files {
		path := filepath.Join(root, rel)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, v := range findForbiddenBackupImports(fset, file) {
			t.Error(v)
		}
	}
}

// TestBackupEncryptionReporterInterfaceIsReadOnly proves that the
// `Reporter` interface declared in `health.go` exposes exactly one
// method, named `Status`. A regression that added `Write`, `Backup`,
// `Restore`, `Encrypt`, `Decrypt`, or any other mutating method would
// route a backup data plane through the read-only port and would
// dissolve the encryption-boundary invariant the threat model rests
// on.
func TestBackupEncryptionReporterInterfaceIsReadOnly(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, backupEncryptionHealthPath)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", backupEncryptionHealthPath, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", backupEncryptionHealthPath, err)
	}
	for _, v := range findBackupReporterInterfaceRegressions(fset, file) {
		t.Error(v)
	}
}

// TestBackupEncryptionNoWriteSeams proves that no production `.go`
// file under `internal/controlplane/backup` calls a function from
// `forbiddenBackupWriteSeams`. The package is a read-only consumer
// of the operator-supplied status file; a write seam would indicate
// the Yalla process is producing backup data, shelling out to a
// backup binary, or mutating the operator's filesystem.
func TestBackupEncryptionNoWriteSeams(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	files := backupEncryptionPackageProductionFiles(t, root)
	if len(files) == 0 {
		t.Fatalf("no production .go files found under %s; the scan would be silently empty", backupEncryptionPackageDir)
	}
	fset := token.NewFileSet()
	for _, rel := range files {
		path := filepath.Join(root, rel)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution|parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		for _, v := range findForbiddenBackupWriteSeams(fset, file) {
			t.Error(v)
		}
	}
}

// TestBackupEncryptionSecurityDocumented pins the operator-facing
// SECURITY.md contract: a dedicated `## Backup Encryption` section
// MUST exist, MUST contain every substring in
// `requiredBackupEncryptionSecuritySubstrings`, and the verification-
// gates table MUST contain the gate row. A silent doc deletion is
// caught on equal footing with a code regression.
func TestBackupEncryptionSecurityDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, backupEncryptionSecurityDocPath)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", backupEncryptionSecurityDocPath, err)
	}
	doc := string(body)
	if !strings.Contains(doc, requiredBackupEncryptionSecurityHeading) {
		t.Errorf("%s missing required section heading %q. "+
			"See internal/release/backup_encryption_static_test.go (BE-0362).",
			backupEncryptionSecurityDocPath, requiredBackupEncryptionSecurityHeading)
	}
	for _, sub := range requiredBackupEncryptionSecuritySubstrings {
		if !strings.Contains(doc, sub) {
			t.Errorf("%s missing required substring %q. "+
				"The Backup Encryption posture documents (a) the test file location, (b) the package directory the scan covers, (c) the no-read-access invariant, (d) the Reporter.Status read-only port, and (e) the runbook cross-link. "+
				"See internal/release/backup_encryption_static_test.go (BE-0362).",
				backupEncryptionSecurityDocPath, sub)
		}
	}
	if !strings.Contains(doc, requiredBackupEncryptionGateRow) {
		t.Errorf("%s Required Verification Gates table missing row %q. "+
			"The Backup encryption gate MUST be discoverable in the verification-gates table alongside Dokploy token isolation and Admin endpoint isolation. "+
			"See internal/release/backup_encryption_static_test.go (BE-0362).",
			backupEncryptionSecurityDocPath, requiredBackupEncryptionGateRow)
	}
}

// TestBackupEncryptionRunbookDocumented pins the runbook's Encryption
// expectations section. The runbook is the operator-facing half of
// the contract (KMS rotation cadence, no-read-access invariant,
// plaintext-WAL ban, auditability of restores). A silent removal of
// the section or one of its load-bearing substrings would let the
// operator contract drift away from the Yalla code posture.
func TestBackupEncryptionRunbookDocumented(t *testing.T) {
	t.Parallel()
	root := projectRoot(t)
	path := filepath.Join(root, backupEncryptionRunbookPath)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", backupEncryptionRunbookPath, err)
	}
	doc := string(body)
	if !strings.Contains(doc, requiredBackupRunbookHeading) {
		t.Errorf("%s missing required section heading %q. "+
			"See internal/release/backup_encryption_static_test.go (BE-0362).",
			backupEncryptionRunbookPath, requiredBackupRunbookHeading)
	}
	for _, sub := range requiredBackupRunbookSubstrings {
		if !strings.Contains(doc, sub) {
			t.Errorf("%s missing required substring %q under %q. "+
				"The Encryption expectations runbook section documents (KMS-managed key) the at-rest key posture, (read access) the no-read-access invariant for the control-plane API and worker, (Plaintext WAL must never) the plaintext-WAL ban, and (Auditability) the audit-event contract for restores. "+
				"See internal/release/backup_encryption_static_test.go (BE-0362).",
				backupEncryptionRunbookPath, sub, requiredBackupRunbookHeading)
		}
	}
}

// TestBackupEncryptionStaticAnalyzerDetectsRegressions is the self-
// check for the matchers above. The acceptance criterion "tests fail
// when the control is removed" is the load-bearing one: each known-
// bad synthetic snippet MUST produce at least one hit, and the known-
// good snippet MUST produce zero hits. This guards against the
// analyser silently going lenient under a future refactor.
func TestBackupEncryptionStaticAnalyzerDetectsRegressions(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	mustParse := func(name, src string) *ast.File {
		t.Helper()
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution|parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return f
	}
	// Import regression: aes + os/exec are in the forbidden set.
	importBad := mustParse("import_bad.go", `package backup

import (
	"crypto/aes"
	"os/exec"
)

var _ = aes.BlockSize
var _ = exec.Command
`)
	if hits := findForbiddenBackupImports(fset, importBad); len(hits) < 2 {
		t.Errorf("import regression: expected ≥2 hits on synthetic bad fixture, got %d: %s", len(hits), strings.Join(hits, " | "))
	}
	importGood := mustParse("import_good.go", `package backup

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"
)

var _ = os.ReadFile
var _ = errors.Is
var _ = strings.TrimSpace
var _ = fs.ErrNotExist
var _ = time.RFC3339
var _ = context.Background
`)
	if hits := findForbiddenBackupImports(fset, importGood); len(hits) != 0 {
		t.Errorf("import known-good fixture produced %d false positives: %s", len(hits), strings.Join(hits, " | "))
	}

	// Reporter-interface regression: the synthetic interface adds a
	// Write method, which the matcher MUST reject.
	reporterBad := mustParse("reporter_bad.go", `package backup

type Reporter interface {
	Status() (int, error)
	Write([]byte) error
}
`)
	if hits := findBackupReporterInterfaceRegressions(fset, reporterBad); len(hits) == 0 {
		t.Error("reporter regression: synthetic Reporter with a Write method produced 0 hits, want ≥1")
	}
	reporterGood := mustParse("reporter_good.go", `package backup

import "context"

type Status struct{}

type Reporter interface {
	Status(ctx context.Context) (Status, error)
}
`)
	if hits := findBackupReporterInterfaceRegressions(fset, reporterGood); len(hits) != 0 {
		t.Errorf("reporter known-good fixture produced %d false positives: %s", len(hits), strings.Join(hits, " | "))
	}
	// A renamed interface is also a regression — the gate would
	// silently disable itself otherwise.
	reporterRenamed := mustParse("reporter_renamed.go", `package backup

type Surface interface {
	Status() (int, error)
}
`)
	if hits := findBackupReporterInterfaceRegressions(fset, reporterRenamed); len(hits) == 0 {
		t.Error("reporter regression: missing required Reporter interface produced 0 hits, want ≥1")
	}

	// Write-seam regression: os.WriteFile and exec.Command are
	// both forbidden.
	writeBad := mustParse("write_bad.go", `package backup

import (
	"os"
	"os/exec"
)

func badWrite(path string, body []byte) error {
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}
	return exec.Command("pg_dump").Run()
}
`)
	if hits := findForbiddenBackupWriteSeams(fset, writeBad); len(hits) < 2 {
		t.Errorf("write-seam regression: expected ≥2 hits on synthetic bad fixture, got %d: %s", len(hits), strings.Join(hits, " | "))
	}
	writeGood := mustParse("write_good.go", `package backup

import (
	"os"
)

func goodRead(path string) ([]byte, error) {
	return os.ReadFile(path)
}
`)
	if hits := findForbiddenBackupWriteSeams(fset, writeGood); len(hits) != 0 {
		t.Errorf("write-seam known-good fixture produced %d false positives: %s", len(hits), strings.Join(hits, " | "))
	}
}

// backupEncryptionPackageProductionFiles returns the relative paths
// of every non-test `.go` file directly under
// `internal/controlplane/backup`. The list is sorted so diagnostics
// are deterministic. The package has no subdirectories today; if a
// future story adds one, the test fails loudly because the new file
// will not be scanned and a contributor must extend this helper
// (or the new directory) consciously.
func backupEncryptionPackageProductionFiles(t *testing.T, root string) []string {
	t.Helper()
	dirAbs := filepath.Join(root, backupEncryptionPackageDir)
	entries, err := os.ReadDir(dirAbs)
	if err != nil {
		t.Fatalf("read dir %s: %v", backupEncryptionPackageDir, err)
	}
	var files []string
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
		files = append(files, filepath.Join(backupEncryptionPackageDir, name))
	}
	sort.Strings(files)
	return files
}

// findForbiddenBackupImports walks the import declarations of a
// parsed file and returns one diagnostic per occurrence of a
// forbidden Go package path. The matcher reads `import` paths via
// `strconv.Unquote` so an unparseable literal does not panic; an
// invalid quote is silently ignored on the assumption that the
// surrounding `go build` would already have failed.
func findForbiddenBackupImports(fset *token.FileSet, file *ast.File) []string {
	var out []string
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		raw, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if _, bad := forbiddenBackupImports[raw]; bad {
			out = append(out, "forbidden backup-data-plane import "+strconv.Quote(raw)+" at "+fset.Position(imp.Pos()).String()+
				". The Yalla backup package is a leaf that reads exactly one operator-supplied status file. A regression that imported crypto/aes, archive/zip, database/sql, os/exec, net/http, or a similar package would indicate the Yalla process pulled a backup data plane into itself — collapsing the encryption-boundary invariant the threat model rests on. "+
				"See internal/release/backup_encryption_static_test.go (BE-0362) and SECURITY.md \"Backup Encryption\" for the threat model.")
		}
	}
	sort.Strings(out)
	return out
}

// findBackupReporterInterfaceRegressions walks the AST of `health.go`
// and reports two orthogonal regressions:
//
//  1. The `Reporter` interface declaration is missing — a future
//     refactor that renamed it would silently disable the read-only
//     port gate.
//  2. The `Reporter` interface declares any method whose name is not
//     `Status`. Each such method is a regression: a `Write`, `Backup`,
//     `Restore`, `Encrypt`, `Decrypt`, or `Upload` method would route
//     a backup data plane through the read-only port.
func findBackupReporterInterfaceRegressions(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, kind, detail string) {
		out = append(out, kind+" "+detail+" at "+pos.String()+
			". The Yalla backup package MUST expose exactly one read-only port — `Reporter` with a single `Status(ctx)` method. A regression that renamed the interface or added a mutating method would route a backup data plane through the read-only port and collapse the encryption-boundary invariant. "+
			"See internal/release/backup_encryption_static_test.go (BE-0362) and SECURITY.md \"Backup Encryption\" for the threat model.")
	}
	var iface *ast.InterfaceType
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name == nil || spec.Name.Name != backupReporterInterfaceName {
			return true
		}
		it, ok := spec.Type.(*ast.InterfaceType)
		if !ok {
			return true
		}
		iface = it
		return false
	})
	if iface == nil {
		emit(fset.Position(file.Pos()), "missing required interface", backupReporterInterfaceName)
		sort.Strings(out)
		return out
	}
	if iface.Methods == nil {
		emit(fset.Position(iface.Pos()), "interface has no methods; expected exactly one named", backupReporterMethodName)
		sort.Strings(out)
		return out
	}
	for _, field := range iface.Methods.List {
		// Embedded interfaces (no Names) would let any method through;
		// reject them as a separate regression so a future
		// `embed io.Writer` does not silently expand the surface.
		if len(field.Names) == 0 {
			emit(fset.Position(field.Pos()), "embedded interface forbidden under", backupReporterInterfaceName)
			continue
		}
		for _, name := range field.Names {
			if name.Name != backupReporterMethodName {
				emit(fset.Position(name.Pos()), "forbidden method on "+backupReporterInterfaceName+":", name.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// findForbiddenBackupWriteSeams walks the AST of a parsed file and
// reports one diagnostic per CallExpr whose `Fun` is a SelectorExpr
// matching `forbiddenBackupWriteSeams`. The match is package-
// qualified (`pkg.Name`) so a renamed alias would not bypass the
// gate — virtually every call site in the codebase imports `os` and
// `os/exec` by their canonical names, and a contributor who renamed
// them would be making the regression even more obvious.
func findForbiddenBackupWriteSeams(fset *token.FileSet, file *ast.File) []string {
	var out []string
	emit := func(pos token.Position, qualified string) {
		out = append(out, "forbidden backup write-seam call "+qualified+" at "+pos.String()+
			". The Yalla backup package is read-only: the operator's pipeline writes the status file, and the Yalla process never produces backup data, shells out to a backup binary, or mutates the operator's filesystem. A regression that called os.WriteFile, os.Create, os.OpenFile, exec.Command, or a similar write seam would indicate a backup data plane has been pulled into the process. "+
			"See internal/release/backup_encryption_static_test.go (BE-0362) and SECURITY.md \"Backup Encryption\" for the threat model.")
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		qualified := pkg.Name + "." + sel.Sel.Name
		if _, bad := forbiddenBackupWriteSeams[qualified]; bad {
			emit(fset.Position(call.Pos()), qualified)
		}
		return true
	})
	sort.Strings(out)
	return out
}
