package backup_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/backup"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// BE-0362: Security verification — backup encryption.
//
// Runtime evidence half of the BE-0344 two-test pattern. The static
// half is `internal/release/backup_encryption_static_test.go` and
// pins the structural seams: the backup package imports no encryption
// / archive / database / exec / HTTP library, the `Reporter` interface
// exposes exactly one read-only method, and the package contains no
// write-seam calls. These runtime tests close the loop by proving the
// redaction seam holds when the operator's pipeline accidentally
// writes an encryption-shaped payload (a KMS key id, an AES wrap blob,
// a base64-encoded key, a restore-failed message naming the bucket) to
// the status file: the parse error MUST NOT echo the file's content,
// and the Status struct's JSON projection MUST NOT carry the bytes
// either.
//
// The marker pattern is intentional: every fixture installs a
// globally unique fixed prefix (`BE0362KMSMARKERXYZ`). The leak
// detector asserts the marker never appears in the projection output,
// independent of the fixture's bytes. Asserting on the fixture's full
// content would false-positive whenever the fixture's content happens
// to share a substring with a stable error phrase (e.g. a fixture
// containing the substring "is malformed" would trip the existing
// "backup: status file is malformed" message); the marker is what
// makes the leak detector load-bearing across fuzzed inputs.
//
// The existing `TestFileReporterParseErrorRedactsContent` (BE-0039)
// pins the same invariant against a DSN-shaped secret. This test
// adds an explicit encryption-vocabulary corpus so a future
// regression that "redacts only the parts that look like a URL"
// is caught — the marker is the leak detector regardless of the
// surrounding shape.

// backupEncryptionMarker is the fixed prefix every encryption-shaped
// fixture inherits. It is alphanumeric, contains the substring
// "MARKER" so its presence in any projection unambiguously identifies
// a leak, and is long enough that a partial-flush leak (the first 8
// bytes appearing in an error) still surfaces.
const backupEncryptionMarker = "BE0362KMSMARKERXYZ"

// backupEncryptionFixtures enumerates the encryption-shaped status-
// file payloads the runtime gate asserts on. Each fixture's `name`
// flows into a subtest name so a regression diagnostic identifies
// the exact shape that leaked; each fixture's `content` is the
// payload bound to the status file. The set is intentionally small —
// the static gate carries the structural load — but every shape was
// chosen to surface a different class of regression a future
// "improvement" to the parse-error message might introduce:
//
//   - "kms-key-id": a content shape that mimics an AWS KMS key id
//     (operators routinely cut-and-paste these into scratch files);
//   - "aes-wrap-blob": base64-shaped bytes that look like an AES
//     wrap output (a misconfigured pipeline that wrote the key
//     instead of the timestamp);
//   - "restore-failed-message": a multi-line error message naming
//     the backup bucket (a pipeline that piped its own stderr into
//     the status file on failure);
//   - "pem-private-key": a PEM-armoured payload (an operator that
//     pointed the status path at the wrong file entirely).
//
// Every fixture is prefixed with the marker so a regression that
// re-introduced raw content into the parse error surfaces the same
// way regardless of shape.
var backupEncryptionFixtures = []struct {
	name    string
	content string
}{
	{
		name:    "kms-key-id",
		content: backupEncryptionMarker + "-arn:aws:kms:us-east-1:111122223333:key/abcdef00-1234-5678-9abc-def012345678\n",
	},
	{
		name:    "aes-wrap-blob",
		content: backupEncryptionMarker + "-" + strings.Repeat("A1b2C3d4", 32) + "\n",
	},
	{
		name:    "restore-failed-message",
		content: "restore failed: " + backupEncryptionMarker + " unable to decrypt object s3://yalla-backups/2026/05/16.dump\n",
	},
	{
		name: "pem-private-key",
		content: "-----BEGIN PRIVATE KEY-----\n" +
			backupEncryptionMarker + "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAL\n" +
			"-----END PRIVATE KEY-----\n",
	},
}

// TestFileReporterEncryptionMarkerNeverLeaks pins the redaction
// invariant against encryption-shaped status-file content. For each
// fixture, the test seeds the status file with a marker-prefixed
// payload, calls `FileReporter.Status`, and asserts:
//
//  1. an error is returned (the payload is not a valid RFC3339
//     timestamp, so a regression that silently returned success
//     would also fail here);
//  2. the returned error wraps the typed `yerr.CodeServer` (the
//     stable classification a Reporter must promise);
//  3. the marker does NOT appear anywhere in `err.Error()`;
//  4. the marker does NOT appear in the JSON projection of the
//     returned `Status` struct (defensive: the struct has no
//     content field today, but a regression that added one would
//     surface here).
//
// A failure on any fixture identifies the exact payload shape that
// leaked, so the diagnostic is actionable without re-running with
// `-v`.
func TestFileReporterEncryptionMarkerNeverLeaks(t *testing.T) {
	t.Parallel()
	for _, tc := range backupEncryptionFixtures {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := writeStatus(t, tc.content)
			reporter, err := backup.NewFileReporter(path, time.Hour, fixedNow(time.Now()))
			if err != nil {
				t.Fatalf("NewFileReporter: %v", err)
			}
			got, err := reporter.Status(context.Background())
			if err == nil {
				t.Fatalf("Status err = nil, want a typed parse error for fixture %q", tc.name)
			}
			var ye *yerr.Error
			if !errors.As(err, &ye) || ye.Code != yerr.CodeServer {
				t.Fatalf("Status err = %v, want yerr.CodeServer for fixture %q", err, tc.name)
			}
			if strings.Contains(err.Error(), backupEncryptionMarker) {
				t.Errorf("error string leaked the encryption marker for fixture %q: %q. "+
					"The Yalla backup package's parse error MUST NOT echo the status file's content; an operator pipeline that accidentally wrote a KMS key id, an AES wrap blob, a PEM-armoured key, or a bucket-restore error message into the status file must not surface that content through the error chain. "+
					"See internal/release/backup_encryption_static_test.go (BE-0362) and SECURITY.md \"Backup Encryption\" for the threat model.",
					tc.name, err.Error())
			}
			// Defensive: project the Status struct to JSON and check
			// the marker is absent. The struct has no content field
			// today, but a regression that surfaced the parsed-but-
			// rejected source bytes (e.g. as a "Detail" field) would
			// surface here.
			body, marshalErr := json.Marshal(got)
			if marshalErr != nil {
				t.Fatalf("marshal Status: %v", marshalErr)
			}
			if strings.Contains(string(body), backupEncryptionMarker) {
				t.Errorf("Status JSON projection leaked the encryption marker for fixture %q: %s. "+
					"A regression that added a free-text field to backup.Status (e.g. a `Detail` carrying the rejected source line) would surface the operator's accidentally-seeded content through every operator-visible projection downstream of Status. "+
					"See internal/release/backup_encryption_static_test.go (BE-0362).",
					tc.name, string(body))
			}
		})
	}
}

// TestFileReporterEncryptionMarkerSurvivesErrorWrapping pins the
// same invariant against the typed-error chain. A regression that
// wrapped the parse error inside an `apierr.Internal(err)` or
// `fmt.Errorf("backup: %w", err)` could re-introduce the file
// content through the `%w` propagation chain if the lower-level
// error string ever carried it. This test seeds the same marker
// fixture, captures the entire error chain via `errors.Unwrap`,
// and asserts the marker never appears in any layer.
//
// The fixture set here is intentionally a single shape (the kms-
// key-id payload) because the goal is to walk the unwrap chain,
// not to enumerate payload shapes — the per-shape coverage already
// lives in `TestFileReporterEncryptionMarkerNeverLeaks`.
func TestFileReporterEncryptionMarkerSurvivesErrorWrapping(t *testing.T) {
	t.Parallel()
	content := backupEncryptionMarker + "-arn:aws:kms:us-east-1:111122223333:key/abcdef00-1234-5678-9abc-def012345678\n"
	path := writeStatus(t, content)
	reporter, err := backup.NewFileReporter(path, time.Hour, fixedNow(time.Now()))
	if err != nil {
		t.Fatalf("NewFileReporter: %v", err)
	}
	_, err = reporter.Status(context.Background())
	if err == nil {
		t.Fatal("Status err = nil, want a typed parse error")
	}
	// Walk the unwrap chain. Every layer's Error() string must be
	// marker-free; a regression that wrapped the file's content
	// inside a deeper layer (visible through `errors.Unwrap`) would
	// be reachable to any caller that formats `%v` on the wrapped
	// error.
	for cur := err; cur != nil; cur = errors.Unwrap(cur) {
		if strings.Contains(cur.Error(), backupEncryptionMarker) {
			t.Errorf("error chain layer leaked the encryption marker: %q. "+
				"The Yalla backup package's parse error and every layer of its wrap chain MUST be free of the operator's accidentally-seeded content. "+
				"See internal/release/backup_encryption_static_test.go (BE-0362) and SECURITY.md \"Backup Encryption\" for the threat model.",
				cur.Error())
			return
		}
	}
}
