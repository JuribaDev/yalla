package backup_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/backup"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// fixedNow returns a deterministic clock function for tests so Status.Age
// computations are reproducible.
func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// writeStatus writes content to a fresh status file in t.TempDir and
// returns the absolute path. The file is cleaned up automatically by
// t.TempDir.
func writeStatus(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "backup.status")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seed status file: %v", err)
	}
	return path
}

func TestUnconfiguredReporterReportsConfiguredFalse(t *testing.T) {
	t.Parallel()

	got, err := backup.Unconfigured().Status(context.Background())
	if err != nil {
		t.Fatalf("Unconfigured().Status() error = %v, want nil", err)
	}
	if got.Configured {
		t.Errorf("Configured = true, want false")
	}
	if !got.LastSuccessAt.IsZero() {
		t.Errorf("LastSuccessAt = %v, want zero", got.LastSuccessAt)
	}
	if got.Age != 0 {
		t.Errorf("Age = %v, want 0", got.Age)
	}
	if got.MaxAge != 0 {
		t.Errorf("MaxAge = %v, want 0", got.MaxAge)
	}
	if !got.Fresh() {
		t.Errorf("Fresh() = false on unconfigured Status, want true")
	}
}

func TestNewFileReporterRejectsEmptyPath(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, path string }{
		{"empty", ""},
		{"whitespace", "   "},
		{"tab", "\t"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := backup.NewFileReporter(tt.path, time.Hour, nil)
			if err == nil {
				t.Fatalf("NewFileReporter(%q) returned reporter, want error", tt.path)
			}
			if got != nil {
				t.Errorf("NewFileReporter returned non-nil reporter on error path")
			}
			var ye *yerr.Error
			if !errors.As(err, &ye) || ye.Code != yerr.CodeConfig {
				t.Errorf("error code = %v, want %v", err, yerr.CodeConfig)
			}
		})
	}
}

func TestFileReporterStatusParsesRFC3339(t *testing.T) {
	t.Parallel()

	stamp := time.Date(2026, 5, 16, 3, 0, 0, 0, time.UTC)
	now := time.Date(2026, 5, 16, 9, 30, 0, 0, time.UTC)

	path := writeStatus(t, stamp.Format(time.RFC3339)+"\n")
	reporter, err := backup.NewFileReporter(path, 24*time.Hour, fixedNow(now))
	if err != nil {
		t.Fatalf("NewFileReporter: %v", err)
	}

	got, err := reporter.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !got.Configured {
		t.Errorf("Configured = false, want true")
	}
	if !got.LastSuccessAt.Equal(stamp) {
		t.Errorf("LastSuccessAt = %v, want %v", got.LastSuccessAt, stamp)
	}
	wantAge := 6*time.Hour + 30*time.Minute
	if got.Age != wantAge {
		t.Errorf("Age = %v, want %v", got.Age, wantAge)
	}
	if got.MaxAge != 24*time.Hour {
		t.Errorf("MaxAge = %v, want 24h", got.MaxAge)
	}
	if !got.Fresh() {
		t.Errorf("Fresh() = false at age 6h30m with 24h MaxAge, want true")
	}
}

func TestFileReporterStatusTolerantOfWhitespace(t *testing.T) {
	t.Parallel()

	stamp := time.Date(2026, 5, 16, 3, 0, 0, 0, time.UTC)
	// Leading blank line + surrounding whitespace + trailing newline.
	path := writeStatus(t, "\n   "+stamp.Format(time.RFC3339)+"   \n")
	reporter, err := backup.NewFileReporter(path, 0, fixedNow(stamp.Add(time.Hour)))
	if err != nil {
		t.Fatalf("NewFileReporter: %v", err)
	}

	got, err := reporter.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !got.LastSuccessAt.Equal(stamp) {
		t.Errorf("LastSuccessAt = %v, want %v", got.LastSuccessAt, stamp)
	}
	if got.MaxAge != 0 {
		t.Errorf("MaxAge = %v, want 0", got.MaxAge)
	}
	if !got.Fresh() {
		t.Errorf("Fresh() = false on zero-MaxAge Status, want true")
	}
}

func TestFileReporterStatusMissingFileReturnsSentinel(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "does-not-exist")
	reporter, err := backup.NewFileReporter(path, time.Hour, fixedNow(time.Now()))
	if err != nil {
		t.Fatalf("NewFileReporter: %v", err)
	}

	got, err := reporter.Status(context.Background())
	if !errors.Is(err, backup.ErrNoBackupRecorded) {
		t.Fatalf("Status err = %v, want backup.ErrNoBackupRecorded", err)
	}
	if !got.Configured {
		t.Errorf("Configured = false on missing-file path, want true (the source is wired, it just hasn't fired yet)")
	}
	if !got.LastSuccessAt.IsZero() {
		t.Errorf("LastSuccessAt = %v, want zero on missing-file path", got.LastSuccessAt)
	}
	if got.MaxAge != time.Hour {
		t.Errorf("MaxAge = %v, want 1h carried through on missing-file path", got.MaxAge)
	}
}

func TestFileReporterStatusEmptyFileIsTypedError(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ name, content string }{
		{"truly empty", ""},
		{"whitespace only", "\n  \n\t\n"},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeStatus(t, tt.content)
			reporter, err := backup.NewFileReporter(path, time.Hour, fixedNow(time.Now()))
			if err != nil {
				t.Fatalf("NewFileReporter: %v", err)
			}

			_, err = reporter.Status(context.Background())
			var ye *yerr.Error
			if !errors.As(err, &ye) || ye.Code != yerr.CodeServer {
				t.Fatalf("Status err = %v, want yerr.CodeServer", err)
			}
		})
	}
}

func TestFileReporterStatusMalformedIsTypedError(t *testing.T) {
	t.Parallel()

	path := writeStatus(t, "not a timestamp\n")
	reporter, err := backup.NewFileReporter(path, time.Hour, fixedNow(time.Now()))
	if err != nil {
		t.Fatalf("NewFileReporter: %v", err)
	}

	_, err = reporter.Status(context.Background())
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeServer {
		t.Fatalf("Status err = %v, want yerr.CodeServer", err)
	}
}

// TestFileReporterParseErrorRedactsContent pins the redaction contract: a
// status file accidentally seeded with a secret (a misconfigured pipeline
// writing a DSN instead of a timestamp) must not leak the secret through
// the error message. This is required by the BE-0039 acceptance criterion
// "Secrets, tokens, API keys, cookies, and rendered environment variable
// values are redacted in logs, errors, audit metadata, and test output."
func TestFileReporterParseErrorRedactsContent(t *testing.T) {
	t.Parallel()

	secret := "postgres://yalla:VERY-SECRET-PASSWORD-NEVER-LEAK@db.internal:5432/yalla"
	path := writeStatus(t, secret+"\n")
	reporter, err := backup.NewFileReporter(path, time.Hour, fixedNow(time.Now()))
	if err != nil {
		t.Fatalf("NewFileReporter: %v", err)
	}

	_, err = reporter.Status(context.Background())
	if err == nil {
		t.Fatal("Status err = nil, want a parse error")
	}
	if strings.Contains(err.Error(), "VERY-SECRET-PASSWORD-NEVER-LEAK") {
		t.Errorf("error message leaked the status file's content: %q", err.Error())
	}
	if strings.Contains(err.Error(), "postgres://") {
		t.Errorf("error message leaked the status file's content: %q", err.Error())
	}
}

func TestFileReporterStatusFutureTimestampClampsAgeToZero(t *testing.T) {
	t.Parallel()

	stamp := time.Date(2026, 5, 16, 3, 0, 0, 0, time.UTC)
	now := stamp.Add(-2 * time.Hour) // clock skew: backup "in the future"
	path := writeStatus(t, stamp.Format(time.RFC3339))
	reporter, err := backup.NewFileReporter(path, time.Hour, fixedNow(now))
	if err != nil {
		t.Fatalf("NewFileReporter: %v", err)
	}

	got, err := reporter.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got.Age != 0 {
		t.Errorf("Age = %v on future timestamp, want 0", got.Age)
	}
	if !got.LastSuccessAt.Equal(stamp) {
		t.Errorf("LastSuccessAt = %v, want %v (timestamp preserved)", got.LastSuccessAt, stamp)
	}
}

func TestFileReporterStatusFreshnessThreshold(t *testing.T) {
	t.Parallel()

	stamp := time.Date(2026, 5, 16, 3, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		now       time.Time
		maxAge    time.Duration
		wantFresh bool
	}{
		{"within window", stamp.Add(23 * time.Hour), 24 * time.Hour, true},
		{"at the boundary", stamp.Add(24 * time.Hour), 24 * time.Hour, true},
		{"past the window", stamp.Add(25 * time.Hour), 24 * time.Hour, false},
		{"zero MaxAge disables the check", stamp.Add(720 * time.Hour), 0, true},
	}

	path := writeStatus(t, stamp.Format(time.RFC3339))
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reporter, err := backup.NewFileReporter(path, tt.maxAge, fixedNow(tt.now))
			if err != nil {
				t.Fatalf("NewFileReporter: %v", err)
			}
			got, err := reporter.Status(context.Background())
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if got.Fresh() != tt.wantFresh {
				t.Errorf("Fresh() = %v, want %v (age=%v, maxAge=%v)",
					got.Fresh(), tt.wantFresh, got.Age, got.MaxAge)
			}
		})
	}
}

func TestFileReporterStatusHonorsContextCancellation(t *testing.T) {
	t.Parallel()

	path := writeStatus(t, time.Now().UTC().Format(time.RFC3339))
	reporter, err := backup.NewFileReporter(path, time.Hour, time.Now)
	if err != nil {
		t.Fatalf("NewFileReporter: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := reporter.Status(ctx)
	if err == nil {
		t.Fatal("Status err = nil on cancelled context, want context.Canceled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Status err = %v, want context.Canceled", err)
	}
	if !got.Configured {
		t.Errorf("Configured = false on cancelled-context path, want true")
	}
}

// TestFileReporterIsConcurrentSafe proves the FileReporter is safe to share
// across goroutines — the /healthz/backup handler reads it while the
// operator's backup pipeline races to update the underlying status file.
func TestFileReporterIsConcurrentSafe(t *testing.T) {
	t.Parallel()

	stamp := time.Date(2026, 5, 16, 3, 0, 0, 0, time.UTC)
	path := writeStatus(t, stamp.Format(time.RFC3339))
	reporter, err := backup.NewFileReporter(path, time.Hour, fixedNow(stamp.Add(30*time.Minute)))
	if err != nil {
		t.Fatalf("NewFileReporter: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := reporter.Status(context.Background()); err != nil {
				t.Errorf("Status: %v", err)
			}
		}()
	}
	wg.Wait()
}

// TestReporterInterfaceSatisfaction is a compile-time guard that the two
// public constructors return values satisfying Reporter, so handler wiring
// stays consistent.
func TestReporterInterfaceSatisfaction(t *testing.T) {
	t.Parallel()

	var _ backup.Reporter = backup.Unconfigured()

	reporter, err := backup.NewFileReporter(filepath.Join(t.TempDir(), "x"), 0, nil)
	if err != nil {
		t.Fatalf("NewFileReporter: %v", err)
	}
	var _ backup.Reporter = reporter
}
