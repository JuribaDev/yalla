package backup_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/backup"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Canonical backup-and-restore rehearsal regression pair (BE-0399). Both
// members of this pair exercise backup.FileReporter — the chokepoint
// between the operator's external backup-and-restore pipeline and the
// unauthenticated GET /healthz/backup probe — and prove that the closed
// set of states the reporter is documented to surface stays stable across
// (a) the closed-set coverage table enumerated by
// buildBackupRestoreRehearsalScenarios, and (b) a concurrent contention
// burst that fires `rehearsalWorkers * rehearsalIterationsPerWorker`
// goroutines against the same per-scenario reporter and asserts every
// observation matches the scenario's predicted verdict.
//
// The PRD's `go test -run TestBackupRestoreRehearsal ./...` filter binds
// to the `TestBackupRestoreRehearsal` prefix; the static defence for the
// surrounding surfaces (CI step, verify.sh prefix, CONTRIBUTING entry,
// SECURITY row + section, PRD command, canonical file existence) lives
// in internal/release/verification_suite_backup_restore_static_test.go.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - The HTTP-layer GET /healthz/backup wire contract is proven by the
//     handler tests in internal/controlplane/httpapi/healthz_backup_test.go.
//   - The backup-data-plane boundary (no import of crypto/aes,
//     archive/zip, os/exec, ...) is proven by the static gate in
//     internal/release/backup_encryption_static_test.go.
//   - The package's individual state-shape behaviour (Unconfigured()
//     returning a zero Status, NewFileReporter rejecting an empty path)
//     is proven by health_test.go in this same package.
//
// Rehearsal framing: a backup-and-restore rehearsal is the closed loop
// between (1) the operator's pipeline producing a backup and writing the
// RFC3339 status timestamp, and (2) the Yalla Control Plane API restoring
// awareness of that backup on its next probe. The reporter is the
// boundary between the two halves; this suite proves the boundary is
// stable for every state the loop can land in — pristine, fresh, on the
// freshness boundary, stale, opt-out, clock-skew, whitespace-tolerant,
// empty, malformed, secret-leaked, unconfigured, and cancelled.

const (
	// rehearsalWorkers and rehearsalIterationsPerWorker bound the
	// contention burst the per-decision stability member fires. The
	// product is also the closed-set sample size against the coverage
	// table — every goroutine asserts its own scenario's predicate, so
	// a cross-write under the race that swapped two goroutines' fixtures
	// would fail the per-iteration assertion even when the aggregate
	// pass count matched.
	rehearsalWorkers             = 12
	rehearsalIterationsPerWorker = 32

	// rehearsalSecretMarker is the sentinel a malformed-status fixture
	// embeds as a stand-in for the kind of secret a misconfigured
	// pipeline could accidentally write (a DSN, an API key, a session
	// token). Asserting on the marker rather than on a literal DSN
	// keeps the redaction guard anchored to a stable token even if the
	// surrounding fixture content shifts in a future revision.
	rehearsalSecretMarker = "BE0399VERYSECRETXYZ-DO-NOT-LEAK"
)

// rehearsalErrKind is the closed enumeration of error shapes the reporter
// is documented to surface. Asserting on the kind rather than the literal
// value keeps the test stable across cosmetic message edits while still
// pinning the load-bearing typed error contract.
type rehearsalErrKind int

const (
	rehearsalErrNil rehearsalErrKind = iota
	rehearsalErrSentinelNoBackup
	rehearsalErrTypedCodeServer
	rehearsalErrContextCanceled
)

// rehearsalScenario is one closed-set coverage tuple plus the predicate
// the reporter MUST satisfy for it. Every coverage and contention
// assertion is derived from this same record so the two members cannot
// drift out of sync.
type rehearsalScenario struct {
	name string
	// build constructs the reporter under test for this scenario. The
	// closure runs once per scenario (shared across burst goroutines)
	// because backup.FileReporter is documented safe for concurrent use.
	build func(t *testing.T) backup.Reporter
	// contextCanceled, when true, invokes reporter.Status against a
	// context cancelled before the call.
	contextCanceled bool

	wantErr            rehearsalErrKind
	wantConfigured     bool
	wantFresh          bool
	wantStampPreserved bool
	wantStamp          time.Time
	wantAgeZero        bool
	wantAge            time.Duration
	wantMaxAge         time.Duration
	// wantPathInMessage asserts the rendered error message names the
	// status file path so an operator reading the diagnostic can
	// correlate the failure with the AC3 resource id without re-running
	// the suite. ErrNoBackupRecorded is a sentinel and does not carry
	// the path; typed CodeServer errors MUST.
	wantPathInMessage bool
	// wantSecretMarker, when non-empty, MUST NOT appear in the rendered
	// error message. The rehearsal redaction guard is the load-bearing
	// proof of AC8 for this suite.
	wantSecretMarker string
}

// rehearsalFixture pairs a built reporter with its scenario so the burst
// member can share one reporter across every goroutine that draws the
// scenario.
type rehearsalFixture struct {
	scenario rehearsalScenario
	reporter backup.Reporter
}

// rehearsalFixedNow returns a deterministic clock returning t.
func rehearsalFixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

// rehearsalWriteStatus writes content to a fresh status file in t.TempDir
// and returns the absolute path. The path is the AC3 resource-id surface
// every typed-error diagnostic in this suite must name.
func rehearsalWriteStatus(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "backup.status")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("seed status file %q: %v", path, err)
	}
	return path
}

// rehearsalMustReporter constructs a FileReporter or fails the test.
func rehearsalMustReporter(t *testing.T, path string, maxAge time.Duration, now func() time.Time) backup.Reporter {
	t.Helper()
	r, err := backup.NewFileReporter(path, maxAge, now)
	if err != nil {
		t.Fatalf("NewFileReporter(%q): %v", path, err)
	}
	return r
}

// buildBackupRestoreRehearsalScenarios enumerates the closed-set rehearsal
// coverage table. Every state the operator's backup-and-restore pipeline
// can hand to the Yalla Control Plane API is represented as one scenario;
// the same table backs both the coverage member and the contention burst,
// so the two cannot drift.
func buildBackupRestoreRehearsalScenarios(t *testing.T) []rehearsalScenario {
	t.Helper()

	stamp := time.Date(2026, 5, 16, 3, 0, 0, 0, time.UTC)
	const maxAge = 24 * time.Hour

	return []rehearsalScenario{
		// (1) Pristine post-restore: status path is wired but no backup
		// has landed yet. The freshly-provisioned (or freshly-restored)
		// environment is healthy; the reporter MUST surface
		// ErrNoBackupRecorded so a caller can render a "no backup yet"
		// envelope rather than a 5xx.
		{
			name: "pristine-post-restore/missing-status-file-returns-ErrNoBackupRecorded",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				path := filepath.Join(t.TempDir(), "missing.status")
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp))
			},
			wantErr:        rehearsalErrSentinelNoBackup,
			wantConfigured: true,
			wantMaxAge:     maxAge,
		},

		// (2) Successful rehearsal: the operator pipeline ran a backup
		// 30m ago; the reporter parses the stamp, reports Configured,
		// computes Age, and Fresh() returns true against a 24h MaxAge.
		{
			name: "successful-rehearsal/parsed-stamp-fresh-30m",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				path := rehearsalWriteStatus(t, stamp.Format(time.RFC3339)+"\n")
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp.Add(30*time.Minute)))
			},
			wantErr:            rehearsalErrNil,
			wantConfigured:     true,
			wantFresh:          true,
			wantStampPreserved: true,
			wantStamp:          stamp,
			wantAge:            30 * time.Minute,
			wantMaxAge:         maxAge,
		},

		// (3) On-boundary rehearsal: Age == MaxAge. The freshness
		// predicate uses Age <= MaxAge so the boundary value MUST stay
		// fresh; a regression that switched to < would flap the probe at
		// the exact boundary.
		{
			name: "boundary-rehearsal/age-equals-maxage-still-fresh",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				path := rehearsalWriteStatus(t, stamp.Format(time.RFC3339))
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp.Add(maxAge)))
			},
			wantErr:            rehearsalErrNil,
			wantConfigured:     true,
			wantFresh:          true,
			wantStampPreserved: true,
			wantStamp:          stamp,
			wantAge:            maxAge,
			wantMaxAge:         maxAge,
		},

		// (4) Past-window rehearsal: Age > MaxAge. Fresh()=false; the
		// probe surfaces "stale" so an operator sees the gate failure.
		// This is the load-bearing assertion: a regression that
		// silently widened the freshness predicate would let an
		// abandoned backup pipeline pass the probe.
		{
			name: "stale-rehearsal/age-past-maxage-not-fresh",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				path := rehearsalWriteStatus(t, stamp.Format(time.RFC3339))
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp.Add(maxAge+time.Hour)))
			},
			wantErr:            rehearsalErrNil,
			wantConfigured:     true,
			wantFresh:          false,
			wantStampPreserved: true,
			wantStamp:          stamp,
			wantAge:            maxAge + time.Hour,
			wantMaxAge:         maxAge,
		},

		// (5) Zero-MaxAge opt-out: MaxAge=0 disables the freshness
		// predicate; any Age yields Fresh()=true so a probe shipped
		// before the operator picks a threshold does not flap.
		{
			name: "opt-out-rehearsal/zero-maxage-disables-freshness",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				path := rehearsalWriteStatus(t, stamp.Format(time.RFC3339))
				return rehearsalMustReporter(t, path, 0, rehearsalFixedNow(stamp.Add(720*time.Hour)))
			},
			wantErr:            rehearsalErrNil,
			wantConfigured:     true,
			wantFresh:          true,
			wantStampPreserved: true,
			wantStamp:          stamp,
			wantAge:            720 * time.Hour,
			wantMaxAge:         0,
		},

		// (6) Clock-skew rehearsal: the pipeline host's clock is ahead
		// of the API host's. The stamp is preserved untouched, but Age
		// is clamped to 0 so downstream JSON rendering and Fresh()
		// get a well-defined non-negative value.
		{
			name: "clock-skew-rehearsal/future-stamp-clamps-age-to-zero",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				path := rehearsalWriteStatus(t, stamp.Format(time.RFC3339))
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp.Add(-2*time.Hour)))
			},
			wantErr:            rehearsalErrNil,
			wantConfigured:     true,
			wantFresh:          true,
			wantStampPreserved: true,
			wantStamp:          stamp,
			wantAgeZero:        true,
			wantMaxAge:         maxAge,
		},

		// (7) Whitespace-tolerant rehearsal: the operator pipeline
		// occasionally seeds the status file with surrounding
		// whitespace (a trailing newline from a shell heredoc, a
		// leading blank from a CI-prepended marker). The reporter MUST
		// parse cleanly and report the inner timestamp.
		{
			name: "whitespace-tolerant-rehearsal/surrounding-whitespace-parsed",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				content := "\n   " + stamp.Format(time.RFC3339) + "   \n"
				path := rehearsalWriteStatus(t, content)
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp.Add(time.Hour)))
			},
			wantErr:            rehearsalErrNil,
			wantConfigured:     true,
			wantFresh:          true,
			wantStampPreserved: true,
			wantStamp:          stamp,
			wantAge:            time.Hour,
			wantMaxAge:         maxAge,
		},

		// (8) Empty-status rehearsal: the pipeline crashed and left a
		// zero-byte status file. The reporter surfaces a typed
		// CodeServer error that names the path; the probe maps the
		// typed error into an apierr.StoreUnavailable envelope on the
		// wire.
		{
			name: "validation-failure/empty-status-file-typed-CodeServer",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				path := rehearsalWriteStatus(t, "")
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp))
			},
			wantErr:           rehearsalErrTypedCodeServer,
			wantConfigured:    true,
			wantMaxAge:        maxAge,
			wantPathInMessage: true,
		},

		// (9) Whitespace-only rehearsal: a typed CodeServer error must
		// fire just like the truly-empty case so a pipeline that
		// half-wrote a record (newlines/whitespace only) cannot pose as
		// "no backup yet" — that is the ErrNoBackupRecorded sentinel's
		// job, not a parse-error masquerade.
		{
			name: "validation-failure/whitespace-only-status-file-typed-CodeServer",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				path := rehearsalWriteStatus(t, "\n  \n\t\n")
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp))
			},
			wantErr:           rehearsalErrTypedCodeServer,
			wantConfigured:    true,
			wantMaxAge:        maxAge,
			wantPathInMessage: true,
		},

		// (10) Malformed-status rehearsal: the pipeline wrote a
		// human-readable status line ("Backup succeeded at ...") rather
		// than the contract RFC3339 timestamp. Typed CodeServer; the
		// status file content is NOT echoed.
		{
			name: "validation-failure/malformed-status-typed-CodeServer-redacted",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				path := rehearsalWriteStatus(t, "Backup succeeded at "+stamp.Format(time.RFC1123)+"\n")
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp))
			},
			wantErr:           rehearsalErrTypedCodeServer,
			wantConfigured:    true,
			wantMaxAge:        maxAge,
			wantPathInMessage: true,
		},

		// (11) Secret-leak rehearsal: a misconfigured pipeline wrote a
		// DSN (carrying the rehearsalSecretMarker sentinel) instead of
		// a timestamp. The parse error MUST surface but MUST NOT echo
		// the marker — this is the AC8 redaction proof every
		// secrets-redaction story (BE-0387) implicitly depends on.
		{
			name: "redaction-guard/secret-seeded-status-file-error-stays-redacted",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				secret := "postgres://yalla:" + rehearsalSecretMarker + "@db.internal:5432/yalla"
				path := rehearsalWriteStatus(t, secret+"\n")
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp))
			},
			wantErr:           rehearsalErrTypedCodeServer,
			wantConfigured:    true,
			wantMaxAge:        maxAge,
			wantPathInMessage: true,
			wantSecretMarker:  rehearsalSecretMarker,
		},

		// (12) Unconfigured-process rehearsal: the operator has not
		// wired any backup pipeline yet. The probe MUST report
		// Configured=false with no error, and Fresh()=true so a probe
		// shipped before the operator wires the source does not flap.
		{
			name: "unconfigured-rehearsal/no-source-no-error",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				return backup.Unconfigured()
			},
			wantErr:        rehearsalErrNil,
			wantConfigured: false,
			wantFresh:      true,
			wantMaxAge:     0,
		},

		// (13) Context-cancellation rehearsal: a shutting-down request
		// must surface context.Canceled rather than an I/O error.
		// Configured stays true so the wire envelope still names the
		// path.
		{
			name: "shutdown-rehearsal/cancelled-context-bubbles-up",
			build: func(t *testing.T) backup.Reporter {
				t.Helper()
				path := rehearsalWriteStatus(t, stamp.Format(time.RFC3339))
				return rehearsalMustReporter(t, path, maxAge, rehearsalFixedNow(stamp))
			},
			contextCanceled: true,
			wantErr:         rehearsalErrContextCanceled,
			wantConfigured:  true,
			wantMaxAge:      maxAge,
		},
	}
}

// assessRehearsalObservation returns the list of human-readable failure
// reasons for one (scenario, status, err) tuple, or nil on success. The
// coverage member calls t.Errorf with each reason inline; the burst
// member records the reasons against the (worker, iteration) origin so
// an operator can correlate a cross-write under the race with a specific
// in-flight observation without re-running the suite locally.
func assessRehearsalObservation(scen rehearsalScenario, got backup.Status, err error) []string {
	var reasons []string

	switch scen.wantErr {
	case rehearsalErrNil:
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("Status err = %v, want nil", err))
		}
	case rehearsalErrSentinelNoBackup:
		if !errors.Is(err, backup.ErrNoBackupRecorded) {
			reasons = append(reasons, fmt.Sprintf("Status err = %v, want backup.ErrNoBackupRecorded", err))
		}
	case rehearsalErrTypedCodeServer:
		var ye *yerr.Error
		if !errors.As(err, &ye) || ye.Code != yerr.CodeServer {
			reasons = append(reasons, fmt.Sprintf("Status err = %v, want a typed yerr.Error with Code=yerr.CodeServer", err))
		}
	case rehearsalErrContextCanceled:
		if !errors.Is(err, context.Canceled) {
			reasons = append(reasons, fmt.Sprintf("Status err = %v, want context.Canceled", err))
		}
	}

	if got.Configured != scen.wantConfigured {
		reasons = append(reasons, fmt.Sprintf("Configured = %v, want %v", got.Configured, scen.wantConfigured))
	}
	if got.MaxAge != scen.wantMaxAge {
		reasons = append(reasons, fmt.Sprintf("MaxAge = %v, want %v", got.MaxAge, scen.wantMaxAge))
	}

	if scen.wantErr == rehearsalErrNil {
		if got.Fresh() != scen.wantFresh {
			reasons = append(reasons, fmt.Sprintf("Fresh() = %v, want %v (age=%v maxAge=%v)",
				got.Fresh(), scen.wantFresh, got.Age, got.MaxAge))
		}
		if scen.wantStampPreserved && !got.LastSuccessAt.Equal(scen.wantStamp) {
			reasons = append(reasons, fmt.Sprintf("LastSuccessAt = %v, want %v", got.LastSuccessAt, scen.wantStamp))
		}
		switch {
		case scen.wantAgeZero:
			if got.Age != 0 {
				reasons = append(reasons, fmt.Sprintf("Age = %v, want 0 (clock-skew clamp)", got.Age))
			}
		case scen.wantAge != 0:
			if got.Age != scen.wantAge {
				reasons = append(reasons, fmt.Sprintf("Age = %v, want %v", got.Age, scen.wantAge))
			}
		}
	}

	if err != nil {
		msg := err.Error()
		if scen.wantSecretMarker != "" && strings.Contains(msg, scen.wantSecretMarker) {
			reasons = append(reasons, fmt.Sprintf("error %q leaked secret marker %q — the rehearsal redaction contract is the boundary every secrets-redaction gate relies on",
				msg, scen.wantSecretMarker))
		}
		if scen.wantPathInMessage && !strings.Contains(msg, "backup: status file") {
			reasons = append(reasons, fmt.Sprintf("error %q missing %q — typed errors MUST name the status file path so operators can correlate the failure with the AC3 resource id",
				msg, "backup: status file"))
		}
	}

	return reasons
}

// TestBackupRestoreRehearsalCoversCallSites is the closed-set rehearsal
// coverage member of the canonical pair. It walks the scenario table
// built by buildBackupRestoreRehearsalScenarios and asserts the
// reporter's response satisfies the scenario's predicate for every
// pristine/fresh/boundary/stale/opt-out/clock-skew/whitespace/empty/
// malformed/secret-leak/unconfigured/cancelled case. A regression in any
// of the documented states trips the gate on the offending scenario
// name.
func TestBackupRestoreRehearsalCoversCallSites(t *testing.T) {
	t.Parallel()

	scenarios := buildBackupRestoreRehearsalScenarios(t)
	if len(scenarios) == 0 {
		t.Fatal("scenario table is empty; the coverage member would vacuously pass")
	}

	for _, scen := range scenarios {
		scen := scen
		t.Run(scen.name, func(t *testing.T) {
			t.Parallel()

			reporter := scen.build(t)

			ctx := context.Background()
			if scen.contextCanceled {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}

			got, err := reporter.Status(ctx)
			for _, reason := range assessRehearsalObservation(scen, got, err) {
				t.Errorf("scenario %s: %s", scen.name, reason)
			}
		})
	}
}

// TestBackupRestoreRehearsalPreservesContractUnderContention is the
// per-decision stability member of the canonical pair. It fires
// `rehearsalWorkers * rehearsalIterationsPerWorker` goroutines against a
// single shared FileReporter per scenario, each goroutine drawing a
// fixture from the same coverage table and asserting the observation it
// recorded matches the fixture's scenario predicate. A cross-write under
// the race that swapped two goroutines' fixtures would fail the
// per-iteration assertion even when the aggregate pass count matched.
func TestBackupRestoreRehearsalPreservesContractUnderContention(t *testing.T) {
	t.Parallel()

	scenarios := buildBackupRestoreRehearsalScenarios(t)
	if len(scenarios) == 0 {
		t.Fatal("scenario table is empty; the burst would vacuously pass")
	}

	// Build one reporter per scenario; share each across every goroutine
	// that draws that scenario. FileReporter is documented safe for
	// concurrent use; sharing here is what makes the burst meaningful.
	fixtures := make([]rehearsalFixture, 0, len(scenarios))
	for _, scen := range scenarios {
		scen := scen
		fixtures = append(fixtures, rehearsalFixture{
			scenario: scen,
			reporter: scen.build(t),
		})
	}

	type failure struct {
		worker    int
		iteration int
		scenario  string
		reasons   []string
	}

	var (
		mu       sync.Mutex
		failures []failure
		total    int
	)

	var wg sync.WaitGroup
	wg.Add(rehearsalWorkers)
	for w := 0; w < rehearsalWorkers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < rehearsalIterationsPerWorker; i++ {
				// Deterministic per-worker + per-iteration index so
				// every parallel run paginates the identical decision
				// set. A cross-write that swapped two goroutines'
				// fixtures would map this iteration to a different
				// scenario than the one its predicate predicted.
				idx := (w*rehearsalIterationsPerWorker + i) % len(fixtures)
				fix := fixtures[idx]

				ctx := context.Background()
				if fix.scenario.contextCanceled {
					c, cancel := context.WithCancel(ctx)
					cancel()
					ctx = c
				}

				got, err := fix.reporter.Status(ctx)
				reasons := assessRehearsalObservation(fix.scenario, got, err)

				mu.Lock()
				total++
				if len(reasons) > 0 {
					failures = append(failures, failure{
						worker:    w,
						iteration: i,
						scenario:  fix.scenario.name,
						reasons:   reasons,
					})
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	wantTotal := rehearsalWorkers * rehearsalIterationsPerWorker
	if total != wantTotal {
		t.Fatalf("observed %d responses, want %d (workers=%d iters=%d)",
			total, wantTotal, rehearsalWorkers, rehearsalIterationsPerWorker)
	}

	// Surface every divergent observation with worker + iteration +
	// scenario so an operator can correlate the regression with the
	// in-flight fixture without re-running the suite. The aggregate
	// pass count alone would hide a single cross-write among thousands
	// of successful observations.
	for _, f := range failures {
		for _, reason := range f.reasons {
			t.Errorf("worker=%d iteration=%d scenario=%s: %s",
				f.worker, f.iteration, f.scenario, reason)
		}
	}
}
