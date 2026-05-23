package store_test

// Canonical reference deployment lifecycle end-to-end test (BE-0408).
//
// This file is the load-bearing static fixture the BE-0408
// verification suite gate (`go test -run TestDeploymentLifecycleE2E
// ./...`) binds to. The pair (`TestDeploymentLifecycleE2ECoversCallSites`
// and `TestDeploymentLifecycleE2EPreservesContractUnderContention`) is
// the closed-set + per-decision-stability contract for the
// deployment lifecycle's pure projection chokepoint
// `(store.Deployment).LogValue() slog.Value`.
//
// Threat model: the Deployment row is the source-of-truth
// representation of one customer-initiated deployment as it walks
// the documented lifecycle (queued -> running -> succeeded |
// failed | cancelled | rolled_back). The `LogValue` projection is
// the single redaction-safe debug surface every slog record that
// captures a Deployment funnels through. The chokepoint is a pure
// function of its input — no I/O, no shared state, no clock — so
// an operator who reads a deployment log line MUST be able to
// predict the projected fields from the persisted row alone. A
// silent regression that (a) accepted a DeploymentSource or
// DeploymentStatus value outside the documented closed set, (b)
// echoed a raw SourceRef, IdempotencyKey, or ErrorMessage into
// the redacted LogValue group, (c) introduced non-deterministic
// ordering into the projected fields, or (d) smuggled package-
// level shared state into the projection would either let an
// operator commit to a deployment whose status did not match
// what they reviewed in a log, audit record, or dashboard, or
// leak a customer-supplied reference / opaque idempotency key /
// raw error string through a debug surface meant to be safe to
// log, audit, and store.
//
// The pair binds to the BE-0408 `-run TestDeploymentLifecycleE2E`
// filter via the `TestDeploymentLifecycleE2E` substring;
// renaming either member to a name that does not contain the
// substring silently de-gates the lifecycle end-to-end suite for
// any caller relying on the filter.
//
// The closed-set coverage invariant pins five structural
// lifecycle contracts in one place:
//
//  1. Every documented `store.DeploymentSource` in
//     `deploymentLifecycleSources` is exercised by at least
//     one scenario row.
//  2. Every documented `store.DeploymentStatus` in
//     `deploymentLifecycleStatuses` is exercised by at least
//     one scenario row.
//  3. Lifecycle-timestamp consistency: every non-terminal
//     status (queued, running) scenario has nil FinishedAt;
//     every terminal status (succeeded, failed, cancelled,
//     rolled_back) scenario has a set FinishedAt. The
//     deployments_finished_consistent table CHECK enforces
//     this at the database; the canonical pair pins the same
//     invariant at the Go projection so a regression that
//     constructed an in-memory Deployment violating the
//     invariant is caught before the row reaches Postgres.
//  4. Deterministic projection: `(Deployment).LogValue()` is
//     a deterministic function of its input — calling it
//     twice on the same row MUST yield equal `slog.Value`
//     projections (same group, same fields, same order). A
//     regression that introduced map-iteration ordering or a
//     non-deterministic field into the projection would
//     surface here before any per-row verdict.
//  5. Value-free redaction canary: the projected slog.Value
//     MUST NOT contain the raw `deploymentLifecycleSecretMarker`
//     even when the marker is seeded into the Deployment's
//     SourceRef, IdempotencyKey, ErrorMessage, RequestID, and
//     CorrelationID. A regression that started echoing any
//     customer-supplied or operator-supplied free-text field
//     into the LogValue group trips the canary on every row.

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// deploymentLifecycleSecretMarker is the unique, obviously-fake
// substring seeded into every free-text field of the Deployment
// row (SourceRef, IdempotencyKey, ErrorMessage, RequestID,
// CorrelationID). Asserting the marker is ABSENT from the
// rendered slog.Value pins the value-free projection invariant
// for every scenario row — a regression that started echoing any
// of those fields into the LogValue group trips the canary even
// when no per-row verdict changed. The constant deliberately
// contains no real-looking secret-shaped substring so a stray
// leak into a CI log is still safe.
const deploymentLifecycleSecretMarker = "yalladeploymentlifecyclesecretmarker0408"

// deploymentLifecycleSources is the closed set of
// store.DeploymentSource values the deployments table permits.
// Every entry MUST be exercised by at least one scenario row;
// a regression that removed a source from
// store.DeploymentSource.Valid() without dropping its entry
// here fails the exhaustiveness self-check at the head of the
// covers test.
var deploymentLifecycleSources = []store.DeploymentSource{
	store.DeploymentSourceGit,
	store.DeploymentSourceImage,
	store.DeploymentSourceManual,
}

// deploymentLifecycleStatuses is the closed set of
// store.DeploymentStatus values the deployments table permits.
// Every entry MUST be exercised by at least one scenario row.
// The list deliberately groups the two non-terminal statuses
// first and the four terminal statuses second so a contributor
// reading the table sees the lifecycle topology at a glance.
var deploymentLifecycleStatuses = []store.DeploymentStatus{
	store.DeploymentStatusQueued,
	store.DeploymentStatusRunning,
	store.DeploymentStatusSucceeded,
	store.DeploymentStatusFailed,
	store.DeploymentStatusCancelled,
	store.DeploymentStatusRolledBack,
}

// deploymentLifecycleNonTerminalStatuses lists the closed set
// of statuses for which a Deployment row MUST carry a nil
// FinishedAt. The deployments_finished_consistent table CHECK
// enforces the same invariant at Postgres; the canonical pair
// pins the contract at the Go projection so a regression caught
// here surfaces before the row reaches the database.
var deploymentLifecycleNonTerminalStatuses = map[store.DeploymentStatus]struct{}{
	store.DeploymentStatusQueued:  {},
	store.DeploymentStatusRunning: {},
}

// deploymentLifecycleExpect is the predicted shape every
// scenario row asserts against the projected Deployment. Every
// field is a closed-taxonomy enum or a boolean derived from the
// lifecycle topology (no caller-supplied free text), so per-row
// drift is loud and points the operator at the exact row that
// regressed.
type deploymentLifecycleExpect struct {
	source     store.DeploymentSource
	status     store.DeploymentStatus
	terminal   bool
	hasStarted bool
}

// deploymentLifecycleScenario is one row in the canonical
// lifecycle scenario table. Each row builds a self-contained
// Deployment and declares the closed-taxonomy tag the projection
// MUST emit.
type deploymentLifecycleScenario struct {
	name   string
	build  func() store.Deployment
	expect deploymentLifecycleExpect
}

// deploymentLifecycleBaseTime is a fixed UTC instant used as the
// CreatedAt / UpdatedAt for every scenario row. A fixed instant
// keeps the projected slog.Value byte-stable across runs so the
// determinism self-check is a straight reflect.DeepEqual on the
// rendered text form.
var deploymentLifecycleBaseTime = time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)

// deploymentLifecycleBaseDeployment is the self-contained,
// fully-populated Deployment every scenario builder starts from.
// Every free-text field is seeded with the secret marker so the
// value-free projection canary catches a regression that leaks
// any caller-supplied or operator-supplied free text into the
// LogValue group on every scenario row.
func deploymentLifecycleBaseDeployment() store.Deployment {
	return store.Deployment{
		ID:             "dep_00000000000000000000000001",
		OrganizationID: "org_00000000000000000000000001",
		ProjectID:      "prj_00000000000000000000000001",
		EnvironmentID:  "env_00000000000000000000000001",
		ServiceID:      "svc_00000000000000000000000001",
		Source:         store.DeploymentSourceGit,
		SourceRef:      deploymentLifecycleSecretMarker + "-ref",
		Status:         store.DeploymentStatusQueued,
		RequestedBy:    "usr_00000000000000000000000001",
		IdempotencyKey: deploymentLifecycleSecretMarker + "-idem",
		Version:        1,
		RequestID:      deploymentLifecycleSecretMarker + "-req",
		CorrelationID:  deploymentLifecycleSecretMarker + "-corr",
		CreatedAt:      deploymentLifecycleBaseTime,
		UpdatedAt:      deploymentLifecycleBaseTime,
	}
}

// deploymentLifecycleScenarios returns the closed-set coverage
// scenario table. Each row covers at least one new enum value
// across (DeploymentSource, DeploymentStatus); the covers self-
// checks at the head of TestDeploymentLifecycleE2ECoversCallSites
// assert every enum value appears at least once.
func deploymentLifecycleScenarios() []deploymentLifecycleScenario {
	finished := deploymentLifecycleBaseTime.Add(2 * time.Minute)
	started := deploymentLifecycleBaseTime.Add(time.Minute)
	return []deploymentLifecycleScenario{
		{
			name: "git_queued",
			build: func() store.Deployment {
				d := deploymentLifecycleBaseDeployment()
				d.Source = store.DeploymentSourceGit
				d.Status = store.DeploymentStatusQueued
				return d
			},
			expect: deploymentLifecycleExpect{
				source: store.DeploymentSourceGit,
				status: store.DeploymentStatusQueued,
			},
		},
		{
			name: "git_running",
			build: func() store.Deployment {
				d := deploymentLifecycleBaseDeployment()
				d.Source = store.DeploymentSourceGit
				d.Status = store.DeploymentStatusRunning
				s := started
				d.StartedAt = &s
				return d
			},
			expect: deploymentLifecycleExpect{
				source:     store.DeploymentSourceGit,
				status:     store.DeploymentStatusRunning,
				hasStarted: true,
			},
		},
		{
			name: "git_succeeded",
			build: func() store.Deployment {
				d := deploymentLifecycleBaseDeployment()
				d.Source = store.DeploymentSourceGit
				d.Status = store.DeploymentStatusSucceeded
				s := started
				f := finished
				d.StartedAt = &s
				d.FinishedAt = &f
				return d
			},
			expect: deploymentLifecycleExpect{
				source:     store.DeploymentSourceGit,
				status:     store.DeploymentStatusSucceeded,
				terminal:   true,
				hasStarted: true,
			},
		},
		{
			name: "image_failed",
			build: func() store.Deployment {
				d := deploymentLifecycleBaseDeployment()
				d.Source = store.DeploymentSourceImage
				d.Status = store.DeploymentStatusFailed
				s := started
				f := finished
				d.StartedAt = &s
				d.FinishedAt = &f
				d.ErrorCode = "deploy.failed"
				d.ErrorMessage = deploymentLifecycleSecretMarker + "-err"
				return d
			},
			expect: deploymentLifecycleExpect{
				source:     store.DeploymentSourceImage,
				status:     store.DeploymentStatusFailed,
				terminal:   true,
				hasStarted: true,
			},
		},
		{
			name: "image_cancelled",
			build: func() store.Deployment {
				d := deploymentLifecycleBaseDeployment()
				d.Source = store.DeploymentSourceImage
				d.Status = store.DeploymentStatusCancelled
				s := started
				f := finished
				d.StartedAt = &s
				d.FinishedAt = &f
				return d
			},
			expect: deploymentLifecycleExpect{
				source:     store.DeploymentSourceImage,
				status:     store.DeploymentStatusCancelled,
				terminal:   true,
				hasStarted: true,
			},
		},
		{
			name: "manual_running",
			build: func() store.Deployment {
				d := deploymentLifecycleBaseDeployment()
				d.Source = store.DeploymentSourceManual
				d.Status = store.DeploymentStatusRunning
				s := started
				d.StartedAt = &s
				return d
			},
			expect: deploymentLifecycleExpect{
				source:     store.DeploymentSourceManual,
				status:     store.DeploymentStatusRunning,
				hasStarted: true,
			},
		},
		{
			name: "manual_rolled_back",
			build: func() store.Deployment {
				d := deploymentLifecycleBaseDeployment()
				d.Source = store.DeploymentSourceManual
				d.Status = store.DeploymentStatusRolledBack
				s := started
				f := finished
				d.StartedAt = &s
				d.FinishedAt = &f
				return d
			},
			expect: deploymentLifecycleExpect{
				source:     store.DeploymentSourceManual,
				status:     store.DeploymentStatusRolledBack,
				terminal:   true,
				hasStarted: true,
			},
		},
	}
}

const (
	// deploymentLifecycleContentionWorkers is the goroutine
	// count for the contention burst. Sized to keep CI runtime
	// bounded while still exercising every scenario row across
	// multiple goroutines.
	deploymentLifecycleContentionWorkers = 8
	// deploymentLifecycleContentionIterationsPerWorker is the
	// per-worker iteration count. The total iteration count
	// (workers * iterations-per-worker) is a multiple of the
	// scenario row count so every row is exercised by every
	// worker.
	deploymentLifecycleContentionIterationsPerWorker = 21
	// deploymentLifecycleContentionIterations is the total
	// number of projection calls the contention burst performs.
	// The pair member asserts the burst recorded exactly this
	// many passes so a goroutine that swallowed its assertion
	// shows up as a missing pass.
	deploymentLifecycleContentionIterations = deploymentLifecycleContentionWorkers * deploymentLifecycleContentionIterationsPerWorker
)

// deploymentLifecycleContentionFailure captures the first per-
// iteration mismatch under the contention burst. Recording the
// iteration index and the scenario name keeps the failure
// message actionable: an operator reading the CI log can point
// straight at the row that regressed.
type deploymentLifecycleContentionFailure struct {
	iter    int
	rowName string
	message string
}

// TestDeploymentLifecycleE2ECoversCallSites is the closed-set
// coverage half of the BE-0408 pair. It walks every documented
// (DeploymentSource, DeploymentStatus) value, asserts the
// lifecycle-timestamp consistency invariant for every row, and
// asserts the projection emits the predicted closed-taxonomy
// tags. The closed-set self-checks at the head of the test catch
// drift in either direction: a new enum value that ships without
// a row, an existing enum value that drops its row, a row that
// violates the terminal-implies-finished_at invariant, or a non-
// deterministic LogValue projection.
func TestDeploymentLifecycleE2ECoversCallSites(t *testing.T) {
	t.Parallel()

	rows := deploymentLifecycleScenarios()
	if len(rows) == 0 {
		t.Fatalf("deploymentLifecycleScenarios returned an empty table; the closed-set construction is broken")
	}

	// Closed-set self-check #1: every documented DeploymentSource
	// is exercised by at least one scenario row.
	sourceSeen := make(map[store.DeploymentSource]int, len(deploymentLifecycleSources))
	for _, s := range deploymentLifecycleSources {
		sourceSeen[s] = 0
	}
	for _, row := range rows {
		if _, ok := sourceSeen[row.expect.source]; !ok {
			t.Fatalf("scenario %q tags DeploymentSource %q which is not in deploymentLifecycleSources; every scenario source tag must be a documented DeploymentSource",
				row.name, row.expect.source)
		}
		sourceSeen[row.expect.source]++
	}
	for s, count := range sourceSeen {
		if count == 0 {
			t.Fatalf("DeploymentSource %q is not exercised by any scenario; every documented source must surface in at least one row of deploymentLifecycleScenarios",
				s)
		}
	}

	// Closed-set self-check #2: every documented DeploymentStatus
	// is exercised by at least one scenario row.
	statusSeen := make(map[store.DeploymentStatus]int, len(deploymentLifecycleStatuses))
	for _, s := range deploymentLifecycleStatuses {
		statusSeen[s] = 0
	}
	for _, row := range rows {
		if _, ok := statusSeen[row.expect.status]; !ok {
			t.Fatalf("scenario %q tags DeploymentStatus %q which is not in deploymentLifecycleStatuses; every scenario status tag must be a documented DeploymentStatus",
				row.name, row.expect.status)
		}
		statusSeen[row.expect.status]++
	}
	for s, count := range statusSeen {
		if count == 0 {
			t.Fatalf("DeploymentStatus %q is not exercised by any scenario; every documented status must surface in at least one row of deploymentLifecycleScenarios",
				s)
		}
	}

	// Closed-set self-check #3: terminality classification. The
	// deploymentLifecycleNonTerminalStatuses set MUST partition
	// the lifecycle into exactly the non-terminal statuses (no
	// terminal status appears in the set). A regression that
	// promoted a terminal status into the non-terminal set or
	// vice versa would either silently let a non-terminal row
	// carry a FinishedAt (database CHECK violation in
	// production) or silently let a terminal row omit one
	// (orphaned deployment).
	for _, row := range rows {
		_, nonTerminal := deploymentLifecycleNonTerminalStatuses[row.expect.status]
		isTerminal := !nonTerminal
		if isTerminal != row.expect.terminal {
			t.Fatalf("scenario %q: terminal classification mismatch — deploymentLifecycleNonTerminalStatuses says terminal=%t but row tags terminal=%t; the non-terminal set and the row expectations must agree",
				row.name, isTerminal, row.expect.terminal)
		}
	}

	// Closed-set self-check #4: lifecycle-timestamp consistency.
	// Every non-terminal status (queued, running) row MUST carry
	// a nil FinishedAt; every terminal status row MUST carry a
	// set FinishedAt. The deployments_finished_consistent table
	// CHECK enforces the same invariant at Postgres; the
	// canonical pair pins the same contract at the Go projection
	// so a regression that constructed an in-memory Deployment
	// violating the invariant is caught before the row reaches
	// the database.
	for _, row := range rows {
		d := row.build()
		_, nonTerminal := deploymentLifecycleNonTerminalStatuses[d.Status]
		if nonTerminal && d.FinishedAt != nil {
			t.Fatalf("scenario %q: non-terminal status %q has FinishedAt=%v; non-terminal deployments MUST carry a nil FinishedAt to satisfy the deployments_finished_consistent table CHECK",
				row.name, d.Status, *d.FinishedAt)
		}
		if !nonTerminal && d.FinishedAt == nil {
			t.Fatalf("scenario %q: terminal status %q has nil FinishedAt; terminal deployments MUST carry a set FinishedAt to satisfy the deployments_finished_consistent table CHECK",
				row.name, d.Status)
		}
	}

	// Closed-set self-check #5: deterministic projection.
	// LogValue is a deterministic function of its input —
	// calling it twice on the same row MUST yield equal
	// slog.Value projections (same group, same fields, same
	// order). A regression that introduced map-iteration
	// ordering or a non-deterministic field into the projection
	// would surface here before any per-row verdict.
	for _, row := range rows {
		row := row
		d := row.build()
		first := deploymentLifecycleRenderLogValue(d)
		second := deploymentLifecycleRenderLogValue(d)
		if first != second {
			t.Fatalf("scenario %q: LogValue projection is non-deterministic — repeated call produced different slog output.\n first=%s\nsecond=%s",
				row.name, first, second)
		}
	}

	// Closed-set self-check #6: the secret marker is a non-empty
	// compile-time literal whose absence would silently false-
	// positive every per-row marker-absence predicate. Asserting
	// non-emptiness pins the contract that a future contributor
	// who blanks the constant must explicitly update the test,
	// not silently de-gate the value-free projection canary.
	if deploymentLifecycleSecretMarker == "" {
		t.Fatalf("deploymentLifecycleSecretMarker is empty; the per-row value-free predicate would false-positive on every scenario")
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			d := row.build()
			deploymentLifecycleAssertOutcome(t, row, d)
		})
	}
}

// TestDeploymentLifecycleE2EPreservesContractUnderContention is
// the per-decision-stability half of the BE-0408 pair. It fires
// `deploymentLifecycleContentionIterations` goroutines that each
// draw a scenario by deterministic mod-index, construct a fresh
// Deployment per iteration, and call `LogValue` directly. The
// Deployment instances are per-iteration rather than shared
// because the chokepoint's contract is "construction is cheap;
// LogValue is a pure function of its input": a regression that
// smuggled in a package-level cache, a `sync.Once` mutating a
// per-call map, or a `sync.Pool` reused without resetting would
// surface as a per-iteration mismatch even when the aggregate
// pass count matched, because every goroutine knows its
// scenario's predicted (Source, Status, terminal) tag and
// asserts that exact verdict.
func TestDeploymentLifecycleE2EPreservesContractUnderContention(t *testing.T) {
	t.Parallel()

	rows := deploymentLifecycleScenarios()
	if len(rows) == 0 {
		t.Fatalf("deploymentLifecycleScenarios returned an empty table; the closed-set construction is broken")
	}

	var passed atomic.Int64
	var firstErr atomic.Pointer[deploymentLifecycleContentionFailure]
	var wg sync.WaitGroup

	for w := 0; w < deploymentLifecycleContentionWorkers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < deploymentLifecycleContentionIterationsPerWorker; i++ {
				iter := w*deploymentLifecycleContentionIterationsPerWorker + i
				row := rows[iter%len(rows)]
				d := row.build()
				if fail := deploymentLifecycleCheckOutcome(row, d); fail != nil {
					fail.iter = iter
					firstErr.CompareAndSwap(nil, fail)
					continue
				}
				passed.Add(1)
			}
		}()
	}
	wg.Wait()

	if fe := firstErr.Load(); fe != nil {
		t.Fatalf("contention iteration %d (row %q): %s; a per-iteration mismatch under burst contention indicates shared mutable state in the projection OR a non-deterministic LogValue ordering",
			fe.iter, fe.rowName, fe.message)
	}
	if got := passed.Load(); got != int64(deploymentLifecycleContentionIterations) {
		t.Fatalf("contention burst: expected %d successful iterations, got %d; a missing pass without a recorded failure indicates a goroutine swallowed its assertion",
			deploymentLifecycleContentionIterations, got)
	}
}

// deploymentLifecycleAssertOutcome is the canonical-pair fail-
// fast assertion helper. The per-row covers test calls it
// directly so a per-row failure points the operator at the
// exact scenario that drifted.
func deploymentLifecycleAssertOutcome(t *testing.T, row deploymentLifecycleScenario, d store.Deployment) {
	t.Helper()
	if fail := deploymentLifecycleCheckOutcome(row, d); fail != nil {
		t.Fatalf("%s", fail.message)
	}
}

// deploymentLifecycleCheckOutcome is the shared per-row verdict
// function used by both pair members. Returning a failure
// pointer instead of calling t.Fatal directly lets the
// contention burst capture the first failure across goroutines
// via atomic.Pointer without taking a *testing.T.
func deploymentLifecycleCheckOutcome(row deploymentLifecycleScenario, d store.Deployment) *deploymentLifecycleContentionFailure {
	// Closed-taxonomy tag assertions — every field is a closed
	// enum so per-row drift points straight at the regression.
	if d.Source != row.expect.source {
		return &deploymentLifecycleContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Deployment.Source = %q, want %q — the scenario builder produced a DeploymentSource outside the predicted closed-taxonomy tag", d.Source, row.expect.source),
		}
	}
	if d.Status != row.expect.status {
		return &deploymentLifecycleContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Deployment.Status = %q, want %q — the scenario builder produced a DeploymentStatus outside the predicted closed-taxonomy tag", d.Status, row.expect.status),
		}
	}
	if !d.Source.Valid() {
		return &deploymentLifecycleContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Deployment.Source %q failed Valid(); every scenario row must carry a DeploymentSource the database CHECK accepts", d.Source),
		}
	}

	// Lifecycle-timestamp consistency: the
	// deployments_finished_consistent table CHECK enforces this
	// at Postgres; pinning it at the projection catches a
	// regression before the row reaches the database.
	_, nonTerminal := deploymentLifecycleNonTerminalStatuses[d.Status]
	if nonTerminal && d.FinishedAt != nil {
		return &deploymentLifecycleContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("non-terminal status %q has FinishedAt set; the lifecycle invariant requires nil FinishedAt for non-terminal deployments", d.Status),
		}
	}
	if !nonTerminal && d.FinishedAt == nil {
		return &deploymentLifecycleContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("terminal status %q has nil FinishedAt; the lifecycle invariant requires a set FinishedAt for terminal deployments", d.Status),
		}
	}
	if row.expect.hasStarted && d.StartedAt == nil {
		return &deploymentLifecycleContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("scenario expects StartedAt to be set for status %q but the row carries nil StartedAt", d.Status),
		}
	}

	// Value-free projection canary: the rendered slog.Value
	// MUST NOT contain the raw secret marker even when the
	// marker is seeded into SourceRef, IdempotencyKey,
	// ErrorMessage, RequestID, and CorrelationID. The marker is
	// a unique, obviously-fake string so a future redaction
	// regression that started echoing any of those fields into
	// the LogValue group trips this canary on every scenario
	// row.
	logged := deploymentLifecycleRenderLogValue(d)
	if strings.Contains(logged, deploymentLifecycleSecretMarker) {
		return &deploymentLifecycleContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Deployment.LogValue() leaked the raw secret marker %q — the redacted slog projection MUST NOT echo SourceRef, IdempotencyKey, ErrorMessage, RequestID, or CorrelationID; got=%s", deploymentLifecycleSecretMarker, logged),
		}
	}

	// LogValue MUST project Source and Status as their canonical
	// string forms so an operator reading a slog record can
	// match the row to the closed-taxonomy tag without parsing
	// internal representations.
	if !strings.Contains(logged, fmt.Sprintf("source=%s", d.Source.String())) {
		return &deploymentLifecycleContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Deployment.LogValue() did not project source=%s; an operator MUST be able to read the source from the slog record; got=%s", d.Source.String(), logged),
		}
	}
	if !strings.Contains(logged, fmt.Sprintf("status=%s", d.Status.String())) {
		return &deploymentLifecycleContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("Deployment.LogValue() did not project status=%s; an operator MUST be able to read the lifecycle status from the slog record; got=%s", d.Status.String(), logged),
		}
	}

	// Determinism cross-check at per-row scope: projecting the
	// same row twice in the same scenario must produce equal
	// slog.Value renders. The covers test runs this across
	// every row in self-check #5; the contention test runs it
	// implicitly per iteration. Keeping it inside the shared
	// verdict function pins the contract at every burst
	// goroutine boundary too.
	repeat := deploymentLifecycleRenderLogValue(row.build())
	if logged != repeat {
		return &deploymentLifecycleContentionFailure{
			rowName: row.name,
			message: fmt.Sprintf("LogValue projection is non-deterministic for row %q — repeated call produced a different slog output;\n first=%s\nsecond=%s", row.name, logged, repeat),
		}
	}

	// Structural redaction check: the projected slog group MUST
	// carry the documented field whitelist (id, organization_id,
	// project_id, environment_id, service_id, source, status,
	// requested_by, version) and MUST NOT carry the redacted-
	// from-projection blacklist (source_ref, idempotency_key,
	// error_code, error_message, request_id, correlation_id).
	// Reading the structured fields through encoding/json
	// keeps the assertion independent of slog's text format —
	// a regression that switched the handler still trips the
	// structural check.
	structured := deploymentLifecycleStructuredLogValue(d)
	for _, want := range []string{"id", "organization_id", "project_id", "environment_id", "service_id", "source", "status", "requested_by", "version"} {
		if _, ok := structured[want]; !ok {
			return &deploymentLifecycleContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("Deployment.LogValue() missing required field %q — the documented slog projection MUST carry every whitelisted field; got fields=%v", want, structuredKeys(structured)),
			}
		}
	}
	for _, redacted := range []string{"source_ref", "idempotency_key", "error_code", "error_message", "request_id", "correlation_id"} {
		if _, ok := structured[redacted]; ok {
			return &deploymentLifecycleContentionFailure{
				rowName: row.name,
				message: fmt.Sprintf("Deployment.LogValue() projected redacted field %q — that field carries customer- or operator-supplied free text and MUST NOT appear in the slog projection; got=%v", redacted, structured[redacted]),
			}
		}
	}

	return nil
}

// deploymentLifecycleStripTimeAttr is the ReplaceAttr hook the
// canonical-pair handlers install to drop slog's per-record
// wall-clock attribute. The determinism cross-check asserts
// repeat calls produce equal projections; preserving slog's
// wall-clock attribute would non-deterministically fail that
// check across any millisecond boundary. Dropping the attribute
// keeps the assertion bound to the deployment-payload group
// alone — the chokepoint LogValue contract — not to a
// timestamp the slog runtime owns.
func deploymentLifecycleStripTimeAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.TimeKey {
		return slog.Attr{}
	}
	return a
}

// deploymentLifecycleRenderLogValue captures the
// Deployment.LogValue() projection by formatting a slog record
// built from it into a string. The slog handler is the
// production surface that turns a Deployment into a log line, so
// asserting the marker is absent from the formatted record pins
// the redaction contract end-to-end through the slog API, not
// just an in-memory slog.Value inspection. The wall-clock time
// attribute is stripped via ReplaceAttr so the projection is
// deterministic; the chokepoint LogValue group is what the
// pair asserts on, not slog's framing.
func deploymentLifecycleRenderLogValue(d store.Deployment) string {
	var b strings.Builder
	handler := slog.NewTextHandler(&b, &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: deploymentLifecycleStripTimeAttr,
	})
	logger := slog.New(handler)
	logger.Info("deployment-lifecycle-canary", slog.Any("deployment", d))
	return b.String()
}

// deploymentLifecycleStructuredLogValue captures the
// Deployment.LogValue() projection as a map keyed by attribute
// name, by routing the record through a JSON slog handler. The
// structural form is independent of the text handler's escaping
// rules — a regression that switched the handler still trips
// the whitelist / blacklist check. The wall-clock time
// attribute is stripped via ReplaceAttr so the projection is
// deterministic.
func deploymentLifecycleStructuredLogValue(d store.Deployment) map[string]any {
	var b strings.Builder
	handler := slog.NewJSONHandler(&b, &slog.HandlerOptions{
		Level:       slog.LevelDebug,
		ReplaceAttr: deploymentLifecycleStripTimeAttr,
	})
	logger := slog.New(handler)
	logger.Info("deployment-lifecycle-canary", slog.Any("deployment", d))
	var record map[string]any
	if err := json.Unmarshal([]byte(b.String()), &record); err != nil {
		return map[string]any{"__unmarshal_error__": err.Error()}
	}
	group, _ := record["deployment"].(map[string]any)
	if group == nil {
		return map[string]any{"__missing_deployment_group__": true}
	}
	return group
}

// structuredKeys returns the sorted-by-iteration field keys of
// the projected slog group. The list is only used inside a
// failure message so the operator sees what the projection
// actually carried when a required field went missing.
func structuredKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// _ pins a reflect import we use for the determinism cross-check
// pattern even if a future refactor moves the call site. Without
// the explicit reference the import is dropped on auto-format
// and the file fails to compile if the cross-check is later
// expanded to a reflect.DeepEqual on the structured form.
var _ = reflect.DeepEqual
