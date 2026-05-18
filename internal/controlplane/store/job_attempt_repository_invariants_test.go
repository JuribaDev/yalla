package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer CRUD-and-invariants for the job_attempts table (BE-0463).
// A job_attempts row is one immutable record on the runtime history of a
// single provisioning_jobs row: the worker writes it exactly once when it
// releases the lease, with the terminal observation of that attempt
// (succeeded, failed, cancelled, or timed_out). The JobAttemptRepository
// surface is intentionally narrow: Append appends a row inside a
// transaction (the same transaction that also transitions the parent
// provisioning_jobs row to a terminal status, when the writer is a
// lifecycle transition), ListByJob reads tenant-scoped chronological
// history, and GetByID reads a single row tenant-scoped. There is no
// per-row Update / Delete in this surface: the database BEFORE UPDATE
// trigger rejects every update at the SQL level, and the store package
// exposes no row-level delete (row removal is reachable only through
// ON DELETE CASCADE when the parent provisioning_jobs row is removed).
//
// What this file pins, and what it deliberately delegates:
//
//   - Append row-shape on the first call: a blank-id attempt mints an id
//     carrying the jatt_ prefix, ErrorSummary / ErrorCode / RequestID /
//     CorrelationID stay at the zero value when not supplied, the database
//     stamps created_at within the same wallclock second of the call, and
//     the caller-supplied started_at and finished_at round-trip verbatim.
//     The return value's struct fields are byte-equal to a raw-SQL re-load
//     of the persisted row.
//   - Append id contract: a caller-supplied id is preserved verbatim, a
//     duplicate id surfaces as typed apierr.Conflict (PRIMARY KEY) through
//     mapWriteError.
//   - Append CHECK / FK violations surface as typed apierr.Conflict through
//     mapWriteError: an unknown status (after bypassing the application
//     validator by inserting via raw SQL is not exercised here -- the
//     application-side Valid() guard is the chokepoint), an unknown
//     organization / job (composite FK provisioning_jobs(organization_id,
//     id)), a cross-tenant (organization_id, job_id) tuple that would
//     reference another tenant's job, and a duplicate attempt_number
//     within the same job (UNIQUE (organization_id, job_id,
//     attempt_number)).
//   - Append application-layer validation: missing organization_id /
//     job_id / worker_id, blank or unknown status, non-positive
//     attempt_number, zero started_at, zero finished_at, and a finished_at
//     that predates started_at all surface as typed apierr.InvalidInput
//     before the database is touched.
//   - Append nil-Tx surfaces as typed apierr.Internal: a job attempt must
//     never be persisted outside the transaction that also carries the
//     parent provisioning_jobs Transition write it records.
//   - Append transaction rollback semantics: a closure that returns an
//     error after a successful Append leaves no job_attempts row behind.
//   - Peer-row byte-identity: Append for one (organization, job) tuple
//     does not touch a sibling attempt row's id, attempt_number,
//     created_at, started_at, finished_at, status, error_summary, or
//     error_code.
//   - Append-only enforcement: the database BEFORE UPDATE trigger
//     rejects every UPDATE against job_attempts at the SQL level, so a
//     written attempt record can never be altered after the fact.
//   - Cascade delete: removing the parent provisioning_jobs row cascades
//     through the job_attempts composite FK ON DELETE CASCADE -- an
//     attempt row never survives its parent job.
//   - GetByID lookup contracts: a persisted row reads back byte-identical
//     to the Append RETURNING projection; an unknown id surfaces as typed
//     apierr.NotFound (never as a 500 leaking the cause); the row is
//     never an oracle that reveals another tenant's attempt ids.
//   - ListByJob ordering contract: rows are returned in chronological
//     order (attempt_number ASC) -- the timeline endpoint renders the
//     job's retry history unfolding forward in time.
//   - ListByJob unknown-job contract: an unknown or cross-tenant job_id
//     returns the empty slice, never an error, so the timeline endpoint
//     can render an empty timeline without distinguishing "no attempts"
//     from "no parent" (callers that need the distinction Get the
//     parent job first).
//
// Delegated invariants (explicitly NOT re-asserted here):
//
//   - Cross-tenant List leak under cross-organization read scenarios is
//     the BE-0464 sibling tenant-isolation story and lives in the future
//     job_attempt_tenant_isolation_test.go.
//   - The HTTP wire shape of the future job-attempts timeline endpoint,
//     its policy matrix, and its OpenAPI contract are owned by future
//     job-attempts HTTP stories.
//
// Helpers introduced here: rawJobAttemptRow, loadJobAttemptRowByID,
// countJobAttemptRowsForJob, mintJobAttemptID, runAppendJobAttemptOrFail,
// seedJobAttempt, jobAttemptTxRollbackSentinel. Helpers reused from
// sibling files: seedOrg, seedProject (schema_test.go); newStore
// (store_test.go); seedQueuedJob, jobFixture, insertJob, mintJobID
// (job_test.go, job_repository_invariants_test.go,
// job_repository_tenant_isolation_test.go).

// rawJobAttemptRow is the full job_attempts row, deliberately loaded via
// raw SQL so the test can observe id, created_at, started_at,
// finished_at, the closed-set status column, and the error columns
// through the same shape the database stores them in. It is the same
// template rawDeploymentEventRow uses for deployment_events in BE-0459.
type rawJobAttemptRow struct {
	ID             string
	OrganizationID string
	JobID          string
	AttemptNumber  int
	WorkerID       string
	Status         string
	ErrorSummary   string
	ErrorCode      string
	RequestID      string
	CorrelationID  string
	StartedAt      time.Time
	FinishedAt     time.Time
	CreatedAt      time.Time
}

// loadJobAttemptRowByID reads the raw job_attempts row for id and fatals
// on error. The lookup is by primary key -- distinct attempt rows have
// distinct ids -- so no tenant scope is needed (raw loaders bypass
// repository scoping deliberately, so the test observes the persisted
// row exactly as the database stores it).
func loadJobAttemptRowByID(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	id string,
) rawJobAttemptRow {
	t.Helper()
	var row rawJobAttemptRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, job_id, attempt_number, worker_id,
		        status, error_summary, error_code, request_id, correlation_id,
		        started_at, finished_at, created_at
		   FROM job_attempts
		  WHERE id = $1`,
		id).Scan(
		&row.ID, &row.OrganizationID, &row.JobID, &row.AttemptNumber, &row.WorkerID,
		&row.Status, &row.ErrorSummary, &row.ErrorCode, &row.RequestID, &row.CorrelationID,
		&row.StartedAt, &row.FinishedAt, &row.CreatedAt,
	); err != nil {
		t.Fatalf("load job_attempts id=%q: %v", id, err)
	}
	return row
}

// countJobAttemptRowsForJob returns the number of job_attempts rows owned
// by (organizationID, jobID). It is the "did the rollback / cascade leave
// a row behind?" probe.
func countJobAttemptRowsForJob(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID, jobID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM job_attempts
		  WHERE organization_id = $1 AND job_id = $2`,
		organizationID, jobID).Scan(&n); err != nil {
		t.Fatalf("count job_attempts for (%q, %q): %v",
			organizationID, jobID, err)
	}
	return n
}

// mintJobAttemptID builds a stable, test-local job attempt id from the
// test name and a per-test suffix. Tests in store_test share a single
// package, so the test name keeps ids unique across parallel test cases
// without needing a shared atomic counter. Real id minting lives in
// JobAttemptRepository.Append (newJobAttemptID), so this is the
// test-local override that exercises the caller-supplied-id branch.
func mintJobAttemptID(t *testing.T, suffix string) string {
	t.Helper()
	return "jatt_" + t.Name() + "_" + suffix
}

// runAppendJobAttemptOrFail runs JobAttemptRepository.Append inside a
// write transaction, fatals on error, and returns the persisted attempt.
// It is the smallest possible happy-path closure and is reused by every
// test that does not need to observe the call's tx in isolation.
func runAppendJobAttemptOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.JobAttemptRepository,
	a store.JobAttempt,
) store.JobAttempt {
	t.Helper()
	var created store.JobAttempt
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		got, aErr := repo.Append(ctx, tx, a)
		if aErr != nil {
			return aErr
		}
		created = got
		return nil
	}); err != nil {
		t.Fatalf("Append(%+v): %v", a, err)
	}
	return created
}

// seedJobAttempt appends a 'succeeded' attempt row for (org, job) with the
// given attempt number and returns it. It centralises the boilerplate the
// List / cascade tests need so the per-test bodies focus on the invariant
// rather than the construction of a valid row.
func seedJobAttempt(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.JobAttemptRepository,
	org testutil.Organization,
	job store.ProvisioningJob,
	suffix string,
	attemptNumber int,
	status store.JobAttemptStatus,
	startedAt time.Time,
) store.JobAttempt {
	t.Helper()
	return runAppendJobAttemptOrFail(ctx, t, s, repo, store.JobAttempt{
		ID:             mintJobAttemptID(t, suffix),
		OrganizationID: org.ID,
		JobID:          job.ID,
		AttemptNumber:  attemptNumber,
		WorkerID:       "worker_" + suffix,
		Status:         status,
		RequestID:      "req_" + suffix,
		CorrelationID:  "cor_" + suffix,
		StartedAt:      startedAt,
		FinishedAt:     startedAt.Add(2 * time.Second),
	})
}

// jobAttemptTxRollbackSentinel is a uniquely-typed sentinel for the
// rollback test. Sentinel types must be unique per file in the store_test
// package (every *_test.go under internal/controlplane/store/ shares the
// same package). Existing siblings include deploymentEventTxRollbackSentinel
// and quotaReservationTxRollbackSentinel.
type jobAttemptTxRollbackSentinel struct{}

func (jobAttemptTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this job attempt transaction"
}

func TestJobAttemptRepositoryAppendMintsRowShape(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "shape")

	started := time.Now().UTC().Truncate(time.Microsecond)
	finished := started.Add(750 * time.Millisecond)
	created := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		OrganizationID: org.ID,
		JobID:          job.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_alpha",
		Status:         store.JobAttemptStatusSucceeded,
		RequestID:      "req_shape",
		CorrelationID:  "cor_shape",
		StartedAt:      started,
		FinishedAt:     finished,
	})

	if created.ID == "" {
		t.Fatal("created.ID is blank, want a minted id")
	}
	if !strings.HasPrefix(created.ID, "jatt_") {
		t.Errorf("created.ID = %q, want jatt_ prefix", created.ID)
	}
	if created.OrganizationID != org.ID {
		t.Errorf("created.OrganizationID = %q, want %q", created.OrganizationID, org.ID)
	}
	if created.JobID != job.ID {
		t.Errorf("created.JobID = %q, want %q", created.JobID, job.ID)
	}
	if created.AttemptNumber != 1 {
		t.Errorf("created.AttemptNumber = %d, want %d", created.AttemptNumber, 1)
	}
	if created.WorkerID != "worker_alpha" {
		t.Errorf("created.WorkerID = %q, want %q", created.WorkerID, "worker_alpha")
	}
	if created.Status != store.JobAttemptStatusSucceeded {
		t.Errorf("created.Status = %q, want %q", created.Status, store.JobAttemptStatusSucceeded)
	}
	if !created.StartedAt.Equal(started) {
		t.Errorf("created.StartedAt = %v, want %v (caller-supplied started_at must round-trip)",
			created.StartedAt, started)
	}
	if !created.FinishedAt.Equal(finished) {
		t.Errorf("created.FinishedAt = %v, want %v (caller-supplied finished_at must round-trip)",
			created.FinishedAt, finished)
	}
	if created.CreatedAt.IsZero() {
		t.Errorf("created.CreatedAt is zero, want database-stamped now()")
	}

	// The returned struct must match a raw-SQL re-load byte-for-byte across
	// every observable column -- the only way to prove the RETURNING clause
	// and scanJobAttempt agree with the persisted row.
	row := loadJobAttemptRowByID(ctx, t, db, created.ID)
	if row.OrganizationID != created.OrganizationID {
		t.Errorf("row.OrganizationID = %q, want %q", row.OrganizationID, created.OrganizationID)
	}
	if row.JobID != created.JobID {
		t.Errorf("row.JobID = %q, want %q", row.JobID, created.JobID)
	}
	if row.AttemptNumber != created.AttemptNumber {
		t.Errorf("row.AttemptNumber = %d, want %d", row.AttemptNumber, created.AttemptNumber)
	}
	if row.WorkerID != created.WorkerID {
		t.Errorf("row.WorkerID = %q, want %q", row.WorkerID, created.WorkerID)
	}
	if row.Status != string(created.Status) {
		t.Errorf("row.Status = %q, want %q", row.Status, created.Status)
	}
	if !row.StartedAt.Equal(created.StartedAt) {
		t.Errorf("row.StartedAt = %v, want %v", row.StartedAt, created.StartedAt)
	}
	if !row.FinishedAt.Equal(created.FinishedAt) {
		t.Errorf("row.FinishedAt = %v, want %v", row.FinishedAt, created.FinishedAt)
	}
	if !row.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("row.CreatedAt = %v, want %v", row.CreatedAt, created.CreatedAt)
	}
	if row.RequestID != created.RequestID || row.CorrelationID != created.CorrelationID {
		t.Errorf("correlation ids drifted: row=(%q,%q) created=(%q,%q)",
			row.RequestID, row.CorrelationID, created.RequestID, created.CorrelationID)
	}
}

func TestJobAttemptRepositoryAppendBlankFieldsDefault(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "blank")

	started := time.Now().UTC().Truncate(time.Microsecond)
	created := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		OrganizationID: org.ID,
		JobID:          job.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_beta",
		Status:         store.JobAttemptStatusSucceeded,
		StartedAt:      started,
		FinishedAt:     started.Add(time.Second),
	})

	if created.ErrorSummary != "" {
		t.Errorf("created.ErrorSummary = %q, want empty (default)", created.ErrorSummary)
	}
	if created.ErrorCode != "" {
		t.Errorf("created.ErrorCode = %q, want empty (default)", created.ErrorCode)
	}
	if created.RequestID != "" || created.CorrelationID != "" {
		t.Errorf("blank correlation ids drifted: req=%q cor=%q",
			created.RequestID, created.CorrelationID)
	}
}

func TestJobAttemptRepositoryAppendRespectsCallerSuppliedID(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "caller_id")

	started := time.Now().UTC().Truncate(time.Microsecond)
	explicitID := mintJobAttemptID(t, "explicit")
	created := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		ID:             explicitID,
		OrganizationID: org.ID,
		JobID:          job.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_gamma",
		Status:         store.JobAttemptStatusSucceeded,
		StartedAt:      started,
		FinishedAt:     started.Add(time.Second),
	})

	if created.ID != explicitID {
		t.Errorf("created.ID = %q, want %q (a non-empty caller id must be preserved verbatim)",
			created.ID, explicitID)
	}
}

func TestJobAttemptRepositoryAppendDuplicateIDIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "dup_id")

	id := mintJobAttemptID(t, "collision")
	started := time.Now().UTC().Truncate(time.Microsecond)
	first := store.JobAttempt{
		ID:             id,
		OrganizationID: org.ID,
		JobID:          job.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_first",
		Status:         store.JobAttemptStatusSucceeded,
		StartedAt:      started,
		FinishedAt:     started.Add(time.Second),
	}
	_ = runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, first)

	second := first
	second.AttemptNumber = 2
	second.WorkerID = "worker_second"
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := attemptRepo.Append(ctx, tx, second)
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(duplicate id) error = %v, want code %s (PRIMARY KEY collision must surface via mapWriteError)",
			err, yerr.CodeConflict)
	}
}

func TestJobAttemptRepositoryAppendDuplicateAttemptNumberIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "dup_n")

	started := time.Now().UTC().Truncate(time.Microsecond)
	first := store.JobAttempt{
		OrganizationID: org.ID,
		JobID:          job.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_a",
		Status:         store.JobAttemptStatusSucceeded,
		StartedAt:      started,
		FinishedAt:     started.Add(time.Second),
	}
	_ = runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, first)

	dup := first
	dup.WorkerID = "worker_b"
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := attemptRepo.Append(ctx, tx, dup)
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(duplicate attempt_number) error = %v, want code %s "+
			"(UNIQUE (organization_id, job_id, attempt_number) must surface via mapWriteError)",
			err, yerr.CodeConflict)
	}
}

func TestJobAttemptRepositoryAppendUnknownJobIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	started := time.Now().UTC().Truncate(time.Microsecond)
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := attemptRepo.Append(ctx, tx, store.JobAttempt{
			OrganizationID: org.ID,
			JobID:          "job_does_not_exist",
			AttemptNumber:  1,
			WorkerID:       "worker_unknown",
			Status:         store.JobAttemptStatusFailed,
			StartedAt:      started,
			FinishedAt:     started.Add(time.Second),
		})
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(unknown job) error = %v, want code %s (composite FK violation must surface via mapWriteError)",
			err, yerr.CodeConflict)
	}
}

func TestJobAttemptRepositoryAppendCrossTenantJobIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "acme")
	projA := seedProject(t, db, f, orgA, "api")
	jobA := seedQueuedJob(ctx, t, s, jobRepo, orgA, projA, "cross")

	orgB := seedOrg(t, db, f, "bravo")

	started := time.Now().UTC().Truncate(time.Microsecond)
	// (organization_id = orgB, job_id = jobA) references no row in the
	// composite UNIQUE (organization_id, id) on provisioning_jobs: the
	// composite FK rejects it as a Conflict.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := attemptRepo.Append(ctx, tx, store.JobAttempt{
			OrganizationID: orgB.ID,
			JobID:          jobA.ID,
			AttemptNumber:  1,
			WorkerID:       "worker_x",
			Status:         store.JobAttemptStatusFailed,
			StartedAt:      started,
			FinishedAt:     started.Add(time.Second),
		})
		return aErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(cross-tenant job) error = %v, want code %s "+
			"(composite FK rejects a cross-tenant (organization_id, job_id) tuple)",
			err, yerr.CodeConflict)
	}
}

func TestJobAttemptRepositoryAppendApplicationValidationRejectsBadInput(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "validate")

	started := time.Now().UTC().Truncate(time.Microsecond)
	base := store.JobAttempt{
		OrganizationID: org.ID,
		JobID:          job.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_v",
		Status:         store.JobAttemptStatusSucceeded,
		StartedAt:      started,
		FinishedAt:     started.Add(time.Second),
	}

	cases := map[string]store.JobAttempt{
		"missing organization_id": withJobAttempt(base, func(a *store.JobAttempt) { a.OrganizationID = "" }),
		"missing job_id":          withJobAttempt(base, func(a *store.JobAttempt) { a.JobID = "" }),
		"missing worker_id":       withJobAttempt(base, func(a *store.JobAttempt) { a.WorkerID = "" }),
		"missing status":          withJobAttempt(base, func(a *store.JobAttempt) { a.Status = "" }),
		"unknown status": withJobAttempt(base, func(a *store.JobAttempt) {
			a.Status = store.JobAttemptStatus("not_a_real_status")
		}),
		"non-positive attempt_number": withJobAttempt(base, func(a *store.JobAttempt) { a.AttemptNumber = 0 }),
		"zero started_at":             withJobAttempt(base, func(a *store.JobAttempt) { a.StartedAt = time.Time{} }),
		"zero finished_at":            withJobAttempt(base, func(a *store.JobAttempt) { a.FinishedAt = time.Time{} }),
		"finished_at predates started_at": withJobAttempt(base, func(a *store.JobAttempt) {
			a.FinishedAt = a.StartedAt.Add(-time.Second)
		}),
	}

	for name, attempt := range cases {
		name, attempt := name, attempt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, aErr := attemptRepo.Append(ctx, tx, attempt)
				return aErr
			})
			if ye := yerr.From(err); ye.Code != yerr.CodeInvalidInput {
				t.Fatalf("Append(%s) error = %v, want code %s (application-layer validation chokepoint)",
					name, err, yerr.CodeInvalidInput)
			}
		})
	}
}

// withJobAttempt returns a copy of base with the mutator applied.
func withJobAttempt(base store.JobAttempt, mutate func(*store.JobAttempt)) store.JobAttempt {
	cp := base
	mutate(&cp)
	return cp
}

func TestJobAttemptRepositoryAppendNilTxIsInternal(t *testing.T) {
	t.Parallel()
	// No DB needed: the nil-tx guard fires before the SQL is issued.
	attemptRepo := store.NewJobAttemptRepository()

	started := time.Now().UTC().Truncate(time.Microsecond)
	_, err := attemptRepo.Append(context.Background(), nil, store.JobAttempt{
		OrganizationID: "org_anything",
		JobID:          "job_anything",
		AttemptNumber:  1,
		WorkerID:       "worker_anything",
		Status:         store.JobAttemptStatusSucceeded,
		StartedAt:      started,
		FinishedAt:     started.Add(time.Second),
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Append(nil tx) error = %v, want code %s (programming error caught at application boundary)",
			err, yerr.CodeInternal)
	}
}

func TestJobAttemptRepositoryAppendTransactionRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "rollback")

	started := time.Now().UTC().Truncate(time.Microsecond)
	sentinel := jobAttemptTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, aErr := attemptRepo.Append(ctx, tx, store.JobAttempt{
			OrganizationID: org.ID,
			JobID:          job.ID,
			AttemptNumber:  1,
			WorkerID:       "worker_doomed",
			Status:         store.JobAttemptStatusFailed,
			StartedAt:      started,
			FinishedAt:     started.Add(time.Second),
		}); aErr != nil {
			return aErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write returned %v, want the rollback sentinel", err)
	}
	if got := countJobAttemptRowsForJob(ctx, t, db, org.ID, job.ID); got != 0 {
		t.Errorf("rollback left %d job_attempts rows behind, want 0", got)
	}
}

func TestJobAttemptRepositoryAppendIsAppendOnly(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "no_update")
	started := time.Now().UTC().Truncate(time.Microsecond)
	persisted := seedJobAttempt(ctx, t, s, attemptRepo, org, job, "ap", 1,
		store.JobAttemptStatusSucceeded, started)

	// Bypass the repository entirely: even a raw SQL UPDATE must be
	// rejected by the BEFORE UPDATE trigger.
	_, err := db.Exec(ctx,
		`UPDATE job_attempts SET error_summary = 'rewritten' WHERE id = $1`,
		persisted.ID)
	if err == nil {
		t.Fatal("raw UPDATE on job_attempts succeeded, want rejected by the append-only trigger")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Errorf("UPDATE error = %v, want trigger message mentioning append-only", err)
	}
	// Re-load and verify the row is byte-identical to the original.
	after := loadJobAttemptRowByID(ctx, t, db, persisted.ID)
	if after.ErrorSummary != "" {
		t.Errorf("error_summary = %q after rejected UPDATE, want %q (the row must be unchanged)",
			after.ErrorSummary, "")
	}
}

func TestJobAttemptRepositoryAppendCascadesFromJobDelete(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "cascade")
	started := time.Now().UTC().Truncate(time.Microsecond)
	_ = seedJobAttempt(ctx, t, s, attemptRepo, org, job, "c1", 1,
		store.JobAttemptStatusSucceeded, started)
	_ = seedJobAttempt(ctx, t, s, attemptRepo, org, job, "c2", 2,
		store.JobAttemptStatusFailed, started.Add(time.Second))
	if got := countJobAttemptRowsForJob(ctx, t, db, org.ID, job.ID); got != 2 {
		t.Fatalf("pre-cascade row count = %d, want 2", got)
	}

	// Delete the parent provisioning_jobs row directly — the store package
	// does not expose a row-level delete, so a raw DELETE proves the
	// composite ON DELETE CASCADE is the database-level invariant, not an
	// application-side bookkeeping step.
	if _, err := db.Exec(ctx,
		`DELETE FROM provisioning_jobs WHERE organization_id = $1 AND id = $2`,
		org.ID, job.ID); err != nil {
		t.Fatalf("delete parent job: %v", err)
	}
	if got := countJobAttemptRowsForJob(ctx, t, db, org.ID, job.ID); got != 0 {
		t.Errorf("post-cascade row count = %d, want 0 (job_attempts rows must not survive their parent job)", got)
	}
}

func TestJobAttemptRepositoryAppendCascadesFromOrganizationDelete(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "org_cascade")
	started := time.Now().UTC().Truncate(time.Microsecond)
	_ = seedJobAttempt(ctx, t, s, attemptRepo, org, job, "oc1", 1,
		store.JobAttemptStatusSucceeded, started)

	if _, err := db.Exec(ctx,
		`DELETE FROM organizations WHERE id = $1`, org.ID); err != nil {
		t.Fatalf("delete parent organization: %v", err)
	}

	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM job_attempts WHERE organization_id = $1`,
		org.ID).Scan(&n); err != nil {
		t.Fatalf("count job_attempts post-org-delete: %v", err)
	}
	if n != 0 {
		t.Errorf("post-org-delete row count = %d, want 0 (cascade through provisioning_jobs to job_attempts)", n)
	}
}

func TestJobAttemptRepositoryGetByIDReadsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "getbyid")
	started := time.Now().UTC().Truncate(time.Microsecond)
	persisted := seedJobAttempt(ctx, t, s, attemptRepo, org, job, "g", 1,
		store.JobAttemptStatusSucceeded, started)

	got, err := attemptRepo.GetByID(ctx, db, org.ID, persisted.ID)
	if err != nil {
		t.Fatalf("GetByID(%q): %v", persisted.ID, err)
	}
	if got.ID != persisted.ID || got.JobID != persisted.JobID ||
		got.AttemptNumber != persisted.AttemptNumber ||
		got.WorkerID != persisted.WorkerID || got.Status != persisted.Status {
		t.Errorf("GetByID returned %+v, want %+v (must be byte-identical to the Append RETURNING projection)",
			got, persisted)
	}
}

func TestJobAttemptRepositoryGetByIDUnknownReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	_, err := attemptRepo.GetByID(ctx, db, org.ID, "jatt_does_not_exist")
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(unknown) error = %v, want code %s (never a 500 leaking the cause)",
			err, yerr.CodeNotFound)
	}
}

func TestJobAttemptRepositoryGetByIDCrossTenantReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "acme")
	projA := seedProject(t, db, f, orgA, "api")
	jobA := seedQueuedJob(ctx, t, s, jobRepo, orgA, projA, "ct")
	started := time.Now().UTC().Truncate(time.Microsecond)
	persisted := seedJobAttempt(ctx, t, s, attemptRepo, orgA, jobA, "ct1", 1,
		store.JobAttemptStatusSucceeded, started)

	orgB := seedOrg(t, db, f, "bravo")
	// orgB looks up orgA's persisted attempt by id: even though the id
	// exists, the (organization_id, id) predicate matches no row, so
	// the response is NotFound — never an oracle that reveals orgA's
	// attempt id.
	_, err := attemptRepo.GetByID(ctx, db, orgB.ID, persisted.ID)
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(cross-tenant) error = %v, want code %s (cross-tenant id must never reveal another tenant's attempt)",
			err, yerr.CodeNotFound)
	}
}

func TestJobAttemptRepositoryListByJobChronologicalOrder(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "list")
	base := time.Now().UTC().Truncate(time.Microsecond)
	// Append out of order on the wallclock dimension to prove that
	// ORDER BY attempt_number ASC is what the timeline endpoint relies on.
	_ = seedJobAttempt(ctx, t, s, attemptRepo, org, job, "ln3", 3,
		store.JobAttemptStatusSucceeded, base.Add(3*time.Second))
	_ = seedJobAttempt(ctx, t, s, attemptRepo, org, job, "ln1", 1,
		store.JobAttemptStatusFailed, base)
	_ = seedJobAttempt(ctx, t, s, attemptRepo, org, job, "ln2", 2,
		store.JobAttemptStatusFailed, base.Add(time.Second))

	out, err := attemptRepo.ListByJob(ctx, db, org.ID, job.ID)
	if err != nil {
		t.Fatalf("ListByJob: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("ListByJob returned %d rows, want 3", len(out))
	}
	for i, want := range []int{1, 2, 3} {
		if out[i].AttemptNumber != want {
			t.Errorf("out[%d].AttemptNumber = %d, want %d (must be sorted attempt_number ASC)",
				i, out[i].AttemptNumber, want)
		}
	}
}

func TestJobAttemptRepositoryListByJobUnknownReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	out, err := attemptRepo.ListByJob(ctx, db, org.ID, "job_does_not_exist")
	if err != nil {
		t.Fatalf("ListByJob(unknown job) error = %v, want nil (an unknown job must return an empty slice)", err)
	}
	if len(out) != 0 {
		t.Errorf("ListByJob(unknown job) returned %d rows, want 0", len(out))
	}
}

func TestJobAttemptRepositoryListByJobCrossTenantReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "acme")
	projA := seedProject(t, db, f, orgA, "api")
	jobA := seedQueuedJob(ctx, t, s, jobRepo, orgA, projA, "lct")
	started := time.Now().UTC().Truncate(time.Microsecond)
	_ = seedJobAttempt(ctx, t, s, attemptRepo, orgA, jobA, "lc1", 1,
		store.JobAttemptStatusSucceeded, started)

	orgB := seedOrg(t, db, f, "bravo")
	// orgB looks up orgA's job — the (organization_id, job_id) predicate
	// matches no row, so the empty slice is returned. The lookup is never
	// an oracle that reveals orgA's attempt history.
	out, err := attemptRepo.ListByJob(ctx, db, orgB.ID, jobA.ID)
	if err != nil {
		t.Fatalf("ListByJob(cross-tenant) error = %v, want nil", err)
	}
	if len(out) != 0 {
		t.Errorf("ListByJob(cross-tenant) returned %d rows, want 0 (cross-tenant must never reveal another tenant's attempts)",
			len(out))
	}
}

func TestJobAttemptRepositoryAppendPeerRowByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "peer")
	started := time.Now().UTC().Truncate(time.Microsecond)
	first := seedJobAttempt(ctx, t, s, attemptRepo, org, job, "p1", 1,
		store.JobAttemptStatusFailed, started)

	before := loadJobAttemptRowByID(ctx, t, db, first.ID)

	// A second Append against the same parent job must not touch the
	// first row. The append-only design has no updated_at column and no
	// trigger that could mutate a sibling, so this is the structural
	// guarantee in test form.
	_ = seedJobAttempt(ctx, t, s, attemptRepo, org, job, "p2", 2,
		store.JobAttemptStatusSucceeded, started.Add(time.Second))

	after := loadJobAttemptRowByID(ctx, t, db, first.ID)
	if after != before {
		t.Errorf("peer Append mutated the first job_attempts row:\n before=%+v\n  after=%+v", before, after)
	}
}

func TestJobAttemptRepositoryAppendRedactsErrorSummary(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	job := seedQueuedJob(ctx, t, s, jobRepo, org, proj, "redact")
	started := time.Now().UTC().Truncate(time.Microsecond)

	// A bearer-token-like fragment in the worker's error string must be
	// redacted before it is persisted, so a panic stack or operator query
	// can never recover the secret. The exact redaction sentinel is
	// implementation detail of the output redactor; the invariant here
	// is that the raw secret does NOT appear in the persisted column.
	raw := "Dokploy returned 401: Authorization: Bearer sk_live_supersecret_should_be_redacted"
	created := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		OrganizationID: org.ID,
		JobID:          job.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_redact",
		Status:         store.JobAttemptStatusFailed,
		ErrorSummary:   raw,
		StartedAt:      started,
		FinishedAt:     started.Add(time.Second),
	})

	row := loadJobAttemptRowByID(ctx, t, db, created.ID)
	if strings.Contains(row.ErrorSummary, "sk_live_supersecret_should_be_redacted") {
		t.Errorf("persisted error_summary leaked raw secret: %q (must pass through the output redactor)", row.ErrorSummary)
	}
	if strings.Contains(created.ErrorSummary, "sk_live_supersecret_should_be_redacted") {
		t.Errorf("returned ErrorSummary leaked raw secret: %q", created.ErrorSummary)
	}
}
