package store_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// Integration tests for JobRepository — the durable provisioning job queue.
// They prove the enqueue surface, tenant-scoped reads, idempotency, the lease
// and state-machine bookkeeping of Transition (claim, retry, dead-letter,
// cancel), and that a job can never target or observe another tenant's data.
// They run against an isolated, freshly migrated Postgres database and skip
// when YALLA_TEST_DATABASE_URL is unset.

// jobFixture builds a valid, minimal store.ProvisioningJob for orgID with the
// given idempotency key.
func jobFixture(orgID, key string) store.ProvisioningJob {
	return store.ProvisioningJob{
		OrganizationID: orgID,
		JobType:        "ensure_project",
		IdempotencyKey: key,
		DesiredVersion: 3,
		Payload:        map[string]string{"reason": "create"},
		RequestID:      "req-job-1",
		CorrelationID:  "corr-job-1",
	}
}

// insertJob enqueues j through Store.Write and returns the stored row.
func insertJob(ctx context.Context, t *testing.T, s *store.Store, repo *store.JobRepository, j store.ProvisioningJob) store.ProvisioningJob {
	t.Helper()
	var stored store.ProvisioningJob
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, j)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("insert provisioning job: %v", err)
	}
	return stored
}

// transitionJob moves a job through Store.Write and returns the updated row.
func transitionJob(ctx context.Context, t *testing.T, s *store.Store, repo *store.JobRepository, orgID, jobID string, to store.JobStatus, mut store.JobTransition) store.ProvisioningJob {
	t.Helper()
	var updated store.ProvisioningJob
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Transition(ctx, tx, orgID, jobID, to, mut)
		if err != nil {
			return err
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("transition provisioning job to %s: %v", to, err)
	}
	return updated
}

func TestJobRepositoryInsertAndGet(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "web")

	in := jobFixture(org.ID, "idem-insert-1")
	in.ProjectID = proj.ID
	stored := insertJob(ctx, t, s, repo, in)

	if stored.ID == "" {
		t.Fatal("Insert did not mint an id for a blank-id job")
	}
	if stored.CreatedAt.IsZero() || stored.UpdatedAt.IsZero() {
		t.Error("Insert did not return database-assigned timestamps")
	}
	if stored.Status != store.JobStatusQueued {
		t.Errorf("stored status = %q, want queued", stored.Status)
	}
	if stored.Attempts != 0 {
		t.Errorf("stored attempts = %d, want 0", stored.Attempts)
	}
	if stored.MaxAttempts <= 0 {
		t.Errorf("stored max_attempts = %d, want the positive default", stored.MaxAttempts)
	}
	if stored.NextRunAt.IsZero() {
		t.Error("stored next_run_at is zero, want it defaulted to now")
	}
	if stored.ProjectID != proj.ID {
		t.Errorf("stored project_id = %q, want %q", stored.ProjectID, proj.ID)
	}
	if !stored.StartedAt.IsZero() || !stored.FinishedAt.IsZero() {
		t.Error("a freshly queued job must not carry started_at or finished_at")
	}
	if stored.LeaseOwner != "" || !stored.LeaseDeadline.IsZero() {
		t.Error("a freshly queued job must not hold a lease")
	}
	if stored.Payload["reason"] != "create" {
		t.Errorf("stored payload = %v, want the fixture payload round-tripped", stored.Payload)
	}

	var got store.ProvisioningJob
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		got, rErr = repo.Get(ctx, q, org.ID, stored.ID)
		return rErr
	}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != stored.ID || got.IdempotencyKey != "idem-insert-1" || got.DesiredVersion != 3 {
		t.Errorf("Get returned %+v, want the stored job", got)
	}
}

func TestJobRepositoryInsertIdempotencyConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	insertJob(ctx, t, s, repo, jobFixture(org.ID, "idem-dup"))

	// A second job with the same idempotency key in the same organization is a
	// Conflict — that is the idempotency guarantee.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insertErr := repo.Insert(ctx, tx, jobFixture(org.ID, "idem-dup"))
		return insertErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate idempotency key error code = %v, want %s", err, yerr.CodeConflict)
	}
}

func TestJobRepositoryInsertSameKeyDifferentOrgs(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")

	// Idempotency is tenant-scoped: the same key in two organizations is two
	// distinct jobs, not a conflict.
	insertJob(ctx, t, s, repo, jobFixture(orgA.ID, "shared-key"))
	insertJob(ctx, t, s, repo, jobFixture(orgB.ID, "shared-key"))
}

func TestJobRepositoryFindByIdempotencyKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")
	stored := insertJob(ctx, t, s, repo, jobFixture(orgA.ID, "idem-find"))

	var (
		found         store.ProvisioningJob
		ok            bool
		missingOK     bool
		crossTenantOK bool
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		found, ok, rErr = repo.FindByIdempotencyKey(ctx, q, orgA.ID, "idem-find")
		if rErr != nil {
			return rErr
		}
		if _, missingOK, rErr = repo.FindByIdempotencyKey(ctx, q, orgA.ID, "no-such-key"); rErr != nil {
			return rErr
		}
		// orgB cannot find orgA's job through its own tenant scope.
		_, crossTenantOK, rErr = repo.FindByIdempotencyKey(ctx, q, orgB.ID, "idem-find")
		return rErr
	}); err != nil {
		t.Fatalf("FindByIdempotencyKey: %v", err)
	}
	if !ok || found.ID != stored.ID {
		t.Errorf("FindByIdempotencyKey(existing) = %+v, %v, want the stored job", found, ok)
	}
	if missingOK {
		t.Error("FindByIdempotencyKey(missing) reported found = true")
	}
	if crossTenantOK {
		t.Error("FindByIdempotencyKey leaked another tenant's job")
	}
}

func TestJobRepositoryGetCrossTenant(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")
	stored := insertJob(ctx, t, s, repo, jobFixture(orgA.ID, "idem-cross"))

	// orgB tries to read orgA's job by its real id: the tenant-scoped query
	// matches no row, so it is NotFound — never another tenant's data.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgB.ID, stored.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(cross-tenant) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

func TestJobRepositoryListByOrganizationTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")
	insertJob(ctx, t, s, repo, jobFixture(orgA.ID, "a-1"))
	insertJob(ctx, t, s, repo, jobFixture(orgA.ID, "a-2"))
	insertJob(ctx, t, s, repo, jobFixture(orgB.ID, "b-1"))

	var listedA []store.ProvisioningJob
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		listedA, rErr = repo.ListByOrganization(ctx, q, orgA.ID, 50)
		return rErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(listedA) != 2 {
		t.Fatalf("orgA job count = %d, want 2 (orgB's job must not be visible)", len(listedA))
	}
	for _, j := range listedA {
		if j.OrganizationID != orgA.ID {
			t.Errorf("ListByOrganization(orgA) returned a job for org %q", j.OrganizationID)
		}
	}
}

// TestJobRepositoryTransitionLifecycle walks a job through the happy path:
// queued -> running (lease taken, attempt counted, started_at stamped) ->
// succeeded (lease released, finished_at stamped, error summary cleared).
func TestJobRepositoryTransitionLifecycle(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	job := insertJob(ctx, t, s, repo, jobFixture(org.ID, "idem-lifecycle"))

	running := transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusRunning, store.JobTransition{
		LeaseOwner:    "worker-1",
		LeaseDuration: 30 * time.Second,
	})
	if running.Status != store.JobStatusRunning {
		t.Fatalf("status after claim = %q, want running", running.Status)
	}
	if running.Attempts != 1 {
		t.Errorf("attempts after claim = %d, want 1", running.Attempts)
	}
	if running.LeaseOwner != "worker-1" || running.LeaseDeadline.IsZero() {
		t.Errorf("claim did not take the lease: owner=%q deadline=%v", running.LeaseOwner, running.LeaseDeadline)
	}
	if running.StartedAt.IsZero() {
		t.Error("claim did not stamp started_at")
	}

	succeeded := transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusSucceeded, store.JobTransition{})
	if succeeded.Status != store.JobStatusSucceeded {
		t.Fatalf("status after success = %q, want succeeded", succeeded.Status)
	}
	if succeeded.LeaseOwner != "" || !succeeded.LeaseDeadline.IsZero() {
		t.Error("success did not release the lease")
	}
	if succeeded.FinishedAt.IsZero() {
		t.Error("success did not stamp finished_at")
	}
	if !succeeded.StartedAt.Equal(running.StartedAt) {
		t.Error("success must not move started_at")
	}
}

// TestJobRepositoryTransitionRetryThenReclaim proves the retry path: a running
// job is sent back to retrying (lease released, backoff scheduled, failure
// summary recorded) and can then be claimed again, counting a second attempt.
func TestJobRepositoryTransitionRetryThenReclaim(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	job := insertJob(ctx, t, s, repo, jobFixture(org.ID, "idem-retry"))

	transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusRunning, store.JobTransition{
		LeaseOwner:    "worker-1",
		LeaseDuration: 30 * time.Second,
	})

	backoff := time.Now().UTC().Add(2 * time.Minute)
	retrying := transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusRetrying, store.JobTransition{
		NextRunAt:    backoff,
		ErrorSummary: "dokploy timed out",
	})
	if retrying.Status != store.JobStatusRetrying {
		t.Fatalf("status after retry = %q, want retrying", retrying.Status)
	}
	if retrying.LeaseOwner != "" || !retrying.LeaseDeadline.IsZero() {
		t.Error("retry did not release the lease")
	}
	if !retrying.NextRunAt.After(job.NextRunAt) {
		t.Errorf("retry did not push next_run_at forward: %v", retrying.NextRunAt)
	}
	if retrying.ErrorSummary != "dokploy timed out" {
		t.Errorf("retry error summary = %q, want the recorded failure", retrying.ErrorSummary)
	}
	if !retrying.FinishedAt.IsZero() {
		t.Error("retrying is not terminal; finished_at must stay unset")
	}

	reclaimed := transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusRunning, store.JobTransition{
		LeaseOwner:    "worker-2",
		LeaseDuration: 30 * time.Second,
	})
	if reclaimed.Attempts != 2 {
		t.Errorf("attempts after reclaim = %d, want 2", reclaimed.Attempts)
	}
	if reclaimed.LeaseOwner != "worker-2" {
		t.Errorf("reclaim lease owner = %q, want worker-2", reclaimed.LeaseOwner)
	}
}

// TestJobRepositoryTransitionDeadLetter proves a job that fails on its last
// permitted attempt is dead-lettered with a redacted failure summary.
func TestJobRepositoryTransitionDeadLetter(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	in := jobFixture(org.ID, "idem-deadletter")
	in.MaxAttempts = 1
	job := insertJob(ctx, t, s, repo, in)

	transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusRunning, store.JobTransition{
		LeaseOwner:    "worker-1",
		LeaseDuration: 30 * time.Second,
	})
	dead := transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusDeadLetter, store.JobTransition{
		ErrorSummary: "permanent failure; Authorization: Bearer sk-leaked-token must not persist",
	})
	if dead.Status != store.JobStatusDeadLetter {
		t.Fatalf("status = %q, want dead_letter", dead.Status)
	}
	if dead.FinishedAt.IsZero() {
		t.Error("dead-letter did not stamp finished_at")
	}
	if dead.LeaseOwner != "" || !dead.LeaseDeadline.IsZero() {
		t.Error("dead-letter did not release the lease")
	}
	if strings.Contains(dead.ErrorSummary, "sk-leaked-token") {
		t.Errorf("dead-letter error summary leaked a secret: %q", dead.ErrorSummary)
	}
	if !strings.Contains(dead.ErrorSummary, output.Sentinel) {
		t.Errorf("dead-letter error summary = %q, want the bearer token redacted", dead.ErrorSummary)
	}
}

// TestJobRepositoryTransitionRetryBudgetExhausted proves a job cannot be
// claimed past its retry budget: the attempt that would exceed max_attempts is
// rejected as a Conflict before any column is written.
func TestJobRepositoryTransitionRetryBudgetExhausted(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	in := jobFixture(org.ID, "idem-budget")
	in.MaxAttempts = 1
	job := insertJob(ctx, t, s, repo, in)

	transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusRunning, store.JobTransition{
		LeaseOwner:    "worker-1",
		LeaseDuration: 30 * time.Second,
	})
	transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusRetrying, store.JobTransition{
		ErrorSummary: "transient failure",
	})

	// The second claim would be attempt 2 against a budget of 1.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, transErr := repo.Transition(ctx, tx, org.ID, job.ID, store.JobStatusRunning, store.JobTransition{
			LeaseOwner:    "worker-2",
			LeaseDuration: 30 * time.Second,
		})
		return transErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("claim past retry budget error code = %v, want %s", err, yerr.CodeConflict)
	}
}

func TestJobRepositoryTransitionCancellation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	job := insertJob(ctx, t, s, repo, jobFixture(org.ID, "idem-cancel"))

	cancelled := transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusCancelled, store.JobTransition{
		ErrorSummary: "cancelled by operator",
	})
	if cancelled.Status != store.JobStatusCancelled {
		t.Fatalf("status = %q, want cancelled", cancelled.Status)
	}
	if cancelled.FinishedAt.IsZero() {
		t.Error("cancellation did not stamp finished_at")
	}
}

// TestJobRepositoryTransitionInvalid proves the state machine is enforced:
// skipping running on the way to succeeded, and any move out of a terminal
// status, are rejected as Conflicts.
func TestJobRepositoryTransitionInvalid(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	job := insertJob(ctx, t, s, repo, jobFixture(org.ID, "idem-invalid"))

	// queued -> succeeded skips running and is not a valid edge.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, transErr := repo.Transition(ctx, tx, org.ID, job.ID, store.JobStatusSucceeded, store.JobTransition{})
		return transErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("queued->succeeded error code = %v, want %s", err, yerr.CodeConflict)
	}

	// Drive the job to a terminal status, then prove it cannot leave it.
	transitionJob(ctx, t, s, repo, org.ID, job.ID, store.JobStatusCancelled, store.JobTransition{})
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, transErr := repo.Transition(ctx, tx, org.ID, job.ID, store.JobStatusRunning, store.JobTransition{
			LeaseOwner:    "worker-1",
			LeaseDuration: 30 * time.Second,
		})
		return transErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("cancelled->running error code = %v, want %s", err, yerr.CodeConflict)
	}
}

func TestJobRepositoryTransitionNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, transErr := repo.Transition(ctx, tx, org.ID, "job_does_not_exist", store.JobStatusRunning, store.JobTransition{
			LeaseOwner:    "worker-1",
			LeaseDuration: 30 * time.Second,
		})
		return transErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Transition(unknown job) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

func TestJobRepositoryTransitionToRunningRequiresLease(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	job := insertJob(ctx, t, s, repo, jobFixture(org.ID, "idem-nolease"))

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, transErr := repo.Transition(ctx, tx, org.ID, job.ID, store.JobStatusRunning, store.JobTransition{})
		return transErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("claim without a lease error code = %v, want %s", err, yerr.CodeInvalidInput)
	}
}

// TestJobRepositoryInsertCrossTenantResourceRejected proves a job cannot
// target another tenant's resource: the composite foreign key on
// (organization_id, project_id) rejects a job in orgB that names orgA's
// project.
func TestJobRepositoryInsertCrossTenantResourceRejected(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")
	projA := seedProject(t, db, f, orgA, "web")

	in := jobFixture(orgB.ID, "idem-cross-resource")
	in.ProjectID = projA.ID // orgA's project, filed under orgB
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insertErr := repo.Insert(ctx, tx, in)
		return insertErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("cross-tenant resource target error code = %v, want %s", err, yerr.CodeConflict)
	}
}

// TestJobRepositoryInsertUnknownOrgRejected proves a job cannot be filed under
// an organization that does not exist: the organization_id foreign key rejects
// it.
func TestJobRepositoryInsertUnknownOrgRejected(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	ctx := context.Background()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insertErr := repo.Insert(ctx, tx, jobFixture("org_does_not_exist", "idem-no-org"))
		return insertErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(unknown org) error code = %v, want %s", err, yerr.CodeConflict)
	}
}

// TestJobRepositoryInsertRedactsErrorSummary proves the redaction backstop:
// even an error summary supplied at enqueue time is scrubbed before it is
// persisted.
func TestJobRepositoryInsertRedactsErrorSummary(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	in := jobFixture(org.ID, "idem-redact")
	in.ErrorSummary = "seed failure x-api-key: sk-should-not-persist"
	stored := insertJob(ctx, t, s, repo, in)

	if strings.Contains(stored.ErrorSummary, "sk-should-not-persist") {
		t.Errorf("Insert persisted a secret in error_summary: %q", stored.ErrorSummary)
	}
}

// claimNext leases the next eligible job through Store.Write and returns the
// claimed job and whether anything was claimed.
func claimNext(ctx context.Context, t *testing.T, s *store.Store, repo *store.JobRepository, owner string, lease time.Duration, now time.Time) (store.ProvisioningJob, bool) {
	t.Helper()
	var (
		job   store.ProvisioningJob
		found bool
	)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		j, ok, err := repo.ClaimNext(ctx, tx, owner, lease, now)
		if err != nil {
			return err
		}
		job, found = j, ok
		return nil
	}); err != nil {
		t.Fatalf("ClaimNext: %v", err)
	}
	return job, found
}

// TestJobRepositoryClaimNextLeasesDueJob proves ClaimNext claims a due queued
// job: it returns it running, with the lease taken and the attempt counted.
func TestJobRepositoryClaimNextLeasesDueJob(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	job := insertJob(ctx, t, s, repo, jobFixture(org.ID, "idem-claim"))

	now := time.Now().UTC().Add(time.Minute)
	claimed, found := claimNext(ctx, t, s, repo, "worker-1", 30*time.Second, now)
	if !found {
		t.Fatal("ClaimNext claimed nothing for a due queued job")
	}
	if claimed.ID != job.ID {
		t.Errorf("claimed job %q, want %q", claimed.ID, job.ID)
	}
	if claimed.Status != store.JobStatusRunning {
		t.Errorf("claimed status = %q, want running", claimed.Status)
	}
	if claimed.Attempts != 1 {
		t.Errorf("claimed attempts = %d, want 1", claimed.Attempts)
	}
	if claimed.LeaseOwner != "worker-1" || claimed.LeaseDeadline.IsZero() {
		t.Errorf("ClaimNext did not take the lease: owner=%q deadline=%v", claimed.LeaseOwner, claimed.LeaseDeadline)
	}

	// The job is now running with a live lease, so a second claim finds nothing.
	if _, found := claimNext(ctx, t, s, repo, "worker-2", 30*time.Second, now); found {
		t.Error("ClaimNext claimed a job that is already leased")
	}
}

// TestJobRepositoryClaimNextEmptyQueue proves ClaimNext reports nothing on an
// empty queue and skips a job whose backoff has not elapsed.
func TestJobRepositoryClaimNextEmptyQueue(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")

	// Nothing enqueued at all.
	if _, found := claimNext(ctx, t, s, repo, "worker-1", 30*time.Second, time.Now().UTC()); found {
		t.Error("ClaimNext claimed a job from an empty queue")
	}

	// A queued job scheduled into the future is not yet due.
	notDue := jobFixture(org.ID, "idem-future")
	notDue.NextRunAt = time.Now().UTC().Add(time.Hour)
	insertJob(ctx, t, s, repo, notDue)
	if _, found := claimNext(ctx, t, s, repo, "worker-1", 30*time.Second, time.Now().UTC()); found {
		t.Error("ClaimNext claimed a job whose next_run_at is still in the future")
	}
}

// TestJobRepositoryClaimNextReclaimsExpiredLease proves a job whose worker
// crashed — running with an expired lease — is reclaimed through the state
// machine, counting another attempt and handing the new worker the lease.
func TestJobRepositoryClaimNextReclaimsExpiredLease(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	job := insertJob(ctx, t, s, repo, jobFixture(org.ID, "idem-reclaim"))

	t0 := time.Now().UTC()
	first, found := claimNext(ctx, t, s, repo, "worker-1", time.Second, t0)
	if !found || first.Attempts != 1 {
		t.Fatalf("first claim: found=%v attempts=%d, want true/1", found, first.Attempts)
	}

	// The lease expired at t0+1s; reclaim it from a worker polling at t0+2s.
	reclaimed, found := claimNext(ctx, t, s, repo, "worker-2", 30*time.Second, t0.Add(2*time.Second))
	if !found {
		t.Fatal("ClaimNext did not reclaim a job with an expired lease")
	}
	if reclaimed.ID != job.ID {
		t.Errorf("reclaimed job %q, want %q", reclaimed.ID, job.ID)
	}
	if reclaimed.Status != store.JobStatusRunning {
		t.Errorf("reclaimed status = %q, want running", reclaimed.Status)
	}
	if reclaimed.Attempts != 2 {
		t.Errorf("reclaimed attempts = %d, want 2 (reclaim counts an attempt)", reclaimed.Attempts)
	}
	if reclaimed.LeaseOwner != "worker-2" {
		t.Errorf("reclaimed lease owner = %q, want worker-2", reclaimed.LeaseOwner)
	}
}

// TestJobRepositoryClaimNextDeadLettersExhaustedExpiredLease proves an
// expired-lease job that has already spent its retry budget is dead-lettered
// rather than handed to another worker.
func TestJobRepositoryClaimNextDeadLettersExhaustedExpiredLease(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	in := jobFixture(org.ID, "idem-reclaim-exhausted")
	in.MaxAttempts = 1
	job := insertJob(ctx, t, s, repo, in)

	t0 := time.Now().UTC()
	if _, found := claimNext(ctx, t, s, repo, "worker-1", time.Second, t0); !found {
		t.Fatal("first claim found nothing")
	}

	// The single attempt is spent; the expired lease cannot be reclaimed.
	if _, found := claimNext(ctx, t, s, repo, "worker-2", 30*time.Second, t0.Add(2*time.Second)); found {
		t.Error("ClaimNext reclaimed a job that has exhausted its retry budget")
	}

	dead := getJobByID(ctx, t, s, repo, org.ID, job.ID)
	if dead.Status != store.JobStatusDeadLetter {
		t.Errorf("status = %q, want dead_letter", dead.Status)
	}
	if dead.FinishedAt.IsZero() {
		t.Error("a dead-lettered job must carry finished_at")
	}
}

// getJobByID reads a job back through a read-only transaction.
func getJobByID(ctx context.Context, t *testing.T, s *store.Store, repo *store.JobRepository, orgID, jobID string) store.ProvisioningJob {
	t.Helper()
	var job store.ProvisioningJob
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		job, rErr = repo.Get(ctx, q, orgID, jobID)
		return rErr
	}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	return job
}

// TestJobRepositoryClaimNextConcurrentSkipLocked proves the SKIP LOCKED claim
// is safe under concurrency: many workers polling the same queue claim every
// job exactly once and never the same job twice.
func TestJobRepositoryClaimNextConcurrentSkipLocked(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	const jobCount = 24
	for i := 0; i < jobCount; i++ {
		insertJob(ctx, t, s, repo, jobFixture(org.ID, fmt.Sprintf("idem-skiplocked-%d", i)))
	}
	// A fixed clock with a long lease: once claimed, a job is never re-eligible
	// for the duration of the test, so every claim must be of a distinct job.
	now := time.Now().UTC()

	var (
		mu      sync.Mutex
		claimed = make(map[string]int, jobCount)
	)
	claimOne := func(owner string) (bool, error) {
		var (
			job   store.ProvisioningJob
			found bool
		)
		err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
			j, ok, cErr := repo.ClaimNext(ctx, tx, owner, time.Hour, now)
			job, found = j, ok
			return cErr
		})
		if err != nil {
			return false, err
		}
		if found {
			mu.Lock()
			claimed[job.ID]++
			mu.Unlock()
		}
		return found, nil
	}

	const workers = 6
	deadline := time.Now().Add(20 * time.Second)
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			owner := fmt.Sprintf("worker-%d", w)
			for {
				found, err := claimOne(owner)
				if err != nil {
					errCh <- err
					return
				}
				if found {
					continue
				}
				// An empty result may just mean every remaining eligible row
				// is locked by another worker's open transaction; retry until
				// the queue is provably drained or the deadline is hit.
				mu.Lock()
				drained := len(claimed) >= jobCount
				mu.Unlock()
				if drained || time.Now().After(deadline) {
					return
				}
				time.Sleep(time.Millisecond)
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent ClaimNext: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(claimed) != jobCount {
		t.Fatalf("claimed %d distinct jobs, want %d", len(claimed), jobCount)
	}
	for id, n := range claimed {
		if n != 1 {
			t.Errorf("job %s claimed %d times, want exactly 1", id, n)
		}
	}
}

// TestJobRepositoryClaimNextValidation proves ClaimNext rejects a nil
// transaction and a missing owner or lease duration rather than issuing a
// malformed claim.
func TestJobRepositoryClaimNextValidation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	ctx := context.Background()

	// A nil transaction is rejected without touching the database.
	if _, _, err := repo.ClaimNext(ctx, nil, "worker-1", time.Second, time.Now().UTC()); err == nil {
		t.Error("ClaimNext(nil tx) returned no error")
	}

	// An empty owner or a non-positive lease duration is a programming error.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, _, e := repo.ClaimNext(ctx, tx, "", time.Second, time.Now().UTC()); e == nil {
			t.Error("ClaimNext(empty owner) returned no error")
		}
		if _, _, e := repo.ClaimNext(ctx, tx, "worker-1", 0, time.Now().UTC()); e == nil {
			t.Error("ClaimNext(zero lease duration) returned no error")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Store.Write: %v", err)
	}
}
