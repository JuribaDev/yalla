package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer CRUD-and-invariants tests for the provisioning_jobs table
// (BE-0461). A provisioning_jobs row is the durable, idempotent, lease-based
// queue item that a worker claims to execute one Dokploy provisioning
// operation on a customer's behalf. The JobRepository surface this file
// pins is a hybrid CRUD: Insert mints the queued row inside a transaction
// (the same transaction that also carries authorization, quota, and the
// desired-state write), Get and FindByIdempotencyKey read tenant-scoped,
// ListByOrganization reads bounded and ordered, and Transition / ClaimNext
// drive the row through the closed state machine. There is no per-row
// Update or Delete in this surface: the worker mutates status through
// Transition only, and the schema's lifecycle CHECKs
// (provisioning_jobs_finished_consistent, provisioning_jobs_lease_consistent,
// provisioning_jobs_attempts_bounded) are owned by the migration.
//
// What this file pins, and what it deliberately delegates:
//
//   - Insert row-shape on the first call: a caller-supplied id is preserved
//     verbatim, a blank Status defaults to 'queued', max_attempts /
//     next_run_at / lease_owner / error_summary / payload / request_id /
//     correlation_id round-trip through their defaulting columns,
//     started_at / finished_at / lease_deadline stay NULL on a queued row,
//     and the database trigger stamps created_at / updated_at within the
//     same wallclock second. The return value's struct fields are
//     byte-equal to a raw-SQL re-load of the persisted row.
//   - Insert id-collision contract: a duplicate primary key surfaces as
//     typed apierr.Conflict through mapWriteError — even when the
//     idempotency-key tuple differs, so the PRIMARY KEY violation is
//     distinguishable from the UNIQUE (organization_id, idempotency_key)
//     violation already pinned by TestJobRepositoryInsertIdempotencyConflict
//     in job_test.go.
//   - Insert transaction rollback semantics: a closure that returns an
//     error after a successful Insert leaves no provisioning_jobs row
//     behind. A job is only legitimate when its desired-state write and
//     audit record commit in the same transaction; an aborted closure
//     must roll the row back atomically.
//   - Get lookup contracts: an unknown id within the caller's own tenant
//     surfaces as typed apierr.NotFound (never as a 500 leaking pgx
//     internals). This is the same-tenant variant of the cross-tenant
//     case TestJobRepositoryGetCrossTenant already pins in job_test.go.
//   - ListByOrganization ordering contract: rows are returned in reverse
//     chronological order (created_at DESC, id DESC tiebreaker) — an
//     agent observing the response sees the most recent job first across
//     calls.
//   - ListByOrganization bounded-read contract: a non-positive limit is
//     clamped up to jobListMaxLimit so a caller that forgot to set a
//     limit cannot issue an unbounded read by accident, and the response
//     is an empty non-nil slice when the organization has no jobs (an
//     agent must be able to range over the response without a nil check).
//
// What this file deliberately does NOT re-cover (already pinned elsewhere
// in the same store_test package):
//
//   - Validation guards on blank organization_id / job_type /
//     idempotency_key, negative desired_version / max_attempts, and a
//     non-queued explicit Status are pinned by
//     TestJobRepositoryInsertValidationFailures in job_internal_test.go.
//     Those are pure-Go guards that need no database.
//   - Nil-Tx surfaces as typed apierr.Internal for Insert and Transition
//     are pinned by TestJobRepositoryInsertNilTransaction /
//     TestJobRepositoryTransitionNilTransaction in job_internal_test.go.
//   - The state-machine paths (queued -> running, retry, dead-letter,
//     cancellation, invalid edge, claim-without-lease, retry-budget) are
//     pinned by TestJobRepositoryTransition* in job_test.go.
//   - The lease-claim contract (ClaimNext: due job, empty queue, expired
//     lease reclaim, exhausted-attempts dead-letter, concurrent
//     SKIP LOCKED, validation) is pinned by
//     TestJobRepositoryClaimNext* in job_test.go.
//   - The cross-tenant Get / Find / List / Insert paths and the
//     error-summary redaction backstop are pinned by their respective
//     TestJobRepository* tests in job_test.go.
//   - The closed status set, valid transition matrix, redactor, payload
//     marshalling, and helper purity are pinned by
//     job_internal_test.go.
//
// Helpers introduced here: rawJobRow, loadJobRowByID, countJobRowsForOrg,
// mintJobID, jobTxRollbackSentinel. Helpers reused from sibling files:
// jobFixture, insertJob, transitionJob (job_test.go); seedOrg, seedProject
// (schema_test.go); newStore (store_test.go).

// rawJobRow is the full provisioning_jobs row, deliberately loaded via raw
// SQL so the test can observe id, created_at, updated_at, the closed-set
// status column, the nullable lease_deadline / started_at / finished_at /
// project_id / environment_id / service_id columns, and the jsonb payload
// through the same shape the database stores them in. It is the same
// template rawDeploymentRow uses for deployments (BE-0457) and
// rawQuotaReservationRow uses for quota_reservations (BE-0455).
type rawJobRow struct {
	ID             string
	OrganizationID string
	JobType        string
	ProjectID      *string
	EnvironmentID  *string
	ServiceID      *string
	DesiredVersion int64
	IdempotencyKey string
	Status         string
	Attempts       int
	MaxAttempts    int
	LeaseOwner     string
	LeaseDeadline  *time.Time
	NextRunAt      time.Time
	ErrorSummary   string
	Payload        []byte
	RequestID      string
	CorrelationID  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
}

// loadJobRowByID reads the raw provisioning_jobs row for id and fatals on
// error. The lookup is by primary key — distinct provisioning_jobs rows have
// distinct ids — so no tenant scope is needed (raw loaders bypass
// repository scoping deliberately, so the test observes the persisted row
// exactly as the database stores it).
func loadJobRowByID(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	id string,
) rawJobRow {
	t.Helper()
	var row rawJobRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, job_type, project_id, environment_id, service_id,
		        desired_version, idempotency_key, status, attempts, max_attempts,
		        lease_owner, lease_deadline, next_run_at, error_summary, payload,
		        request_id, correlation_id, created_at, updated_at, started_at, finished_at
		   FROM provisioning_jobs
		  WHERE id = $1`,
		id).Scan(
		&row.ID, &row.OrganizationID, &row.JobType, &row.ProjectID, &row.EnvironmentID, &row.ServiceID,
		&row.DesiredVersion, &row.IdempotencyKey, &row.Status, &row.Attempts, &row.MaxAttempts,
		&row.LeaseOwner, &row.LeaseDeadline, &row.NextRunAt, &row.ErrorSummary, &row.Payload,
		&row.RequestID, &row.CorrelationID, &row.CreatedAt, &row.UpdatedAt, &row.StartedAt, &row.FinishedAt,
	); err != nil {
		t.Fatalf("load provisioning_jobs id=%q: %v", id, err)
	}
	return row
}

// countJobRowsForOrg returns the number of provisioning_jobs rows owned by
// organizationID. It is the "did the rollback leave a row behind?" probe.
func countJobRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM provisioning_jobs WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count provisioning_jobs for org %q: %v", organizationID, err)
	}
	return n
}

// mintJobID builds a stable, test-local provisioning_job id from the test
// name and a per-test suffix. Tests in store_test share a single package, so
// the test name keeps ids unique across parallel test cases without needing
// a shared atomic counter. Real id minting lives in JobRepository.Insert
// (domain.NewID(domain.KindJob)) when the caller passes a blank ID; this
// helper mints a CHECK-safe (length(id) > 0) literal that satisfies the
// application's expectation of a 'job_' prefix without depending on the
// random-token minter.
func mintJobID(t *testing.T, suffix string) string {
	t.Helper()
	return "job_" + t.Name() + "_" + suffix
}

// jobTxRollbackSentinel is a typed error a transaction closure can return to
// force a rollback. The type name is intentionally distinct from every other
// rollback sentinel in store_test (every *_test.go file under
// internal/controlplane/store/ shares the same package) — collisions would
// block compilation. Existing siblings include
// deployment_repository_invariants_test.go's deploymentTxRollbackSentinel
// and quota_reservation_repository_invariants_test.go's
// quotaReservationTxRollbackSentinel.
type jobTxRollbackSentinel struct{}

func (jobTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this provisioning job transaction"
}

func TestJobRepositoryInsertMintsRowShape(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "api")
	id := mintJobID(t, "shape")

	in := jobFixture(org.ID, "idem_shape")
	in.ID = id
	in.ProjectID = proj.ID
	created := insertJob(ctx, t, s, repo, in)

	if created.ID != id {
		t.Errorf("created.ID = %q, want %q (Insert must preserve a caller-supplied id verbatim)", created.ID, id)
	}
	if created.OrganizationID != org.ID {
		t.Errorf("created.OrganizationID = %q, want %q", created.OrganizationID, org.ID)
	}
	if created.JobType != "ensure_project" {
		t.Errorf("created.JobType = %q, want %q", created.JobType, "ensure_project")
	}
	if created.ProjectID != proj.ID {
		t.Errorf("created.ProjectID = %q, want %q", created.ProjectID, proj.ID)
	}
	if created.EnvironmentID != "" || created.ServiceID != "" {
		t.Errorf("created environment/service ids = (%q, %q), want empty (the fixture targets only a project; the unset legs must round-trip as NULL -> empty string)", created.EnvironmentID, created.ServiceID)
	}
	if created.DesiredVersion != 3 {
		t.Errorf("created.DesiredVersion = %d, want 3 (the fixture's desired_version must be persisted verbatim)", created.DesiredVersion)
	}
	if created.IdempotencyKey != "idem_shape" {
		t.Errorf("created.IdempotencyKey = %q, want %q", created.IdempotencyKey, "idem_shape")
	}
	if created.Status != store.JobStatusQueued {
		t.Errorf("created.Status = %q, want %q (a new job must always start in 'queued', regardless of caller input)", created.Status, store.JobStatusQueued)
	}
	if created.Attempts != 0 {
		t.Errorf("created.Attempts = %d, want 0 (a new job spends zero attempts)", created.Attempts)
	}
	if created.MaxAttempts <= 0 {
		t.Errorf("created.MaxAttempts = %d, want the positive default (a blank or non-positive MaxAttempts must default to defaultJobMaxAttempts)", created.MaxAttempts)
	}
	if created.LeaseOwner != "" || !created.LeaseDeadline.IsZero() {
		t.Errorf("created lease = (owner=%q deadline=%v), want unset (a freshly queued job holds no lease; the provisioning_jobs_lease_consistent CHECK enforces this)", created.LeaseOwner, created.LeaseDeadline)
	}
	if created.NextRunAt.IsZero() {
		t.Error("created.NextRunAt is zero, want it defaulted to now (the column DEFAULT now() must be observed via Go-side fallback when the caller does not set it)")
	}
	if created.ErrorSummary != "" {
		t.Errorf("created.ErrorSummary = %q, want empty (a freshly queued job carries no failure summary)", created.ErrorSummary)
	}
	if v, ok := created.Payload["reason"]; !ok || v != "create" {
		t.Errorf("created.Payload = %v, want the fixture payload round-tripped", created.Payload)
	}
	if created.RequestID != "req-job-1" || created.CorrelationID != "corr-job-1" {
		t.Errorf("created correlation ids = (%q, %q), want (%q, %q)", created.RequestID, created.CorrelationID, "req-job-1", "corr-job-1")
	}
	if !created.StartedAt.IsZero() {
		t.Errorf("created.StartedAt = %v, want zero (a queued job has not started)", created.StartedAt)
	}
	if !created.FinishedAt.IsZero() {
		t.Errorf("created.FinishedAt = %v, want zero (a non-terminal row must carry NULL finished_at; the provisioning_jobs_finished_consistent CHECK enforces this)", created.FinishedAt)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("timestamps zero on insert: created_at=%v updated_at=%v", created.CreatedAt, created.UpdatedAt)
	}
	if delta := created.UpdatedAt.Sub(created.CreatedAt); delta < 0 || delta > time.Second {
		t.Errorf("updated_at - created_at = %v on insert, want within 1s", delta)
	}

	// The returned struct must match a raw-SQL re-load byte-for-byte
	// across every observable column — the only way to prove the
	// RETURNING clause and scanProvisioningJob agree with the persisted
	// row.
	row := loadJobRowByID(ctx, t, db, created.ID)
	if row.OrganizationID != created.OrganizationID || row.JobType != created.JobType {
		t.Errorf("row tenant/job_type = (%q, %q), want (%q, %q)",
			row.OrganizationID, row.JobType, created.OrganizationID, created.JobType)
	}
	if row.ProjectID == nil || *row.ProjectID != created.ProjectID {
		t.Errorf("row.ProjectID = %v, want pointer to %q (a caller-supplied project_id must round-trip through the nullable column)", row.ProjectID, created.ProjectID)
	}
	if row.EnvironmentID != nil || row.ServiceID != nil {
		t.Errorf("row environment/service = (%v, %v), want both NULL (the unset legs must round-trip as SQL NULL, not the empty string)", row.EnvironmentID, row.ServiceID)
	}
	if row.DesiredVersion != created.DesiredVersion {
		t.Errorf("row.DesiredVersion = %d, want %d (RETURNING vs re-load disagree)", row.DesiredVersion, created.DesiredVersion)
	}
	if row.IdempotencyKey != created.IdempotencyKey {
		t.Errorf("row.IdempotencyKey = %q, want %q", row.IdempotencyKey, created.IdempotencyKey)
	}
	if row.Status != string(created.Status) {
		t.Errorf("row.Status = %q, want %q (RETURNING vs re-load disagree)", row.Status, created.Status)
	}
	if row.Attempts != created.Attempts || row.MaxAttempts != created.MaxAttempts {
		t.Errorf("row attempts/max = (%d, %d), want (%d, %d)", row.Attempts, row.MaxAttempts, created.Attempts, created.MaxAttempts)
	}
	if row.LeaseOwner != "" || row.LeaseDeadline != nil {
		t.Errorf("row lease = (owner=%q deadline=%v), want unset (queued -> lease columns NULL/'', enforced by provisioning_jobs_lease_consistent)", row.LeaseOwner, row.LeaseDeadline)
	}
	if !row.NextRunAt.Equal(created.NextRunAt) {
		t.Errorf("row.NextRunAt = %v, want %v (RETURNING vs re-load disagree)", row.NextRunAt, created.NextRunAt)
	}
	if row.ErrorSummary != "" {
		t.Errorf("row.ErrorSummary = %q, want empty (a freshly queued job persists no failure summary)", row.ErrorSummary)
	}
	if row.RequestID != created.RequestID || row.CorrelationID != created.CorrelationID {
		t.Errorf("row request/correlation = (%q, %q), want (%q, %q)", row.RequestID, row.CorrelationID, created.RequestID, created.CorrelationID)
	}
	if !row.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("row.CreatedAt = %v, want %v (RETURNING vs re-load disagree)", row.CreatedAt, created.CreatedAt)
	}
	if !row.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("row.UpdatedAt = %v, want %v (RETURNING vs re-load disagree)", row.UpdatedAt, created.UpdatedAt)
	}
	if row.StartedAt != nil {
		t.Errorf("row.StartedAt = %v, want NULL (a queued job has not started)", *row.StartedAt)
	}
	if row.FinishedAt != nil {
		t.Errorf("row.FinishedAt = %v, want NULL (a non-terminal row must carry NULL finished_at)", *row.FinishedAt)
	}

	if n := countJobRowsForOrg(ctx, t, db, org.ID); n != 1 {
		t.Errorf("provisioning_jobs rows for org = %d, want exactly 1", n)
	}
}

func TestJobRepositoryInsertDuplicateIDReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	id := mintJobID(t, "dup_id")

	first := jobFixture(org.ID, "idem_dup_id_a")
	first.ID = id
	insertJob(ctx, t, s, repo, first)

	// A second Insert with the SAME id but a DIFFERENT idempotency key must
	// surface the PRIMARY KEY violation as a typed Conflict — distinct from
	// the UNIQUE (organization_id, idempotency_key) violation already pinned
	// by TestJobRepositoryInsertIdempotencyConflict.
	second := jobFixture(org.ID, "idem_dup_id_b")
	second.ID = id
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, second)
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(duplicate id) error = %v, want code %s (PRIMARY KEY violation must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}

	if n := countJobRowsForOrg(ctx, t, db, org.ID); n != 1 {
		t.Errorf("provisioning_jobs rows for org after rejected duplicate = %d, want 1 (the rejected Insert must not double-write)", n)
	}
}

func TestJobRepositoryInsertRollbackPersistsNoRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	id := mintJobID(t, "rollback")

	// Insert succeeds inside the closure, but the closure then returns a
	// sentinel that aborts the transaction. The provisioning_jobs row must
	// not survive the rollback: a job is only legitimate when its
	// desired-state write and audit record commit in the same transaction.
	in := jobFixture(org.ID, "idem_rollback")
	in.ID = id
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, iErr := repo.Insert(ctx, tx, in); iErr != nil {
			return iErr
		}
		return jobTxRollbackSentinel{}
	})
	if !errors.As(err, new(jobTxRollbackSentinel)) {
		t.Fatalf("Write returned %v, want a wrapped jobTxRollbackSentinel (the closure error must propagate)", err)
	}

	if n := countJobRowsForOrg(ctx, t, db, org.ID); n != 0 {
		t.Errorf("provisioning_jobs rows for org after rollback = %d, want 0", n)
	}
}

func TestJobRepositoryGetUnknownReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")

	// An id that does not exist in the caller's own tenant must surface as
	// typed apierr.NotFound — never as a 500 leaking pgx.ErrNoRows. This is
	// the same-tenant variant of the cross-tenant case
	// TestJobRepositoryGetCrossTenant already pins.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.Get(ctx, q, org.ID, "job_does_not_exist")
		return gErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(unknown id) error = %v, want code %s (pgx.ErrNoRows must map to typed NotFound)", err, yerr.CodeNotFound)
	}
}

func TestJobRepositoryListByOrganizationReturnsReverseChronological(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")

	// Insert three jobs with explicit sleeps so created_at is strictly
	// ordered at sub-second resolution. The repository orders by
	// (created_at DESC, id DESC); the test pins the most-recent-first
	// projection an agent observes.
	first := insertJob(ctx, t, s, repo, jobFixture(org.ID, "list_a"))
	time.Sleep(10 * time.Millisecond)
	second := insertJob(ctx, t, s, repo, jobFixture(org.ID, "list_b"))
	time.Sleep(10 * time.Millisecond)
	third := insertJob(ctx, t, s, repo, jobFixture(org.ID, "list_c"))

	var list []store.ProvisioningJob
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := repo.ListByOrganization(ctx, q, org.ID, 50)
		if lErr != nil {
			return lErr
		}
		list = l
		return nil
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}

	if len(list) != 3 {
		t.Fatalf("ListByOrganization len = %d, want 3 (rows = %+v)", len(list), list)
	}
	gotIDs := []string{list[0].ID, list[1].ID, list[2].ID}
	wantIDs := []string{third.ID, second.ID, first.ID}
	for i := range gotIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Errorf("ListByOrganization[%d].ID = %q, want %q (rows must be reverse chronological, most recent first)", i, gotIDs[i], wantIDs[i])
		}
	}
}

func TestJobRepositoryListByOrganizationEmptyReturnsEmptySlice(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")

	var list []store.ProvisioningJob
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := repo.ListByOrganization(ctx, q, org.ID, 50)
		if lErr != nil {
			return lErr
		}
		list = l
		return nil
	}); err != nil {
		t.Fatalf("ListByOrganization(empty): %v", err)
	}

	if len(list) != 0 {
		t.Errorf("ListByOrganization(empty) len = %d, want 0", len(list))
	}
}

func TestJobRepositoryListByOrganizationClampsNonPositiveLimit(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	insertJob(ctx, t, s, repo, jobFixture(org.ID, "clamp_a"))
	insertJob(ctx, t, s, repo, jobFixture(org.ID, "clamp_b"))

	// limit = 0 must be clamped to the repository's bounded cap, NOT used
	// as a literal LIMIT 0 (that would silently hide every row). The
	// caller forgetting to pass a limit can never issue an unbounded read
	// either — the cap is the upper bound.
	var list []store.ProvisioningJob
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := repo.ListByOrganization(ctx, q, org.ID, 0)
		if lErr != nil {
			return lErr
		}
		list = l
		return nil
	}); err != nil {
		t.Fatalf("ListByOrganization(limit=0): %v", err)
	}
	if len(list) != 2 {
		t.Errorf("ListByOrganization(limit=0) len = %d, want 2 (a non-positive limit must be clamped to the cap, never used as LIMIT 0)", len(list))
	}

	// A negative limit is the same kind of caller error — also clamped to
	// the cap rather than rejected, so the worker control plane stays
	// available even when a buggy caller passes -1.
	var listNeg []store.ProvisioningJob
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := repo.ListByOrganization(ctx, q, org.ID, -1)
		if lErr != nil {
			return lErr
		}
		listNeg = l
		return nil
	}); err != nil {
		t.Fatalf("ListByOrganization(limit=-1): %v", err)
	}
	if len(listNeg) != 2 {
		t.Errorf("ListByOrganization(limit=-1) len = %d, want 2 (a negative limit must be clamped, never used as LIMIT -1)", len(listNeg))
	}
}
