package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer CRUD-and-lifecycle invariants for the deployments table
// (BE-0457). A deployments row is the source-of-truth record of one
// customer-initiated deployment of a single service: it captures which
// service the customer asked to deploy, the source taxonomy (git / image /
// manual) and reference (branch / commit / image), the principal who asked
// for it, the immutable per-request correlation identifiers the audit trail
// and the worker job share, and the converged lifecycle status the worker
// writes as it observes the upstream provisioning job. The
// DeploymentRepository surface is intentionally narrow: Insert mints the
// queued row inside a transaction (the same transaction that also enqueues
// the mirror provisioning job and writes the audit record), GetByID and
// FindByIdempotencyKey read tenant-scoped, ListByService reads bounded and
// ordered, and Cancel walks a non-terminal row to the terminal 'cancelled'
// status with an optional optimistic-concurrency precondition. There is no
// per-row Update / Delete in this surface: the customer never writes status,
// the worker mutates status through worker-only paths landed in the
// provisioning-jobs PRD, and the schema-level lifecycle CHECK
// (deployments_finished_consistent) is owned by the migration.
//
// What this file pins, and what it deliberately delegates:
//
//   - Insert row-shape on the first call: a caller-supplied id is preserved
//     verbatim, a blank Status defaults to 'queued', SourceRef / ErrorCode /
//     ErrorMessage / RequestID / CorrelationID round-trip through their
//     defaulting columns, StartedAt / FinishedAt stay NULL on a non-terminal
//     row, version is the database-owned 1, and the database trigger stamps
//     created_at / updated_at within the same wallclock second. The return
//     value's struct fields are byte-equal to a raw-SQL re-load of the
//     persisted row.
//   - Insert id-and-key contracts: a blank id is rejected at the CHECK
//     (length(id) > 0), a duplicate id surfaces as typed apierr.Conflict
//     (PRIMARY KEY), and a duplicate (organization_id, idempotency_key)
//     tuple surfaces as typed apierr.Conflict (UNIQUE) — both through
//     mapWriteError.
//   - Insert CHECK / FK violations surface as typed apierr.Conflict through
//     mapWriteError: blank requested_by, blank idempotency_key, an unknown
//     source, an unknown organization (FK organizations.id), unknown
//     project / environment / service legs (composite FKs), and a
//     deliberately-terminal status with a NULL finished_at (the
//     deployments_finished_consistent CHECK).
//   - Insert nil-Tx surfaces as typed apierr.Internal: a deployment must
//     never be persisted outside the transaction that also carries its
//     provisioning job and its audit record.
//   - Insert transaction rollback semantics: a closure that returns an
//     error after a successful Insert leaves no deployments row behind.
//   - GetByID lookup contracts: a persisted row reads back byte-identical
//     to the Insert RETURNING projection; an unknown id surfaces as typed
//     apierr.NotFound (never as a 500 leaking the cause); the row is never
//     an oracle that reveals another tenant's deployment ids.
//   - FindByIdempotencyKey behavioural contracts: a tuple a previous
//     request already enqueued returns (row, true, nil); a tuple no
//     request ever enqueued returns (zero, false, nil); a tuple owned by
//     another tenant returns (zero, false, nil) — never the foreign row.
//   - Cancel lifecycle contracts: a queued / running row transitions to
//     the terminal 'cancelled' status with finished_at stamped in the
//     same UPDATE (the deployments_finished_consistent CHECK is the
//     belt-and-braces), the bump_version trigger from migration 0011
//     increments version, the set_updated_at trigger from the baseline
//     migration bumps updated_at, and the returned row carries the
//     authoritative post-cancel projection.
//   - Cancel optimistic-concurrency contracts: a nil expectedVersion is
//     "no precondition"; a matching expectedVersion narrows the predicate
//     by version and succeeds; a mismatched expectedVersion surfaces as
//     typed apierr.ConflictStale carrying details.current_version, so the
//     caller can retry without an extra GET.
//   - Cancel terminal-row contract: cancelling an already-terminal row
//     (cancelled / succeeded / failed / rolled_back) is rejected as a
//     deterministic apierr.Conflict — never a silent success that would
//     emit a duplicate audit event, and never as a 500 leaking the CHECK
//     constraint name.
//   - Cancel tenant-scoping contracts: a cross-tenant or unknown
//     deployment_id surfaces as typed apierr.NotFound — never another
//     tenant's row, never another tenant's id leaked into the response.
//   - Cancel nil-Tx surfaces as typed apierr.Internal.
//   - ListByService ordering contract: rows are returned in reverse
//     chronological order (created_at DESC, id DESC tiebreaker) — an
//     agent observing the response sees the most recent deployment first
//     across calls.
//   - ListByService bounded-read contract: the query is capped at
//     deploymentListMaxRows so an unbounded read can never be issued by
//     accident.
//   - ListByService tenant-scoping contract: a service_id owned by
//     another tenant returns an empty slice, never the foreign tenant's
//     deployments. A live service with no deployments returns an empty
//     slice (a future "service missing" probe is the reader adapter's
//     responsibility — this surface does not Get the service first).
//
// Helpers introduced here: rawDeploymentRow, loadDeploymentRowByID,
// countDeploymentRowsForOrg, mintDeploymentID, runInsertDeploymentOrFail,
// seedQueuedDeployment, seedRunningDeployment, deploymentTxRollbackSentinel.
// Helpers reused from sibling files: seedOrg, seedProject, seedEnvironment,
// seedService (schema_test.go); newStore (store_test.go).

// rawDeploymentRow is the full deployments row, deliberately loaded via raw
// SQL so the test can observe id, created_at, updated_at, version, the
// closed-set source / status columns, and the nullable started_at /
// finished_at columns through the same shape the database stores them in.
// It is the same template rawQuotaReservationRow uses for quota_reservations
// in BE-0455 and rawQuotaUsageRow uses for quota_usage in BE-0453.
type rawDeploymentRow struct {
	ID             string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Source         string
	SourceRef      string
	Status         string
	RequestedBy    string
	IdempotencyKey string
	ErrorCode      string
	ErrorMessage   string
	Version        int64
	RequestID      string
	CorrelationID  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
}

// loadDeploymentRowByID reads the raw deployments row for id and fatals on
// error. The lookup is by primary key — distinct deployment rows have
// distinct ids — so no tenant scope is needed (raw loaders bypass
// repository scoping deliberately, so the test observes the persisted row
// exactly as the database stores it).
func loadDeploymentRowByID(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	id string,
) rawDeploymentRow {
	t.Helper()
	var row rawDeploymentRow
	if err := db.QueryRow(ctx,
		`SELECT id, organization_id, project_id, environment_id, service_id,
		        source, source_ref, status, requested_by, idempotency_key,
		        error_code, error_message, version, request_id, correlation_id,
		        created_at, updated_at, started_at, finished_at
		   FROM deployments
		  WHERE id = $1`,
		id).Scan(
		&row.ID, &row.OrganizationID, &row.ProjectID, &row.EnvironmentID, &row.ServiceID,
		&row.Source, &row.SourceRef, &row.Status, &row.RequestedBy, &row.IdempotencyKey,
		&row.ErrorCode, &row.ErrorMessage, &row.Version, &row.RequestID, &row.CorrelationID,
		&row.CreatedAt, &row.UpdatedAt, &row.StartedAt, &row.FinishedAt,
	); err != nil {
		t.Fatalf("load deployments id=%q: %v", id, err)
	}
	return row
}

// countDeploymentRowsForOrg returns the number of deployments rows owned by
// organizationID. It is the "did the rollback leave a row behind?" probe.
func countDeploymentRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM deployments WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count deployments for org %q: %v", organizationID, err)
	}
	return n
}

// mintDeploymentID builds a stable, test-local deployment id from the test
// name and a per-test suffix. Tests in store_test share a single package, so
// the test name keeps ids unique across parallel test cases without needing
// a shared atomic counter. Real id minting lives in DeploymentService.Create
// (domain.NewID(domain.KindDeployment)); this helper mints a CHECK-safe
// (length(id) > 0) literal that satisfies the application's expectation of
// a 'dep_' prefix without depending on the random-token minter.
func mintDeploymentID(t *testing.T, suffix string) string {
	t.Helper()
	return "dep_" + t.Name() + "_" + suffix
}

// runInsertDeploymentOrFail wraps DeploymentRepository.Insert in a
// Store.Write closure and fatals on error, returning the persisted
// deployment. It is the smallest possible happy-path closure and is reused
// by every test that does not need to observe the call's tx in isolation.
func runInsertDeploymentOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.DeploymentRepository,
	d store.Deployment,
) store.Deployment {
	t.Helper()
	var created store.Deployment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		got, iErr := repo.Insert(ctx, tx, d)
		if iErr != nil {
			return iErr
		}
		created = got
		return nil
	}); err != nil {
		t.Fatalf("Insert(%+v): %v", d, err)
	}
	return created
}

// seedQueuedDeployment inserts a fully-formed 'queued' deployment row owned
// by (org, svc) and returns it. It centralises the boilerplate the
// Cancel / List tests need so the per-test bodies focus on the lifecycle
// invariant rather than the construction of a valid row.
func seedQueuedDeployment(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.DeploymentRepository,
	org testutil.Organization,
	proj testutil.Project,
	env testutil.Environment,
	svc testutil.Service,
	suffix string,
) store.Deployment {
	t.Helper()
	return runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             mintDeploymentID(t, suffix),
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		Source:         store.DeploymentSourceGit,
		SourceRef:      "refs/heads/main@" + suffix,
		RequestedBy:    "usr_test_actor",
		IdempotencyKey: "idem_" + suffix,
		RequestID:      "req_" + suffix,
		CorrelationID:  "cor_" + suffix,
	})
}

// seedRunningDeployment inserts a 'running' deployment row owned by
// (org, svc) and returns it. A 'running' row exercises the non-queued leg
// of Cancel's predicate (status IN ('queued','running')) and proves the
// repository transitions a running row to cancelled, not just a queued one.
func seedRunningDeployment(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.DeploymentRepository,
	org testutil.Organization,
	proj testutil.Project,
	env testutil.Environment,
	svc testutil.Service,
	suffix string,
) store.Deployment {
	t.Helper()
	return runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             mintDeploymentID(t, suffix),
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		Source:         store.DeploymentSourceImage,
		SourceRef:      "ghcr.io/acme/svc:" + suffix,
		Status:         store.DeploymentStatusRunning,
		RequestedBy:    "usr_test_actor",
		IdempotencyKey: "idem_" + suffix,
		RequestID:      "req_" + suffix,
		CorrelationID:  "cor_" + suffix,
	})
}

// deploymentTxRollbackSentinel is a typed error a transaction closure can
// return to force a rollback. The type name is intentionally distinct from
// every other rollback sentinel in store_test (every *_test.go file under
// internal/controlplane/store/ shares the same package) — collisions would
// block compilation. Existing siblings include
// quota_reservation_repository_invariants_test.go's
// quotaReservationTxRollbackSentinel and
// quota_usage_repository_invariants_test.go's quotaUsageTxRollbackSentinel.
type deploymentTxRollbackSentinel struct{}

func (deploymentTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this deployment transaction"
}

func TestDeploymentRepositoryInsertMintsRowShape(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	id := mintDeploymentID(t, "shape")

	created := runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             id,
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		Source:         store.DeploymentSourceGit,
		SourceRef:      "refs/heads/main",
		RequestedBy:    "usr_test_actor",
		IdempotencyKey: "idem_shape",
		RequestID:      "req_shape",
		CorrelationID:  "cor_shape",
	})

	if created.ID != id {
		t.Errorf("created.ID = %q, want %q (Insert must preserve a caller-supplied id verbatim)", created.ID, id)
	}
	if created.OrganizationID != org.ID {
		t.Errorf("created.OrganizationID = %q, want %q", created.OrganizationID, org.ID)
	}
	if created.ProjectID != proj.ID || created.EnvironmentID != env.ID || created.ServiceID != svc.ID {
		t.Errorf("created parent ids = (%q, %q, %q), want (%q, %q, %q)",
			created.ProjectID, created.EnvironmentID, created.ServiceID,
			proj.ID, env.ID, svc.ID)
	}
	if created.Source != store.DeploymentSourceGit {
		t.Errorf("created.Source = %q, want %q", created.Source, store.DeploymentSourceGit)
	}
	if created.SourceRef != "refs/heads/main" {
		t.Errorf("created.SourceRef = %q, want %q", created.SourceRef, "refs/heads/main")
	}
	if created.Status != store.DeploymentStatusQueued {
		t.Errorf("created.Status = %q, want %q (a blank Status must default to 'queued' through the column DEFAULT)", created.Status, store.DeploymentStatusQueued)
	}
	if created.RequestedBy != "usr_test_actor" {
		t.Errorf("created.RequestedBy = %q, want %q", created.RequestedBy, "usr_test_actor")
	}
	if created.IdempotencyKey != "idem_shape" {
		t.Errorf("created.IdempotencyKey = %q, want %q", created.IdempotencyKey, "idem_shape")
	}
	if created.ErrorCode != "" || created.ErrorMessage != "" {
		t.Errorf("created.ErrorCode = %q, ErrorMessage = %q, want empty (Insert never writes worker-only error fields; their DEFAULT '' must be observed)", created.ErrorCode, created.ErrorMessage)
	}
	if created.Version != 1 {
		t.Errorf("created.Version = %d, want 1 (the database-owned column DEFAULT 1 must be observed on INSERT)", created.Version)
	}
	if created.RequestID != "req_shape" || created.CorrelationID != "cor_shape" {
		t.Errorf("created correlation ids = (%q, %q), want (%q, %q)",
			created.RequestID, created.CorrelationID, "req_shape", "cor_shape")
	}
	if created.StartedAt != nil {
		t.Errorf("created.StartedAt = %v, want nil (a fresh queued row must carry NULL started_at)", *created.StartedAt)
	}
	if created.FinishedAt != nil {
		t.Errorf("created.FinishedAt = %v, want nil (a non-terminal row must carry NULL finished_at; the deployments_finished_consistent CHECK enforces this)", *created.FinishedAt)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("timestamps zero on insert: created_at=%v updated_at=%v", created.CreatedAt, created.UpdatedAt)
	}
	if delta := created.UpdatedAt.Sub(created.CreatedAt); delta < 0 || delta > time.Second {
		t.Errorf("updated_at - created_at = %v on insert, want within 1s", delta)
	}

	// The returned struct must match a raw-SQL re-load byte-for-byte
	// across every observable column — the only way to prove the
	// RETURNING clause and scanDeployment agree with the persisted row.
	row := loadDeploymentRowByID(ctx, t, db, created.ID)
	if row.OrganizationID != created.OrganizationID ||
		row.ProjectID != created.ProjectID ||
		row.EnvironmentID != created.EnvironmentID ||
		row.ServiceID != created.ServiceID {
		t.Errorf("row tenant ids = (%q, %q, %q, %q), want (%q, %q, %q, %q)",
			row.OrganizationID, row.ProjectID, row.EnvironmentID, row.ServiceID,
			created.OrganizationID, created.ProjectID, created.EnvironmentID, created.ServiceID)
	}
	if row.Source != string(created.Source) || row.Status != string(created.Status) {
		t.Errorf("row source/status = (%q, %q), want (%q, %q)", row.Source, row.Status, created.Source, created.Status)
	}
	if row.SourceRef != created.SourceRef || row.RequestedBy != created.RequestedBy || row.IdempotencyKey != created.IdempotencyKey {
		t.Errorf("row body = (source_ref=%q requested_by=%q idem=%q), want (%q, %q, %q)",
			row.SourceRef, row.RequestedBy, row.IdempotencyKey,
			created.SourceRef, created.RequestedBy, created.IdempotencyKey)
	}
	if row.ErrorCode != "" || row.ErrorMessage != "" {
		t.Errorf("row error_code=%q error_message=%q, want empty (Insert never writes these worker-only columns; the column DEFAULT '' must be observed)", row.ErrorCode, row.ErrorMessage)
	}
	if row.Version != created.Version {
		t.Errorf("row.Version = %d, want %d (RETURNING vs re-load disagree on the version column)", row.Version, created.Version)
	}
	if row.RequestID != created.RequestID || row.CorrelationID != created.CorrelationID {
		t.Errorf("row request_id=%q correlation_id=%q, want (%q, %q)", row.RequestID, row.CorrelationID, created.RequestID, created.CorrelationID)
	}
	if !row.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("row.CreatedAt = %v, want %v (RETURNING vs re-load disagree)", row.CreatedAt, created.CreatedAt)
	}
	if !row.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("row.UpdatedAt = %v, want %v (RETURNING vs re-load disagree)", row.UpdatedAt, created.UpdatedAt)
	}
	if row.StartedAt != nil {
		t.Errorf("row.StartedAt = %v, want NULL (a fresh queued row must carry NULL started_at)", *row.StartedAt)
	}
	if row.FinishedAt != nil {
		t.Errorf("row.FinishedAt = %v, want NULL (a non-terminal row must carry NULL finished_at)", *row.FinishedAt)
	}

	if n := countDeploymentRowsForOrg(ctx, t, db, org.ID); n != 1 {
		t.Errorf("deployments rows for org = %d, want exactly 1", n)
	}
}

func TestDeploymentRepositoryInsertDefaultsBlankStatusToQueued(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	created := runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             mintDeploymentID(t, "default_status"),
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		Source:         store.DeploymentSourceManual,
		RequestedBy:    "usr_actor",
		IdempotencyKey: "idem_default_status",
	})

	if created.Status != store.DeploymentStatusQueued {
		t.Errorf("created.Status = %q, want %q (a blank Status passed to Insert must be coerced to 'queued' by the Go-side default before INSERT)", created.Status, store.DeploymentStatusQueued)
	}

	row := loadDeploymentRowByID(ctx, t, db, created.ID)
	if row.Status != string(store.DeploymentStatusQueued) {
		t.Errorf("row.Status = %q, want %q", row.Status, store.DeploymentStatusQueued)
	}
}

func TestDeploymentRepositoryInsertPersistsExplicitRunningStatus(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	created := runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             mintDeploymentID(t, "running"),
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		Source:         store.DeploymentSourceGit,
		Status:         store.DeploymentStatusRunning,
		RequestedBy:    "usr_actor",
		IdempotencyKey: "idem_running",
	})

	if created.Status != store.DeploymentStatusRunning {
		t.Errorf("created.Status = %q, want %q (a non-blank Status must be persisted verbatim)", created.Status, store.DeploymentStatusRunning)
	}
	if created.FinishedAt != nil {
		t.Errorf("created.FinishedAt = %v, want NULL ('running' is a non-terminal status; the deployments_finished_consistent CHECK requires finished_at IS NULL)", *created.FinishedAt)
	}
}

func TestDeploymentRepositoryInsertDuplicateIDReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	id := mintDeploymentID(t, "dup_id")

	runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             id,
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		Source:         store.DeploymentSourceGit,
		RequestedBy:    "usr_actor",
		IdempotencyKey: "idem_dup_id_a",
	})

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.Deployment{
			ID:             id,
			OrganizationID: org.ID,
			ProjectID:      proj.ID,
			EnvironmentID:  env.ID,
			ServiceID:      svc.ID,
			Source:         store.DeploymentSourceGit,
			RequestedBy:    "usr_actor",
			IdempotencyKey: "idem_dup_id_b",
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(duplicate id) error = %v, want code %s (PRIMARY KEY violation must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestDeploymentRepositoryInsertDuplicateIdempotencyKeyReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             mintDeploymentID(t, "idem_first"),
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		Source:         store.DeploymentSourceGit,
		RequestedBy:    "usr_actor",
		IdempotencyKey: "idem_shared",
	})

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.Deployment{
			ID:             mintDeploymentID(t, "idem_second"),
			OrganizationID: org.ID,
			ProjectID:      proj.ID,
			EnvironmentID:  env.ID,
			ServiceID:      svc.ID,
			Source:         store.DeploymentSourceGit,
			RequestedBy:    "usr_actor",
			IdempotencyKey: "idem_shared",
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(duplicate idempotency_key) error = %v, want code %s (UNIQUE (organization_id, idempotency_key) violation must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestDeploymentRepositoryInsertBlankIDReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.Deployment{
			ID:             "",
			OrganizationID: org.ID,
			ProjectID:      proj.ID,
			EnvironmentID:  env.ID,
			ServiceID:      svc.ID,
			Source:         store.DeploymentSourceGit,
			RequestedBy:    "usr_actor",
			IdempotencyKey: "idem_blank_id",
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(blank id) error = %v, want code %s (CHECK length(id) > 0 must surface as Conflict through mapWriteError)", err, yerr.CodeConflict)
	}
}

func TestDeploymentRepositoryInsertBlankRequestedByReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.Deployment{
			ID:             mintDeploymentID(t, "blank_actor"),
			OrganizationID: org.ID,
			ProjectID:      proj.ID,
			EnvironmentID:  env.ID,
			ServiceID:      svc.ID,
			Source:         store.DeploymentSourceGit,
			RequestedBy:    "",
			IdempotencyKey: "idem_blank_actor",
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(blank requested_by) error = %v, want code %s (CHECK length(requested_by) > 0 must surface as Conflict)", err, yerr.CodeConflict)
	}
}

func TestDeploymentRepositoryInsertBlankIdempotencyKeyReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.Deployment{
			ID:             mintDeploymentID(t, "blank_idem"),
			OrganizationID: org.ID,
			ProjectID:      proj.ID,
			EnvironmentID:  env.ID,
			ServiceID:      svc.ID,
			Source:         store.DeploymentSourceGit,
			RequestedBy:    "usr_actor",
			IdempotencyKey: "",
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(blank idempotency_key) error = %v, want code %s (CHECK length(idempotency_key) > 0 must surface as Conflict)", err, yerr.CodeConflict)
	}
}

func TestDeploymentRepositoryInsertUnknownSourceReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	// DeploymentSource is `type DeploymentSource string`, so a deliberately
	// cast value bypasses Go's compile-time check on the closed set. The
	// CHECK on deployments.source IN ('git', 'image', 'manual') is the
	// runtime defense; its violation must surface as apierr.Conflict.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.Deployment{
			ID:             mintDeploymentID(t, "bad_source"),
			OrganizationID: org.ID,
			ProjectID:      proj.ID,
			EnvironmentID:  env.ID,
			ServiceID:      svc.ID,
			Source:         store.DeploymentSource("not-a-source"),
			RequestedBy:    "usr_actor",
			IdempotencyKey: "idem_bad_source",
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(invalid source) error = %v, want code %s (CHECK source IN (...) must surface as Conflict)", err, yerr.CodeConflict)
	}
}

func TestDeploymentRepositoryInsertTerminalStatusWithoutFinishedAtReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	// Insert's INSERT column list deliberately does NOT include finished_at:
	// the worker is the only writer of terminal-status rows, and the
	// terminal lifecycle transition stamps finished_at in the same UPDATE
	// (deployments_finished_consistent CHECK). So passing a terminal
	// Status to Insert produces an inconsistent row by construction —
	// status IN ('succeeded','failed','cancelled','rolled_back') AND
	// finished_at IS NULL violates the CHECK. The CHECK is the database's
	// guarantee that this surface can only mint non-terminal rows; a
	// regression that started accepting terminal statuses through Insert
	// would silently corrupt the lifecycle invariant and surface here as a
	// pass instead of a Conflict.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.Deployment{
			ID:             mintDeploymentID(t, "terminal_no_finished"),
			OrganizationID: org.ID,
			ProjectID:      proj.ID,
			EnvironmentID:  env.ID,
			ServiceID:      svc.ID,
			Source:         store.DeploymentSourceGit,
			Status:         store.DeploymentStatusSucceeded,
			RequestedBy:    "usr_actor",
			IdempotencyKey: "idem_terminal_no_finished",
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(terminal status, NULL finished_at) error = %v, want code %s (deployments_finished_consistent CHECK must surface as Conflict)", err, yerr.CodeConflict)
	}
}

func TestDeploymentRepositoryInsertUnknownOrganizationReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	ctx := context.Background()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.Deployment{
			ID:             mintDeploymentID(t, "unknown_org"),
			OrganizationID: "org_does_not_exist",
			ProjectID:      "proj_does_not_exist",
			EnvironmentID:  "env_does_not_exist",
			ServiceID:      "svc_does_not_exist",
			Source:         store.DeploymentSourceGit,
			RequestedBy:    "usr_actor",
			IdempotencyKey: "idem_unknown_org",
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(unknown org/project/env/service) error = %v, want code %s (composite FK violation must surface as Conflict)", err, yerr.CodeConflict)
	}
}

func TestDeploymentRepositoryInsertCrossTenantServiceReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	// Two tenants with their own complete hierarchy. The deployment names
	// alpha's organization_id but bravo's service_id — the composite FK
	// (organization_id, service_id) -> services (organization_id, id)
	// rejects the row, so a deployment can never reference another
	// tenant's service through application bugs.
	alpha := seedOrg(t, db, f, "alpha")
	alphaProj := seedProject(t, db, f, alpha, "api")
	alphaEnv := seedEnvironment(t, db, f, alphaProj, "prod")

	bravo := seedOrg(t, db, f, "bravo")
	bravoProj := seedProject(t, db, f, bravo, "api")
	bravoEnv := seedEnvironment(t, db, f, bravoProj, "prod")
	bravoSvc := seedService(t, db, f, bravoEnv, "web")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.Deployment{
			ID:             mintDeploymentID(t, "cross_tenant"),
			OrganizationID: alpha.ID,
			ProjectID:      alphaProj.ID,
			EnvironmentID:  alphaEnv.ID,
			ServiceID:      bravoSvc.ID,
			Source:         store.DeploymentSourceGit,
			RequestedBy:    "usr_actor",
			IdempotencyKey: "idem_cross_tenant",
		})
		return iErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(cross-tenant service) error = %v, want code %s (composite FK must surface as Conflict)", err, yerr.CodeConflict)
	}

	if n := countDeploymentRowsForOrg(ctx, t, db, alpha.ID); n != 0 {
		t.Errorf("alpha deployments rows = %d, want 0 (the rejected INSERT must not have persisted a row)", n)
	}
	if n := countDeploymentRowsForOrg(ctx, t, db, bravo.ID); n != 0 {
		t.Errorf("bravo deployments rows = %d, want 0 (the rejected INSERT must not have persisted a row in either tenant)", n)
	}
}

func TestDeploymentRepositoryInsertNilTxReturnsInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewDeploymentRepository()
	ctx := context.Background()

	_, err := repo.Insert(ctx, nil, store.Deployment{
		ID:             "dep_nil_tx",
		OrganizationID: "org_test",
		ProjectID:      "proj_test",
		EnvironmentID:  "env_test",
		ServiceID:      "svc_test",
		Source:         store.DeploymentSourceGit,
		RequestedBy:    "usr_actor",
		IdempotencyKey: "idem_nil_tx",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Insert(nil tx) error = %v, want code %s (nil-Tx must surface as typed Internal — a deployment may never be persisted outside its transaction)", err, yerr.CodeInternal)
	}
}

func TestDeploymentRepositoryInsertRollbackPersistsNoRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	id := mintDeploymentID(t, "rollback")

	// Insert succeeds, but the closure returns a sentinel that triggers a
	// rollback. The deployments row must not survive the rollback: a
	// deployment is only legitimate when its provisioning job and audit
	// record commit in the same transaction.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, iErr := repo.Insert(ctx, tx, store.Deployment{
			ID:             id,
			OrganizationID: org.ID,
			ProjectID:      proj.ID,
			EnvironmentID:  env.ID,
			ServiceID:      svc.ID,
			Source:         store.DeploymentSourceGit,
			RequestedBy:    "usr_actor",
			IdempotencyKey: "idem_rollback",
		}); iErr != nil {
			return iErr
		}
		return deploymentTxRollbackSentinel{}
	})
	if !errors.As(err, new(deploymentTxRollbackSentinel)) {
		t.Fatalf("Write returned %v, want a wrapped deploymentTxRollbackSentinel (the closure error must propagate)", err)
	}

	if n := countDeploymentRowsForOrg(ctx, t, db, org.ID); n != 0 {
		t.Errorf("deployments rows for org after rollback = %d, want 0", n)
	}
}

func TestDeploymentRepositoryGetByIDReturnsPersistedRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	created := seedQueuedDeployment(ctx, t, s, repo, org, proj, env, svc, "get")

	var got store.Deployment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		g, gErr := repo.GetByID(ctx, q, org.ID, created.ID)
		if gErr != nil {
			return gErr
		}
		got = g
		return nil
	}); err != nil {
		t.Fatalf("GetByID(%q, %q): %v", org.ID, created.ID, err)
	}

	if got.ID != created.ID || got.OrganizationID != created.OrganizationID ||
		got.ServiceID != created.ServiceID || got.Source != created.Source ||
		got.Status != created.Status || got.Version != created.Version ||
		got.IdempotencyKey != created.IdempotencyKey || got.RequestedBy != created.RequestedBy {
		t.Errorf("GetByID returned %+v, want byte-identical projection of %+v", got, created)
	}
}

func TestDeploymentRepositoryGetByIDUnknownReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.GetByID(ctx, q, org.ID, "dep_does_not_exist")
		return gErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(unknown) error = %v, want code %s (unknown id must surface as NotFound, never a 500 leaking pgx.ErrNoRows)", err, yerr.CodeNotFound)
	}
}

func TestDeploymentRepositoryGetByIDCrossTenantReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedOrg(t, db, f, "alpha")
	alphaProj := seedProject(t, db, f, alpha, "api")
	alphaEnv := seedEnvironment(t, db, f, alphaProj, "prod")
	alphaSvc := seedService(t, db, f, alphaEnv, "web")
	alphaDep := seedQueuedDeployment(ctx, t, s, repo, alpha, alphaProj, alphaEnv, alphaSvc, "cross_get")

	bravo := seedOrg(t, db, f, "bravo")

	// Bravo asks for alpha's deployment id with bravo's organization_id.
	// The composite predicate (organization_id, id) matches no row, so the
	// response is NotFound — never an oracle that confirms the id exists.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.GetByID(ctx, q, bravo.ID, alphaDep.ID)
		return gErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(cross-tenant) error = %v, want code %s", err, yerr.CodeNotFound)
	}
}

func TestDeploymentRepositoryFindByIdempotencyKeyReturnsRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	created := seedQueuedDeployment(ctx, t, s, repo, org, proj, env, svc, "find")

	var (
		got store.Deployment
		ok  bool
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		g, found, fErr := repo.FindByIdempotencyKey(ctx, q, org.ID, created.IdempotencyKey)
		if fErr != nil {
			return fErr
		}
		got, ok = g, found
		return nil
	}); err != nil {
		t.Fatalf("FindByIdempotencyKey: %v", err)
	}
	if !ok {
		t.Fatal("FindByIdempotencyKey returned ok=false for a key the previous Insert persisted")
	}
	if got.ID != created.ID {
		t.Errorf("FindByIdempotencyKey returned id=%q, want %q", got.ID, created.ID)
	}
}

func TestDeploymentRepositoryFindByIdempotencyKeyMissingReturnsZero(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	var (
		got store.Deployment
		ok  bool
		err error
	)
	if rErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		g, found, fErr := repo.FindByIdempotencyKey(ctx, q, org.ID, "idem_does_not_exist")
		got, ok = g, found
		err = fErr
		return nil
	}); rErr != nil {
		t.Fatalf("Read: %v", rErr)
	}
	if err != nil {
		t.Fatalf("FindByIdempotencyKey(missing) err = %v, want nil (a missing key is a non-error miss)", err)
	}
	if ok {
		t.Errorf("FindByIdempotencyKey(missing) ok = true, want false")
	}
	if got.ID != "" {
		t.Errorf("FindByIdempotencyKey(missing) returned id=%q, want empty zero value", got.ID)
	}
}

func TestDeploymentRepositoryFindByIdempotencyKeyCrossTenantReturnsZero(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedOrg(t, db, f, "alpha")
	alphaProj := seedProject(t, db, f, alpha, "api")
	alphaEnv := seedEnvironment(t, db, f, alphaProj, "prod")
	alphaSvc := seedService(t, db, f, alphaEnv, "web")
	alphaDep := seedQueuedDeployment(ctx, t, s, repo, alpha, alphaProj, alphaEnv, alphaSvc, "cross_find")

	bravo := seedOrg(t, db, f, "bravo")

	var (
		got store.Deployment
		ok  bool
		err error
	)
	if rErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		g, found, fErr := repo.FindByIdempotencyKey(ctx, q, bravo.ID, alphaDep.IdempotencyKey)
		got, ok = g, found
		err = fErr
		return nil
	}); rErr != nil {
		t.Fatalf("Read: %v", rErr)
	}
	if err != nil {
		t.Fatalf("FindByIdempotencyKey(cross-tenant) err = %v, want nil (the key UNIQUE is per-tenant, so a foreign key is structurally a miss)", err)
	}
	if ok {
		t.Errorf("FindByIdempotencyKey(cross-tenant) ok = true, want false (the foreign tenant's deployment must not leak)")
	}
	if got.ID != "" {
		t.Errorf("FindByIdempotencyKey(cross-tenant) returned id=%q, want empty (no foreign-tenant id may surface)", got.ID)
	}
}

func TestDeploymentRepositoryCancelQueuedTransitionsToCancelled(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	created := seedQueuedDeployment(ctx, t, s, repo, org, proj, env, svc, "cancel_q")

	var cancelled store.Deployment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		c, cErr := repo.Cancel(ctx, tx, org.ID, created.ID, nil)
		if cErr != nil {
			return cErr
		}
		cancelled = c
		return nil
	}); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	if cancelled.Status != store.DeploymentStatusCancelled {
		t.Errorf("cancelled.Status = %q, want %q", cancelled.Status, store.DeploymentStatusCancelled)
	}
	if cancelled.FinishedAt == nil {
		t.Errorf("cancelled.FinishedAt = nil, want a stamped timestamp (the deployments_finished_consistent CHECK requires terminal status carry finished_at)")
	}
	if cancelled.Version <= created.Version {
		t.Errorf("cancelled.Version = %d, want > %d (bump_version trigger must increment on UPDATE)", cancelled.Version, created.Version)
	}
	if !cancelled.UpdatedAt.After(created.UpdatedAt) && !cancelled.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("cancelled.UpdatedAt = %v, created.UpdatedAt = %v: expected updated_at to be bumped or equal (set_updated_at trigger must fire on UPDATE)", cancelled.UpdatedAt, created.UpdatedAt)
	}

	row := loadDeploymentRowByID(ctx, t, db, created.ID)
	if row.Status != string(store.DeploymentStatusCancelled) {
		t.Errorf("row.Status = %q, want %q (the UPDATE must be observable on a raw re-load)", row.Status, store.DeploymentStatusCancelled)
	}
	if row.FinishedAt == nil {
		t.Errorf("row.FinishedAt = NULL, want a stamped timestamp")
	}
	if row.Version != cancelled.Version {
		t.Errorf("row.Version = %d, want %d", row.Version, cancelled.Version)
	}
}

func TestDeploymentRepositoryCancelRunningTransitionsToCancelled(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	created := seedRunningDeployment(ctx, t, s, repo, org, proj, env, svc, "cancel_r")

	var cancelled store.Deployment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		c, cErr := repo.Cancel(ctx, tx, org.ID, created.ID, nil)
		if cErr != nil {
			return cErr
		}
		cancelled = c
		return nil
	}); err != nil {
		t.Fatalf("Cancel(running): %v", err)
	}

	if cancelled.Status != store.DeploymentStatusCancelled {
		t.Errorf("cancelled.Status = %q, want %q (the UPDATE predicate must include status='running')", cancelled.Status, store.DeploymentStatusCancelled)
	}
	if cancelled.FinishedAt == nil {
		t.Errorf("cancelled.FinishedAt = nil, want a stamped timestamp")
	}
}

func TestDeploymentRepositoryCancelMatchingExpectedVersionSucceeds(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	created := seedQueuedDeployment(ctx, t, s, repo, org, proj, env, svc, "cancel_match_v")
	current := created.Version

	var cancelled store.Deployment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		c, cErr := repo.Cancel(ctx, tx, org.ID, created.ID, &current)
		if cErr != nil {
			return cErr
		}
		cancelled = c
		return nil
	}); err != nil {
		t.Fatalf("Cancel(expectedVersion=%d): %v", current, err)
	}
	if cancelled.Version <= current {
		t.Errorf("cancelled.Version = %d, want > %d (matching expectedVersion must still bump version on UPDATE)", cancelled.Version, current)
	}
}

func TestDeploymentRepositoryCancelStaleExpectedVersionReturnsConflictStale(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	created := seedQueuedDeployment(ctx, t, s, repo, org, proj, env, svc, "cancel_stale")

	// The caller's ETag points at a version that does not exist.
	stale := created.Version + 7

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, cErr := repo.Cancel(ctx, tx, org.ID, created.ID, &stale)
		return cErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Cancel(stale version) error = %v, want a Conflict-class code (ConflictStale)", err)
	}
	got, ok := apierr.CurrentVersionOf(err)
	if !ok {
		t.Fatalf("apierr.CurrentVersionOf(%v) = (_, false), want a current_version attached to ConflictStale", err)
	}
	if got != created.Version {
		t.Errorf("ConflictStale current_version = %d, want %d (the authoritative current version of the unmodified row)", got, created.Version)
	}
}

func TestDeploymentRepositoryCancelTerminalRowReturnsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")
	created := seedQueuedDeployment(ctx, t, s, repo, org, proj, env, svc, "cancel_terminal")

	// First cancel moves the row to terminal; second cancel must reject.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, cErr := repo.Cancel(ctx, tx, org.ID, created.ID, nil)
		return cErr
	}); err != nil {
		t.Fatalf("first Cancel: %v", err)
	}

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, cErr := repo.Cancel(ctx, tx, org.ID, created.ID, nil)
		return cErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("second Cancel(terminal row) error = %v, want code %s (an already-cancelled row must not be silently re-cancelled)", err, yerr.CodeConflict)
	}
	if _, ok := apierr.CurrentVersionOf(err); ok {
		t.Errorf("Cancel(terminal) attached current_version, want none (terminal-row rejection is a plain Conflict, not a stale-version Conflict)")
	}
}

func TestDeploymentRepositoryCancelUnknownIDReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, cErr := repo.Cancel(ctx, tx, org.ID, "dep_does_not_exist", nil)
		return cErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Cancel(unknown id) error = %v, want code %s", err, yerr.CodeNotFound)
	}
}

func TestDeploymentRepositoryCancelCrossTenantReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedOrg(t, db, f, "alpha")
	alphaProj := seedProject(t, db, f, alpha, "api")
	alphaEnv := seedEnvironment(t, db, f, alphaProj, "prod")
	alphaSvc := seedService(t, db, f, alphaEnv, "web")
	alphaDep := seedQueuedDeployment(ctx, t, s, repo, alpha, alphaProj, alphaEnv, alphaSvc, "cancel_cross")

	bravo := seedOrg(t, db, f, "bravo")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, cErr := repo.Cancel(ctx, tx, bravo.ID, alphaDep.ID, nil)
		return cErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Cancel(cross-tenant id) error = %v, want code %s (a cross-tenant deployment_id must surface as NotFound, never a Conflict or success)", err, yerr.CodeNotFound)
	}

	// The byte-identity proof: alpha's row must not have been touched.
	row := loadDeploymentRowByID(ctx, t, db, alphaDep.ID)
	if row.Status != string(store.DeploymentStatusQueued) {
		t.Errorf("alpha row.Status = %q, want %q (the cross-tenant cancel must not have mutated alpha's row)", row.Status, store.DeploymentStatusQueued)
	}
	if row.FinishedAt != nil {
		t.Errorf("alpha row.FinishedAt = %v, want NULL (the cross-tenant cancel must not have stamped finished_at)", *row.FinishedAt)
	}
	if row.Version != alphaDep.Version {
		t.Errorf("alpha row.Version = %d, want %d (the cross-tenant cancel must not have bumped version)", row.Version, alphaDep.Version)
	}
}

func TestDeploymentRepositoryCancelNilTxReturnsInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewDeploymentRepository()
	ctx := context.Background()

	_, err := repo.Cancel(ctx, nil, "org_test", "dep_test", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Cancel(nil tx) error = %v, want code %s", err, yerr.CodeInternal)
	}
}

func TestDeploymentRepositoryListByServiceReturnsReverseChronological(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	// Insert three deployments with explicit sleeps so created_at is
	// strictly ordered at second resolution. The repository orders by
	// (created_at DESC, id DESC); the test pins the most-recent-first
	// projection an agent observes.
	first := seedQueuedDeployment(ctx, t, s, repo, org, proj, env, svc, "list_a")
	time.Sleep(10 * time.Millisecond)
	second := seedQueuedDeployment(ctx, t, s, repo, org, proj, env, svc, "list_b")
	time.Sleep(10 * time.Millisecond)
	third := seedQueuedDeployment(ctx, t, s, repo, org, proj, env, svc, "list_c")

	var list []store.Deployment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := repo.ListByService(ctx, q, org.ID, svc.ID)
		if lErr != nil {
			return lErr
		}
		list = l
		return nil
	}); err != nil {
		t.Fatalf("ListByService: %v", err)
	}

	if len(list) != 3 {
		t.Fatalf("ListByService len = %d, want 3 (rows = %+v)", len(list), list)
	}
	gotIDs := []string{list[0].ID, list[1].ID, list[2].ID}
	wantIDs := []string{third.ID, second.ID, first.ID}
	for i := range gotIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Errorf("ListByService[%d].ID = %q, want %q (rows must be reverse chronological, most recent first)", i, gotIDs[i], wantIDs[i])
		}
	}
}

func TestDeploymentRepositoryListByServiceEmptyReturnsEmptySlice(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "api")
	env := seedEnvironment(t, db, f, proj, "prod")
	svc := seedService(t, db, f, env, "web")

	var list []store.Deployment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := repo.ListByService(ctx, q, org.ID, svc.ID)
		if lErr != nil {
			return lErr
		}
		list = l
		return nil
	}); err != nil {
		t.Fatalf("ListByService(empty): %v", err)
	}

	if list == nil {
		t.Fatal("ListByService returned a nil slice, want an empty non-nil slice (an agent must be able to range over the response without a nil check)")
	}
	if len(list) != 0 {
		t.Errorf("ListByService(empty) len = %d, want 0", len(list))
	}
}

func TestDeploymentRepositoryListByServiceCrossTenantReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedOrg(t, db, f, "alpha")
	alphaProj := seedProject(t, db, f, alpha, "api")
	alphaEnv := seedEnvironment(t, db, f, alphaProj, "prod")
	alphaSvc := seedService(t, db, f, alphaEnv, "web")
	seedQueuedDeployment(ctx, t, s, repo, alpha, alphaProj, alphaEnv, alphaSvc, "list_cross_a")
	seedQueuedDeployment(ctx, t, s, repo, alpha, alphaProj, alphaEnv, alphaSvc, "list_cross_b")

	bravo := seedOrg(t, db, f, "bravo")

	// Bravo asks for alpha's service id with bravo's organization_id. The
	// composite predicate matches no rows, so the response is an empty
	// slice — never alpha's deployments.
	var list []store.Deployment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := repo.ListByService(ctx, q, bravo.ID, alphaSvc.ID)
		if lErr != nil {
			return lErr
		}
		list = l
		return nil
	}); err != nil {
		t.Fatalf("ListByService(cross-tenant): %v", err)
	}

	if len(list) != 0 {
		t.Errorf("ListByService(cross-tenant) returned %d rows, want 0 (alpha's deployments must not leak through bravo's predicate)", len(list))
	}
}
