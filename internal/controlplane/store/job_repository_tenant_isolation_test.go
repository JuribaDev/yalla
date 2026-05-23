package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the provisioning_jobs table
// (BE-0462). provisioning_jobs is the durable, source-of-truth queue of
// Dokploy provisioning operations the worker executes on behalf of customer
// requests: every row carries an idempotency_key the table disambiguates
// per-tenant (UNIQUE (organization_id, idempotency_key)), a lease pair
// (lease_owner, lease_deadline) the worker takes while status='running', and
// a closed-set status the JobRepository moves through the JobStatus state
// machine. A row that belongs to one tenant is anchored to that tenant by:
//
//	(a) the organization_id column itself, with an
//	    ON DELETE CASCADE FK to organizations(id);
//	(b) composite foreign keys (organization_id, project_id),
//	    (organization_id, environment_id) and
//	    (organization_id, service_id) into the parent tables so a job
//	    whose resource-target ids do not match its organization_id is
//	    rejected at the database before it can be persisted; and
//	(c) every JobRepository write/read going through the
//	    organization_id predicate as the non-optional left leg:
//	    Insert is tenant-attributed by the input, Get /
//	    FindByIdempotencyKey / ListByOrganization filter by
//	    organization_id first, and Transition locks the row FOR
//	    UPDATE under (organization_id = $1 AND id = $2).
//
// The JobRepository surface this file exercises against the cross-tenant
// boundary: Insert (caller-id, queued-only), Get, FindByIdempotencyKey,
// ListByOrganization (tenant-scoped read), and Transition (the single
// state-machine mutation surface, with queued -> cancelled as the
// representative cross-tenant probe). ClaimNext is intentionally
// NOT tenant-scoped — it is the worker-side dispatcher that polls jobs
// across every tenant under SELECT ... FOR UPDATE SKIP LOCKED, with the
// claimed job's own organization_id supplied to the subsequent Transition
// — so a "cross-tenant ClaimNext" probe has no analogue and is omitted by
// design.
//
// This file pins the cross-tenant invariants of every customer-facing
// surface and the cross-tenant invariant of the organizations cascade:
//
//   - Insert(orgA) cross-tenant bystander byte-identity: when orgB
//     already owns provisioning_jobs rows (including a queued row, a
//     running row carrying a lease, and a row whose idempotency_key
//     collides with the key orgA is about to use), an Insert on orgA
//     must mint a fresh row owned by orgA and leave every observable
//     column on every orgB row byte-identical to its baseline. The
//     provisioning_jobs_set_updated_at trigger is the load-bearing
//     anchor: it refreshes updated_at on every matched UPDATE, so a
//     missing organization_id predicate that swept an orgB row through
//     an UPDATE would surface here as an updated_at drift even when
//     every other column happened to look right.
//   - Insert(orgA) row-count invariant: orgB's row count is unchanged
//     and orgA's row count grows by exactly +1.
//   - Same-(idempotency_key) provisioning_jobs in two tenants both
//     persist: UNIQUE (organization_id, idempotency_key) is per-tenant
//     — the same key SHOULD be permitted in two tenants concurrently.
//     This is the load-bearing positive-direction pair: without it, a
//     regression that resolved a phantom UNIQUE on (idempotency_key)
//     alone would prevent orgA's INSERT and every byte-identical
//     bystander assertion above would silently pass against an
//     unmutated row that was never written. The per-tenant
//     FindByIdempotencyKey round-trip is the read-side proof of the
//     same shape.
//   - Get(orgB, alphaJob.ID) cross-tenant rejection: the call returns
//     a typed apierr.NotFound and the not-found payload names only
//     the job_id the caller already supplied — never a foreign
//     idempotency_key, request_id, correlation_id, error_summary, or
//     resource-target id.
//   - FindByIdempotencyKey(orgB, alphaJob.IdempotencyKey) cross-tenant
//     miss: returns (zero, false, nil) even when orgA owns a job
//     with that exact key, AND no observable field on the returned
//     zero value references alpha's row.
//   - Transition(orgB, alphaJob.ID, cancelled) cross-tenant
//     rejection: returns apierr.NotFound (never an oracle that
//     confirms the id exists in another tenant), and every orgA
//     bystander row — the named target, a queued sibling, and a
//     running sibling carrying a lease — is byte-identical to its
//     baseline. A regression that dropped the organization_id leg
//     from either the locking SELECT or the UPDATE would surface as
//     a status drift (queued -> cancelled), a stamped finished_at,
//     a refreshed updated_at, or a released lease on alpha's rows.
//   - ListByOrganization(orgB) cross-tenant empty: returns an empty
//     slice and the per-tenant COUNT(*) is unaffected — the response
//     never leaks a total-rows hint from another tenant and the
//     read itself has no side effect on the underlying table.
//   - organizations DELETE cascade is tenant-scoped: deleting orgA
//     removes only orgA's provisioning_jobs and every orgB row
//     (including the row carrying a live lease) is byte-identical to
//     its baseline. A regression that dropped the organization_id
//     leg of the FK would surface here as either an orgB row
//     vanishing or its updated_at drifting.
//
// What this file deliberately delegates:
//
//   - The composite-FK cross-tenant-parent INSERT path (a job whose
//     project_id belongs to another tenant) is already pinned by
//     job_test.go's TestJobRepositoryInsertCrossTenantResourceRejected
//     as a typed apierr.Conflict; rerunning it here would duplicate
//     coverage without adding a bystander byte-identity proof the
//     existing test does not need.
//   - The closed-set status CHECK, the finished_consistent and
//     lease_consistent row-body CHECKs, the state-machine transition
//     matrix, the lease-bookkeeping and attempt-budget invariants,
//     ClaimNext SKIP LOCKED, and the error-summary redaction backstop
//     are pinned by job_test.go and job_internal_test.go.
//   - The repository invariants (row-shape, primary-key collision,
//     rollback-persists-no-row, list ordering, limit clamp) are
//     pinned by job_repository_invariants_test.go.
//   - The HTTP envelope shape (yalla.output.v1 / yalla.error.v1) is a
//     transport-layer concern; the repository surface returns typed
//     apierr values and the HTTP layer's contract tests render the
//     envelope. Cross-tenant repository tests assert the typed
//     apierr code only.
//   - provisioning_jobs stores NO secret-bearing column —
//     error_summary is run through the output redactor by the
//     JobRepository before persistence and payload carries only
//     non-secret references — so the BE-0434-style raw-secret probe
//     has no analogue here. Per the BE-0462 acceptance criteria,
//     secrets, tokens, API keys, cookies and rendered environment
//     variable values would be redacted; the provisioning_jobs table
//     simply does not carry any.
//
// Database-backed cases run against an isolated, freshly migrated
// Postgres and skip when YALLA_TEST_DATABASE_URL is unset.

// timePtrEqualJob compares nullable timestamp columns observed in rawJobRow
// (lease_deadline, started_at, finished_at — all timestamptz). The per-file
// Job suffix is mandatory: every *_test.go file under
// internal/controlplane/store/ shares the same package, and other tenant-
// isolation files already export Dep / QR / QP / "" variants of the same
// name — collisions would block compilation.
func timePtrEqualJob(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// fmtTimePtrJob renders a nullable timestamp column for error messages so a
// missing vs zero distinction is obvious.
func fmtTimePtrJob(p *time.Time) string {
	if p == nil {
		return "<nil>"
	}
	return p.Format(time.RFC3339Nano)
}

// strPtrEqualJob compares nullable string columns observed in rawJobRow
// (project_id, environment_id, service_id). A nil pointer means SQL NULL —
// the database stores the "no resource target" shape that way — and an
// empty-string pointer is structurally different (it would round-trip
// through nullableID as nil, so the two should never collide in a
// well-formed test fixture, but the comparison is explicit anyway).
func strPtrEqualJob(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// fmtStrPtrJob renders a nullable string column for error messages so a
// missing vs empty distinction is obvious.
func fmtStrPtrJob(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// assertJobByteIdentical asserts every observable column on a bystander
// provisioning_jobs row is byte-identical to its baseline. The
// trigger-managed updated_at column is the load-bearing anchor: the BEFORE
// UPDATE provisioning_jobs_set_updated_at trigger refreshes it on every
// matched UPDATE, so a missing organization_id predicate in Insert,
// Transition or the cascade would surface here as an updated_at drift even
// if every other column happened to look right. The provisioning_jobs
// table has NO version column (unlike deployments / projects / services),
// so version-bump detection is unavailable; updated_at is the sole
// trigger-managed anchor and every business column is compared
// individually.
func assertJobByteIdentical(t *testing.T, label string, baseline, after rawJobRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: bystander.id = %q, want %q", label, after.ID, baseline.ID)
	}
	if after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander.organization_id = %q, want %q",
			label, after.OrganizationID, baseline.OrganizationID)
	}
	if after.JobType != baseline.JobType {
		t.Errorf("%s: bystander.job_type = %q, want %q", label, after.JobType, baseline.JobType)
	}
	if !strPtrEqualJob(after.ProjectID, baseline.ProjectID) {
		t.Errorf("%s: bystander.project_id = %s, want %s",
			label, fmtStrPtrJob(after.ProjectID), fmtStrPtrJob(baseline.ProjectID))
	}
	if !strPtrEqualJob(after.EnvironmentID, baseline.EnvironmentID) {
		t.Errorf("%s: bystander.environment_id = %s, want %s",
			label, fmtStrPtrJob(after.EnvironmentID), fmtStrPtrJob(baseline.EnvironmentID))
	}
	if !strPtrEqualJob(after.ServiceID, baseline.ServiceID) {
		t.Errorf("%s: bystander.service_id = %s, want %s",
			label, fmtStrPtrJob(after.ServiceID), fmtStrPtrJob(baseline.ServiceID))
	}
	if after.DesiredVersion != baseline.DesiredVersion {
		t.Errorf("%s: bystander.desired_version = %d, want %d",
			label, after.DesiredVersion, baseline.DesiredVersion)
	}
	if after.IdempotencyKey != baseline.IdempotencyKey {
		t.Errorf("%s: bystander.idempotency_key = %q, want %q",
			label, after.IdempotencyKey, baseline.IdempotencyKey)
	}
	if after.Status != baseline.Status {
		t.Errorf("%s: bystander.status = %q, want %q — a foreign-tenant Transition wrote through a missing organization_id predicate",
			label, after.Status, baseline.Status)
	}
	if after.Attempts != baseline.Attempts {
		t.Errorf("%s: bystander.attempts = %d, want %d",
			label, after.Attempts, baseline.Attempts)
	}
	if after.MaxAttempts != baseline.MaxAttempts {
		t.Errorf("%s: bystander.max_attempts = %d, want %d",
			label, after.MaxAttempts, baseline.MaxAttempts)
	}
	if after.LeaseOwner != baseline.LeaseOwner {
		t.Errorf("%s: bystander.lease_owner = %q, want %q — a foreign-tenant claim/release crossed the organization_id predicate",
			label, after.LeaseOwner, baseline.LeaseOwner)
	}
	if !timePtrEqualJob(after.LeaseDeadline, baseline.LeaseDeadline) {
		t.Errorf("%s: bystander.lease_deadline = %s, want %s",
			label, fmtTimePtrJob(after.LeaseDeadline), fmtTimePtrJob(baseline.LeaseDeadline))
	}
	if !after.NextRunAt.Equal(baseline.NextRunAt) {
		t.Errorf("%s: bystander.next_run_at = %v, want %v",
			label, after.NextRunAt, baseline.NextRunAt)
	}
	if after.ErrorSummary != baseline.ErrorSummary {
		t.Errorf("%s: bystander.error_summary = %q, want %q",
			label, after.ErrorSummary, baseline.ErrorSummary)
	}
	if string(after.Payload) != string(baseline.Payload) {
		t.Errorf("%s: bystander.payload = %s, want %s",
			label, string(after.Payload), string(baseline.Payload))
	}
	if after.RequestID != baseline.RequestID {
		t.Errorf("%s: bystander.request_id = %q, want %q",
			label, after.RequestID, baseline.RequestID)
	}
	if after.CorrelationID != baseline.CorrelationID {
		t.Errorf("%s: bystander.correlation_id = %q, want %q",
			label, after.CorrelationID, baseline.CorrelationID)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v",
			label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE UPDATE provisioning_jobs_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE silently crossed the organization_id predicate",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
	if !timePtrEqualJob(after.StartedAt, baseline.StartedAt) {
		t.Errorf("%s: bystander.started_at = %s, want %s",
			label, fmtTimePtrJob(after.StartedAt), fmtTimePtrJob(baseline.StartedAt))
	}
	if !timePtrEqualJob(after.FinishedAt, baseline.FinishedAt) {
		t.Errorf("%s: bystander.finished_at = %s, want %s",
			label, fmtTimePtrJob(after.FinishedAt), fmtTimePtrJob(baseline.FinishedAt))
	}
}

// twoTenantJobFixture builds two completely-independent tenant hierarchies
// (orgA and orgB), each with its own project, environment and service.
// Every provisioning_jobs test in this file needs both halves — keeping
// the construction in one helper keeps the per-test bodies focused on the
// cross-tenant invariant rather than the boilerplate of minting a second
// hierarchy.
type twoTenantJobFixture struct {
	orgA  testutil.Organization
	projA testutil.Project
	envA  testutil.Environment
	svcA  testutil.Service
	orgB  testutil.Organization
	projB testutil.Project
	envB  testutil.Environment
	svcB  testutil.Service
}

func seedTwoTenantJobFixture(t *testing.T, db *testutil.DB, f *testutil.Factory) twoTenantJobFixture {
	t.Helper()
	orgA := seedOrg(t, db, f, "tenant-a")
	projA := seedProject(t, db, f, orgA, "api")
	envA := seedEnvironment(t, db, f, projA, "prod")
	svcA := seedService(t, db, f, envA, "web")

	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "api")
	envB := seedEnvironment(t, db, f, projB, "prod")
	svcB := seedService(t, db, f, envB, "web")

	return twoTenantJobFixture{
		orgA: orgA, projA: projA, envA: envA, svcA: svcA,
		orgB: orgB, projB: projB, envB: envB, svcB: svcB,
	}
}

// seedQueuedJob enqueues a queued provisioning job for (org, project) with
// idempotency-suffixed key and returns the stored row. JobRepository.Insert
// always mints a queued row regardless of the input status, so this helper
// is just an opinionated fixture wrapper around insertJob.
func seedQueuedJob(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.JobRepository,
	org testutil.Organization,
	proj testutil.Project,
	suffix string,
) store.ProvisioningJob {
	t.Helper()
	j := jobFixture(org.ID, "idem_"+suffix)
	j.ID = mintJobID(t, suffix)
	j.ProjectID = proj.ID
	j.RequestID = "req_" + suffix
	j.CorrelationID = "cor_" + suffix
	return insertJob(ctx, t, s, repo, j)
}

// seedRunningJob enqueues a queued job and immediately transitions it to
// running with a fixed lease so the bystander assertions can observe the
// non-empty lease_owner, the non-null lease_deadline, the bumped attempts
// counter, and the stamped started_at. The lease values are deterministic so
// the baseline raw row is stable across the test's lifetime.
func seedRunningJob(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.JobRepository,
	org testutil.Organization,
	proj testutil.Project,
	suffix string,
) store.ProvisioningJob {
	t.Helper()
	queued := seedQueuedJob(ctx, t, s, repo, org, proj, suffix)
	return transitionJob(ctx, t, s, repo, org.ID, queued.ID, store.JobStatusRunning, store.JobTransition{
		LeaseOwner:    "worker_" + suffix,
		LeaseDuration: 5 * time.Minute,
	})
}

// TestJobRepositoryInsertOnOrgADoesNotTouchOrgB proves the load-bearing
// cross-tenant invariant of Insert: when orgB owns several provisioning_jobs
// rows — including a queued row, a running row carrying a live lease, and a
// row with a deliberately recognisable idempotency_key — an Insert on orgA
// lands as a fresh row owned by orgA and leaves every observable column on
// every orgB row byte-identical to its baseline. A regression that swept an
// orgB row through a missing organization_id predicate would surface as an
// updated_at drift or a column rewrite on any bystander.
func TestJobRepositoryInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobFixture(t, db, f)

	// orgB owns three peer rows: a queued row, a running row (with a live
	// lease so lease_owner / lease_deadline / started_at are non-empty
	// anchors the bystander assertion can pin), and a row whose
	// idempotency_key collides with the key orgA is about to use — the
	// load-bearing peer.
	bravoQueued := seedQueuedJob(ctx, t, s, repo, fix.orgB, fix.projB, "bravo_queued")
	bravoRunning := seedRunningJob(ctx, t, s, repo, fix.orgB, fix.projB, "bravo_running")
	bravoCollide := seedQueuedJob(ctx, t, s, repo, fix.orgB, fix.projB, "collide")

	baselineQueued := loadJobRowByID(ctx, t, db, bravoQueued.ID)
	baselineRunning := loadJobRowByID(ctx, t, db, bravoRunning.ID)
	baselineCollide := loadJobRowByID(ctx, t, db, bravoCollide.ID)

	// orgA inserts a job whose idempotency_key matches the recognisable
	// suffix orgB already holds. UNIQUE (organization_id, idempotency_key)
	// is per-tenant, so the INSERT must mint a fresh row owned by orgA
	// — never UPDATE orgB's collide row.
	alpha := jobFixture(fix.orgA.ID, "idem_collide")
	alpha.ID = mintJobID(t, "alpha")
	alpha.ProjectID = fix.projA.ID
	alpha.RequestID = "req_alpha"
	alpha.CorrelationID = "cor_alpha"
	created := insertJob(ctx, t, s, repo, alpha)

	if created.OrganizationID != fix.orgA.ID {
		t.Fatalf("Insert lifted organization_id = %q, want %q (orgA's Insert was attributed to the wrong tenant)",
			created.OrganizationID, fix.orgA.ID)
	}
	if created.ID == bravoCollide.ID {
		t.Fatalf("Insert returned orgB's job id %q — the INSERT silently UPDATEd orgB's row instead of minting a fresh row for orgA",
			created.ID)
	}

	afterQueued := loadJobRowByID(ctx, t, db, bravoQueued.ID)
	assertJobByteIdentical(t,
		"orgB queued bystander after orgA Insert",
		baselineQueued, afterQueued)

	afterRunning := loadJobRowByID(ctx, t, db, bravoRunning.ID)
	assertJobByteIdentical(t,
		"orgB running bystander after orgA Insert",
		baselineRunning, afterRunning)

	afterCollide := loadJobRowByID(ctx, t, db, bravoCollide.ID)
	assertJobByteIdentical(t,
		"orgB idempotency-key collide bystander after orgA Insert",
		baselineCollide, afterCollide)
}

// TestJobRepositoryInsertOnOrgADoesNotChangeOrgBRowCount proves the per-tenant
// row count is invariant under another tenant's Insert. orgB owns two rows
// before orgA makes any call; orgA then inserts a row. orgB's count must
// remain at 2 — neither lower (an accidental cross-tenant DELETE) nor
// higher (an accidental cross-tenant INSERT). orgA's count goes from 0 to 1.
// This complements the byte-identity bystander proof above: a regression
// that silently dropped one orgB row and minted a new one with the same
// content would defeat the byte-identity test but trip here.
func TestJobRepositoryInsertOnOrgADoesNotChangeOrgBRowCount(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobFixture(t, db, f)

	seedQueuedJob(ctx, t, s, repo, fix.orgB, fix.projB, "count_a")
	seedRunningJob(ctx, t, s, repo, fix.orgB, fix.projB, "count_b")

	if n := countJobRowsForOrg(ctx, t, db, fix.orgB.ID); n != 2 {
		t.Fatalf("baseline orgB count = %d, want 2 — test fixture is invalid", n)
	}
	if n := countJobRowsForOrg(ctx, t, db, fix.orgA.ID); n != 0 {
		t.Fatalf("baseline orgA count = %d, want 0 — test fixture is invalid", n)
	}

	seedQueuedJob(ctx, t, s, repo, fix.orgA, fix.projA, "alpha")

	if n := countJobRowsForOrg(ctx, t, db, fix.orgB.ID); n != 2 {
		t.Errorf("orgB count after Insert(orgA, ...) = %d, want 2 — orgA's Insert touched orgB", n)
	}
	if n := countJobRowsForOrg(ctx, t, db, fix.orgA.ID); n != 1 {
		t.Errorf("orgA count after Insert(orgA, ...) = %d, want 1 — orgA's Insert did not land", n)
	}
}

// TestJobRepositoryInsertSameIdempotencyKeyInTwoTenantsBothPersist is the
// load-bearing positive-direction pair for the bystander byte-identity
// proofs. UNIQUE (organization_id, idempotency_key) is per-tenant — there
// is no UNIQUE constraint on (idempotency_key) alone — so two tenants each
// holding a job with the same idempotency_key is the expected concurrent
// shape. Without this test, a regression that resolved a phantom UNIQUE on
// (idempotency_key) alone would prevent orgA's Insert and every
// byte-identical assertion in the bystander tests would silently pass
// against an unmutated row that was never written. The per-tenant
// FindByIdempotencyKey round-trip is the read-side proof of the same shape:
// the SAME key must resolve to the per-tenant row, never cross-tenant.
//
// This gap-fill is structurally distinct from job_test.go's lightweight
// TestJobRepositoryInsertSameKeyDifferentOrgs (which only proves both
// Inserts succeed): it adds the cross-tenant id distinctness assertion and
// the per-tenant FindByIdempotencyKey round-trip the tenant-isolation
// pattern requires.
func TestJobRepositoryInsertSameIdempotencyKeyInTwoTenantsBothPersist(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobFixture(t, db, f)

	const sharedKey = "idem_shared_across_tenants"

	bravoIn := jobFixture(fix.orgB.ID, sharedKey)
	bravoIn.ID = mintJobID(t, "bravo")
	bravoIn.ProjectID = fix.projB.ID
	bravoIn.RequestID = "req_bravo"
	bravoIn.CorrelationID = "cor_bravo"
	bravo := insertJob(ctx, t, s, repo, bravoIn)

	alphaIn := jobFixture(fix.orgA.ID, sharedKey)
	alphaIn.ID = mintJobID(t, "alpha")
	alphaIn.ProjectID = fix.projA.ID
	alphaIn.RequestID = "req_alpha"
	alphaIn.CorrelationID = "cor_alpha"
	alpha := insertJob(ctx, t, s, repo, alphaIn)

	if alpha.OrganizationID != fix.orgA.ID {
		t.Errorf("alpha.OrganizationID = %q, want %q", alpha.OrganizationID, fix.orgA.ID)
	}
	if bravo.OrganizationID != fix.orgB.ID {
		t.Errorf("bravo.OrganizationID = %q, want %q", bravo.OrganizationID, fix.orgB.ID)
	}
	if alpha.ID == bravo.ID {
		t.Errorf("alpha.ID == bravo.ID (= %q): the two tenants must hold distinct job ids even with a shared idempotency_key",
			alpha.ID)
	}
	if alpha.IdempotencyKey != sharedKey || bravo.IdempotencyKey != sharedKey {
		t.Errorf("alpha.IdempotencyKey=%q bravo.IdempotencyKey=%q, want both %q",
			alpha.IdempotencyKey, bravo.IdempotencyKey, sharedKey)
	}

	// FindByIdempotencyKey must resolve the SAME key to the per-tenant row
	// — never cross-tenant. This is the read-side proof of the
	// positive-direction shape.
	var (
		alphaFound, bravoFound store.ProvisioningJob
		alphaOK, bravoOK       bool
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		a, aOK, aErr := repo.FindByIdempotencyKey(ctx, q, fix.orgA.ID, sharedKey)
		if aErr != nil {
			return aErr
		}
		b, bOK, bErr := repo.FindByIdempotencyKey(ctx, q, fix.orgB.ID, sharedKey)
		if bErr != nil {
			return bErr
		}
		alphaFound, alphaOK = a, aOK
		bravoFound, bravoOK = b, bOK
		return nil
	}); err != nil {
		t.Fatalf("FindByIdempotencyKey(per-tenant): %v", err)
	}
	if !alphaOK || alphaFound.ID != alpha.ID {
		t.Errorf("FindByIdempotencyKey(orgA, sharedKey) = (%q, %v), want (%q, true)",
			alphaFound.ID, alphaOK, alpha.ID)
	}
	if !bravoOK || bravoFound.ID != bravo.ID {
		t.Errorf("FindByIdempotencyKey(orgB, sharedKey) = (%q, %v), want (%q, true)",
			bravoFound.ID, bravoOK, bravo.ID)
	}
	if alphaFound.OrganizationID != fix.orgA.ID {
		t.Errorf("FindByIdempotencyKey(orgA, sharedKey).OrganizationID = %q, want %q (the key resolved to a foreign tenant's row)",
			alphaFound.OrganizationID, fix.orgA.ID)
	}
	if bravoFound.OrganizationID != fix.orgB.ID {
		t.Errorf("FindByIdempotencyKey(orgB, sharedKey).OrganizationID = %q, want %q (the key resolved to a foreign tenant's row)",
			bravoFound.OrganizationID, fix.orgB.ID)
	}
}

// TestJobRepositoryGetCrossTenantReturnsNotFoundAndDoesNotEcho proves
// Get(orgB, alphaJob.ID) is tenant-scoped at the SQL predicate AND that
// the not-found payload names only the job_id the caller already supplied
// — never a foreign idempotency_key, request_id, correlation_id,
// error_summary, or resource-target id. A regression that resolved the
// composite (organization_id, id) by id alone would either return orgA's
// row (defeated by the assertion on the typed apierr.NotFound code) OR
// would attach orgA's idempotency_key / request id / resource ids to the
// not-found details (defeated by the explicit no-leak substring checks
// below).
//
// This is the gap-fill: job_test.go's TestJobRepositoryGetCrossTenant
// already asserts the typed NotFound code but does NOT pin the
// no-leak-substring invariant the tenant-isolation pattern requires.
func TestJobRepositoryGetCrossTenantReturnsNotFoundAndDoesNotEcho(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobFixture(t, db, f)

	// alpha owns a job with deliberately distinctive idempotency_key /
	// request_id / correlation_id suffixes — if a regression echoed any of
	// them into the not-found payload, the substring checks below would
	// trip.
	alphaIn := jobFixture(fix.orgA.ID, "idem_no_echo_distinctive_alpha_key")
	alphaIn.ID = mintJobID(t, "alpha")
	alphaIn.ProjectID = fix.projA.ID
	alphaIn.RequestID = "req_no_echo_distinctive_alpha_req"
	alphaIn.CorrelationID = "cor_no_echo_distinctive_alpha_cor"
	alpha := insertJob(ctx, t, s, repo, alphaIn)

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.Get(ctx, q, fix.orgB.ID, alpha.ID)
		return gErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(cross-tenant) error = %v, want code %s (a cross-tenant id must surface as NotFound, never a successful read of another tenant's row)",
			err, yerr.CodeNotFound)
	}
	msg := err.Error()
	if containsValue(msg, "no_echo_distinctive_alpha_key") {
		t.Errorf("Get(cross-tenant) error message %q echoed alpha's idempotency_key — the not-found payload must name only the supplied id", msg)
	}
	if containsValue(msg, "no_echo_distinctive_alpha_req") {
		t.Errorf("Get(cross-tenant) error message %q echoed alpha's request_id — the not-found payload must name only the supplied id", msg)
	}
	if containsValue(msg, "no_echo_distinctive_alpha_cor") {
		t.Errorf("Get(cross-tenant) error message %q echoed alpha's correlation_id — the not-found payload must name only the supplied id", msg)
	}
	if containsValue(msg, fix.projA.ID) {
		t.Errorf("Get(cross-tenant) error message %q echoed alpha's project_id — the not-found payload must name only the supplied job_id", msg)
	}
}

// TestJobRepositoryFindByIdempotencyKeyCrossTenantDoesNotLeak proves
// FindByIdempotencyKey(orgB, alphaKey) returns (zero, false, nil) AND that
// no observable field on the returned zero value references alpha's row.
// UNIQUE (organization_id, idempotency_key) is per-tenant — a foreign key
// is structurally a miss.
//
// This is the gap-fill: job_test.go's TestJobRepositoryFindByIdempotencyKey
// already asserts crossTenantOK == false but does NOT pin no-leak on the
// returned zero value (a regression that surfaced the foreign row could
// populate fields even with ok=false).
func TestJobRepositoryFindByIdempotencyKeyCrossTenantDoesNotLeak(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobFixture(t, db, f)

	alpha := seedQueuedJob(ctx, t, s, repo, fix.orgA, fix.projA, "leak_check")

	var (
		got store.ProvisioningJob
		ok  bool
		err error
	)
	if rErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		g, found, fErr := repo.FindByIdempotencyKey(ctx, q, fix.orgB.ID, alpha.IdempotencyKey)
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
		t.Errorf("FindByIdempotencyKey(cross-tenant) ok = true, want false (the foreign tenant's job must not leak)")
	}
	if got.ID != "" {
		t.Errorf("FindByIdempotencyKey(cross-tenant) returned id=%q, want empty (no foreign-tenant id may surface)", got.ID)
	}
	if got.OrganizationID != "" {
		t.Errorf("FindByIdempotencyKey(cross-tenant) returned organization_id=%q, want empty", got.OrganizationID)
	}
	if got.IdempotencyKey != "" {
		t.Errorf("FindByIdempotencyKey(cross-tenant) returned idempotency_key=%q, want empty (no foreign-tenant idempotency_key may surface)", got.IdempotencyKey)
	}
	if got.ProjectID != "" {
		t.Errorf("FindByIdempotencyKey(cross-tenant) returned project_id=%q, want empty (no foreign-tenant project_id may surface)", got.ProjectID)
	}
	if got.RequestID != "" {
		t.Errorf("FindByIdempotencyKey(cross-tenant) returned request_id=%q, want empty (no foreign-tenant request_id may surface)", got.RequestID)
	}
}

// TestJobRepositoryTransitionCrossTenantLeavesOrgABystandersByteIdentical
// proves Transition(orgB, alphaJob.ID, cancelled) does not touch any orgA
// row — neither the named target, a queued sibling, nor a running sibling
// carrying a live lease — and surfaces as a typed apierr.NotFound. Several
// orgA rows in differing lifecycle states are seeded to expose any
// regression that widened the predicate (e.g. UPDATE by id alone would
// touch the target; UPDATE by status alone would touch every queued row
// across both tenants; a missing organization_id leg on the FOR UPDATE
// SELECT would either return another tenant's row or silently release
// another tenant's lease). The queued -> cancelled edge is the
// representative cross-tenant probe: it exercises the locking SELECT, the
// state-machine validator, the UPDATE projection, and the lease-release
// + finished_at-stamp bookkeeping all at once.
func TestJobRepositoryTransitionCrossTenantLeavesOrgABystandersByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobFixture(t, db, f)

	target := seedQueuedJob(ctx, t, s, repo, fix.orgA, fix.projA, "target")
	queuedSibling := seedQueuedJob(ctx, t, s, repo, fix.orgA, fix.projA, "queued_sibling")
	runningSibling := seedRunningJob(ctx, t, s, repo, fix.orgA, fix.projA, "running_sibling")

	baselineTarget := loadJobRowByID(ctx, t, db, target.ID)
	baselineQueued := loadJobRowByID(ctx, t, db, queuedSibling.ID)
	baselineRunning := loadJobRowByID(ctx, t, db, runningSibling.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, tErr := repo.Transition(ctx, tx, fix.orgB.ID, target.ID, store.JobStatusCancelled, store.JobTransition{
			ErrorSummary: "cross-tenant cancel attempt",
		})
		return tErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Transition(cross-tenant id) error = %v, want code %s (a cross-tenant job_id must surface as NotFound, never a Conflict or success)",
			err, yerr.CodeNotFound)
	}

	afterTarget := loadJobRowByID(ctx, t, db, target.ID)
	assertJobByteIdentical(t,
		"orgA target row after orgB Transition(target.ID, cancelled)",
		baselineTarget, afterTarget)

	afterQueued := loadJobRowByID(ctx, t, db, queuedSibling.ID)
	assertJobByteIdentical(t,
		"orgA queued sibling after orgB Transition(target.ID, cancelled)",
		baselineQueued, afterQueued)

	afterRunning := loadJobRowByID(ctx, t, db, runningSibling.ID)
	assertJobByteIdentical(t,
		"orgA running sibling after orgB Transition(target.ID, cancelled)",
		baselineRunning, afterRunning)
}

// TestJobRepositoryListByOrganizationCrossTenantReturnsEmptyAndDoesNotLeakTotal
// proves ListByOrganization(orgB) returns an empty slice AND the per-tenant
// COUNT(*) for orgA is unaffected — no count is leaked through the response
// shape or through a side effect on the underlying table. The acceptance
// criterion "List queries return stable pagination without leaking total
// counts from other tenants" is pinned here: the response carries no
// total-count field and the foreign-tenant query returns zero rows even
// when the underlying organization owns several jobs.
//
// This is the gap-fill: job_test.go's
// TestJobRepositoryListByOrganizationTenantIsolation already proves orgA's
// list does not surface orgB's row, but does NOT pin the side-effect-free
// read invariant or the per-tenant COUNT(*) invariance under a foreign
// tenant's List call.
func TestJobRepositoryListByOrganizationCrossTenantReturnsEmptyAndDoesNotLeakTotal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobFixture(t, db, f)

	seedQueuedJob(ctx, t, s, repo, fix.orgA, fix.projA, "list_a")
	seedQueuedJob(ctx, t, s, repo, fix.orgA, fix.projA, "list_b")
	seedRunningJob(ctx, t, s, repo, fix.orgA, fix.projA, "list_c")

	baselineCountA := countJobRowsForOrg(ctx, t, db, fix.orgA.ID)
	if baselineCountA != 3 {
		t.Fatalf("baseline orgA count = %d, want 3 — test fixture is invalid", baselineCountA)
	}
	baselineCountB := countJobRowsForOrg(ctx, t, db, fix.orgB.ID)
	if baselineCountB != 0 {
		t.Fatalf("baseline orgB count = %d, want 0 — test fixture is invalid", baselineCountB)
	}

	var list []store.ProvisioningJob
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := repo.ListByOrganization(ctx, q, fix.orgB.ID, 50)
		if lErr != nil {
			return lErr
		}
		list = l
		return nil
	}); err != nil {
		t.Fatalf("ListByOrganization(cross-tenant): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("ListByOrganization(cross-tenant) returned %d rows, want 0 (alpha's jobs must not leak through bravo's predicate)", len(list))
	}

	// Reading must not have side-effected the underlying counts.
	if n := countJobRowsForOrg(ctx, t, db, fix.orgA.ID); n != baselineCountA {
		t.Errorf("orgA count after cross-tenant List = %d, want %d (a read leaked into a write)", n, baselineCountA)
	}
	if n := countJobRowsForOrg(ctx, t, db, fix.orgB.ID); n != baselineCountB {
		t.Errorf("orgB count after cross-tenant List = %d, want %d (a read leaked into a write)", n, baselineCountB)
	}
}

// TestJobOrganizationDeleteCascadeIsTenantScoped proves orgA's deletion
// cascades only to orgA's provisioning_jobs. orgB's rows (including a
// queued, a running carrying a live lease, and an extra queued row) must
// remain byte-identical. The provisioning_jobs.organization_id FK CASCADE
// on organizations(id) confines the cleanup to the deleted tenant; a
// regression that dropped the organization_id leg of the FK would surface
// here as either an orgB row vanishing or its updated_at drifting. The
// composite (organization_id, project_id|environment_id|service_id) FKs
// also cascade through the parent rows, but those cascades fire BEFORE
// the organization cascade and are not the tenant-scope-bearing edge under
// test — the organizations FK is the load-bearing one for the
// "deleting a tenant removes only that tenant's rows" invariant.
func TestJobOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobFixture(t, db, f)

	// orgA owns two rows (which will be cascaded away). orgB owns three
	// rows (which must survive byte-identically), including a running row
	// carrying a live lease so the bystander assertion can pin
	// lease_owner / lease_deadline / started_at / attempts as anchors.
	seedQueuedJob(ctx, t, s, repo, fix.orgA, fix.projA, "cascade_alpha_queued")
	seedRunningJob(ctx, t, s, repo, fix.orgA, fix.projA, "cascade_alpha_running")

	bravoQueued := seedQueuedJob(ctx, t, s, repo, fix.orgB, fix.projB, "cascade_bravo_queued")
	bravoRunning := seedRunningJob(ctx, t, s, repo, fix.orgB, fix.projB, "cascade_bravo_running")
	bravoExtra := seedQueuedJob(ctx, t, s, repo, fix.orgB, fix.projB, "cascade_bravo_extra")

	baselineQueued := loadJobRowByID(ctx, t, db, bravoQueued.ID)
	baselineRunning := loadJobRowByID(ctx, t, db, bravoRunning.ID)
	baselineExtra := loadJobRowByID(ctx, t, db, bravoExtra.ID)

	// Deleting orgA cascades through the full hierarchy — projects,
	// environments, services and provisioning_jobs are all anchored by
	// composite FKs to organizations(id).
	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, fix.orgA.ID); err != nil {
		t.Fatalf("delete orgA: %v", err)
	}

	if n := countJobRowsForOrg(ctx, t, db, fix.orgA.ID); n != 0 {
		t.Errorf("provisioning_jobs rows for orgA after delete = %d, want 0 (cascade must remove the deleted tenant's rows)", n)
	}
	if n := countJobRowsForOrg(ctx, t, db, fix.orgB.ID); n != 3 {
		t.Errorf("provisioning_jobs rows for orgB after orgA delete = %d, want 3 — the cascade bled into another tenant", n)
	}

	afterQueued := loadJobRowByID(ctx, t, db, bravoQueued.ID)
	assertJobByteIdentical(t,
		"orgB queued bystander survives orgA delete",
		baselineQueued, afterQueued)

	afterRunning := loadJobRowByID(ctx, t, db, bravoRunning.ID)
	assertJobByteIdentical(t,
		"orgB running bystander survives orgA delete",
		baselineRunning, afterRunning)

	afterExtra := loadJobRowByID(ctx, t, db, bravoExtra.ID)
	assertJobByteIdentical(t,
		"orgB extra queued bystander survives orgA delete",
		baselineExtra, afterExtra)
}
