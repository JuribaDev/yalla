package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the job_attempts table
// (BE-0464). job_attempts is the immutable, append-only history of every
// finished provisioning-worker attempt against a parent provisioning_jobs
// row: every row carries an organization_id leg, a composite FK
// (organization_id, job_id) into provisioning_jobs(organization_id, id) so
// an attempt can never sit under a foreign tenant's job, a UNIQUE
// (organization_id, job_id, attempt_number) per-tenant retry-number
// invariant, and a closed-set status the application validates before the
// row reaches the database. A row that belongs to one tenant is anchored to
// that tenant by:
//
//	(a) the organization_id column itself, with an
//	    ON DELETE CASCADE FK to organizations(id);
//	(b) the composite (organization_id, job_id) FK into
//	    provisioning_jobs(organization_id, id) so an attempt whose
//	    job_id belongs to another tenant is rejected at the database
//	    before it can be persisted (already pinned cross-tenant in
//	    job_attempt_repository_invariants_test.go as a typed
//	    apierr.Conflict by the BE-0463 invariants story);
//	(c) every JobAttemptRepository write/read going through the
//	    organization_id predicate as the non-optional left leg:
//	    Append is tenant-attributed by the input, GetByID and
//	    ListByJob filter by organization_id first.
//
// The JobAttemptRepository surface this file exercises against the
// cross-tenant boundary: Append (the sole write — append-only, *Tx-bound,
// with the database BEFORE UPDATE trigger rejecting any post-write
// mutation), GetByID (tenant-scoped point lookup), and ListByJob
// (tenant-scoped per-job read). There is no Update, no Delete, no
// Transition surface: a job_attempts row is written exactly once and
// removed only via ON DELETE CASCADE when the parent provisioning_jobs row
// (and in turn the organization) is deleted — so the cross-tenant probe
// pool is structurally narrower than for provisioning_jobs (BE-0462).
//
// This file pins the cross-tenant invariants of every customer-facing
// surface and the cross-tenant invariant of both cascade edges:
//
//   - Append(orgA) cross-tenant bystander byte-identity: when orgB
//     already owns several job_attempts rows (across different statuses
//     and a parallel attempt_number = 1) an Append on orgA mints a fresh
//     row owned by orgA and leaves every observable column on every
//     orgB row byte-identical to its baseline. job_attempts has no
//     updated_at and no BEFORE UPDATE trigger that would surface a
//     foreign-tenant UPDATE as a column drift (the trigger rejects every
//     UPDATE outright), so the bystander assertion compares every
//     business column directly — error_summary, error_code, worker_id,
//     attempt_number, started_at, finished_at, status, created_at — and
//     any rewrite would surface here.
//   - Append(orgA) per-tenant row-count invariant: orgB's per-org count
//     and orgA's per-org count change as expected (+1 for the writer,
//     unchanged for the bystander) — neither lower (an accidental
//     cross-tenant DELETE) nor higher (an accidental cross-tenant
//     INSERT) on the bystander.
//   - Same (job_id, attempt_number) in two tenants both persist:
//     UNIQUE (organization_id, job_id, attempt_number) is per-tenant —
//     two tenants each holding an attempt_number = 1 against THEIR OWN
//     job is the expected concurrent shape. This is the load-bearing
//     positive-direction pair: without it, a regression that resolved
//     a phantom UNIQUE on (job_id, attempt_number) alone would prevent
//     orgA's Append and every byte-identical bystander assertion above
//     would silently pass against an unmutated row that was never
//     written. The per-tenant ListByJob round-trip is the read-side
//     proof of the same shape.
//   - GetByID(orgB, alphaAttempt.ID) cross-tenant rejection: the call
//     returns a typed apierr.NotFound and the not-found payload names
//     only the attempt id the caller already supplied — never a
//     foreign worker_id, request_id, correlation_id, error_summary,
//     or error_code.
//   - ListByJob(orgB, alphaAttempt.JobID) cross-tenant empty:
//     returns an empty slice and the per-tenant COUNT(*) is unaffected
//     — the response never leaks a total-rows hint from another
//     tenant and the read itself has no side effect on the underlying
//     table.
//   - provisioning_jobs DELETE cascade is tenant-scoped: deleting
//     orgA's parent job removes only orgA's attempts and every orgB
//     attempt is byte-identical to its baseline. A regression that
//     widened the composite ON DELETE CASCADE to cascade by id alone
//     would surface here as an orgB row vanishing.
//   - organizations DELETE cascade is tenant-scoped: deleting orgA
//     removes only orgA's job_attempts and every orgB row is
//     byte-identical to its baseline. A regression that dropped the
//     organization_id leg of either the organizations FK or the
//     composite FK to provisioning_jobs would surface here as either
//     an orgB row vanishing or its business columns drifting.
//
// What this file deliberately delegates:
//
//   - The composite-FK cross-tenant-parent Append path (an attempt
//     whose job_id belongs to another tenant) is already pinned by
//     job_attempt_repository_invariants_test.go's
//     TestJobAttemptRepositoryAppendCrossTenantJobIsConflict as a
//     typed apierr.Conflict; rerunning it here would duplicate
//     coverage without adding a bystander byte-identity proof the
//     existing test does not need.
//   - The closed-set status CHECK, the attempt_number positivity
//     CHECK, the finished_at >= started_at CHECK, the append-only
//     enforcement trigger, the duplicate-(job_id, attempt_number)
//     Conflict, the duplicate-id Conflict, the application-level
//     validation matrix, the nil-Tx Internal rejection, the
//     transaction-rollback-persists-no-row probe, the error_summary
//     redaction backstop, and the same-tenant cascade tests are
//     pinned by job_attempt_repository_invariants_test.go.
//   - The HTTP envelope shape (yalla.output.v1 / yalla.error.v1) is a
//     transport-layer concern; the repository surface returns typed
//     apierr values and the HTTP layer's contract tests render the
//     envelope. Cross-tenant repository tests assert the typed
//     apierr code only.
//   - job_attempts stores NO secret-bearing column verbatim —
//     error_summary is run through the output redactor by the
//     JobAttemptRepository before persistence, and no other column
//     stores tokens, API keys, cookies or rendered environment
//     variable values — so the BE-0434-style raw-secret probe has
//     no analogue here. Per the BE-0464 acceptance criteria,
//     secrets, tokens, API keys, cookies and rendered environment
//     variable values would be redacted; the job_attempts table
//     simply does not carry any.
//
// Database-backed cases run against an isolated, freshly migrated
// Postgres and skip when YALLA_TEST_DATABASE_URL is unset.

// assertJobAttemptByteIdentical asserts every observable column on a
// bystander job_attempts row is byte-identical to its baseline. job_attempts
// has no updated_at and no version column — the BEFORE UPDATE trigger on
// the table rejects every update outright, so a foreign-tenant UPDATE
// would surface here as either a constraint-error-induced rollback (no
// row drift to observe) or, if the trigger were silently dropped, as a
// column rewrite the per-field comparison catches. Every business column
// is compared individually so a rewrite of any one would surface as a
// named field diff in the failure message.
func assertJobAttemptByteIdentical(t *testing.T, label string, baseline, after rawJobAttemptRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: bystander.id = %q, want %q", label, after.ID, baseline.ID)
	}
	if after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander.organization_id = %q, want %q",
			label, after.OrganizationID, baseline.OrganizationID)
	}
	if after.JobID != baseline.JobID {
		t.Errorf("%s: bystander.job_id = %q, want %q",
			label, after.JobID, baseline.JobID)
	}
	if after.AttemptNumber != baseline.AttemptNumber {
		t.Errorf("%s: bystander.attempt_number = %d, want %d — a foreign-tenant Append silently rewrote the attempt number",
			label, after.AttemptNumber, baseline.AttemptNumber)
	}
	if after.WorkerID != baseline.WorkerID {
		t.Errorf("%s: bystander.worker_id = %q, want %q",
			label, after.WorkerID, baseline.WorkerID)
	}
	if after.Status != baseline.Status {
		t.Errorf("%s: bystander.status = %q, want %q — a foreign-tenant write crossed the organization_id predicate",
			label, after.Status, baseline.Status)
	}
	if after.ErrorSummary != baseline.ErrorSummary {
		t.Errorf("%s: bystander.error_summary = %q, want %q",
			label, after.ErrorSummary, baseline.ErrorSummary)
	}
	if after.ErrorCode != baseline.ErrorCode {
		t.Errorf("%s: bystander.error_code = %q, want %q",
			label, after.ErrorCode, baseline.ErrorCode)
	}
	if after.RequestID != baseline.RequestID {
		t.Errorf("%s: bystander.request_id = %q, want %q",
			label, after.RequestID, baseline.RequestID)
	}
	if after.CorrelationID != baseline.CorrelationID {
		t.Errorf("%s: bystander.correlation_id = %q, want %q",
			label, after.CorrelationID, baseline.CorrelationID)
	}
	if !after.StartedAt.Equal(baseline.StartedAt) {
		t.Errorf("%s: bystander.started_at = %v, want %v",
			label, after.StartedAt, baseline.StartedAt)
	}
	if !after.FinishedAt.Equal(baseline.FinishedAt) {
		t.Errorf("%s: bystander.finished_at = %v, want %v",
			label, after.FinishedAt, baseline.FinishedAt)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v — created_at drifted on a bystander row, which means an UPDATE crossed the BEFORE UPDATE rejection trigger",
			label, after.CreatedAt, baseline.CreatedAt)
	}
}

// twoTenantJobAttemptFixture pairs orgA and orgB hierarchies and their
// parent provisioning_jobs row so per-test bodies focus on the
// cross-tenant invariant rather than the boilerplate of minting two
// independent (org -> project -> job) chains. The per-file JAtt suffix is
// mandatory: every *_test.go file under internal/controlplane/store/
// shares the same store_test package, and the parallel
// twoTenantJobFixture / twoTenantDeploymentFixture / etc. already exist.
type twoTenantJobAttemptFixture struct {
	orgA  testutil.Organization
	projA testutil.Project
	jobA  store.ProvisioningJob
	orgB  testutil.Organization
	projB testutil.Project
	jobB  store.ProvisioningJob
}

func seedTwoTenantJobAttemptFixture(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	f *testutil.Factory,
	s *store.Store,
	jobRepo *store.JobRepository,
) twoTenantJobAttemptFixture {
	t.Helper()
	orgA := seedOrg(t, db, f, "tenant-a")
	projA := seedProject(t, db, f, orgA, "api")
	jobA := seedQueuedJob(ctx, t, s, jobRepo, orgA, projA, "parent_a")

	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "api")
	jobB := seedQueuedJob(ctx, t, s, jobRepo, orgB, projB, "parent_b")

	return twoTenantJobAttemptFixture{
		orgA: orgA, projA: projA, jobA: jobA,
		orgB: orgB, projB: projB, jobB: jobB,
	}
}

// countJobAttemptRowsForOrg returns the total number of job_attempts rows
// owned by organizationID, across every parent job. The invariants file
// only exposes a per-(org, job) counter; this per-org total is the
// "did a cross-tenant cascade or read leak into the bystander tenant?"
// probe the tenant-isolation pattern requires.
func countJobAttemptRowsForOrg(
	ctx context.Context,
	t *testing.T,
	db *testutil.DB,
	organizationID string,
) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM job_attempts WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		t.Fatalf("count job_attempts for org %q: %v", organizationID, err)
	}
	return n
}

// TestJobAttemptRepositoryAppendOnOrgADoesNotTouchOrgB proves the
// load-bearing cross-tenant invariant of Append: when orgB already owns
// several job_attempts rows (a succeeded attempt, a failed attempt, and an
// attempt whose attempt_number deliberately collides with the number orgA
// is about to use) an Append on orgA mints a fresh row owned by orgA and
// leaves every observable column on every orgB row byte-identical to its
// baseline. job_attempts is append-only with the BEFORE UPDATE trigger
// rejecting any mutation, so a foreign-tenant UPDATE that snuck past the
// trigger would surface here as a column rewrite or a created_at drift on
// any bystander.
func TestJobAttemptRepositoryAppendOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobAttemptFixture(ctx, t, db, f, s, jobRepo)

	base := time.Now().UTC().Truncate(time.Microsecond)
	// orgB owns three peer rows: a succeeded attempt, a failed attempt
	// carrying a distinctive error_summary and error_code, and an attempt
	// whose attempt_number collides with the number orgA is about to use
	// — the load-bearing peer for "UNIQUE (organization_id, job_id,
	// attempt_number) is per-tenant".
	bravoSucceeded := seedJobAttempt(ctx, t, s, attemptRepo, fix.orgB, fix.jobB, "bravo_ok", 1,
		store.JobAttemptStatusSucceeded, base)
	bravoFailed := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		ID:             mintJobAttemptID(t, "bravo_fail"),
		OrganizationID: fix.orgB.ID,
		JobID:          fix.jobB.ID,
		AttemptNumber:  2,
		WorkerID:       "worker_bravo_fail",
		Status:         store.JobAttemptStatusFailed,
		ErrorSummary:   "bravo distinctive summary",
		ErrorCode:      "BRAVO_DISTINCTIVE_CODE",
		RequestID:      "req_bravo_fail",
		CorrelationID:  "cor_bravo_fail",
		StartedAt:      base.Add(time.Second),
		FinishedAt:     base.Add(2 * time.Second),
	})
	bravoCollide := seedJobAttempt(ctx, t, s, attemptRepo, fix.orgB, fix.jobB, "bravo_collide", 3,
		store.JobAttemptStatusSucceeded, base.Add(3*time.Second))

	baselineSucceeded := loadJobAttemptRowByID(ctx, t, db, bravoSucceeded.ID)
	baselineFailed := loadJobAttemptRowByID(ctx, t, db, bravoFailed.ID)
	baselineCollide := loadJobAttemptRowByID(ctx, t, db, bravoCollide.ID)

	// orgA appends an attempt under ITS OWN job, with attempt_number=3
	// — the same number bravoCollide already holds against orgB's job.
	// UNIQUE (organization_id, job_id, attempt_number) is per-tenant, so
	// the INSERT must mint a fresh row owned by orgA — never UPDATE
	// orgB's collide row.
	created := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		ID:             mintJobAttemptID(t, "alpha"),
		OrganizationID: fix.orgA.ID,
		JobID:          fix.jobA.ID,
		AttemptNumber:  3,
		WorkerID:       "worker_alpha",
		Status:         store.JobAttemptStatusSucceeded,
		RequestID:      "req_alpha",
		CorrelationID:  "cor_alpha",
		StartedAt:      base.Add(4 * time.Second),
		FinishedAt:     base.Add(5 * time.Second),
	})
	if created.OrganizationID != fix.orgA.ID {
		t.Fatalf("Append lifted organization_id = %q, want %q (orgA's Append was attributed to the wrong tenant)",
			created.OrganizationID, fix.orgA.ID)
	}
	if created.ID == bravoCollide.ID {
		t.Fatalf("Append returned orgB's attempt id %q — the INSERT silently UPDATEd orgB's row instead of minting a fresh row for orgA",
			created.ID)
	}

	assertJobAttemptByteIdentical(t,
		"orgB succeeded bystander after orgA Append",
		baselineSucceeded, loadJobAttemptRowByID(ctx, t, db, bravoSucceeded.ID))
	assertJobAttemptByteIdentical(t,
		"orgB failed bystander (distinctive error_summary/error_code) after orgA Append",
		baselineFailed, loadJobAttemptRowByID(ctx, t, db, bravoFailed.ID))
	assertJobAttemptByteIdentical(t,
		"orgB attempt_number-collide bystander after orgA Append",
		baselineCollide, loadJobAttemptRowByID(ctx, t, db, bravoCollide.ID))
}

// TestJobAttemptRepositoryAppendOnOrgADoesNotChangeOrgBRowCount proves the
// per-tenant row count is invariant under another tenant's Append. orgB
// owns two attempts before orgA makes any call; orgA then appends one.
// orgB's count must remain at 2 — neither lower (an accidental cross-tenant
// DELETE) nor higher (an accidental cross-tenant INSERT). orgA's count
// goes from 0 to 1. This complements the byte-identity bystander proof
// above: a regression that silently dropped one orgB row and minted a new
// one with the same content would defeat the byte-identity test but trip
// here.
func TestJobAttemptRepositoryAppendOnOrgADoesNotChangeOrgBRowCount(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobAttemptFixture(ctx, t, db, f, s, jobRepo)
	base := time.Now().UTC().Truncate(time.Microsecond)

	_ = seedJobAttempt(ctx, t, s, attemptRepo, fix.orgB, fix.jobB, "count_a", 1,
		store.JobAttemptStatusSucceeded, base)
	_ = seedJobAttempt(ctx, t, s, attemptRepo, fix.orgB, fix.jobB, "count_b", 2,
		store.JobAttemptStatusFailed, base.Add(time.Second))

	if n := countJobAttemptRowsForOrg(ctx, t, db, fix.orgB.ID); n != 2 {
		t.Fatalf("baseline orgB count = %d, want 2 — test fixture is invalid", n)
	}
	if n := countJobAttemptRowsForOrg(ctx, t, db, fix.orgA.ID); n != 0 {
		t.Fatalf("baseline orgA count = %d, want 0 — test fixture is invalid", n)
	}

	_ = seedJobAttempt(ctx, t, s, attemptRepo, fix.orgA, fix.jobA, "alpha", 1,
		store.JobAttemptStatusSucceeded, base.Add(2*time.Second))

	if n := countJobAttemptRowsForOrg(ctx, t, db, fix.orgB.ID); n != 2 {
		t.Errorf("orgB count after Append(orgA, ...) = %d, want 2 — orgA's Append touched orgB", n)
	}
	if n := countJobAttemptRowsForOrg(ctx, t, db, fix.orgA.ID); n != 1 {
		t.Errorf("orgA count after Append(orgA, ...) = %d, want 1 — orgA's Append did not land", n)
	}
}

// TestJobAttemptRepositoryAppendSameAttemptNumberInTwoTenantsBothPersist is
// the load-bearing positive-direction pair for the bystander byte-identity
// proofs. UNIQUE (organization_id, job_id, attempt_number) is per-tenant —
// there is no UNIQUE constraint on (job_id, attempt_number) alone — so two
// tenants each holding an attempt against THEIR OWN job with the same
// attempt_number is the expected concurrent shape. Without this test, a
// regression that resolved a phantom UNIQUE on (job_id, attempt_number)
// alone would prevent orgA's Append (the parent FK already disallows a
// cross-tenant (organization_id, job_id) tuple, so the regression would
// surface as a duplicate-row Conflict) and every byte-identical assertion
// in the bystander tests would silently pass against an unmutated row
// that was never written. The per-tenant ListByJob round-trip is the
// read-side proof of the same shape: the same attempt_number must resolve
// to the per-tenant row, never cross-tenant.
func TestJobAttemptRepositoryAppendSameAttemptNumberInTwoTenantsBothPersist(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobAttemptFixture(ctx, t, db, f, s, jobRepo)

	base := time.Now().UTC().Truncate(time.Microsecond)

	bravo := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		ID:             mintJobAttemptID(t, "bravo"),
		OrganizationID: fix.orgB.ID,
		JobID:          fix.jobB.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_bravo",
		Status:         store.JobAttemptStatusSucceeded,
		RequestID:      "req_bravo",
		CorrelationID:  "cor_bravo",
		StartedAt:      base,
		FinishedAt:     base.Add(time.Second),
	})
	alpha := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		ID:             mintJobAttemptID(t, "alpha"),
		OrganizationID: fix.orgA.ID,
		JobID:          fix.jobA.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_alpha",
		Status:         store.JobAttemptStatusSucceeded,
		RequestID:      "req_alpha",
		CorrelationID:  "cor_alpha",
		StartedAt:      base,
		FinishedAt:     base.Add(time.Second),
	})

	if alpha.OrganizationID != fix.orgA.ID {
		t.Errorf("alpha.OrganizationID = %q, want %q", alpha.OrganizationID, fix.orgA.ID)
	}
	if bravo.OrganizationID != fix.orgB.ID {
		t.Errorf("bravo.OrganizationID = %q, want %q", bravo.OrganizationID, fix.orgB.ID)
	}
	if alpha.ID == bravo.ID {
		t.Errorf("alpha.ID == bravo.ID (= %q): the two tenants must hold distinct attempt ids even with a shared attempt_number against their respective jobs",
			alpha.ID)
	}
	if alpha.AttemptNumber != 1 || bravo.AttemptNumber != 1 {
		t.Errorf("alpha.AttemptNumber=%d bravo.AttemptNumber=%d, want both 1",
			alpha.AttemptNumber, bravo.AttemptNumber)
	}

	// ListByJob must resolve each tenant's attempts to that tenant's
	// list only — never cross-tenant. This is the read-side proof of
	// the positive-direction shape.
	alphaList, err := attemptRepo.ListByJob(ctx, db, fix.orgA.ID, fix.jobA.ID)
	if err != nil {
		t.Fatalf("ListByJob(orgA, jobA): %v", err)
	}
	if len(alphaList) != 1 || alphaList[0].ID != alpha.ID {
		t.Errorf("ListByJob(orgA, jobA) = %d rows (first id %q), want 1 row with id %q",
			len(alphaList), firstAttemptID(alphaList), alpha.ID)
	}
	bravoList, err := attemptRepo.ListByJob(ctx, db, fix.orgB.ID, fix.jobB.ID)
	if err != nil {
		t.Fatalf("ListByJob(orgB, jobB): %v", err)
	}
	if len(bravoList) != 1 || bravoList[0].ID != bravo.ID {
		t.Errorf("ListByJob(orgB, jobB) = %d rows (first id %q), want 1 row with id %q",
			len(bravoList), firstAttemptID(bravoList), bravo.ID)
	}
}

// firstAttemptID returns the id of the first element of out (or "<empty>"
// when the slice is empty) so the parent test's diff messages can name
// which row was actually returned. This is the same shape every read-back
// list assertion in the repository test files uses informally; centralising
// it here keeps the per-test bodies focused on the assertion.
func firstAttemptID(out []store.JobAttempt) string {
	if len(out) == 0 {
		return "<empty>"
	}
	return out[0].ID
}

// TestJobAttemptRepositoryGetByIDCrossTenantDoesNotEcho proves
// GetByID(orgB, alphaAttempt.ID) is tenant-scoped at the SQL predicate AND
// that the not-found payload names only the attempt id the caller already
// supplied — never a foreign worker_id, request_id, correlation_id,
// error_summary, or error_code. A regression that resolved the composite
// (organization_id, id) by id alone would either return orgA's row
// (defeated by the assertion on the typed apierr.NotFound code) OR would
// attach orgA's foreign fields to the not-found details (defeated by the
// explicit no-leak substring checks below).
//
// This is the gap-fill:
// job_attempt_repository_invariants_test.go's
// TestJobAttemptRepositoryGetByIDCrossTenantReturnsNotFound already asserts
// the typed NotFound code but does NOT pin the no-leak-substring invariant
// the tenant-isolation pattern requires.
func TestJobAttemptRepositoryGetByIDCrossTenantDoesNotEcho(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobAttemptFixture(ctx, t, db, f, s, jobRepo)

	base := time.Now().UTC().Truncate(time.Microsecond)
	// alpha owns an attempt with deliberately distinctive
	// worker_id / request_id / correlation_id / error_summary / error_code
	// suffixes — if a regression echoed any of them into the not-found
	// payload, the substring checks below would trip.
	alpha := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		ID:             mintJobAttemptID(t, "alpha"),
		OrganizationID: fix.orgA.ID,
		JobID:          fix.jobA.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_no_echo_distinctive_alpha_worker",
		Status:         store.JobAttemptStatusFailed,
		ErrorSummary:   "no_echo_distinctive_alpha_summary",
		ErrorCode:      "NO_ECHO_DISTINCTIVE_ALPHA_CODE",
		RequestID:      "req_no_echo_distinctive_alpha_req",
		CorrelationID:  "cor_no_echo_distinctive_alpha_cor",
		StartedAt:      base,
		FinishedAt:     base.Add(time.Second),
	})

	_, err := attemptRepo.GetByID(ctx, db, fix.orgB.ID, alpha.ID)
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(cross-tenant) error = %v, want code %s (a cross-tenant id must surface as NotFound, never a successful read of another tenant's row)",
			err, yerr.CodeNotFound)
	}
	msg := err.Error()
	if containsValue(msg, "no_echo_distinctive_alpha_worker") {
		t.Errorf("GetByID(cross-tenant) error message %q echoed alpha's worker_id — the not-found payload must name only the supplied id", msg)
	}
	if containsValue(msg, "no_echo_distinctive_alpha_summary") {
		t.Errorf("GetByID(cross-tenant) error message %q echoed alpha's error_summary — the not-found payload must name only the supplied id", msg)
	}
	if containsValue(msg, "NO_ECHO_DISTINCTIVE_ALPHA_CODE") {
		t.Errorf("GetByID(cross-tenant) error message %q echoed alpha's error_code — the not-found payload must name only the supplied id", msg)
	}
	if containsValue(msg, "no_echo_distinctive_alpha_req") {
		t.Errorf("GetByID(cross-tenant) error message %q echoed alpha's request_id — the not-found payload must name only the supplied id", msg)
	}
	if containsValue(msg, "no_echo_distinctive_alpha_cor") {
		t.Errorf("GetByID(cross-tenant) error message %q echoed alpha's correlation_id — the not-found payload must name only the supplied id", msg)
	}
	if containsValue(msg, fix.jobA.ID) {
		t.Errorf("GetByID(cross-tenant) error message %q echoed alpha's job_id — the not-found payload must name only the supplied attempt id", msg)
	}
}

// TestJobAttemptRepositoryListByJobCrossTenantReturnsEmptyAndDoesNotLeakTotal
// proves ListByJob(orgB, alphaJob.ID) returns an empty slice AND the
// per-tenant COUNT(*) for both orgA and orgB is unaffected — no count is
// leaked through the response shape or through a side effect on the
// underlying table. The acceptance criterion "List queries return stable
// pagination without leaking total counts from other tenants" is pinned
// here: the response carries no total-count field and the foreign-tenant
// query returns zero rows even when the underlying organization owns
// several attempts.
//
// This is the gap-fill:
// job_attempt_repository_invariants_test.go's
// TestJobAttemptRepositoryListByJobCrossTenantReturnsEmpty already proves
// orgB's list does not surface orgA's rows, but does NOT pin the
// side-effect-free read invariant or the per-tenant COUNT(*) invariance
// under a foreign tenant's List call.
func TestJobAttemptRepositoryListByJobCrossTenantReturnsEmptyAndDoesNotLeakTotal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobAttemptFixture(ctx, t, db, f, s, jobRepo)
	base := time.Now().UTC().Truncate(time.Microsecond)

	_ = seedJobAttempt(ctx, t, s, attemptRepo, fix.orgA, fix.jobA, "la1", 1,
		store.JobAttemptStatusFailed, base)
	_ = seedJobAttempt(ctx, t, s, attemptRepo, fix.orgA, fix.jobA, "la2", 2,
		store.JobAttemptStatusFailed, base.Add(time.Second))
	_ = seedJobAttempt(ctx, t, s, attemptRepo, fix.orgA, fix.jobA, "la3", 3,
		store.JobAttemptStatusSucceeded, base.Add(2*time.Second))

	baselineCountA := countJobAttemptRowsForOrg(ctx, t, db, fix.orgA.ID)
	if baselineCountA != 3 {
		t.Fatalf("baseline orgA count = %d, want 3 — test fixture is invalid", baselineCountA)
	}
	baselineCountB := countJobAttemptRowsForOrg(ctx, t, db, fix.orgB.ID)
	if baselineCountB != 0 {
		t.Fatalf("baseline orgB count = %d, want 0 — test fixture is invalid", baselineCountB)
	}

	// orgB queries orgA's job — the (organization_id, job_id) predicate
	// matches no row, so the empty slice is returned. The lookup is
	// never an oracle that reveals orgA's attempt history.
	list, err := attemptRepo.ListByJob(ctx, db, fix.orgB.ID, fix.jobA.ID)
	if err != nil {
		t.Fatalf("ListByJob(cross-tenant): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("ListByJob(cross-tenant) returned %d rows, want 0 (alpha's attempts must not leak through bravo's predicate)", len(list))
	}

	// Reading must not have side-effected the underlying counts.
	if n := countJobAttemptRowsForOrg(ctx, t, db, fix.orgA.ID); n != baselineCountA {
		t.Errorf("orgA count after cross-tenant List = %d, want %d (a read leaked into a write)", n, baselineCountA)
	}
	if n := countJobAttemptRowsForOrg(ctx, t, db, fix.orgB.ID); n != baselineCountB {
		t.Errorf("orgB count after cross-tenant List = %d, want %d (a read leaked into a write)", n, baselineCountB)
	}
}

// TestJobAttemptParentJobDeleteCascadeIsTenantScoped proves deleting
// orgA's parent provisioning_jobs row cascades only to orgA's
// job_attempts. orgB's attempts (under orgB's own parent job) must remain
// byte-identical to their baseline. The composite ON DELETE CASCADE on
// (organization_id, job_id) confines the cleanup to attempts whose parent
// is the deleted row; a regression that widened the cascade predicate to
// id alone would surface here as an orgB attempt vanishing.
//
// The same-tenant cascade (deleting a job removes its own attempts) is
// already pinned by
// job_attempt_repository_invariants_test.go's
// TestJobAttemptRepositoryAppendCascadesFromJobDelete; this is the
// cross-tenant variant the tenant-isolation pattern requires.
func TestJobAttemptParentJobDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobAttemptFixture(ctx, t, db, f, s, jobRepo)
	base := time.Now().UTC().Truncate(time.Microsecond)

	// orgA owns two attempts (cascaded away). orgB owns two attempts
	// (survive byte-identically) — one failed (so error_summary /
	// error_code are non-empty anchors the bystander assertion can pin)
	// and one succeeded.
	_ = seedJobAttempt(ctx, t, s, attemptRepo, fix.orgA, fix.jobA, "alpha1", 1,
		store.JobAttemptStatusFailed, base)
	_ = seedJobAttempt(ctx, t, s, attemptRepo, fix.orgA, fix.jobA, "alpha2", 2,
		store.JobAttemptStatusSucceeded, base.Add(time.Second))

	bravoFailed := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		ID:             mintJobAttemptID(t, "bravo_fail"),
		OrganizationID: fix.orgB.ID,
		JobID:          fix.jobB.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_bravo_fail",
		Status:         store.JobAttemptStatusFailed,
		ErrorSummary:   "bravo distinctive summary",
		ErrorCode:      "BRAVO_DISTINCTIVE_CODE",
		RequestID:      "req_bravo_fail",
		CorrelationID:  "cor_bravo_fail",
		StartedAt:      base,
		FinishedAt:     base.Add(time.Second),
	})
	bravoSucceeded := seedJobAttempt(ctx, t, s, attemptRepo, fix.orgB, fix.jobB, "bravo_ok", 2,
		store.JobAttemptStatusSucceeded, base.Add(2*time.Second))

	baselineFailed := loadJobAttemptRowByID(ctx, t, db, bravoFailed.ID)
	baselineSucceeded := loadJobAttemptRowByID(ctx, t, db, bravoSucceeded.ID)

	if _, err := db.Exec(ctx,
		`DELETE FROM provisioning_jobs WHERE organization_id = $1 AND id = $2`,
		fix.orgA.ID, fix.jobA.ID); err != nil {
		t.Fatalf("delete orgA parent job: %v", err)
	}

	if got := countJobAttemptRowsForJob(ctx, t, db, fix.orgA.ID, fix.jobA.ID); got != 0 {
		t.Errorf("post-cascade orgA attempt count = %d, want 0 (cascade must remove the deleted job's attempts)", got)
	}
	if got := countJobAttemptRowsForJob(ctx, t, db, fix.orgB.ID, fix.jobB.ID); got != 2 {
		t.Errorf("post-cascade orgB attempt count = %d, want 2 — the cascade bled into another tenant", got)
	}

	assertJobAttemptByteIdentical(t,
		"orgB failed bystander survives orgA parent-job delete",
		baselineFailed, loadJobAttemptRowByID(ctx, t, db, bravoFailed.ID))
	assertJobAttemptByteIdentical(t,
		"orgB succeeded bystander survives orgA parent-job delete",
		baselineSucceeded, loadJobAttemptRowByID(ctx, t, db, bravoSucceeded.ID))
}

// TestJobAttemptOrganizationDeleteCascadeIsTenantScoped proves orgA's
// deletion cascades only to orgA's job_attempts. orgB's attempts must
// remain byte-identical to their baseline. The
// job_attempts.organization_id FK CASCADE on organizations(id) and the
// composite (organization_id, job_id) FK on provisioning_jobs both
// participate in the cascade chain; a regression that dropped the
// organization_id leg of either FK would surface here as either an orgB
// row vanishing or its business columns drifting.
//
// The same-tenant cascade (deleting an organization removes its own
// attempts) is already pinned by
// job_attempt_repository_invariants_test.go's
// TestJobAttemptRepositoryAppendCascadesFromOrganizationDelete; this is
// the cross-tenant variant the tenant-isolation pattern requires.
func TestJobAttemptOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	jobRepo := store.NewJobRepository()
	attemptRepo := store.NewJobAttemptRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantJobAttemptFixture(ctx, t, db, f, s, jobRepo)
	base := time.Now().UTC().Truncate(time.Microsecond)

	_ = seedJobAttempt(ctx, t, s, attemptRepo, fix.orgA, fix.jobA, "alpha_ok", 1,
		store.JobAttemptStatusSucceeded, base)
	_ = seedJobAttempt(ctx, t, s, attemptRepo, fix.orgA, fix.jobA, "alpha_fail", 2,
		store.JobAttemptStatusFailed, base.Add(time.Second))

	bravoFailed := runAppendJobAttemptOrFail(ctx, t, s, attemptRepo, store.JobAttempt{
		ID:             mintJobAttemptID(t, "bravo_fail"),
		OrganizationID: fix.orgB.ID,
		JobID:          fix.jobB.ID,
		AttemptNumber:  1,
		WorkerID:       "worker_bravo_fail",
		Status:         store.JobAttemptStatusFailed,
		ErrorSummary:   "bravo distinctive summary",
		ErrorCode:      "BRAVO_DISTINCTIVE_CODE",
		RequestID:      "req_bravo_fail",
		CorrelationID:  "cor_bravo_fail",
		StartedAt:      base,
		FinishedAt:     base.Add(time.Second),
	})
	bravoSucceeded := seedJobAttempt(ctx, t, s, attemptRepo, fix.orgB, fix.jobB, "bravo_ok", 2,
		store.JobAttemptStatusSucceeded, base.Add(2*time.Second))
	bravoTimedOut := seedJobAttempt(ctx, t, s, attemptRepo, fix.orgB, fix.jobB, "bravo_to", 3,
		store.JobAttemptStatusTimedOut, base.Add(3*time.Second))

	baselineFailed := loadJobAttemptRowByID(ctx, t, db, bravoFailed.ID)
	baselineSucceeded := loadJobAttemptRowByID(ctx, t, db, bravoSucceeded.ID)
	baselineTimedOut := loadJobAttemptRowByID(ctx, t, db, bravoTimedOut.ID)

	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, fix.orgA.ID); err != nil {
		t.Fatalf("delete orgA: %v", err)
	}

	if n := countJobAttemptRowsForOrg(ctx, t, db, fix.orgA.ID); n != 0 {
		t.Errorf("job_attempts rows for orgA after delete = %d, want 0 (cascade must remove the deleted tenant's rows)", n)
	}
	if n := countJobAttemptRowsForOrg(ctx, t, db, fix.orgB.ID); n != 3 {
		t.Errorf("job_attempts rows for orgB after orgA delete = %d, want 3 — the cascade bled into another tenant", n)
	}

	assertJobAttemptByteIdentical(t,
		"orgB failed bystander survives orgA delete",
		baselineFailed, loadJobAttemptRowByID(ctx, t, db, bravoFailed.ID))
	assertJobAttemptByteIdentical(t,
		"orgB succeeded bystander survives orgA delete",
		baselineSucceeded, loadJobAttemptRowByID(ctx, t, db, bravoSucceeded.ID))
	assertJobAttemptByteIdentical(t,
		"orgB timed_out bystander survives orgA delete",
		baselineTimedOut, loadJobAttemptRowByID(ctx, t, db, bravoTimedOut.ID))
}
