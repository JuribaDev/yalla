package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the deployments table
// (BE-0458). deployments captures a customer's intent to deploy a single
// service through a closed-set source taxonomy plus an immutable
// caller-supplied source reference, an idempotency key the table
// disambiguates per-tenant, and a converged lifecycle status the worker
// writes as it observes the provisioning job. A row that belongs to one
// tenant is anchored to that tenant by:
//
//	(a) the organization_id column itself, with an
//	    ON DELETE CASCADE FK to organizations(id);
//	(b) composite foreign keys (organization_id, project_id),
//	    (organization_id, environment_id) and
//	    (organization_id, service_id) into the parent tables so a row
//	    whose parent ids do not match its organization_id is rejected
//	    at the database before it can be persisted; and
//	(c) every DeploymentRepository write/read (Insert, GetByID,
//	    FindByIdempotencyKey, Cancel, ListByService) going through the
//	    organization_id predicate as the non-optional left leg.
//
// The DeploymentRepository surface is intentionally narrow: Insert mints a
// new row inside a *Tx, GetByID/FindByIdempotencyKey/ListByService are
// read-only, and Cancel is the only state transition surface (queued |
// running -> cancelled). This file pins the cross-tenant invariants of
// every one of those surfaces and the cross-tenant invariant of the
// organizations cascade:
//
//   - Insert(orgA) cross-tenant bystander byte-identity: when orgB
//     already owns deployments rows (including a row with the SAME
//     idempotency_key, the SAME source_ref, and the SAME service_id
//     look-alike), an Insert on orgA must mint a fresh row owned by
//     orgA and leave every observable column on every orgB row
//     byte-identical to its baseline. The bump_version trigger and the
//     deployments_set_updated_at trigger are the load-bearing anchors:
//     a missing organization_id predicate that swept an orgB row
//     through an UPDATE would surface here as a version bump or an
//     updated_at drift even when the other columns happened to look
//     right.
//   - Insert(orgA) row-count invariant: orgB's row count is unchanged
//     and orgA's row count grows by exactly +1.
//   - Same-(idempotency_key, source_ref, service_id-looking)
//     deployments in two tenants both persist: UNIQUE
//     (organization_id, idempotency_key) is per-tenant — the same key
//     SHOULD be permitted in two tenants concurrently. This is the
//     load-bearing positive-direction pair: without it, a regression
//     that resolved a phantom UNIQUE on (idempotency_key) alone would
//     prevent orgA's INSERT and every byte-identical bystander
//     assertion above would silently pass against an unmutated row
//     that was never written.
//   - Cancel(orgB, alphaDep.ID) cross-tenant rejection: when orgB
//     calls Cancel against orgA's deployment_id, the call returns
//     NotFound (never an oracle that confirms the id exists in
//     another tenant), and every orgA bystander row is byte-identical
//     to its baseline. A regression that dropped the organization_id
//     predicate from the UPDATE would surface as a status drift
//     (queued -> cancelled), a stamped finished_at, or a bumped
//     version on alpha's row.
//   - GetByID(orgB, alphaDep.ID) cross-tenant rejection: NotFound,
//     never another tenant's row, and the not-found payload names
//     only the deployment_id the caller already supplied — never a
//     foreign source_ref, idempotency_key, or service_id.
//   - FindByIdempotencyKey(orgB, alphaDep.IdempotencyKey) cross-tenant
//     miss: returns (zero, false, nil) even when orgA owns a
//     deployment with that exact key. The key UNIQUE is per-tenant,
//     so a foreign key is structurally a miss.
//   - ListByService(orgB, alphaSvc.ID) cross-tenant empty: returns an
//     empty slice and the per-tenant COUNT(*) is unaffected — the
//     response never leaks a total-rows hint from another tenant.
//   - organizations DELETE cascade is tenant-scoped: deleting orgA
//     removes only orgA's deployments and every orgB row is
//     byte-identical to its baseline. A regression that targeted the
//     cascade by id alone (or that wired the FK to ON DELETE NO ACTION
//     and let the cleanup path widen the predicate) would surface
//     here as either an orgB row vanishing or its updated_at drifting.
//
// What this file deliberately delegates:
//
//   - Composite-FK cross-tenant-parent INSERT (a deployment whose
//     service_id belongs to another tenant) is covered by BE-0457's
//     TestDeploymentRepositoryInsertCrossTenantServiceReturnsConflict
//     in deployment_repository_invariants_test.go; that path is
//     already a typed apierr.Conflict at the database and rerunning
//     it here would duplicate coverage without adding a bystander
//     byte-identity proof the invariants file already implies.
//   - The lifecycle CHECK
//     (deployments_finished_consistent: terminal-status <-> finished_at)
//     and the closed-set source / status CHECK constraints are covered
//     by BE-0457 row-shape tests; cross-tenant probes do not need to
//     repeat them.
//   - The HTTP envelope shape (yalla.output.v1 / yalla.error.v1) is a
//     transport-layer concern; the repository surface returns typed
//     apierr values and the HTTP layer's contract tests render the
//     envelope. Cross-tenant repository tests assert the typed apierr
//     code only.
//   - The deployments table stores NO secret-bearing column —
//     source_ref is a branch / commit / tag / image name and
//     error_message is written through the output redactor by the
//     worker before persistence — so the BE-0434-style raw-secret
//     probe has no analogue here. Per the BE-0458 acceptance criteria,
//     secrets, tokens, API keys, cookies and rendered environment
//     variable values would be redacted; the deployments table simply
//     does not carry any.
//
// Database-backed cases run against an isolated, freshly migrated
// Postgres and skip when YALLA_TEST_DATABASE_URL is unset.

// timePtrEqualDep compares nullable timestamp columns observed in
// rawDeploymentRow (started_at, finished_at — both timestamptz). The
// per-file Dep suffix is mandatory: every *_test.go file under
// internal/controlplane/store/ shares the same package, and other tenant-
// isolation files already export QP / QR / "" variants of the same name —
// collisions would block compilation. rawDeploymentRow has no nullable
// string columns, so no stringPtrEqualDep helper is needed.
func timePtrEqualDep(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// fmtTimePtrDep renders a nullable timestamp column for error messages so
// a missing vs zero distinction is obvious.
func fmtTimePtrDep(p *time.Time) string {
	if p == nil {
		return "<nil>"
	}
	return p.Format(time.RFC3339Nano)
}

// assertDeploymentByteIdentical asserts every observable column on a
// bystander deployments row is byte-identical to its baseline. The
// trigger-managed updated_at column is the load-bearing anchor: the BEFORE
// UPDATE deployments_set_updated_at trigger refreshes it on every matched
// UPDATE, and the bump_version trigger increments version on the same
// UPDATE — so a missing organization_id predicate in Insert, Cancel or
// the cascade would surface here either as an updated_at drift or a
// bumped version even if every other column happened to look right.
func assertDeploymentByteIdentical(t *testing.T, label string, baseline, after rawDeploymentRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: bystander.id = %q, want %q", label, after.ID, baseline.ID)
	}
	if after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander.organization_id = %q, want %q",
			label, after.OrganizationID, baseline.OrganizationID)
	}
	if after.ProjectID != baseline.ProjectID {
		t.Errorf("%s: bystander.project_id = %q, want %q",
			label, after.ProjectID, baseline.ProjectID)
	}
	if after.EnvironmentID != baseline.EnvironmentID {
		t.Errorf("%s: bystander.environment_id = %q, want %q",
			label, after.EnvironmentID, baseline.EnvironmentID)
	}
	if after.ServiceID != baseline.ServiceID {
		t.Errorf("%s: bystander.service_id = %q, want %q",
			label, after.ServiceID, baseline.ServiceID)
	}
	if after.Source != baseline.Source {
		t.Errorf("%s: bystander.source = %q, want %q", label, after.Source, baseline.Source)
	}
	if after.SourceRef != baseline.SourceRef {
		t.Errorf("%s: bystander.source_ref = %q, want %q",
			label, after.SourceRef, baseline.SourceRef)
	}
	if after.Status != baseline.Status {
		t.Errorf("%s: bystander.status = %q, want %q", label, after.Status, baseline.Status)
	}
	if after.RequestedBy != baseline.RequestedBy {
		t.Errorf("%s: bystander.requested_by = %q, want %q",
			label, after.RequestedBy, baseline.RequestedBy)
	}
	if after.IdempotencyKey != baseline.IdempotencyKey {
		t.Errorf("%s: bystander.idempotency_key = %q, want %q",
			label, after.IdempotencyKey, baseline.IdempotencyKey)
	}
	if after.ErrorCode != baseline.ErrorCode {
		t.Errorf("%s: bystander.error_code = %q, want %q",
			label, after.ErrorCode, baseline.ErrorCode)
	}
	if after.ErrorMessage != baseline.ErrorMessage {
		t.Errorf("%s: bystander.error_message = %q, want %q",
			label, after.ErrorMessage, baseline.ErrorMessage)
	}
	if after.Version != baseline.Version {
		t.Errorf("%s: bystander.version = %d, want %d — the bump_version trigger fired on a peer tenant's row, which means an UPDATE silently crossed the organization_id predicate",
			label, after.Version, baseline.Version)
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
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE UPDATE deployments_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE silently crossed the organization_id predicate",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
	if !timePtrEqualDep(after.StartedAt, baseline.StartedAt) {
		t.Errorf("%s: bystander.started_at = %s, want %s",
			label, fmtTimePtrDep(after.StartedAt), fmtTimePtrDep(baseline.StartedAt))
	}
	if !timePtrEqualDep(after.FinishedAt, baseline.FinishedAt) {
		t.Errorf("%s: bystander.finished_at = %s, want %s",
			label, fmtTimePtrDep(after.FinishedAt), fmtTimePtrDep(baseline.FinishedAt))
	}
}

// twoTenantDeploymentFixture builds two completely-independent tenant
// hierarchies (orgA and orgB), each with its own project, environment
// and service. Every deployments test in this file needs both halves —
// keeping the construction in one helper keeps the per-test bodies
// focused on the cross-tenant invariant rather than the boilerplate of
// minting a second hierarchy.
type twoTenantDeploymentFixture struct {
	orgA  testutil.Organization
	projA testutil.Project
	envA  testutil.Environment
	svcA  testutil.Service
	orgB  testutil.Organization
	projB testutil.Project
	envB  testutil.Environment
	svcB  testutil.Service
}

func seedTwoTenantDeploymentFixture(t *testing.T, db *testutil.DB, f *testutil.Factory) twoTenantDeploymentFixture {
	t.Helper()
	orgA := seedOrg(t, db, f, "tenant-a")
	projA := seedProject(t, db, f, orgA, "api")
	envA := seedEnvironment(t, db, f, projA, "prod")
	svcA := seedService(t, db, f, envA, "web")

	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "api")
	envB := seedEnvironment(t, db, f, projB, "prod")
	svcB := seedService(t, db, f, envB, "web")

	return twoTenantDeploymentFixture{
		orgA: orgA, projA: projA, envA: envA, svcA: svcA,
		orgB: orgB, projB: projB, envB: envB, svcB: svcB,
	}
}

// TestDeploymentRepositoryInsertOnOrgADoesNotTouchOrgB proves the
// load-bearing cross-tenant invariant of Insert: when orgB owns
// several deployments rows — including a queued row, a running row,
// and a row with a deliberately recognisable idempotency_key — an
// Insert on orgA lands as a fresh row owned by orgA and leaves every
// observable column on every orgB row byte-identical to its baseline.
// A regression that swept an orgB row through a missing
// organization_id predicate would surface as a version bump, an
// updated_at drift, or a column rewrite on any bystander.
func TestDeploymentRepositoryInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentFixture(t, db, f)

	// orgB owns three peer rows: a queued row, a running row, and a row
	// whose idempotency_key collides with the key orgA is about to use
	// — the load-bearing peer. Recognisable suffixes make a regression
	// that silently rewrote a column surface immediately.
	bravoQueued := seedQueuedDeployment(ctx, t, s, repo, fix.orgB, fix.projB, fix.envB, fix.svcB, "bravo_queued")
	bravoRunning := seedRunningDeployment(ctx, t, s, repo, fix.orgB, fix.projB, fix.envB, fix.svcB, "bravo_running")
	bravoCollide := seedQueuedDeployment(ctx, t, s, repo, fix.orgB, fix.projB, fix.envB, fix.svcB, "collide")

	baselineQueued := loadDeploymentRowByID(ctx, t, db, bravoQueued.ID)
	baselineRunning := loadDeploymentRowByID(ctx, t, db, bravoRunning.ID)
	baselineCollide := loadDeploymentRowByID(ctx, t, db, bravoCollide.ID)

	// orgA inserts a deployment whose idempotency_key matches the
	// recognisable suffix orgB already holds. UNIQUE (organization_id,
	// idempotency_key) is per-tenant, so the INSERT must mint a fresh
	// row owned by orgA — never UPDATE orgB's collide row.
	created := runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             mintDeploymentID(t, "alpha"),
		OrganizationID: fix.orgA.ID,
		ProjectID:      fix.projA.ID,
		EnvironmentID:  fix.envA.ID,
		ServiceID:      fix.svcA.ID,
		Source:         store.DeploymentSourceGit,
		SourceRef:      "refs/heads/main@alpha",
		RequestedBy:    "usr_test_actor",
		IdempotencyKey: "idem_collide",
		RequestID:      "req_alpha",
		CorrelationID:  "cor_alpha",
	})
	if created.OrganizationID != fix.orgA.ID {
		t.Fatalf("Insert lifted organization_id = %q, want %q (orgA's Insert was attributed to the wrong tenant)",
			created.OrganizationID, fix.orgA.ID)
	}
	if created.ID == bravoCollide.ID {
		t.Fatalf("Insert returned orgB's deployment id %q — the INSERT silently UPDATEd orgB's row instead of minting a fresh row for orgA", created.ID)
	}

	afterQueued := loadDeploymentRowByID(ctx, t, db, bravoQueued.ID)
	assertDeploymentByteIdentical(t,
		"orgB queued bystander after orgA Insert",
		baselineQueued, afterQueued)

	afterRunning := loadDeploymentRowByID(ctx, t, db, bravoRunning.ID)
	assertDeploymentByteIdentical(t,
		"orgB running bystander after orgA Insert",
		baselineRunning, afterRunning)

	afterCollide := loadDeploymentRowByID(ctx, t, db, bravoCollide.ID)
	assertDeploymentByteIdentical(t,
		"orgB idempotency-key collide bystander after orgA Insert",
		baselineCollide, afterCollide)
}

// TestDeploymentRepositoryInsertOnOrgADoesNotChangeOrgBRowCount proves
// the per-tenant row count is invariant under another tenant's
// Insert. orgB owns two rows before orgA makes any call; orgA then
// inserts a row. orgB's count must remain at 2 — neither lower (an
// accidental cross-tenant DELETE) nor higher (an accidental
// cross-tenant INSERT). orgA's count goes from 0 to 1. This complements
// the byte-identity bystander proof above: a regression that
// silently dropped one orgB row and minted a new one with the same
// content would defeat the byte-identity test but trip here.
func TestDeploymentRepositoryInsertOnOrgADoesNotChangeOrgBRowCount(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentFixture(t, db, f)

	seedQueuedDeployment(ctx, t, s, repo, fix.orgB, fix.projB, fix.envB, fix.svcB, "count_a")
	seedRunningDeployment(ctx, t, s, repo, fix.orgB, fix.projB, fix.envB, fix.svcB, "count_b")

	if n := countDeploymentRowsForOrg(ctx, t, db, fix.orgB.ID); n != 2 {
		t.Fatalf("baseline orgB count = %d, want 2 — test fixture is invalid", n)
	}
	if n := countDeploymentRowsForOrg(ctx, t, db, fix.orgA.ID); n != 0 {
		t.Fatalf("baseline orgA count = %d, want 0 — test fixture is invalid", n)
	}

	seedQueuedDeployment(ctx, t, s, repo, fix.orgA, fix.projA, fix.envA, fix.svcA, "alpha")

	if n := countDeploymentRowsForOrg(ctx, t, db, fix.orgB.ID); n != 2 {
		t.Errorf("orgB count after Insert(orgA, ...) = %d, want 2 — orgA's Insert touched orgB", n)
	}
	if n := countDeploymentRowsForOrg(ctx, t, db, fix.orgA.ID); n != 1 {
		t.Errorf("orgA count after Insert(orgA, ...) = %d, want 1 — orgA's Insert did not land", n)
	}
}

// TestDeploymentRepositoryInsertSameIdempotencyKeyInTwoTenantsBothPersist
// is the load-bearing positive-direction pair for the bystander
// byte-identity proofs. UNIQUE (organization_id, idempotency_key) is
// per-tenant — there is no UNIQUE constraint on (idempotency_key) alone
// — so two tenants each holding a deployment with the same
// idempotency_key (and the same source_ref) is the expected concurrent
// shape. Without this test, a regression that resolved a phantom
// UNIQUE on (idempotency_key) alone would prevent orgA's Insert and
// every byte-identical assertion in the bystander tests would silently
// pass against an unmutated row that was never written.
func TestDeploymentRepositoryInsertSameIdempotencyKeyInTwoTenantsBothPersist(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentFixture(t, db, f)

	const sharedKey = "idem_shared_across_tenants"
	const sharedRef = "refs/heads/main@shared"

	bravo := runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             mintDeploymentID(t, "bravo"),
		OrganizationID: fix.orgB.ID,
		ProjectID:      fix.projB.ID,
		EnvironmentID:  fix.envB.ID,
		ServiceID:      fix.svcB.ID,
		Source:         store.DeploymentSourceGit,
		SourceRef:      sharedRef,
		RequestedBy:    "usr_test_actor",
		IdempotencyKey: sharedKey,
		RequestID:      "req_bravo",
		CorrelationID:  "cor_bravo",
	})
	alpha := runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             mintDeploymentID(t, "alpha"),
		OrganizationID: fix.orgA.ID,
		ProjectID:      fix.projA.ID,
		EnvironmentID:  fix.envA.ID,
		ServiceID:      fix.svcA.ID,
		Source:         store.DeploymentSourceGit,
		SourceRef:      sharedRef,
		RequestedBy:    "usr_test_actor",
		IdempotencyKey: sharedKey,
		RequestID:      "req_alpha",
		CorrelationID:  "cor_alpha",
	})

	if alpha.OrganizationID != fix.orgA.ID {
		t.Errorf("alpha.OrganizationID = %q, want %q", alpha.OrganizationID, fix.orgA.ID)
	}
	if bravo.OrganizationID != fix.orgB.ID {
		t.Errorf("bravo.OrganizationID = %q, want %q", bravo.OrganizationID, fix.orgB.ID)
	}
	if alpha.ID == bravo.ID {
		t.Errorf("alpha.ID == bravo.ID (= %q): the two tenants must hold distinct deployment ids even with a shared idempotency_key", alpha.ID)
	}
	if alpha.IdempotencyKey != sharedKey || bravo.IdempotencyKey != sharedKey {
		t.Errorf("alpha.IdempotencyKey=%q bravo.IdempotencyKey=%q, want both %q",
			alpha.IdempotencyKey, bravo.IdempotencyKey, sharedKey)
	}

	// FindByIdempotencyKey must resolve the SAME key to the per-tenant
	// row — never cross-tenant. This is the read-side proof of the
	// positive-direction shape.
	var (
		alphaFound, bravoFound store.Deployment
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

// TestDeploymentRepositoryGetByIDCrossTenantReturnsNotFoundAndDoesNotEcho
// proves GetByID(orgB, alphaDep.ID) is tenant-scoped at the SQL
// predicate AND that the not-found payload names only the
// deployment_id the caller already supplied — never a foreign
// source_ref, idempotency_key, or service_id. A regression that
// resolved the composite (organization_id, id) by id alone would
// either return orgA's row (defeated by the assertion on the typed
// apierr.NotFound code) OR would attach orgA's source_ref /
// idempotency_key to the not-found details (defeated by the explicit
// no-leak substring checks below).
func TestDeploymentRepositoryGetByIDCrossTenantReturnsNotFoundAndDoesNotEcho(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentFixture(t, db, f)

	// alpha owns a deployment with deliberately distinctive
	// source_ref and idempotency_key suffixes — if a regression
	// echoed them into the not-found payload, the substring checks
	// below would trip.
	alphaDep := runInsertDeploymentOrFail(ctx, t, s, repo, store.Deployment{
		ID:             mintDeploymentID(t, "alpha"),
		OrganizationID: fix.orgA.ID,
		ProjectID:      fix.projA.ID,
		EnvironmentID:  fix.envA.ID,
		ServiceID:      fix.svcA.ID,
		Source:         store.DeploymentSourceGit,
		SourceRef:      "refs/heads/main@no_echo_distinctive_alpha_ref",
		RequestedBy:    "usr_test_actor",
		IdempotencyKey: "idem_no_echo_distinctive_alpha_key",
		RequestID:      "req_alpha",
		CorrelationID:  "cor_alpha",
	})

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.GetByID(ctx, q, fix.orgB.ID, alphaDep.ID)
		return gErr
	})
	ye := yerr.From(err)
	if ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(cross-tenant) error = %v, want code %s (a cross-tenant id must surface as NotFound, never a successful read of another tenant's row)",
			err, yerr.CodeNotFound)
	}
	msg := err.Error()
	if containsValue(msg, "no_echo_distinctive_alpha_ref") {
		t.Errorf("GetByID(cross-tenant) error message %q echoed alpha's source_ref — the not-found payload must name only the supplied id", msg)
	}
	if containsValue(msg, "no_echo_distinctive_alpha_key") {
		t.Errorf("GetByID(cross-tenant) error message %q echoed alpha's idempotency_key — the not-found payload must name only the supplied id", msg)
	}
	if containsValue(msg, fix.svcA.ID) {
		t.Errorf("GetByID(cross-tenant) error message %q echoed alpha's service_id — the not-found payload must name only the supplied deployment_id", msg)
	}
}

// TestDeploymentRepositoryFindByIdempotencyKeyCrossTenantDoesNotLeak
// proves FindByIdempotencyKey(orgB, alphaKey) returns (zero, false,
// nil) AND that no observable field on the returned zero value
// references alpha's row. UNIQUE (organization_id, idempotency_key) is
// per-tenant — a foreign key is structurally a miss.
func TestDeploymentRepositoryFindByIdempotencyKeyCrossTenantDoesNotLeak(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentFixture(t, db, f)

	alphaDep := seedQueuedDeployment(ctx, t, s, repo, fix.orgA, fix.projA, fix.envA, fix.svcA, "leak_check")

	var (
		got store.Deployment
		ok  bool
		err error
	)
	if rErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		g, found, fErr := repo.FindByIdempotencyKey(ctx, q, fix.orgB.ID, alphaDep.IdempotencyKey)
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
	if got.OrganizationID != "" {
		t.Errorf("FindByIdempotencyKey(cross-tenant) returned organization_id=%q, want empty", got.OrganizationID)
	}
	if got.SourceRef != "" {
		t.Errorf("FindByIdempotencyKey(cross-tenant) returned source_ref=%q, want empty (no foreign-tenant source_ref may surface)", got.SourceRef)
	}
}

// TestDeploymentRepositoryCancelCrossTenantLeavesOrgABystandersByteIdentical
// proves Cancel(orgB, alphaDep.ID) does not touch any orgA row —
// neither the named target nor any sibling — and surfaces as a typed
// apierr.NotFound. Several orgA rows are seeded to expose any
// regression that widened the predicate (e.g. UPDATE by id alone
// would touch alphaDep; UPDATE by status alone would touch every
// queued row across both tenants).
func TestDeploymentRepositoryCancelCrossTenantLeavesOrgABystandersByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentFixture(t, db, f)

	target := seedQueuedDeployment(ctx, t, s, repo, fix.orgA, fix.projA, fix.envA, fix.svcA, "target")
	sibling := seedRunningDeployment(ctx, t, s, repo, fix.orgA, fix.projA, fix.envA, fix.svcA, "sibling")

	baselineTarget := loadDeploymentRowByID(ctx, t, db, target.ID)
	baselineSibling := loadDeploymentRowByID(ctx, t, db, sibling.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, cErr := repo.Cancel(ctx, tx, fix.orgB.ID, target.ID, nil)
		return cErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Cancel(cross-tenant id) error = %v, want code %s (a cross-tenant deployment_id must surface as NotFound, never a Conflict or success)", err, yerr.CodeNotFound)
	}

	afterTarget := loadDeploymentRowByID(ctx, t, db, target.ID)
	assertDeploymentByteIdentical(t,
		"orgA target row after orgB Cancel(target.ID)",
		baselineTarget, afterTarget)

	afterSibling := loadDeploymentRowByID(ctx, t, db, sibling.ID)
	assertDeploymentByteIdentical(t,
		"orgA running sibling after orgB Cancel(target.ID)",
		baselineSibling, afterSibling)
}

// TestDeploymentRepositoryListByServiceCrossTenantReturnsEmptyAndDoesNotLeakTotal
// proves ListByService(orgB, alphaSvc.ID) returns an empty slice AND
// the per-tenant COUNT(*) for orgA is unaffected — no count is
// leaked through the response shape or through a side effect on the
// underlying table. The acceptance criterion "List queries return
// stable pagination without leaking total counts from other
// tenants" is pinned here: the response carries no total-count
// field and the foreign-tenant query returns zero rows even when
// the underlying service owns several deployments.
func TestDeploymentRepositoryListByServiceCrossTenantReturnsEmptyAndDoesNotLeakTotal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentFixture(t, db, f)

	seedQueuedDeployment(ctx, t, s, repo, fix.orgA, fix.projA, fix.envA, fix.svcA, "list_a")
	seedQueuedDeployment(ctx, t, s, repo, fix.orgA, fix.projA, fix.envA, fix.svcA, "list_b")
	seedRunningDeployment(ctx, t, s, repo, fix.orgA, fix.projA, fix.envA, fix.svcA, "list_c")

	baselineCountA := countDeploymentRowsForOrg(ctx, t, db, fix.orgA.ID)
	if baselineCountA != 3 {
		t.Fatalf("baseline orgA count = %d, want 3 — test fixture is invalid", baselineCountA)
	}
	baselineCountB := countDeploymentRowsForOrg(ctx, t, db, fix.orgB.ID)
	if baselineCountB != 0 {
		t.Fatalf("baseline orgB count = %d, want 0 — test fixture is invalid", baselineCountB)
	}

	var list []store.Deployment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := repo.ListByService(ctx, q, fix.orgB.ID, fix.svcA.ID)
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

	// Reading must not have side-effected the underlying counts.
	if n := countDeploymentRowsForOrg(ctx, t, db, fix.orgA.ID); n != baselineCountA {
		t.Errorf("orgA count after cross-tenant List = %d, want %d (a read leaked into a write)", n, baselineCountA)
	}
	if n := countDeploymentRowsForOrg(ctx, t, db, fix.orgB.ID); n != baselineCountB {
		t.Errorf("orgB count after cross-tenant List = %d, want %d (a read leaked into a write)", n, baselineCountB)
	}
}

// TestDeploymentRepositoryListByServiceForeignServiceIDOfSameTenantReturnsEmpty
// proves ListByService is scoped by the COMPOSITE (organization_id,
// service_id) — passing a service_id that exists in another tenant
// MUST NOT return that tenant's deployments even though the
// organization_id supplied is the caller's own. A regression that
// resolved by service_id alone would surface here.
func TestDeploymentRepositoryListByServiceForeignServiceIDOfSameTenantReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentFixture(t, db, f)

	seedQueuedDeployment(ctx, t, s, repo, fix.orgA, fix.projA, fix.envA, fix.svcA, "self_a")
	seedQueuedDeployment(ctx, t, s, repo, fix.orgB, fix.projB, fix.envB, fix.svcB, "peer_b")

	// orgA passes its own organization_id but orgB's service_id — the
	// composite predicate matches no rows, so the response must be
	// empty.
	var list []store.Deployment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		l, lErr := repo.ListByService(ctx, q, fix.orgA.ID, fix.svcB.ID)
		if lErr != nil {
			return lErr
		}
		list = l
		return nil
	}); err != nil {
		t.Fatalf("ListByService(self org, foreign svc): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("ListByService(orgA, svcB) returned %d rows, want 0 (a foreign-tenant service_id must not surface its deployments via the caller's own org)",
			len(list))
	}
}

// TestDeploymentOrganizationDeleteCascadeIsTenantScoped proves
// orgA's deletion cascades only to orgA's deployments. orgB's rows
// (including a queued, a running, and a row whose source / source_ref
// look like a peer's) must remain byte-identical. The
// deployments_organization_id_fkey CASCADE on organizations(id)
// confines the cleanup to the deleted tenant; a regression that
// dropped the organization_id leg of the FK would surface here as
// either an orgB row vanishing or its updated_at drifting.
func TestDeploymentOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDeploymentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDeploymentFixture(t, db, f)

	// orgA owns two rows (which will be cascaded away). orgB owns
	// three rows (which must survive byte-identically). Suffixes are
	// per-tenant unique because the global PRIMARY KEY on deployments
	// (id) means two tenants cannot share a deployment id even though
	// every OTHER per-row anchor — UNIQUE (organization_id,
	// idempotency_key), source_ref shape, source taxonomy — is
	// per-tenant. The cascade-by-organization_id assertion below is
	// load-bearing on its own: it does not require the per-tenant
	// rows to look indistinguishable.
	seedQueuedDeployment(ctx, t, s, repo, fix.orgA, fix.projA, fix.envA, fix.svcA, "cascade_alpha_queued")
	seedRunningDeployment(ctx, t, s, repo, fix.orgA, fix.projA, fix.envA, fix.svcA, "cascade_alpha_running")

	bravoQueued := seedQueuedDeployment(ctx, t, s, repo, fix.orgB, fix.projB, fix.envB, fix.svcB, "cascade_bravo_queued")
	bravoRunning := seedRunningDeployment(ctx, t, s, repo, fix.orgB, fix.projB, fix.envB, fix.svcB, "cascade_bravo_running")
	bravoExtra := seedQueuedDeployment(ctx, t, s, repo, fix.orgB, fix.projB, fix.envB, fix.svcB, "cascade_bravo_extra")

	baselineQueued := loadDeploymentRowByID(ctx, t, db, bravoQueued.ID)
	baselineRunning := loadDeploymentRowByID(ctx, t, db, bravoRunning.ID)
	baselineExtra := loadDeploymentRowByID(ctx, t, db, bravoExtra.ID)

	// Deleting orgA cascades through the full hierarchy — projects,
	// environments, services and deployments are all anchored by
	// composite FKs to organizations(id). Tear down dependents first
	// so a row from a sibling table cannot block the delete.
	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, fix.orgA.ID); err != nil {
		t.Fatalf("delete orgA: %v", err)
	}

	if n := countDeploymentRowsForOrg(ctx, t, db, fix.orgA.ID); n != 0 {
		t.Errorf("deployments rows for orgA after delete = %d, want 0 (cascade must remove the deleted tenant's rows)", n)
	}
	if n := countDeploymentRowsForOrg(ctx, t, db, fix.orgB.ID); n != 3 {
		t.Errorf("deployments rows for orgB after orgA delete = %d, want 3 — the cascade bled into another tenant", n)
	}

	afterQueued := loadDeploymentRowByID(ctx, t, db, bravoQueued.ID)
	assertDeploymentByteIdentical(t,
		"orgB queued bystander survives orgA delete",
		baselineQueued, afterQueued)

	afterRunning := loadDeploymentRowByID(ctx, t, db, bravoRunning.ID)
	assertDeploymentByteIdentical(t,
		"orgB running bystander survives orgA delete",
		baselineRunning, afterRunning)

	afterExtra := loadDeploymentRowByID(ctx, t, db, bravoExtra.ID)
	assertDeploymentByteIdentical(t,
		"orgB extra queued bystander survives orgA delete",
		baselineExtra, afterExtra)
}
