// Repository-layer tenant-isolation tests for the drift_findings
// table (BE-0472). drift_findings is the durable triage queue of
// reconcile-detected divergences between Yalla's desired state and
// Dokploy's actual state. A row that belongs to one tenant is anchored
// to that tenant by:
//
//	(a) the organization_id column itself, with an
//	    ON DELETE CASCADE FK to organizations(id) — the load-bearing
//	    parent FK every finding carries unconditionally;
//	(b) each optional resource leg (project_id / environment_id /
//	    service_id / service_domain_id) being a composite FK
//	    referencing the parent's UNIQUE (organization_id, id) with
//	    MATCH SIMPLE semantics — the FK fires only when the column is
//	    set, but when set it pins the leg to the row's OWN tenant so a
//	    finding can never reference another tenant's resource;
//	(c) every DriftFindingRepository read going through the
//	    organization_id predicate first: GetByID's WHERE is
//	    `organization_id = $1 AND id = $2`; ListByOrganization's WHERE
//	    is `organization_id = $1` and the ORDER BY / LIMIT clauses run
//	    AFTER the tenant predicate; MarkResolved's UPDATE WHERE is
//	    `organization_id = $1 AND id = $2 AND resolved_at IS NULL`.
//
// The DriftFindingRepository surface this file exercises against the
// cross-tenant boundary is the FULL public surface: Append (write),
// GetByID (read), ListByOrganization (read), and MarkResolved
// (state-transitioning UPDATE). There is no per-row Delete on
// drift_findings — row removal is reachable only through ON DELETE
// CASCADE when the parent organization or any scoped parent is
// removed, which is the final cross-tenant cascade probe in this file.
//
// This file pins the cross-tenant gap-fill probes the drift_findings
// invariants file (drift_finding_repository_invariants_test.go)
// explicitly delegates here:
//
//   - Append(orgA) cross-tenant bystander byte-identity: when orgB
//     owns several drift_findings rows of varying shape — including a
//     row whose dokploy_resource_id text matches the one orgA writes
//     (the tenant-shared text shape probe) — an Append on orgA mints a
//     fresh row owned by orgA and leaves every observable column on
//     every orgB row unchanged. A regression that misrouted the
//     INSERT (e.g. ON CONFLICT (dokploy_resource_id) DO UPDATE under
//     a denormalised target) would either rewrite orgB's mirror-text
//     row or cause orgA's RETURNING row to carry orgB's id.
//   - Append(orgA) per-tenant row-count: orgA's count goes up by one,
//     orgB's count is unchanged. The count probe is independent of the
//     byte-identity probe — a phantom Append misrouted under orgB
//     would surface only here (the byte-identity loop iterates over
//     baseline ids, so a stray new row is invisible to it).
//   - Cross-tenant id-collision is Conflict, bystander byte-identical,
//     no foreign-column leak: drift_findings.id is a global PRIMARY
//     KEY. A second Append under a different tenant attempting to
//     mint the SAME id surfaces a PK-violation
//     mapWriteError → apierr.Conflict; orgA's bystander row is
//     byte-identical, the Conflict payload never echoes any of orgA's
//     distinctive business columns (no kind / reason / level / actor /
//     resource leak), and the global row count is unchanged so the
//     rolled-back row did not land in some other tenant's slot.
//   - ListByOrganization(orgB) cross-tenant: even when orgA owns a
//     larger pool whose rows mirror orgB's dokploy_resource_id and
//     kind / reason / level shape, the list returns exactly orgB's
//     rows, every returned row's organization_id is orgB, every
//     returned row is byte-identical to its baseline, and orgA's
//     per-tenant count is unchanged afterwards (the read is
//     side-effect-free). A regression that dropped organization_id
//     from the ListByOrganization predicate would surface here as a
//     leak of orgA's rows into orgB's result set — the worst-case
//     drift-findings data-leak shape (operator triage panels would
//     expose another tenant's drift descriptions).
//   - ListByOrganization(orgB) limit-clamping is tenant-scoped: when
//     orgA seeds a pool ABOVE the repository cap and orgB seeds a
//     small fixed count, an above-cap orgB list resolves to exactly
//     orgB's count — not the cap (which would prove the leak) and
//     not orgA's pool + orgB's pool clamped at the cap (which would
//     prove the merged-pool regression).
//   - ListByOrganization(unknown tenant) is empty AND side-effect-free:
//     a never-persisted organization_id resolves to the empty slice
//     and every real tenant's per-org count is unchanged afterwards.
//   - GetByID(orgA, orgB's id) cross-tenant is NotFound AND bystander
//     byte-identical: the existing
//     TestDriftFindingGetByIDCrossTenantIsNotFound in the invariants
//     file asserts the typed not-found, this probe deepens it by
//     asserting orgB's bystander row stays byte-identical AND orgB's
//     per-tenant count is unchanged (the read is side-effect-free).
//   - MarkResolved(orgA, orgB's id) cross-tenant: bystander
//     byte-identity is asserted with a MULTI-ROW orgB pool — the
//     existing TestDriftFindingMarkResolvedCrossTenantIsNotFound in
//     the invariants file targets one row; this probe deepens it with
//     a three-row orgB pool covering the
//     pending / shared-dokploy_resource_id / resolved spread so a
//     column drift on any persisted shape surfaces as a named field
//     diff.
//   - organizations DELETE cascade is tenant-scoped: deleting orgA
//     removes only orgA's drift_findings rows. orgB's rows must
//     remain byte-identical to their baselines, including the
//     nullable resolved_at column and the closed-set kind / reason /
//     level columns. The single-bystander variant of this cascade is
//     already pinned by the invariants file's
//     TestDriftFindingCascadeDeleteOnOrganization (which seeds one
//     orgA row, no orgB rows); the BE-0472 variant deepens it with a
//     multi-row orgB pool covering the lifecycle spread (pending +
//     resolved) and a byte-identity assertion on every bystander row.
//
// Helpers introduced here: seedTwoTenantDriftFindingFixture (two
// organizations and the per-tenant parent chain orgA / orgB need to
// produce findings without sharing parent rows).
//
// Helpers reused from sibling files: seedOrg, seedProject,
// seedEnvironment, seedService (schema_test.go); newStore
// (store_test.go); wantErrCode (idempotency_test.go); containsValue
// (organization_variable_tenant_isolation_test.go); itoa
// (audit_repository_tenant_isolation_test.go); rawDriftFindingRow,
// loadDriftFindingRowByID, countDriftFindingRowsForOrg,
// mintDriftFindingID, driftFindingFixture, seedDriftFinding,
// assertDriftFindingByteIdentical
// (drift_finding_repository_invariants_test.go).
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// twoTenantDriftFindingFixture is the two-organization shape every
// test in this file seeds before the cross-tenant probe runs.
// drift_findings carries optional resource legs through composite FKs,
// so each tenant needs its OWN parent chain — a cross-tenant FK is
// already pinned as a Conflict in the invariants file's
// TestDriftFindingAppendCrossTenantParentIsConflict, so the fixtures
// here keep parent chains strictly per-tenant.
type twoTenantDriftFindingFixture struct {
	orgA  testutil.Organization
	projA testutil.Project
	envA  testutil.Environment
	svcA  testutil.Service
	orgB  testutil.Organization
	projB testutil.Project
	envB  testutil.Environment
	svcB  testutil.Service
}

// seedTwoTenantDriftFindingFixture creates the two-tenant parent chain
// drift_findings tenant-isolation tests need. Both tenants get a
// project / environment / service so every finding can carry the full
// resource-leg shape and the byte-identity assertions can observe the
// non-nullable optional-leg projections.
func seedTwoTenantDriftFindingFixture(
	t *testing.T,
	db *testutil.DB,
	f *testutil.Factory,
) twoTenantDriftFindingFixture {
	t.Helper()
	orgA := seedOrg(t, db, f, "drift-tenant-a")
	projA := seedProject(t, db, f, orgA, "drift-A-project")
	envA := seedEnvironment(t, db, f, projA, "drift-A-env")
	svcA := seedService(t, db, f, envA, "drift-A-svc")
	orgB := seedOrg(t, db, f, "drift-tenant-b")
	projB := seedProject(t, db, f, orgB, "drift-B-project")
	envB := seedEnvironment(t, db, f, projB, "drift-B-env")
	svcB := seedService(t, db, f, envB, "drift-B-svc")
	return twoTenantDriftFindingFixture{
		orgA: orgA, projA: projA, envA: envA, svcA: svcA,
		orgB: orgB, projB: projB, envB: envB, svcB: svcB,
	}
}

// TestDriftFindingRepositoryAppendOnOrgADoesNotTouchOrgBRows pins the
// load-bearing cross-tenant Append isolation invariant: when orgB owns
// drift_findings rows of varying shape — including a row whose
// dokploy_resource_id text matches the value orgA is about to write
// (the tenant-shared text shape probe) — an Append on orgA mints a
// fresh row owned by orgA and leaves every column of every orgB row
// byte-identical to its baseline.
//
// The bystander pool deliberately spans the lifecycle and taxonomy
// spread: (a) a service-level unmanaged finding with a non-empty
// dokploy_resource_id, (b) a project-level safe finding with an
// env_var_key, (c) an organization-level dangerous finding with both
// resource legs unset (so the null-leg projections are exercised), and
// (d) a resolved row (so the nullable resolved_at column is exercised).
// A regression that touched any one of these legs would surface as a
// named field diff via assertDriftFindingByteIdentical. The
// shared-dokploy_resource_id row is the tenant-shared text probe: a
// regression that confused tenants by dokploy_resource_id rather than
// organization_id would surface as a rewrite of that orgB row.
func TestDriftFindingRepositoryAppendOnOrgADoesNotTouchOrgBRows(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	fix := seedTwoTenantDriftFindingFixture(t, db, f)

	base := time.Now().UTC().Truncate(time.Microsecond)
	sharedDokployResourceID := "dokploy_application_shared_by_tenant_id_text_only"

	// orgB row #1: service-level unmanaged finding sharing the
	// dokploy_resource_id text with the orgA writer. This is the
	// load-bearing tenant-shared-text probe.
	bravoSharedResource := store.DriftFinding{
		OrganizationID:    fix.orgB.ID,
		Kind:              store.DriftKindUnmanaged,
		Reason:            store.DriftReasonResourceUnmanaged,
		Level:             store.DriftLevelService,
		ProjectID:         fix.svcB.ProjectID,
		EnvironmentID:     fix.svcB.EnvironmentID,
		ServiceID:         fix.svcB.ID,
		DokployResourceID: sharedDokployResourceID,
		ParentDokployID:   "dokploy_project_bravo",
		RequestID:         "req_bravo_shared",
		CorrelationID:     "cor_bravo_shared",
		DetectedAt:        base,
	}
	bravoSharedStored := seedDriftFinding(ctx, t, s, repo, bravoSharedResource)

	// orgB row #2: project-level safe finding with a populated
	// env_var_key.
	bravoProjectLevel := store.DriftFinding{
		OrganizationID: fix.orgB.ID,
		Kind:           store.DriftKindSafe,
		Reason:         store.DriftReasonEnvVarChanged,
		Level:          store.DriftLevelProject,
		ProjectID:      fix.projB.ID,
		EnvVarKey:      "DATABASE_URL",
		RequestID:      "req_bravo_proj",
		CorrelationID:  "cor_bravo_proj",
		DetectedAt:     base.Add(time.Second),
	}
	bravoProjectStored := seedDriftFinding(ctx, t, s, repo, bravoProjectLevel)

	// orgB row #3: organization-level dangerous finding with every
	// optional resource leg unset (NULL on disk). Pins the null-leg
	// projections in assertDriftFindingByteIdentical.
	bravoOrgLevel := store.DriftFinding{
		OrganizationID: fix.orgB.ID,
		Kind:           store.DriftKindDangerous,
		Reason:         store.DriftReasonServiceMissing,
		Level:          store.DriftLevelOrganization,
		RequestID:      "req_bravo_org",
		CorrelationID:  "cor_bravo_org",
		DetectedAt:     base.Add(2 * time.Second),
	}
	bravoOrgStored := seedDriftFinding(ctx, t, s, repo, bravoOrgLevel)

	// orgB row #4: resolved row. Pins the nullable resolved_at /
	// resolved_by_actor_id projection so a regression that flipped a
	// resolved row's columns back to nil under cross-tenant pressure
	// surfaces here.
	bravoToResolve := store.DriftFinding{
		OrganizationID: fix.orgB.ID,
		Kind:           store.DriftKindSafe,
		Reason:         store.DriftReasonDomainRenamed,
		Level:          store.DriftLevelService,
		ProjectID:      fix.svcB.ProjectID,
		EnvironmentID:  fix.svcB.EnvironmentID,
		ServiceID:      fix.svcB.ID,
		RequestID:      "req_bravo_resolved",
		CorrelationID:  "cor_bravo_resolved",
		DetectedAt:     base.Add(3 * time.Second),
	}
	bravoToResolveStored := seedDriftFinding(ctx, t, s, repo, bravoToResolve)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, mErr := repo.MarkResolved(ctx, tx, fix.orgB.ID, bravoToResolveStored.ID, "usr_bravo_resolver", base.Add(10*time.Second))
		return mErr
	}); err != nil {
		t.Fatalf("seed orgB MarkResolved: %v", err)
	}

	baselines := []rawDriftFindingRow{
		loadDriftFindingRowByID(ctx, t, db, bravoSharedStored.ID),
		loadDriftFindingRowByID(ctx, t, db, bravoProjectStored.ID),
		loadDriftFindingRowByID(ctx, t, db, bravoOrgStored.ID),
		loadDriftFindingRowByID(ctx, t, db, bravoToResolveStored.ID),
	}

	// orgA writes a finding sharing the SAME dokploy_resource_id text
	// as bravoSharedResource. The Append must mint a fresh row owned
	// by orgA — never resolve any conflict onto orgB's mirror-text
	// row — and the RETURNING row must carry orgA's tenant.
	alpha := store.DriftFinding{
		OrganizationID:    fix.orgA.ID,
		Kind:              store.DriftKindUnmanaged,
		Reason:            store.DriftReasonResourceUnmanaged,
		Level:             store.DriftLevelService,
		ProjectID:         fix.svcA.ProjectID,
		EnvironmentID:     fix.svcA.EnvironmentID,
		ServiceID:         fix.svcA.ID,
		DokployResourceID: sharedDokployResourceID,
		ParentDokployID:   "dokploy_project_alpha",
		RequestID:         "req_alpha_shared",
		CorrelationID:     "cor_alpha_shared",
		DetectedAt:        base.Add(5 * time.Second),
	}
	alphaStored := seedDriftFinding(ctx, t, s, repo, alpha)

	if alphaStored.OrganizationID != fix.orgA.ID {
		t.Fatalf("orgA Append returned organization_id %q, want %q — the writer's RETURNING row must echo the writer's tenant",
			alphaStored.OrganizationID, fix.orgA.ID)
	}
	if alphaStored.ID == bravoSharedStored.ID {
		t.Fatalf("orgA Append returned id %q, equal to orgB's mirror-text row id — the Append must mint a distinct id under tenant-shared text shapes",
			alphaStored.ID)
	}

	// Every orgB row must be byte-identical to its baseline. A
	// regression that mutated any column on any bystander row would
	// surface as a named field diff.
	for _, baseline := range baselines {
		after := loadDriftFindingRowByID(ctx, t, db, baseline.ID)
		assertDriftFindingByteIdentical(t,
			"orgB bystander row after orgA Append",
			baseline, after)
	}
}

// TestDriftFindingRepositoryAppendOnOrgADoesNotChangeOrgBRowCount is
// the corollary count probe. A regression that mutated one bystander
// column on one row would surface in the byte-identity probe, but a
// regression that misrouted an Append (e.g. an off-by-one in the
// organization_id bind parameter) would mint a phantom row under the
// wrong tenant — invisible to the byte-identity loop (which iterates
// over baseline ids) but caught by the per-tenant COUNT(*) probe.
func TestDriftFindingRepositoryAppendOnOrgADoesNotChangeOrgBRowCount(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	fix := seedTwoTenantDriftFindingFixture(t, db, f)

	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 2; i++ {
		seedDriftFinding(ctx, t, s, repo, driftFindingFixture(fix.orgA, fix.svcA, base.Add(time.Duration(i)*time.Second)))
	}
	for i := 0; i < 5; i++ {
		seedDriftFinding(ctx, t, s, repo, driftFindingFixture(fix.orgB, fix.svcB, base.Add(time.Duration(i)*time.Second)))
	}

	priorAlphaCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID)
	priorBravoCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID)
	if priorAlphaCount != 2 {
		t.Fatalf("baseline orgA drift_findings count = %d, want 2", priorAlphaCount)
	}
	if priorBravoCount != 5 {
		t.Fatalf("baseline orgB drift_findings count = %d, want 5", priorBravoCount)
	}

	seedDriftFinding(ctx, t, s, repo, driftFindingFixture(fix.orgA, fix.svcA, base.Add(10*time.Second)))

	afterAlphaCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID)
	afterBravoCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID)
	if afterAlphaCount != priorAlphaCount+1 {
		t.Errorf("after orgA Append: orgA count = %d, want %d", afterAlphaCount, priorAlphaCount+1)
	}
	if afterBravoCount != priorBravoCount {
		t.Errorf("after orgA Append: orgB count = %d, want %d (the cross-tenant Append altered the foreign tenant's row count)",
			afterBravoCount, priorBravoCount)
	}
}

// TestDriftFindingRepositoryAppendCrossTenantIDCollisionIsConflictAndBystanderByteIdentical
// pins that a global PRIMARY KEY collision across tenants surfaces as
// the same typed Conflict the same-tenant collision does, AND that the
// rolled-back failing INSERT leaves orgA's bystander row
// byte-identical, AND that the Conflict payload does NOT echo any of
// orgA's distinctive business columns (no kind / reason / level /
// actor / resource leak), AND that the global drift_findings row count
// is unchanged. drift_findings.id is a global PRIMARY KEY without an
// ON CONFLICT clause in the Append INSERT, so the PK violation flows
// through the database and back out through mapWriteError → Conflict.
// A regression that switched the Append to an ON CONFLICT (id) DO
// UPDATE would either rewrite orgA's bystander row or silently merge
// orgB's payload through it.
func TestDriftFindingRepositoryAppendCrossTenantIDCollisionIsConflictAndBystanderByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	fix := seedTwoTenantDriftFindingFixture(t, db, f)
	sharedID := mintDriftFindingID(t, "cross-tenant-collision")
	base := time.Now().UTC().Truncate(time.Microsecond)

	// orgA writes a row carrying distinctive business columns so the
	// no-leak assertions on the Conflict payload can prove orgB's
	// error message echoes only the supplied id (which orgB has) and
	// never any column from orgA's row.
	alpha := store.DriftFinding{
		ID:                sharedID,
		OrganizationID:    fix.orgA.ID,
		Kind:              store.DriftKindUnmanaged,
		Reason:            store.DriftReasonResourceUnmanaged,
		Level:             store.DriftLevelService,
		ProjectID:         fix.svcA.ProjectID,
		EnvironmentID:     fix.svcA.EnvironmentID,
		ServiceID:         fix.svcA.ID,
		EnvVarKey:         "alpha_distinctive_env_var",
		DokployResourceID: "alpha_distinctive_dokploy_resource",
		ParentDokployID:   "alpha_distinctive_parent_dokploy",
		RequestID:         "alpha_distinctive_request",
		CorrelationID:     "alpha_distinctive_correlation",
		DetectedAt:        base,
	}
	alphaStored := seedDriftFinding(ctx, t, s, repo, alpha)
	if alphaStored.ID != sharedID {
		t.Fatalf("seed Append(orgA) preserved id %q, want %q", alphaStored.ID, sharedID)
	}
	baseline := loadDriftFindingRowByID(ctx, t, db, sharedID)

	priorGlobalCount := totalDriftFindingRows(ctx, t, db)

	// orgB attempts to mint a row with the SAME id under its own
	// tenant AND under different business columns. The global PRIMARY
	// KEY catches the collision regardless of organization_id; the
	// typed Conflict surfaces through mapWriteError.
	bravo := store.DriftFinding{
		ID:             sharedID,
		OrganizationID: fix.orgB.ID,
		Kind:           store.DriftKindSafe,
		Reason:         store.DriftReasonEnvVarChanged,
		Level:          store.DriftLevelService,
		ProjectID:      fix.svcB.ProjectID,
		EnvironmentID:  fix.svcB.EnvironmentID,
		ServiceID:      fix.svcB.ID,
		EnvVarKey:      "bravo_writer_env_var",
		RequestID:      "bravo_writer_request",
		CorrelationID:  "bravo_writer_correlation",
		DetectedAt:     base.Add(time.Second),
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, aErr := repo.Append(ctx, tx, bravo)
		return aErr
	})
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(cross-tenant id collision) error = %v, want code %s — a duplicate id under a foreign tenant must surface as the same typed Conflict as a same-tenant duplicate id",
			err, yerr.CodeConflict)
	}

	// The Conflict payload must NOT echo any column from orgA's
	// distinctive row. The id leg is intentionally not asserted out —
	// orgB supplied that id, so it is permitted to appear.
	msg := err.Error()
	leaks := []string{
		"alpha_distinctive_env_var",
		"alpha_distinctive_dokploy_resource",
		"alpha_distinctive_parent_dokploy",
		"alpha_distinctive_request",
		"alpha_distinctive_correlation",
		fix.orgA.ID,
		fix.svcA.ID,
	}
	for _, leak := range leaks {
		if containsValue(msg, leak) {
			t.Errorf("Append(cross-tenant id collision) error message %q echoed orgA's foreign column %q — the conflict payload must echo only the supplied id and never a foreign tenant's column",
				msg, leak)
		}
	}

	// orgA's bystander row must be byte-identical to its baseline.
	after := loadDriftFindingRowByID(ctx, t, db, sharedID)
	assertDriftFindingByteIdentical(t,
		"orgA bystander after orgB cross-tenant id-collision attempt",
		baseline, after)

	// The rolled-back row did not land in some other tenant's slot:
	// the global row count is unchanged.
	if got := totalDriftFindingRows(ctx, t, db); got != priorGlobalCount {
		t.Errorf("global drift_findings count = %d, want %d (a rolled-back cross-tenant PK collision left a row behind)",
			got, priorGlobalCount)
	}
	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID); got != 1 {
		t.Errorf("after cross-tenant id collision: orgA count = %d, want 1 (the original row must persist exactly once)", got)
	}
	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID); got != 0 {
		t.Errorf("after cross-tenant id collision: orgB count = %d, want 0 (the rejected Append must leave no row behind)", got)
	}
}

// TestDriftFindingRepositoryListByOrganizationCrossTenantReturnsOnlyOwnRows
// is the load-bearing read-side cross-tenant proof: even when orgA
// owns many drift_findings rows whose dokploy_resource_id text mirrors
// orgB's rows AND whose kind / reason / level shape mirrors orgB's
// rows (the tenant-shared-text-and-shape probe),
// ListByOrganization(orgB.ID) returns exactly orgB's row count, every
// returned row is owned by orgB, every returned row is byte-identical
// to its baseline, and orgA's per-tenant count is unchanged afterwards
// (the read is side-effect-free).
//
// A regression that dropped the organization_id predicate from the
// ListByOrganization query (e.g. SELECT ... FROM drift_findings ORDER
// BY ... LIMIT $2 — i.e. ignoring $1) would surface here as a leak of
// orgA's rows into orgB's result set — the worst-case drift-findings
// data-leak shape (operator triage panels would expose another
// tenant's drift descriptions and dokploy_resource_id strings).
func TestDriftFindingRepositoryListByOrganizationCrossTenantReturnsOnlyOwnRows(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	fix := seedTwoTenantDriftFindingFixture(t, db, f)
	base := time.Now().UTC().Truncate(time.Microsecond)
	sharedDokployResourceID := "dokploy_application_shared_across_tenants"

	// orgA seeds 5 rows across the kind / reason / level spread,
	// every row carrying the SAME dokploy_resource_id text orgB uses
	// (the tenant-shared text probe — a regression that confused
	// tenants by dokploy_resource_id rather than organization_id
	// would surface here as orgA rows in orgB's result set).
	for i := 0; i < 5; i++ {
		alpha := store.DriftFinding{
			OrganizationID:    fix.orgA.ID,
			Kind:              store.DriftKindUnmanaged,
			Reason:            store.DriftReasonResourceUnmanaged,
			Level:             store.DriftLevelService,
			ProjectID:         fix.svcA.ProjectID,
			EnvironmentID:     fix.svcA.EnvironmentID,
			ServiceID:         fix.svcA.ID,
			DokployResourceID: sharedDokployResourceID,
			ParentDokployID:   "dokploy_project_alpha",
			RequestID:         "req_alpha_seed_" + itoa(i),
			CorrelationID:     "cor_alpha_seed_" + itoa(i),
			DetectedAt:        base.Add(time.Duration(i) * time.Second),
		}
		seedDriftFinding(ctx, t, s, repo, alpha)
	}

	bravoStored := make([]store.DriftFinding, 0, 3)
	for i := 0; i < 3; i++ {
		bravo := store.DriftFinding{
			OrganizationID:    fix.orgB.ID,
			Kind:              store.DriftKindUnmanaged,
			Reason:            store.DriftReasonResourceUnmanaged,
			Level:             store.DriftLevelService,
			ProjectID:         fix.svcB.ProjectID,
			EnvironmentID:     fix.svcB.EnvironmentID,
			ServiceID:         fix.svcB.ID,
			DokployResourceID: sharedDokployResourceID,
			ParentDokployID:   "dokploy_project_bravo",
			RequestID:         "req_bravo_seed_" + itoa(i),
			CorrelationID:     "cor_bravo_seed_" + itoa(i),
			DetectedAt:        base.Add(time.Duration(i+10) * time.Second),
		}
		bravoStored = append(bravoStored, seedDriftFinding(ctx, t, s, repo, bravo))
	}

	bravoBaselines := make(map[string]rawDriftFindingRow, len(bravoStored))
	for _, e := range bravoStored {
		bravoBaselines[e.ID] = loadDriftFindingRowByID(ctx, t, db, e.ID)
	}

	priorAlphaCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID)

	var listed []store.DriftFinding
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var lErr error
		listed, lErr = repo.ListByOrganization(ctx, q, fix.orgB.ID, 100)
		return lErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB): %v", err)
	}

	if len(listed) != len(bravoStored) {
		t.Fatalf("ListByOrganization(orgB) returned %d rows, want %d — a different count means the orgA pool leaked into orgB's result set (or a row was lost)",
			len(listed), len(bravoStored))
	}
	for _, e := range listed {
		if e.OrganizationID != fix.orgB.ID {
			t.Errorf("ListByOrganization(orgB) returned a row owned by org %q — the organization_id predicate must filter cross-tenant rows out",
				e.OrganizationID)
		}
		baseline, ok := bravoBaselines[e.ID]
		if !ok {
			t.Errorf("ListByOrganization(orgB) returned an unexpected id %q (not in the bravo baseline set) — a regression must have either minted a phantom row or returned an orgA row",
				e.ID)
			continue
		}
		after := loadDriftFindingRowByID(ctx, t, db, e.ID)
		assertDriftFindingByteIdentical(t,
			"orgB returned row after cross-tenant List",
			baseline, after)
	}

	// The read must have no side effect on orgA's per-tenant count.
	afterAlphaCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID)
	if afterAlphaCount != priorAlphaCount {
		t.Errorf("after orgB ListByOrganization: orgA count = %d, want %d (the read must not have any side effect on the bystander tenant's row count)",
			afterAlphaCount, priorAlphaCount)
	}
}

// TestDriftFindingRepositoryListByOrganizationLimitClampingIsTenantScoped
// pins that driftFindingListMaxLimit clamps the orgB row pool, NOT a
// globally-merged pool. A regression that dropped the organization_id
// predicate but still honoured the LIMIT clause would surface here:
// orgA seeds rows ABOVE the cap and orgB seeds a small fixed count, so
// the malformed query would return min(orgA_count + orgB_count, cap)
// rows — a number well above orgB's actual count.
//
// orgA seeds 205 rows (slightly above the cap of 200 so the leak shape
// is observable but the seed time is bounded) via raw SQL, and orgB
// seeds 4 rows through the repository. orgB's ListByOrganization with
// an above-cap limit (1000) must resolve to exactly 4 rows — not the
// cap (which would prove the leak) and not 200 (the cap clamped after
// the predicate was dropped).
func TestDriftFindingRepositoryListByOrganizationLimitClampingIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	fix := seedTwoTenantDriftFindingFixture(t, db, f)
	base := time.Now().UTC().Truncate(time.Microsecond)

	// Seed orgA's row pool ABOVE the repository-level cap (200) so
	// the "ignored the predicate, honoured the LIMIT" regression
	// shape is observable. Use raw SQL to keep the seed fast: 205
	// Append calls through the store would multiply the transaction
	// setup cost by 205. The INSERT mirrors driftFindingColumns minus
	// created_at / updated_at (which DEFAULT now() — same pattern as
	// the audit_events raw-SQL seed in
	// TestAuditRepositoryListByOrganizationLimitClampingIsTenantScoped).
	alphaSeedCount := 205
	for i := 0; i < alphaSeedCount; i++ {
		id := mintDriftFindingID(t, "alpha-cap-leak-probe-") + "_" + itoa(i)
		_, err := db.Exec(ctx,
			`INSERT INTO drift_findings
			   (id, organization_id, kind, reason, level,
			    project_id, environment_id, service_id, service_domain_id,
			    env_var_key, dokploy_resource_id, parent_dokploy_id,
			    request_id, correlation_id, detected_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9, $10, $11, $12, $13, $14)`,
			id, fix.orgA.ID,
			string(store.DriftKindSafe),
			string(store.DriftReasonEnvVarChanged),
			string(store.DriftLevelService),
			fix.svcA.ProjectID, fix.svcA.EnvironmentID, fix.svcA.ID,
			"alpha_seed_env_var", "", "",
			"req-alpha-cap-"+itoa(i), "cor-alpha-cap-"+itoa(i),
			base.Add(time.Duration(i)*time.Millisecond))
		if err != nil {
			t.Fatalf("seed orgA row %d: %v", i, err)
		}
	}

	bravoSeedCount := 4
	for i := 0; i < bravoSeedCount; i++ {
		seedDriftFinding(ctx, t, s, repo,
			driftFindingFixture(fix.orgB, fix.svcB, base.Add(time.Duration(i+1000)*time.Millisecond)))
	}

	// Above-cap limit request: with a tenant-scoped predicate this
	// resolves to exactly orgB's row count. Without the predicate it
	// would resolve to min(alphaSeedCount + bravoSeedCount,
	// driftFindingListMaxLimit) — i.e. 200 (the cap), well above
	// bravoSeedCount.
	var listed []store.DriftFinding
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var lErr error
		listed, lErr = repo.ListByOrganization(ctx, q, fix.orgB.ID, 1000)
		return lErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB, above-cap limit): %v", err)
	}

	if len(listed) != bravoSeedCount {
		t.Fatalf("ListByOrganization(orgB, above-cap limit) returned %d rows, want %d — a count matching the repository cap (or any number above bravoSeedCount) proves the orgA pool leaked through the limit clause",
			len(listed), bravoSeedCount)
	}
	for _, e := range listed {
		if e.OrganizationID != fix.orgB.ID {
			t.Errorf("ListByOrganization(orgB, above-cap limit) returned a row owned by org %q — every returned row must be tenant-owned",
				e.OrganizationID)
		}
	}

	// orgA's per-tenant count is unchanged after orgB's read.
	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID); got != alphaSeedCount {
		t.Errorf("after orgB above-cap List: orgA count = %d, want %d (the read must be side-effect-free)",
			got, alphaSeedCount)
	}
}

// TestDriftFindingRepositoryListByOrganizationUnknownTenantReturnsEmptyAndPreservesCounts
// pins the phantom-tenant variant of ListByOrganization: a
// never-persisted organization_id resolves to the empty slice AND
// every existing tenant's per-org count is unchanged after the read.
// The single-tenant variant of this branch is already pinned by the
// invariants file's
// TestDriftFindingListByOrganizationUnknownOrgIsEmptySlice; this probe
// seeds two real tenants and proves the phantom-tenant read leaks no
// hint of either real tenant's existence through a per-tenant count
// side-effect.
func TestDriftFindingRepositoryListByOrganizationUnknownTenantReturnsEmptyAndPreservesCounts(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	fix := seedTwoTenantDriftFindingFixture(t, db, f)
	base := time.Now().UTC().Truncate(time.Microsecond)

	for i := 0; i < 2; i++ {
		seedDriftFinding(ctx, t, s, repo, driftFindingFixture(fix.orgA, fix.svcA, base.Add(time.Duration(i)*time.Second)))
	}
	for i := 0; i < 5; i++ {
		seedDriftFinding(ctx, t, s, repo, driftFindingFixture(fix.orgB, fix.svcB, base.Add(time.Duration(i+10)*time.Second)))
	}

	priorAlphaCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID)
	priorBravoCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID)

	phantomID := "org_phantom_drift_tenant_does_not_exist"

	var listed []store.DriftFinding
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var lErr error
		listed, lErr = repo.ListByOrganization(ctx, q, phantomID, 50)
		return lErr
	}); err != nil {
		t.Fatalf("ListByOrganization(phantom): %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("ListByOrganization(phantom) returned %d rows, want 0 — an unknown org id must resolve to the empty slice and never leak rows from any real tenant",
			len(listed))
	}

	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID); got != priorAlphaCount {
		t.Errorf("after phantom-tenant read: orgA count = %d, want %d (the read must be side-effect-free)",
			got, priorAlphaCount)
	}
	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID); got != priorBravoCount {
		t.Errorf("after phantom-tenant read: orgB count = %d, want %d (the read must be side-effect-free)",
			got, priorBravoCount)
	}
}

// TestDriftFindingRepositoryGetByIDCrossTenantBystanderByteIdentical
// deepens the existing
// TestDriftFindingGetByIDCrossTenantIsNotFound (which asserts only the
// typed not-found shape) with a bystander byte-identity assertion AND
// a per-tenant row-count side-effect-free probe. A regression that
// fell back to a side-channel read (e.g. a buggy retry path that
// re-issued a non-tenant-scoped query on miss) would surface here as
// either orgB's bystander row drift OR a per-tenant count side effect.
func TestDriftFindingRepositoryGetByIDCrossTenantBystanderByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	fix := seedTwoTenantDriftFindingFixture(t, db, f)
	base := time.Now().UTC().Truncate(time.Microsecond)

	bravoStored := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(fix.orgB, fix.svcB, base))
	baseline := loadDriftFindingRowByID(ctx, t, db, bravoStored.ID)

	priorAlphaCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID)
	priorBravoCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID)

	// orgA reads orgB's row through GetByID. The tenant-scoped WHERE
	// returns NotFound; the row body must not be observable through
	// the error.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, gErr := repo.GetByID(ctx, q, fix.orgA.ID, bravoStored.ID)
		return gErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	// The error must not echo orgB's distinctive columns (the
	// dokploy_resource_id, env_var_key, request_id, etc.). The id is
	// supplied by orgA so its presence in the error message is
	// permitted; only the foreign row's body columns are forbidden.
	msg := err.Error()
	leaks := []string{
		baseline.DokployResourceID,
		baseline.ParentDokployID,
		baseline.RequestID,
		baseline.CorrelationID,
		fix.orgB.ID,
		fix.projB.ID,
		fix.envB.ID,
		fix.svcB.ID,
	}
	for _, leak := range leaks {
		if leak == "" {
			continue
		}
		if containsValue(msg, leak) {
			t.Errorf("GetByID(orgA, orgB.id) error message %q echoed orgB's foreign column %q — the not-found payload must echo only the supplied id and never a foreign tenant's column",
				msg, leak)
		}
	}

	// orgB's bystander row stays byte-identical.
	after := loadDriftFindingRowByID(ctx, t, db, bravoStored.ID)
	assertDriftFindingByteIdentical(t,
		"orgB bystander after orgA cross-tenant GetByID",
		baseline, after)

	// The read is side-effect-free on both tenants' counts.
	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID); got != priorAlphaCount {
		t.Errorf("after cross-tenant GetByID: orgA count = %d, want %d (the read must be side-effect-free)",
			got, priorAlphaCount)
	}
	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID); got != priorBravoCount {
		t.Errorf("after cross-tenant GetByID: orgB count = %d, want %d (the read must be side-effect-free)",
			got, priorBravoCount)
	}
}

// TestDriftFindingRepositoryMarkResolvedCrossTenantDeepBystanderByteIdentical
// deepens the existing
// TestDriftFindingMarkResolvedCrossTenantIsNotFound (which targets one
// row and asserts byte-identity inline) with a MULTI-ROW orgB pool
// covering the lifecycle spread (open + resolved) and a separate
// targeted row that orgA tries to resolve. The bystander pool also
// includes a row sharing the (kind, reason, level) tuple of the
// target — a regression that filtered MarkResolved by (kind, reason,
// level) rather than (organization_id, id) would surface as that
// peer row being silently resolved.
//
// A regression that dropped organization_id from MarkResolved's WHERE
// would either (a) rewrite orgB's target row's resolved_at /
// resolved_by_actor_id columns into orgA's actor stamp, or (b) silently
// resolve orgA's "claim" with no real divergence to mark — the
// byte-identity loop catches (a) as a named field diff and the
// per-tenant count probe catches a misrouted phantom UPDATE in (b).
func TestDriftFindingRepositoryMarkResolvedCrossTenantDeepBystanderByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	fix := seedTwoTenantDriftFindingFixture(t, db, f)
	base := time.Now().UTC().Truncate(time.Microsecond)

	// orgB row #1: the target — open, service-level, safe.
	bravoTarget := seedDriftFinding(ctx, t, s, repo, driftFindingFixture(fix.orgB, fix.svcB, base))

	// orgB row #2: a sibling sharing the (kind, reason, level) tuple
	// of the target. A regression that selected the row to resolve by
	// any combination of those three columns would surface here as
	// this row's resolved_at / resolved_by_actor_id changing.
	bravoSibling := seedDriftFinding(ctx, t, s, repo,
		driftFindingFixture(fix.orgB, fix.svcB, base.Add(time.Second)))

	// orgB row #3: an already-resolved row. Its baseline carries a
	// non-nil resolved_at and a non-empty resolved_by_actor_id — a
	// regression that overwrote the resolved row through a cross-
	// tenant MarkResolved would surface as the actor / timestamp
	// being rewritten.
	bravoResolvedSource := seedDriftFinding(ctx, t, s, repo,
		driftFindingFixture(fix.orgB, fix.svcB, base.Add(2*time.Second)))
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, mErr := repo.MarkResolved(ctx, tx, fix.orgB.ID, bravoResolvedSource.ID, "usr_bravo_resolver_original", base.Add(5*time.Second))
		return mErr
	}); err != nil {
		t.Fatalf("seed orgB MarkResolved: %v", err)
	}

	baselines := []rawDriftFindingRow{
		loadDriftFindingRowByID(ctx, t, db, bravoTarget.ID),
		loadDriftFindingRowByID(ctx, t, db, bravoSibling.ID),
		loadDriftFindingRowByID(ctx, t, db, bravoResolvedSource.ID),
	}

	priorAlphaCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID)
	priorBravoCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID)

	// orgA tries to mark orgB's target row resolved. The
	// tenant-scoped WHERE filters the row out; the typed NotFound
	// surfaces through mapWriteError and Get's typed NotFound branch.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, mErr := repo.MarkResolved(ctx, tx, fix.orgA.ID, bravoTarget.ID, "usr_alpha_attacker", base.Add(10*time.Second))
		return mErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	// Every orgB row must be byte-identical to its baseline.
	for _, baseline := range baselines {
		after := loadDriftFindingRowByID(ctx, t, db, baseline.ID)
		assertDriftFindingByteIdentical(t,
			"orgB bystander after orgA cross-tenant MarkResolved",
			baseline, after)
	}

	// Per-tenant counts unchanged: a misrouted phantom UPDATE under
	// orgA's tenant would not change orgB's count (since the row is
	// unchanged) but a regression that fell back to a non-tenant-
	// scoped INSERT (silently logging the resolve as a new finding)
	// would bump orgA's count.
	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID); got != priorAlphaCount {
		t.Errorf("after cross-tenant MarkResolved: orgA count = %d, want %d (the failed cross-tenant MarkResolved must not mint a phantom finding under orgA)",
			got, priorAlphaCount)
	}
	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID); got != priorBravoCount {
		t.Errorf("after cross-tenant MarkResolved: orgB count = %d, want %d (the failed cross-tenant MarkResolved must not alter the bystander tenant's count)",
			got, priorBravoCount)
	}
}

// TestDriftFindingOrganizationDeleteCascadeIsTenantScoped proves
// orgA's deletion cascades only to orgA's drift_findings. orgB's
// rows — including pending findings, resolved findings, and a row
// sharing the dokploy_resource_id text with orgA's pool — must remain
// byte-identical to their baselines. The drift_findings.organization_id
// FK CASCADE on organizations(id) is the cascade chain; a regression
// that dropped the organization_id leg of the FK (or scoped the
// cascade too widely) would surface here as either an orgB row
// vanishing or its columns drifting.
//
// The single-bystander variant of this cascade is already pinned by
// the invariants file's TestDriftFindingCascadeDeleteOnOrganization
// (which seeds one orgA row, no orgB rows). The BE-0472 variant
// deepens it with a three-row orgB pool covering the open / resolved /
// shared-dokploy_resource_id spread and a byte-identity assertion on
// every bystander row.
func TestDriftFindingOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	s := newStore(t, db)
	repo := store.NewDriftFindingRepository()

	fix := seedTwoTenantDriftFindingFixture(t, db, f)
	base := time.Now().UTC().Truncate(time.Microsecond)
	sharedDokployResourceID := "dokploy_application_cascade_shared"

	// orgA owns two rows (cascaded away). One of them shares the
	// dokploy_resource_id text with an orgB bystander so a regression
	// that cascaded by dokploy_resource_id rather than organization_id
	// would surface as the orgB row vanishing.
	alphaShared := store.DriftFinding{
		OrganizationID:    fix.orgA.ID,
		Kind:              store.DriftKindUnmanaged,
		Reason:            store.DriftReasonResourceUnmanaged,
		Level:             store.DriftLevelService,
		ProjectID:         fix.svcA.ProjectID,
		EnvironmentID:     fix.svcA.EnvironmentID,
		ServiceID:         fix.svcA.ID,
		DokployResourceID: sharedDokployResourceID,
		ParentDokployID:   "dokploy_project_alpha_cascade",
		RequestID:         "req_alpha_cascade_shared",
		CorrelationID:     "cor_alpha_cascade_shared",
		DetectedAt:        base,
	}
	seedDriftFinding(ctx, t, s, repo, alphaShared)
	seedDriftFinding(ctx, t, s, repo, driftFindingFixture(fix.orgA, fix.svcA, base.Add(time.Second)))

	// orgB row #1: pending, sharing the dokploy_resource_id text
	// with orgA's pool.
	bravoSharedResource := store.DriftFinding{
		OrganizationID:    fix.orgB.ID,
		Kind:              store.DriftKindUnmanaged,
		Reason:            store.DriftReasonResourceUnmanaged,
		Level:             store.DriftLevelService,
		ProjectID:         fix.svcB.ProjectID,
		EnvironmentID:     fix.svcB.EnvironmentID,
		ServiceID:         fix.svcB.ID,
		DokployResourceID: sharedDokployResourceID,
		ParentDokployID:   "dokploy_project_bravo_cascade",
		RequestID:         "req_bravo_cascade_shared",
		CorrelationID:     "cor_bravo_cascade_shared",
		DetectedAt:        base.Add(2 * time.Second),
	}
	bravoSharedStored := seedDriftFinding(ctx, t, s, repo, bravoSharedResource)

	// orgB row #2: pending, distinct dokploy_resource_id.
	bravoPending := seedDriftFinding(ctx, t, s, repo,
		driftFindingFixture(fix.orgB, fix.svcB, base.Add(3*time.Second)))

	// orgB row #3: resolved, pins the resolved_at / resolved_by_actor_id
	// projection.
	bravoToResolve := seedDriftFinding(ctx, t, s, repo,
		driftFindingFixture(fix.orgB, fix.svcB, base.Add(4*time.Second)))
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, mErr := repo.MarkResolved(ctx, tx, fix.orgB.ID, bravoToResolve.ID, "usr_bravo_resolver_cascade", base.Add(8*time.Second))
		return mErr
	}); err != nil {
		t.Fatalf("seed orgB MarkResolved: %v", err)
	}

	bravoBaselines := []rawDriftFindingRow{
		loadDriftFindingRowByID(ctx, t, db, bravoSharedStored.ID),
		loadDriftFindingRowByID(ctx, t, db, bravoPending.ID),
		loadDriftFindingRowByID(ctx, t, db, bravoToResolve.ID),
	}

	priorBravoCount := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID)
	if priorBravoCount != 3 {
		t.Fatalf("baseline orgB drift_findings count = %d, want 3", priorBravoCount)
	}

	// Cascade-delete orgA. The drift_findings.organization_id FK
	// CASCADE removes only the rows tagged with orgA.
	if _, err := db.Exec(ctx,
		`DELETE FROM organizations WHERE id = $1`, fix.orgA.ID); err != nil {
		t.Fatalf("DELETE orgA: %v", err)
	}

	// orgA's drift_findings rows must be gone.
	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgA.ID); got != 0 {
		t.Errorf("after orgA cascade: orgA count = %d, want 0", got)
	}

	// orgB's count must be unchanged.
	if got := countDriftFindingRowsForOrg(ctx, t, db, fix.orgB.ID); got != priorBravoCount {
		t.Errorf("after orgA cascade: orgB count = %d, want %d (the cascade crossed the organization_id predicate — worst-case data loss)",
			got, priorBravoCount)
	}

	// Every orgB row must be byte-identical to its baseline.
	for _, baseline := range bravoBaselines {
		after := loadDriftFindingRowByID(ctx, t, db, baseline.ID)
		assertDriftFindingByteIdentical(t,
			"orgB bystander after orgA cascade",
			baseline, after)
	}

	// ListByOrganization(orgB) after the cascade must still return
	// exactly orgB's row set — the cascade did not silently corrupt
	// the repository read predicate.
	var listed []store.DriftFinding
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var lErr error
		listed, lErr = repo.ListByOrganization(ctx, q, fix.orgB.ID, 100)
		return lErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB) after orgA cascade: %v", err)
	}
	if len(listed) != priorBravoCount {
		t.Errorf("ListByOrganization(orgB) after orgA cascade returned %d rows, want %d",
			len(listed), priorBravoCount)
	}
	for _, e := range listed {
		if e.OrganizationID != fix.orgB.ID {
			t.Errorf("ListByOrganization(orgB) after orgA cascade returned a row owned by org %q",
				e.OrganizationID)
		}
	}
}

// totalDriftFindingRows returns the global drift_findings row count.
// It is the global counterpart to countDriftFindingRowsForOrg, used by
// the cross-tenant id-collision test to prove a rolled-back PK
// violation did not land the failing row in some other tenant's slot —
// the per-tenant probe alone cannot prove the absence (the failing
// row's organization_id is unknown to the probe).
func totalDriftFindingRows(ctx context.Context, t *testing.T, db *testutil.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM drift_findings`).Scan(&n); err != nil {
		t.Fatalf("count drift_findings global: %v", err)
	}
	return n
}
