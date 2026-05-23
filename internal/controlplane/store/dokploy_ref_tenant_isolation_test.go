package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the dokploy_refs table
// (BE-0466). dokploy_refs is the polymorphic mapping from a Yalla resource
// (identified by (organization_id, yalla_kind, yalla_id)) to a Dokploy
// object (identified by (dokploy_resource, dokploy_id), globally unique).
// A row that belongs to one tenant is anchored to that tenant by:
//
//	(a) the organization_id column itself, with an
//	    ON DELETE CASCADE FK to organizations(id);
//	(b) every DokployRefRepository write/read going through the
//	    organization_id predicate as the non-optional left leg:
//	    Insert is tenant-attributed by the input, Get / GetByDokployTarget /
//	    ListByYallaResource / ListByOrganization / Delete all filter by
//	    organization_id first.
//
// The DokployRefRepository surface this file exercises against the
// cross-tenant boundary: Insert, Get, GetByDokployTarget,
// ListByYallaResource, ListByOrganization, Delete. The dokploy_refs row
// has no customer-mutable column so there is no Update method to exercise
// (see BE-0465 file header).
//
// The table carries TWO UNIQUE invariants with very different
// cross-tenant shapes; both are pinned here because they are
// load-bearing for a tenant-isolation regression that would surface
// nowhere else:
//
//   - GLOBAL UNIQUE (dokploy_resource, dokploy_id): a Dokploy object can
//     NEVER be claimed by two tenants. The cross-tenant probe is the
//     mirror of the per-tenant Conflict pinned in
//     dokploy_ref_repository_invariants_test.go's
//     TestDokployRefRepositoryInsertDuplicateDokployTargetIsConflict, with
//     the added invariant that orgA's row (the original owner) is
//     byte-identical AFTER orgB's rejected Insert — a regression that
//     widened the UNIQUE to (organization_id, dokploy_resource, dokploy_id)
//     would let orgB's row through and surface as a UNIQUE drift in
//     migration tests; a regression that erased the row before the UNIQUE
//     fired would surface here as a column drift on orgA's bystander row.
//     The same probe also pins the no-side-effect read shape of
//     GetByDokployTarget: orgB calling GetByDokployTarget(orgB,
//     resource, alphaDokployID) must return NotFound even though the
//     globally-unique target tuple resolves to orgA's existing row —
//     the per-tenant predicate is the gate, not the GLOBAL UNIQUE.
//
//   - PER-TENANT UNIQUE (organization_id, yalla_id, dokploy_resource,
//     dokploy_id): the positive-direction shape is that two tenants can
//     each hold the same yalla_kind / dokploy_resource pair under THEIR
//     OWN yalla_id and dokploy_id — i.e. there is no UNIQUE on
//     (yalla_kind, dokploy_resource) or (yalla_id, dokploy_resource)
//     alone. Without this test, a regression that resolved a phantom
//     UNIQUE on either of those tuples would prevent orgA's Insert (the
//     parent FK already disallows a cross-tenant organization_id, so the
//     regression would surface as a duplicate-row Conflict) and every
//     byte-identical assertion in the bystander tests would silently
//     pass against an unmutated row that was never written.
//
// This file pins the cross-tenant invariants of every customer-facing
// surface and the cross-tenant invariant of the organizations cascade
// edge:
//
//   - Insert(orgA) cross-tenant bystander byte-identity: when orgB
//     already owns several dokploy_refs rows (across different
//     yalla_kinds and dokploy_resources, including the global-UNIQUE
//     collide-target probe) an Insert on orgA mints a fresh row owned by
//     orgA and leaves every observable column on every orgB row
//     byte-identical to its baseline. A foreign-tenant UPDATE that snuck
//     past the organization_id predicate would surface here as a column
//     rewrite or a created_at/updated_at drift on any bystander.
//   - Insert(orgA) per-tenant row-count invariant: orgB's per-org count
//     and orgA's per-org count change as expected (+1 for the writer,
//     unchanged for the bystander) — neither lower (an accidental
//     cross-tenant DELETE) nor higher (an accidental cross-tenant
//     INSERT) on the bystander.
//   - Insert(orgA, dokploy_id already owned by orgB) is the cross-tenant
//     mirror of the global-UNIQUE Conflict: the typed apierr.Conflict
//     surfaces and orgB's pre-existing row is byte-identical after the
//     rejection. The per-tenant count for orgB stays at 1 and the
//     per-tenant count for orgA stays at 0 (the failed Insert leaves no
//     row behind).
//   - Same (yalla_kind, dokploy_resource) in two tenants both persist:
//     UNIQUE (organization_id, yalla_id, dokploy_resource, dokploy_id) is
//     per-tenant, so two tenants each holding the same yalla_kind /
//     dokploy_resource pair against THEIR OWN service is the expected
//     concurrent shape. ListByYallaResource is the read-side proof of
//     the same shape — each tenant's list resolves to that tenant's row
//     only, never cross-tenant.
//   - Get(orgB, alphaRef.ID) cross-tenant rejection: the call returns a
//     typed apierr.NotFound and the not-found payload names only the
//     mapping id the caller already supplied — never a foreign
//     yalla_id, dokploy_id, yalla_kind, or dokploy_resource. Get's
//     numeric id parameter means the message never has an opportunity
//     to echo orgA's identifiers unless the regression looked them up
//     and embedded them, so the explicit no-substring checks here are
//     the second-line defence behind the apierr.NotFound code probe.
//   - GetByDokployTarget(orgB, resource, alphaDokployID) cross-tenant
//     rejection: this is the load-bearing dokploy_refs-specific probe
//     because the GLOBAL UNIQUE means the row exists at (resource,
//     dokploy_id) — the tenant predicate is the ONLY thing hiding it.
//     A regression that dropped the organization_id predicate would
//     surface a successful read of orgA's row here.
//   - ListByYallaResource(orgB, alphaKind, alphaYallaID) cross-tenant:
//     returns an empty slice and the per-tenant COUNT(*) is unaffected
//     — the response never leaks a total-rows hint from another tenant
//     and the read itself has no side effect on the underlying table.
//     The yalla_id leg is not globally unique (the domain package mints
//     yalla_ids per-resource so collisions are improbable, not
//     impossible) so the test seeds orgB's yalla_id verbatim into the
//     orgA-scoped query input as the worst-case probe.
//   - ListByOrganization(orgB) cross-tenant: returns only orgB's rows
//     even when orgA owns several mappings under the same (yalla_kind,
//     dokploy_resource) combinations, and the per-tenant COUNT(*) is
//     unaffected by orgB's read.
//   - Delete(orgB, alphaRef.ID) cross-tenant rejection: the call
//     returns typed apierr.NotFound (via the tag.RowsAffected() == 0
//     path) AND orgA's row is byte-identical after the call. A
//     regression that dropped the organization_id predicate would
//     surface as either tag.RowsAffected() == 1 (orgB's call returns
//     nil and orgA's row vanishes — the worst-case data-loss bug) or
//     as an orgA bystander column drift.
//   - organizations DELETE cascade is tenant-scoped: deleting orgA
//     removes only orgA's dokploy_refs rows. orgB's mappings must
//     remain byte-identical to their baseline. A regression that
//     dropped the organization_id leg of the FK would surface here as
//     orgB rows vanishing.
//
// What this file deliberately delegates:
//
//   - The application-level validation matrix (blank yalla_kind, blank
//     dokploy_resource, nil tx, unknown CHECK / FK values, the
//     transaction-rollback-persists-no-row probe, the SetUpdatedAt
//     trigger behaviour, and the within-tenant Insert/Get/Delete happy
//     paths) is pinned by dokploy_ref_repository_invariants_test.go.
//   - The HTTP envelope shape (yalla.output.v1 / yalla.error.v1) is a
//     transport-layer concern; the repository surface returns typed
//     apierr values and the HTTP layer's contract tests render the
//     envelope. Cross-tenant repository tests assert the typed apierr
//     code only.
//   - dokploy_refs stores NO secret-bearing column: dokploy_id is an
//     opaque identifier minted by Dokploy (not a token), and no other
//     column stores tokens, API keys, cookies, or rendered environment
//     variable values — so the BE-0434-style raw-secret probe has no
//     analogue here. Per the BE-0466 acceptance criteria, secrets,
//     tokens, API keys, cookies, and rendered environment variable
//     values would be redacted; the dokploy_refs table simply does not
//     carry any.
//
// Database-backed cases run against an isolated, freshly migrated
// Postgres and skip when YALLA_TEST_DATABASE_URL is unset.

// assertDokployRefByteIdentical asserts every observable column on a
// bystander dokploy_refs row is byte-identical to its baseline. The
// table has no version column (see the BE-0465 file header) but it does
// have an updated_at column maintained by the dokploy_refs_set_updated_at
// trigger — any foreign-tenant UPDATE that snuck past the
// organization_id predicate would fire the trigger and surface here as
// an updated_at drift, in addition to whichever business column the
// rewrite touched. Every business column is compared individually so a
// rewrite of any one would surface as a named field diff in the failure
// message.
func assertDokployRefByteIdentical(t *testing.T, label string, baseline, after rawDokployRefRow) {
	t.Helper()
	if after.ID != baseline.ID {
		t.Errorf("%s: bystander.id = %d, want %d", label, after.ID, baseline.ID)
	}
	if after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander.organization_id = %q, want %q",
			label, after.OrganizationID, baseline.OrganizationID)
	}
	if after.YallaKind != baseline.YallaKind {
		t.Errorf("%s: bystander.yalla_kind = %q, want %q",
			label, after.YallaKind, baseline.YallaKind)
	}
	if after.YallaID != baseline.YallaID {
		t.Errorf("%s: bystander.yalla_id = %q, want %q",
			label, after.YallaID, baseline.YallaID)
	}
	if after.DokployResource != baseline.DokployResource {
		t.Errorf("%s: bystander.dokploy_resource = %q, want %q",
			label, after.DokployResource, baseline.DokployResource)
	}
	if after.DokployID != baseline.DokployID {
		t.Errorf("%s: bystander.dokploy_id = %q, want %q — a foreign-tenant write rewrote a globally-unique target id",
			label, after.DokployID, baseline.DokployID)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v — created_at drifted on a bystander row, which means an UPDATE crossed the organization_id predicate",
			label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — updated_at drifted on a bystander row, which means an UPDATE fired the set_updated_at trigger on a foreign tenant's row",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}

// twoTenantDokployRefFixture pairs orgA and orgB hierarchies so per-test
// bodies focus on the cross-tenant invariant rather than the boilerplate
// of minting two independent (org -> project -> env -> service) chains.
// The per-file DokRef suffix is mandatory: every *_test.go file under
// internal/controlplane/store/ shares the same store_test package, and
// the parallel twoTenantJobAttemptFixture / twoTenantDeploymentFixture /
// etc. already exist.
type twoTenantDokployRefFixture struct {
	orgA  testutil.Organization
	projA testutil.Project
	envA  testutil.Environment
	svcA  testutil.Service
	orgB  testutil.Organization
	projB testutil.Project
	envB  testutil.Environment
	svcB  testutil.Service
}

func seedTwoTenantDokployRefFixture(
	t *testing.T,
	db *testutil.DB,
	f *testutil.Factory,
) twoTenantDokployRefFixture {
	t.Helper()
	orgA := seedOrg(t, db, f, "tenant-a")
	projA := seedProject(t, db, f, orgA, "web")
	envA := seedEnvironment(t, db, f, projA, "prod")
	svcA := seedService(t, db, f, envA, "api")

	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web")
	envB := seedEnvironment(t, db, f, projB, "prod")
	svcB := seedService(t, db, f, envB, "api")

	return twoTenantDokployRefFixture{
		orgA: orgA, projA: projA, envA: envA, svcA: svcA,
		orgB: orgB, projB: projB, envB: envB, svcB: svcB,
	}
}

// firstDokployRefDokployID returns the dokploy_id of the first element of
// out (or "<empty>" when the slice is empty) so the parent test's diff
// messages can name which row was actually returned. This is the same
// shape every read-back list assertion in the repository test files uses
// informally; centralising it here keeps the per-test bodies focused on
// the assertion.
func firstDokployRefDokployID(out []store.DokployRef) string {
	if len(out) == 0 {
		return "<empty>"
	}
	return out[0].DokployID
}

// TestDokployRefRepositoryInsertOnOrgADoesNotTouchOrgB proves the
// load-bearing cross-tenant invariant of Insert: when orgB already owns
// several dokploy_refs rows (across different yalla_kinds and
// dokploy_resources) an Insert on orgA mints a fresh row owned by orgA
// and leaves every observable column on every orgB row byte-identical to
// its baseline. The bystander set deliberately covers a project mapping,
// a service-application mapping, and a service-domain mapping so a
// regression that rewrote yalla_kind / dokploy_resource on a foreign
// tenant's row would surface here as a per-row field diff.
func TestDokployRefRepositoryInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDokployRefFixture(t, db, f)

	bravoProject := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindProject,
		YallaID:         fix.projB.ID,
		DokployResource: store.DokployResourceProject,
		DokployID:       mintDokployID(t, "bravo-proj"),
	})
	bravoApp := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcB.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "bravo-app"),
	})
	bravoDomain := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcB.ID,
		DokployResource: store.DokployResourceDomain,
		DokployID:       mintDokployID(t, "bravo-domain"),
	})

	baselineProject := loadDokployRefRowByID(ctx, t, db, bravoProject.ID)
	baselineApp := loadDokployRefRowByID(ctx, t, db, bravoApp.ID)
	baselineDomain := loadDokployRefRowByID(ctx, t, db, bravoDomain.ID)

	// orgA inserts a mapping under ITS OWN service for the same
	// (yalla_kind, dokploy_resource) pair as bravoApp. Per-tenant UNIQUE
	// (organization_id, yalla_id, dokploy_resource, dokploy_id) is the
	// only UNIQUE that can match this shape, so the INSERT must mint a
	// fresh row owned by orgA — never UPDATE orgB's app row.
	created := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "alpha-app"),
	})
	if created.OrganizationID != fix.orgA.ID {
		t.Fatalf("Insert lifted organization_id = %q, want %q (orgA's Insert was attributed to the wrong tenant)",
			created.OrganizationID, fix.orgA.ID)
	}
	if created.ID == bravoApp.ID {
		t.Fatalf("Insert returned orgB's mapping id %d — the INSERT silently UPDATEd orgB's row instead of minting a fresh row for orgA",
			created.ID)
	}

	assertDokployRefByteIdentical(t,
		"orgB project bystander after orgA Insert",
		baselineProject, loadDokployRefRowByID(ctx, t, db, bravoProject.ID))
	assertDokployRefByteIdentical(t,
		"orgB application bystander (same kind/resource as orgA's new row) after orgA Insert",
		baselineApp, loadDokployRefRowByID(ctx, t, db, bravoApp.ID))
	assertDokployRefByteIdentical(t,
		"orgB domain bystander after orgA Insert",
		baselineDomain, loadDokployRefRowByID(ctx, t, db, bravoDomain.ID))
}

// TestDokployRefRepositoryInsertOnOrgADoesNotChangeOrgBRowCount proves
// the per-tenant row count is invariant under another tenant's Insert.
// orgB owns two mappings before orgA makes any call; orgA then inserts
// one. orgB's count must remain at 2 — neither lower (an accidental
// cross-tenant DELETE) nor higher (an accidental cross-tenant INSERT).
// orgA's count goes from 0 to 1. This complements the byte-identity
// bystander proof above: a regression that silently dropped one orgB row
// and minted a new one with the same content would defeat the
// byte-identity test but trip here.
func TestDokployRefRepositoryInsertOnOrgADoesNotChangeOrgBRowCount(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDokployRefFixture(t, db, f)

	_ = runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcB.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "bravo-count-app"),
	})
	_ = runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcB.ID,
		DokployResource: store.DokployResourceDomain,
		DokployID:       mintDokployID(t, "bravo-count-domain"),
	})

	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgB.ID); n != 2 {
		t.Fatalf("baseline orgB count = %d, want 2 — test fixture is invalid", n)
	}
	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgA.ID); n != 0 {
		t.Fatalf("baseline orgA count = %d, want 0 — test fixture is invalid", n)
	}

	_ = runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "alpha-count-app"),
	})

	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgB.ID); n != 2 {
		t.Errorf("orgB count after Insert(orgA, ...) = %d, want 2 — orgA's Insert touched orgB", n)
	}
	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgA.ID); n != 1 {
		t.Errorf("orgA count after Insert(orgA, ...) = %d, want 1 — orgA's Insert did not land", n)
	}
}

// TestDokployRefRepositoryInsertCrossTenantDokployIDIsConflictAndBystanderByteIdentical
// proves the dokploy_refs-specific cross-tenant invariant of the GLOBAL
// UNIQUE (dokploy_resource, dokploy_id): when orgB already owns a row at
// some (resource, dokployID), an Insert on orgA that supplies the same
// (resource, dokployID) is rejected with a typed apierr.Conflict AND
// orgB's row is byte-identical after the rejection. orgA's count stays
// at 0; orgB's count stays at 1.
//
// This is the cross-tenant mirror of
// TestDokployRefRepositoryInsertDuplicateDokployTargetIsConflict (which
// asserts the typed Conflict code but not the bystander byte-identity).
// A regression that widened the global UNIQUE to (organization_id,
// dokploy_resource, dokploy_id) would let orgA's INSERT through and
// surface as orgA.count == 1; a regression that silently UPDATEd orgB's
// row before the UNIQUE fired would surface as a yalla_kind / yalla_id
// rewrite on the bystander.
func TestDokployRefRepositoryInsertCrossTenantDokployIDIsConflictAndBystanderByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDokployRefFixture(t, db, f)

	contestedDokployID := mintDokployID(t, "contested-app")
	bravoOriginal := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcB.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       contestedDokployID,
	})
	baseline := loadDokployRefRowByID(ctx, t, db, bravoOriginal.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, iErr := repo.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  fix.orgA.ID,
			YallaKind:       store.YallaKindService,
			YallaID:         fix.svcA.ID,
			DokployResource: store.DokployResourceApplication,
			DokployID:       contestedDokployID,
		})
		return iErr
	})
	if err == nil {
		t.Fatal("Insert with cross-tenant dokploy_id returned nil, want typed Conflict (GLOBAL UNIQUE) — a Dokploy object must never be claimed twice across tenants")
	}
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeConflict {
		t.Errorf("cross-tenant duplicate Insert error = %v, want code %s", err, yerr.CodeConflict)
	}

	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgA.ID); n != 0 {
		t.Errorf("rejected cross-tenant Insert persisted %d rows under orgA, want 0", n)
	}
	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgB.ID); n != 1 {
		t.Errorf("after cross-tenant Insert rejection, orgB has %d rows, want 1 (the original)", n)
	}

	assertDokployRefByteIdentical(t,
		"orgB original survives orgA's cross-tenant duplicate Insert byte-identically",
		baseline, loadDokployRefRowByID(ctx, t, db, bravoOriginal.ID))
}

// TestDokployRefRepositoryInsertSameYallaKindInTwoTenantsBothPersist is
// the load-bearing positive-direction pair for the bystander byte-identity
// proofs. UNIQUE (organization_id, yalla_id, dokploy_resource, dokploy_id)
// is per-tenant — there is no UNIQUE on (yalla_kind, dokploy_resource) or
// (yalla_id, dokploy_resource) alone — so two tenants each holding a row
// with the same yalla_kind + dokploy_resource pair against THEIR OWN
// service is the expected concurrent shape. Without this test, a
// regression that resolved a phantom UNIQUE on either of those tuples
// would prevent orgA's Insert (the parent FK already disallows a
// cross-tenant organization_id, so the regression would surface as a
// duplicate-row Conflict) and every byte-identical assertion in the
// bystander tests would silently pass against an unmutated row that was
// never written. The per-tenant ListByYallaResource round-trip is the
// read-side proof of the same shape: each tenant's list resolves to that
// tenant's row only, never cross-tenant.
func TestDokployRefRepositoryInsertSameYallaKindInTwoTenantsBothPersist(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDokployRefFixture(t, db, f)

	bravo := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcB.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "bravo-app"),
	})
	alpha := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "alpha-app"),
	})

	if alpha.OrganizationID != fix.orgA.ID {
		t.Errorf("alpha.OrganizationID = %q, want %q", alpha.OrganizationID, fix.orgA.ID)
	}
	if bravo.OrganizationID != fix.orgB.ID {
		t.Errorf("bravo.OrganizationID = %q, want %q", bravo.OrganizationID, fix.orgB.ID)
	}
	if alpha.ID == bravo.ID {
		t.Errorf("alpha.ID == bravo.ID (= %d): the two tenants must hold distinct mapping ids even with a shared (yalla_kind, dokploy_resource) pair against their respective services",
			alpha.ID)
	}
	if alpha.YallaKind != bravo.YallaKind || alpha.DokployResource != bravo.DokployResource {
		t.Errorf("alpha=(yalla_kind=%q,dokploy_resource=%q) bravo=(yalla_kind=%q,dokploy_resource=%q): the positive-direction probe must hold the (yalla_kind, dokploy_resource) pair invariant",
			alpha.YallaKind, alpha.DokployResource, bravo.YallaKind, bravo.DokployResource)
	}

	// ListByYallaResource must resolve each tenant's mapping to that
	// tenant's list only — never cross-tenant. This is the read-side
	// proof of the positive-direction shape.
	alphaList, err := repo.ListByYallaResource(ctx, db, fix.orgA.ID, store.YallaKindService, fix.svcA.ID)
	if err != nil {
		t.Fatalf("ListByYallaResource(orgA, service, svcA): %v", err)
	}
	if len(alphaList) != 1 || alphaList[0].ID != alpha.ID {
		t.Errorf("ListByYallaResource(orgA, service, svcA) = %d rows (first dokploy_id %q), want 1 row with id %d",
			len(alphaList), firstDokployRefDokployID(alphaList), alpha.ID)
	}
	bravoList, err := repo.ListByYallaResource(ctx, db, fix.orgB.ID, store.YallaKindService, fix.svcB.ID)
	if err != nil {
		t.Fatalf("ListByYallaResource(orgB, service, svcB): %v", err)
	}
	if len(bravoList) != 1 || bravoList[0].ID != bravo.ID {
		t.Errorf("ListByYallaResource(orgB, service, svcB) = %d rows (first dokploy_id %q), want 1 row with id %d",
			len(bravoList), firstDokployRefDokployID(bravoList), bravo.ID)
	}
}

// TestDokployRefRepositoryGetCrossTenantReturnsNotFoundAndDoesNotEcho
// proves Get(orgB, alphaRef.ID) is tenant-scoped at the SQL predicate AND
// that the not-found payload names only the mapping id the caller already
// supplied — never a foreign yalla_id, dokploy_id, yalla_kind, or
// dokploy_resource. A regression that resolved the composite
// (organization_id, id) by id alone would either return orgA's row
// (defeated by the assertion on the typed apierr.NotFound code) OR would
// attach orgA's foreign fields to the not-found details (defeated by the
// explicit no-leak substring checks below).
func TestDokployRefRepositoryGetCrossTenantReturnsNotFoundAndDoesNotEcho(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDokployRefFixture(t, db, f)

	// alpha owns a mapping with deliberately distinctive yalla_id and
	// dokploy_id suffixes — if a regression echoed either of them into
	// the not-found payload, the substring checks below would trip.
	alphaDokployID := mintDokployID(t, "no-echo-distinctive-alpha-dokploy")
	alpha := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       alphaDokployID,
	})

	_, err := repo.Get(ctx, db, fix.orgB.ID, alpha.ID)
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(cross-tenant) error = %v, want code %s (a cross-tenant id must surface as NotFound, never a successful read of another tenant's row)",
			err, yerr.CodeNotFound)
	}
	msg := err.Error()
	if containsValue(msg, alphaDokployID) {
		t.Errorf("Get(cross-tenant) error message %q echoed alpha's dokploy_id — the not-found payload must name only the supplied mapping id", msg)
	}
	if containsValue(msg, fix.svcA.ID) {
		t.Errorf("Get(cross-tenant) error message %q echoed alpha's yalla_id (svcA.ID) — the not-found payload must name only the supplied mapping id", msg)
	}
	if containsValue(msg, store.DokployResourceApplication.String()) {
		t.Errorf("Get(cross-tenant) error message %q echoed alpha's dokploy_resource — the not-found payload must name only the supplied mapping id", msg)
	}
}

// TestDokployRefRepositoryGetByDokployTargetCrossTenantReturnsNotFoundAndDoesNotEcho
// proves the load-bearing dokploy_refs-specific tenant-isolation
// invariant: the GLOBAL UNIQUE (dokploy_resource, dokploy_id) means a row
// at (resource, alphaDokployID) exists in the database, but the
// per-tenant predicate in GetByDokployTarget must hide it from orgB. The
// tenant predicate — not the UNIQUE — is the gate.
//
// A regression that dropped the organization_id predicate from
// GetByDokployTarget would surface here as a successful read of orgA's
// row from orgB's caller, the worst-case cross-tenant data-leak shape.
// The not-found payload echoes only the supplied dokploy_id (which the
// caller already has) and never the foreign yalla_id, yalla_kind, or
// mapping id.
func TestDokployRefRepositoryGetByDokployTargetCrossTenantReturnsNotFoundAndDoesNotEcho(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDokployRefFixture(t, db, f)

	alphaDokployID := mintDokployID(t, "target-echo-alpha-dokploy")
	alpha := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       alphaDokployID,
	})

	// orgB calls GetByDokployTarget with orgA's globally-unique dokploy
	// target. The (resource, dokploy_id) tuple resolves to a real row in
	// the database (under orgA), but the (organization_id, resource,
	// dokploy_id) predicate finds nothing for orgB.
	_, err := repo.GetByDokployTarget(ctx, db, fix.orgB.ID, store.DokployResourceApplication, alphaDokployID)
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByDokployTarget(cross-tenant) error = %v, want code %s — the GLOBAL UNIQUE row exists at this target tuple but the per-tenant predicate must hide it",
			err, yerr.CodeNotFound)
	}
	msg := err.Error()
	if containsValue(msg, fix.svcA.ID) {
		t.Errorf("GetByDokployTarget(cross-tenant) error message %q echoed alpha's yalla_id (svcA.ID) — the not-found payload must name only the supplied dokploy_id", msg)
	}
	if containsValue(msg, store.YallaKindService.String()) {
		// YallaKindService is the value "service"; we are checking the
		// raw string is not embedded in the not-found details. A
		// regression that pulled the row server-side before the
		// predicate filtered it would have access to yalla_kind and
		// might echo it.
		t.Errorf("GetByDokployTarget(cross-tenant) error message %q echoed alpha's yalla_kind — the not-found payload must name only the supplied dokploy_id", msg)
	}
	// Confirm the read had no side effect on the underlying row: orgA's
	// row count is still 1 and orgB's is still 0.
	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgA.ID); n != 1 {
		t.Errorf("after orgB's cross-tenant GetByDokployTarget, orgA count = %d, want 1 (the read leaked into a write)", n)
	}
	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgB.ID); n != 0 {
		t.Errorf("after orgB's cross-tenant GetByDokployTarget, orgB count = %d, want 0 (the read leaked into a write)", n)
	}

	// Sanity: orgA itself can read the row through GetByDokployTarget.
	// Without this the entire test could silently pass even if the
	// repository broke for both tenants.
	got, err := repo.GetByDokployTarget(ctx, db, fix.orgA.ID, store.DokployResourceApplication, alphaDokployID)
	if err != nil {
		t.Fatalf("GetByDokployTarget(orgA, ...) sanity: %v", err)
	}
	if got.ID != alpha.ID {
		t.Errorf("GetByDokployTarget(orgA, ...).ID = %d, want %d (sanity)", got.ID, alpha.ID)
	}
}

// TestDokployRefRepositoryListByYallaResourceCrossTenantReturnsEmptyAndDoesNotLeakTotal
// proves ListByYallaResource(orgB, alphaKind, alphaYallaID) returns an
// empty slice AND the per-tenant COUNT(*) for both orgA and orgB is
// unaffected — no count is leaked through the response shape or through
// a side effect on the underlying table. The acceptance criterion "List
// queries return stable pagination without leaking total counts from
// other tenants" is pinned here: the response carries no total-count
// field and the foreign-tenant query returns zero rows even when the
// underlying organization owns several mappings under the same
// (yalla_kind, yalla_id) shape.
//
// The yalla_id leg is the parent service id minted by the domain
// package, which is per-tenant scoped (it's globally distinct in
// practice but not by schema) — the worst-case probe seeds orgB's call
// with orgA's yalla_id verbatim. A regression that dropped the
// organization_id predicate would surface here as a non-empty slice.
func TestDokployRefRepositoryListByYallaResourceCrossTenantReturnsEmptyAndDoesNotLeakTotal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDokployRefFixture(t, db, f)

	// orgA owns three mappings under its service: an application and
	// two domains.
	_ = runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "alpha-list-app"),
	})
	_ = runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceDomain,
		DokployID:       mintDokployID(t, "alpha-list-domain-1"),
	})
	_ = runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceDomain,
		DokployID:       mintDokployID(t, "alpha-list-domain-2"),
	})

	baselineCountA := countDokployRefRowsForOrg(ctx, t, db, fix.orgA.ID)
	if baselineCountA != 3 {
		t.Fatalf("baseline orgA count = %d, want 3 — test fixture is invalid", baselineCountA)
	}
	baselineCountB := countDokployRefRowsForOrg(ctx, t, db, fix.orgB.ID)
	if baselineCountB != 0 {
		t.Fatalf("baseline orgB count = %d, want 0 — test fixture is invalid", baselineCountB)
	}

	// orgB queries orgA's service — the (organization_id, yalla_kind,
	// yalla_id) predicate matches no row, so the empty slice is returned.
	// The lookup is never an oracle that reveals orgA's mapping history.
	list, err := repo.ListByYallaResource(ctx, db, fix.orgB.ID, store.YallaKindService, fix.svcA.ID)
	if err != nil {
		t.Fatalf("ListByYallaResource(cross-tenant): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("ListByYallaResource(cross-tenant) returned %d rows, want 0 (alpha's mappings must not leak through bravo's predicate)", len(list))
	}

	// Reading must not have side-effected the underlying counts.
	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgA.ID); n != baselineCountA {
		t.Errorf("orgA count after cross-tenant List = %d, want %d (a read leaked into a write)", n, baselineCountA)
	}
	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgB.ID); n != baselineCountB {
		t.Errorf("orgB count after cross-tenant List = %d, want %d (a read leaked into a write)", n, baselineCountB)
	}
}

// TestDokployRefRepositoryListByOrganizationCrossTenantReturnsOnlyOwnRows
// proves ListByOrganization(orgB) returns only orgB's rows even when
// orgA owns several mappings under the same (yalla_kind,
// dokploy_resource) combinations as orgB. The acceptance criterion "List
// queries return stable pagination without leaking total counts from
// other tenants" is pinned here: the response carries no total-count
// field and a per-tenant query returns only that tenant's rows.
//
// A regression that dropped the organization_id predicate from
// ListByOrganization would surface as len(orgB's list) >= 2 (orgA's two
// rows would leak through).
func TestDokployRefRepositoryListByOrganizationCrossTenantReturnsOnlyOwnRows(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDokployRefFixture(t, db, f)

	// orgA owns two mappings.
	alphaApp := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "alpha-orglist-app"),
	})
	alphaDomain := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceDomain,
		DokployID:       mintDokployID(t, "alpha-orglist-domain"),
	})

	// orgB owns one mapping, deliberately at the same (yalla_kind,
	// dokploy_resource) shape as alphaApp.
	bravoApp := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcB.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "bravo-orglist-app"),
	})

	bravoList, err := repo.ListByOrganization(ctx, db, fix.orgB.ID)
	if err != nil {
		t.Fatalf("ListByOrganization(orgB): %v", err)
	}
	if len(bravoList) != 1 {
		t.Fatalf("ListByOrganization(orgB) returned %d rows, want 1 — alpha's rows leaked through bravo's predicate (first dokploy_id %q)",
			len(bravoList), firstDokployRefDokployID(bravoList))
	}
	if bravoList[0].ID != bravoApp.ID {
		t.Errorf("ListByOrganization(orgB)[0].ID = %d, want %d (orgB resolved to the wrong row)",
			bravoList[0].ID, bravoApp.ID)
	}
	if bravoList[0].OrganizationID != fix.orgB.ID {
		t.Errorf("ListByOrganization(orgB)[0].OrganizationID = %q, want %q",
			bravoList[0].OrganizationID, fix.orgB.ID)
	}

	// Sanity: orgA's list still contains both of orgA's rows. Without
	// this the previous assertion could pass against a regression that
	// silently emptied both lists.
	alphaList, err := repo.ListByOrganization(ctx, db, fix.orgA.ID)
	if err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(alphaList) != 2 {
		t.Fatalf("ListByOrganization(orgA) returned %d rows, want 2", len(alphaList))
	}
	foundApp, foundDomain := false, false
	for _, ref := range alphaList {
		if ref.ID == alphaApp.ID {
			foundApp = true
		}
		if ref.ID == alphaDomain.ID {
			foundDomain = true
		}
		if ref.OrganizationID != fix.orgA.ID {
			t.Errorf("ListByOrganization(orgA): row %d carried organization_id %q, want %q",
				ref.ID, ref.OrganizationID, fix.orgA.ID)
		}
	}
	if !foundApp || !foundDomain {
		t.Errorf("ListByOrganization(orgA) missing rows: foundApp=%v foundDomain=%v", foundApp, foundDomain)
	}
}

// TestDokployRefRepositoryDeleteCrossTenantReturnsNotFoundAndOrgARowSurvives
// proves Delete(orgB, alphaRef.ID) is tenant-scoped at the SQL predicate
// (the tag.RowsAffected() == 0 path surfaces apierr.NotFound) AND orgA's
// row is byte-identical after the call. A regression that dropped the
// organization_id leg from the DELETE predicate would surface as either
// tag.RowsAffected() == 1 (orgB's call returns nil and orgA's row
// vanishes — the worst-case data-loss bug) or as an orgA bystander
// column drift.
//
// This is the gap-fill:
// dokploy_ref_repository_invariants_test.go's
// TestDokployRefRepositoryDeleteUnknownReturnsTypedNotFound already
// asserts the typed NotFound code for an unknown id, but does NOT pin
// the cross-tenant byte-identity invariant — the failing-NotFound path
// runs against a row that does not exist, while this test runs against a
// row that exists under a foreign tenant.
func TestDokployRefRepositoryDeleteCrossTenantReturnsNotFoundAndOrgARowSurvives(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDokployRefFixture(t, db, f)

	alpha := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "alpha-delete-target"),
	})
	baseline := loadDokployRefRowByID(ctx, t, db, alpha.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, fix.orgB.ID, alpha.ID)
	})
	if ye := yerr.From(err); ye == nil || ye.Code != yerr.CodeNotFound {
		t.Fatalf("Delete(cross-tenant) error = %v, want code %s (a cross-tenant id must surface as NotFound, never silently delete another tenant's row)",
			err, yerr.CodeNotFound)
	}

	// orgA's row must still exist AND be byte-identical to its baseline.
	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgA.ID); n != 1 {
		t.Errorf("after orgB's cross-tenant Delete, orgA count = %d, want 1 — the DELETE crossed the organization_id predicate (worst-case data loss)", n)
	}
	assertDokployRefByteIdentical(t,
		"orgA bystander after orgB's cross-tenant Delete",
		baseline, loadDokployRefRowByID(ctx, t, db, alpha.ID))
}

// TestDokployRefOrganizationDeleteCascadeIsTenantScoped proves orgA's
// deletion cascades only to orgA's dokploy_refs. orgB's mappings must
// remain byte-identical to their baseline. The dokploy_refs.organization_id
// FK CASCADE on organizations(id) is the cascade chain; a regression
// that dropped the organization_id leg of the FK would surface here as
// either an orgB row vanishing or its business columns drifting.
//
// The same-tenant cascade (deleting an organization removes its own
// mappings) is already pinned by
// dokploy_ref_repository_invariants_test.go's
// TestDokployRefRepositoryOrganizationDeleteCascades; this is the
// cross-tenant variant the tenant-isolation pattern requires.
func TestDokployRefOrganizationDeleteCascadeIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewDokployRefRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	fix := seedTwoTenantDokployRefFixture(t, db, f)

	// orgA owns two mappings (cascaded away). orgB owns three mappings
	// across different yalla_kinds and dokploy_resources (survive
	// byte-identically) so the bystander assertion is anchored against
	// a representative spread.
	_ = runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "alpha-cascade-app"),
	})
	_ = runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgA.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcA.ID,
		DokployResource: store.DokployResourceDomain,
		DokployID:       mintDokployID(t, "alpha-cascade-domain"),
	})

	bravoProject := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindProject,
		YallaID:         fix.projB.ID,
		DokployResource: store.DokployResourceProject,
		DokployID:       mintDokployID(t, "bravo-cascade-proj"),
	})
	bravoApp := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcB.ID,
		DokployResource: store.DokployResourceApplication,
		DokployID:       mintDokployID(t, "bravo-cascade-app"),
	})
	bravoDomain := runInsertDokployRefOrFail(ctx, t, s, repo, store.DokployRef{
		OrganizationID:  fix.orgB.ID,
		YallaKind:       store.YallaKindService,
		YallaID:         fix.svcB.ID,
		DokployResource: store.DokployResourceDomain,
		DokployID:       mintDokployID(t, "bravo-cascade-domain"),
	})

	baselineProject := loadDokployRefRowByID(ctx, t, db, bravoProject.ID)
	baselineApp := loadDokployRefRowByID(ctx, t, db, bravoApp.ID)
	baselineDomain := loadDokployRefRowByID(ctx, t, db, bravoDomain.ID)

	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, fix.orgA.ID); err != nil {
		t.Fatalf("delete orgA: %v", err)
	}

	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgA.ID); n != 0 {
		t.Errorf("dokploy_refs rows for orgA after delete = %d, want 0 (cascade must remove the deleted tenant's rows)", n)
	}
	if n := countDokployRefRowsForOrg(ctx, t, db, fix.orgB.ID); n != 3 {
		t.Errorf("dokploy_refs rows for orgB after orgA delete = %d, want 3 — the cascade bled into another tenant", n)
	}

	assertDokployRefByteIdentical(t,
		"orgB project bystander survives orgA delete",
		baselineProject, loadDokployRefRowByID(ctx, t, db, bravoProject.ID))
	assertDokployRefByteIdentical(t,
		"orgB application bystander survives orgA delete",
		baselineApp, loadDokployRefRowByID(ctx, t, db, bravoApp.ID))
	assertDokployRefByteIdentical(t,
		"orgB domain bystander survives orgA delete",
		baselineDomain, loadDokployRefRowByID(ctx, t, db, bravoDomain.ID))
}
