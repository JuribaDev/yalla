package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Repository-layer tenant-isolation tests for the project_grants table
// (BE-0440). project_grants is a tenant-scoped grandchild table whose row
// body is anchored to a single tenant by THREE load-bearing schema facts:
//
//	(a) every column carries organization_id explicitly, and the
//	    composite FK (organization_id, project_id) -> projects
//	    (organization_id, id) is MATCH SIMPLE — so a row whose project
//	    belongs to one tenant is structurally unrepresentable as another
//	    tenant's grant at the database layer. The BE-0439 invariants file
//	    already proves Upsert rejects the cross-tenant FK violation with
//	    a typed apierr.Conflict, so this file does not re-prove it.
//	(b) every repository method (ListByProject / Upsert /
//	    DeleteByProjectExceptIDs) carries organization_id as the first
//	    SQL predicate, ahead of the project identifier. The cross-tenant
//	    guarantee at this layer is therefore the byte-identical-bystander
//	    invariant every other tenant-scoped table is held to.
//	(c) the ON CONFLICT target is the COMPOSITE tuple (organization_id,
//	    project_id, principal_id, COALESCE(environment_id, ''),
//	    COALESCE(service_id, '')) — organization_id is in the conflict
//	    target itself, so two tenants can legitimately each own a row
//	    with the SAME (principal_id, environment_id, service_id) tuple on
//	    their OWN projects. The shared-scope-tuple safety net below pins
//	    this and makes the byte-identical-bystander projection on Upsert
//	    load-bearing (a regression that resolved the conflict by the
//	    scope tuple alone would have hit the peer tenant's row).
//
// The project_grants row body carries NO secret-bearing column — the
// principal_id / role / environment_id / service_id triple is the
// capability the wire layer surfaces in clear text — so the BE-0434
// raw-secret_hash probe has no analogue here. The row body is fully
// observable through the typed ListByProject read path (there is no
// per-id Get for grants); the byte-identical-bystander assertion below
// covers every observable column (id, organization_id, project_id,
// principal_id, principal_kind, role, environment_id, service_id,
// version, created_at, updated_at).
//
// The BEFORE-UPDATE project_grants_set_updated_at trigger refreshes
// updated_at on every matched UPDATE — including a WHERE-less or
// WHERE-on-scope-tuple-only UPDATE that touched the wrong tenant's row
// — and the project_grants_bump_version trigger increments version on
// the same path. Either of those two columns drifting on the bystander
// is independently sufficient to catch a missing tenant predicate even
// when the column writes themselves look correct, and every
// byte-identical-bystander test below asserts BOTH against the baseline.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Upsert INSERT RETURNING shape, Upsert UPDATE-branch dual-anchor
//     (updated_at refreshed, created_at preserved, version bumped,
//     caller-id ignored, principal_kind preserved), cross-tenant
//     project_id FK Conflict, duplicate-PK Conflict, ON DELETE CASCADE
//     from projects, Upsert tx-rollback, and nil-Tx guards are proved by
//     project_grant_repository_invariants_test.go (BE-0439).
//   - ListByProject deterministic ordering, non-nil empty slice, the
//     basic ListByProject tenant-scoping property (cross-tenant
//     projectID returns an empty slice), and the ProjectGrantReader's
//     project-existence-check -> typed NotFound contract are proved by
//     project_grant_test.go.
//   - The HTTP-layer "another tenant's grant id is a 404, not a 403"
//     rule is proved by the per-endpoint policy matrix and contract
//     tests in httpapi.
//   - project_grants exposes NO per-id Get and NO per-id Delete on the
//     repository surface — the only mutation paths are Upsert (which
//     either INSERTs or fires the ON CONFLICT DO UPDATE branch) and
//     DeleteByProjectExceptIDs (bulk delete by exclusion). The
//     byte-identical-bystander projection is therefore observed
//     through ListByProject (the only read surface for a grant row).
//   - project_grants has no deletion_scheduled_at / soft-delete column —
//     rows are hard-deleted in a single statement, and the cross-tenant
//     cascade behaviour (projects deletion removing child grant rows)
//     belongs to the parent table. The acceptance-criteria mention of
//     "soft-deleted rows where applicable" therefore has no surface
//     here; documenting the deliberate absence keeps a future reader
//     from looking for a missing test (mirrors
//     api_key_scope_tenant_isolation_test.go's no-soft-delete note for
//     api_key_scopes).
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.

// TestProjectGrantRepositoryListByProjectReturnsCorrectRowsAcrossTenants
// proves ListByProject is keyed strictly by BOTH organization_id AND
// project_id: each tenant has its own project and its own grant row,
// and ListByProject(orgA, projA) / ListByProject(orgB, projB) must each
// return their own row — never a swapped or merged response. The two
// fixtures use different principal ids and roles per tenant so a
// WHERE-on-project_id-only mistake would diverge from the expected
// per-tenant values.
func TestProjectGrantRepositoryListByProjectReturnsCorrectRowsAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	grantA := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "alpha"), orgA.ID, projA.ID,
		"usr_a", "usr", "developer", nil, nil)
	grantB := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "beta"), orgB.ID, projB.ID,
		"usr_b", "usr", "viewer", nil, nil)

	listA := listGrantsOrFail(ctx, t, s, repo, orgA.ID, projA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByProject(orgA, projA) returned %d rows, want exactly 1 — orgB grant rows leaked", len(listA))
	}
	if listA[0].ID != grantA.ID || listA[0].OrganizationID != orgA.ID || listA[0].ProjectID != projA.ID || listA[0].PrincipalID != "usr_a" || listA[0].Role != "developer" {
		t.Errorf("ListByProject(orgA, projA)[0] = %+v, want orgA/projA/usr_a/developer", listA[0])
	}

	listB := listGrantsOrFail(ctx, t, s, repo, orgB.ID, projB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByProject(orgB, projB) returned %d rows, want exactly 1 — orgA grant rows leaked", len(listB))
	}
	if listB[0].ID != grantB.ID || listB[0].OrganizationID != orgB.ID || listB[0].ProjectID != projB.ID || listB[0].PrincipalID != "usr_b" || listB[0].Role != "viewer" {
		t.Errorf("ListByProject(orgB, projB)[0] = %+v, want orgB/projB/usr_b/viewer", listB[0])
	}

	// The two reads MUST have returned distinct rows on EVERY anchor —
	// id, organization_id, project_id, principal_id, role. A
	// WHERE-on-project_id-only or WHERE-less SELECT would have
	// collapsed both lookups onto the same response, and an overlap on
	// any single anchor would surface here.
	if listA[0].ID == listB[0].ID || listA[0].OrganizationID == listB[0].OrganizationID ||
		listA[0].ProjectID == listB[0].ProjectID || listA[0].PrincipalID == listB[0].PrincipalID ||
		listA[0].Role == listB[0].Role {
		t.Errorf("ListByProject returned overlapping rows across two tenants: %+v vs %+v", listA[0], listB[0])
	}
}

// TestProjectGrantRepositoryListByProjectCrossTenantProjectIDReturnsEmpty
// proves ListByProject is tenant scoped at the SQL predicate: a
// cross-tenant project_id (a real project in another organization)
// matches no rows and yields a non-nil empty slice, and an unknown
// project_id under the same organization lands on the same empty-slice
// shape. A probing caller cannot infer the existence of a peer
// tenant's project from the response either.
//
// The basic "cross-tenant projectID returns empty" property is also
// asserted by project_grant_test.go's
// TestProjectGrantRepoListByProjectIsTenantScoped; this file's
// contribution is the indistinguishability projection: cross-tenant
// projectID and unknown-id-under-own-tenant render the SAME response
// shape (non-nil empty slice) so the cross-tenant probe is not a
// "does this projectID exist?" oracle.
func TestProjectGrantRepositoryListByProjectCrossTenantProjectIDReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web-b")
	// orgB owns two grants on its own project — exactly what a
	// regression would have leaked through if the WHERE-on-project_id-
	// only mistake resolved against the orgA call.
	upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "leak1"), orgB.ID, projB.ID,
		"usr_x", "usr", "developer", nil, nil)
	upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "leak2"), orgB.ID, projB.ID,
		"usr_y", "usr", "viewer", nil, nil)

	// orgA passes orgB's real project_id. The composite predicate
	// (organization_id = orgA AND project_id = orgB's project) matches
	// no rows and returns an empty (non-nil) slice — never another
	// tenant's grants.
	crossTenant := listGrantsOrFail(ctx, t, s, repo, orgA.ID, projB.ID)
	if len(crossTenant) != 0 {
		t.Errorf("ListByProject(orgA, projB) returned %d rows, want 0 — orgB grants leaked through a cross-tenant project_id", len(crossTenant))
	}
	if crossTenant == nil {
		t.Error("ListByProject(orgA, projB) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice so callers can iterate without a nil check")
	}

	// And an unknown project_id under orgA lands on the same empty-
	// slice shape — the cross-tenant probe must not be distinguishable
	// from "no such project at all".
	unknown := listGrantsOrFail(ctx, t, s, repo, orgA.ID, "prj_never_existed")
	if len(unknown) != 0 {
		t.Errorf("ListByProject(orgA, unknown) returned %d rows, want 0", len(unknown))
	}
	if unknown == nil {
		t.Error("ListByProject(orgA, unknown) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice")
	}
}

// TestProjectGrantRepositoryListByProjectIsolatesSharedPrincipal proves
// that when both tenants have a grant row whose principal_id and role
// are IDENTICAL — but on their OWN respective projects — each
// ListByProject call renders only THIS tenant's row, never the
// other's, never a duplicate. principal_id is a string field that can
// legitimately repeat across tenants (the principal could be the same
// human / service-account-id-string referenced under both tenants from
// the customer's perspective, or a coincidentally identical string),
// and a regression that resolved the WHERE filter by principal_id
// alone — without organization_id — would surface here as a leak.
func TestProjectGrantRepositoryListByProjectIsolatesSharedPrincipal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	// Same principal_id + role on two tenants' OWN projects. The
	// (organization_id, project_id, principal_id, ...) UNIQUE conflict
	// target is per-tenant, so both rows coexist.
	grantA := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "shared-a"), orgA.ID, projA.ID,
		"usr_shared", "usr", "developer", nil, nil)
	grantB := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "shared-b"), orgB.ID, projB.ID,
		"usr_shared", "usr", "developer", nil, nil)

	listA := listGrantsOrFail(ctx, t, s, repo, orgA.ID, projA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByProject(orgA, projA) returned %d rows, want exactly 1 — orgB row for the same principal_id leaked or duplicated", len(listA))
	}
	if listA[0].ID != grantA.ID || listA[0].OrganizationID != orgA.ID {
		t.Errorf("ListByProject(orgA, projA)[0] = %+v, want id=%q org=%q", listA[0], grantA.ID, orgA.ID)
	}

	listB := listGrantsOrFail(ctx, t, s, repo, orgB.ID, projB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByProject(orgB, projB) returned %d rows, want exactly 1 — orgA row for the same principal_id leaked or duplicated", len(listB))
	}
	if listB[0].ID != grantB.ID || listB[0].OrganizationID != orgB.ID {
		t.Errorf("ListByProject(orgB, projB)[0] = %+v, want id=%q org=%q", listB[0], grantB.ID, orgB.ID)
	}

	// The two responses must not overlap on grant id — if any id
	// appeared in both lists, the WHERE filter is the only thing
	// keeping them apart and the only way for both calls to share a
	// row is a WHERE-less SELECT.
	if listA[0].ID == listB[0].ID {
		t.Errorf("grant id %q appears in both List(orgA, projA) and List(orgB, projB) responses", listA[0].ID)
	}
}

// TestProjectGrantRepositoryUpsertInsertOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for the Upsert INSERT branch: when
// orgA inserts a fresh grant on its own project, orgB's bystander
// grant row — which legitimately shares the SAME scope tuple
// (principal_id, environment_id, service_id) on its own project — must
// be byte-identical to its baseline across EVERY observable column,
// including the trigger-managed updated_at and the trigger-bumped
// version (which would have stamped if the INSERT statement had
// somehow matched orgB's row).
//
// The fixture is the load-bearing case: BOTH tenants share the SAME
// (principal_id, env, svc) tuple on their OWN projects, so a
// regression that resolved the ON CONFLICT branch by the scope tuple
// alone — without organization_id and project_id in the conflict
// target — would have UPDATEd orgB's row instead of INSERTing orgA's.
func TestProjectGrantRepositoryUpsertInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	// orgB's bystander row lands FIRST so the baseline timestamps and
	// version are stable before orgA mutates.
	grantB := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "bystander"), orgB.ID, projB.ID,
		"usr_shared", "usr", "developer", nil, nil)
	baselineB := getGrantFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, grantB.ID, "baseline")

	// orgA INSERTs a row with the IDENTICAL scope tuple on its own
	// project. If the conflict target leaked across tenants this would
	// fire the UPDATE branch on orgB's row and refresh both
	// updated_at and version on the peer.
	insertedA := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "alpha"), orgA.ID, projA.ID,
		"usr_shared", "usr", "developer", nil, nil)
	if insertedA.OrganizationID != orgA.ID || insertedA.ProjectID != projA.ID || insertedA.Version != 1 {
		t.Errorf("Upsert(orgA, projA) inserted row = %+v, want orgA/projA/version=1", insertedA)
	}
	if insertedA.ID == grantB.ID {
		t.Fatalf("orgA's freshly inserted grant id %q collides with orgB's bystander id — the id mint is unsound and the bystander test below is invalid", insertedA.ID)
	}

	afterB := getGrantFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, grantB.ID, "after orgA Upsert INSERT")
	assertGrantByteIdentical(t, "Upsert INSERT(orgA) bystander orgB", baselineB, afterB)
}

// TestProjectGrantRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for the Upsert UPDATE branch: when
// orgA re-upserts its own grant (firing the ON CONFLICT DO UPDATE
// branch on its own row), orgB's bystander grant row — which
// legitimately shares the SAME scope tuple (principal_id,
// environment_id, service_id) on its own project — must be
// byte-identical to its baseline across EVERY observable column,
// including the trigger-managed updated_at and the trigger-bumped
// version, which are the independent anchors that catch a WHERE-on-
// scope-tuple-only UPDATE even when the column writes themselves
// happened to look correct.
//
// The fixture is the load-bearing case: BOTH tenants share the SAME
// (principal_id, env, svc) tuple on their OWN projects, so a
// regression that resolved the ON CONFLICT branch by the scope tuple
// alone would have UPDATEd orgB's row in addition to (or instead of)
// orgA's.
func TestProjectGrantRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	// Both tenants seed an identical-scope-tuple grant first so the
	// re-upsert below fires the ON CONFLICT DO UPDATE branch on orgA's
	// row.
	envID := "env_e1"
	svcID := "svc_web"
	grantA := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "alpha"), orgA.ID, projA.ID,
		"usr_shared", "usr", "developer", &envID, &svcID)
	grantB := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "bystander"), orgB.ID, projB.ID,
		"usr_shared", "usr", "developer", &envID, &svcID)

	baselineB := getGrantFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, grantB.ID, "baseline")

	// orgA re-upserts the SAME scope tuple with a different role. The
	// ON CONFLICT DO UPDATE branch fires on orgA's row only — the
	// per-tenant conflict target rules out orgB.
	updatedA := upsertProjectGrant(ctx, t, s, repo,
		// Caller-supplied id is IGNORED on the conflict branch — pass a
		// fresh one to prove that.
		newProjectGrantID(f, "alpha-rebump"), orgA.ID, projA.ID,
		"usr_shared", "usr", "viewer", &envID, &svcID)
	// orgA's row must have actually changed — a no-op repository
	// cannot silently pass the byte-identical-orgB check below.
	if updatedA.ID != grantA.ID {
		t.Errorf("UpdatedA.ID = %q, want %q (caller-id should be ignored on the conflict branch)", updatedA.ID, grantA.ID)
	}
	if updatedA.Role != "viewer" || updatedA.Version != grantA.Version+1 {
		t.Errorf("UpdatedA = %+v, want role=viewer version=%d", updatedA, grantA.Version+1)
	}

	afterB := getGrantFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, grantB.ID, "after orgA Upsert UPDATE")
	assertGrantByteIdentical(t, "Upsert UPDATE(orgA) bystander orgB", baselineB, afterB)
}

// TestProjectGrantRepositoryDeleteByProjectExceptIDsClearAllOnOrgADoesNotTouchOrgB
// is the byte-identical snapshot proof for the unconditional-DELETE
// codepath of DeleteByProjectExceptIDs: when orgA clears every grant
// on its own project (nil keepIDs), orgB's bystander grant row on its
// own project must be byte-identical to its baseline. The trigger
// would refresh updated_at if the DELETE statement had matched orgB's
// row even momentarily, even though a successful DELETE removes the
// row — the invariant is that orgB's stamps are untouched.
//
// DeleteByProjectExceptIDs has TWO codepaths in the repository
// (len(keepIDs)==0 -> unconditional DELETE; len>0 -> DELETE WHERE id
// NOT IN ANY); this test exercises the first one. The paired test
// below exercises the second.
func TestProjectGrantRepositoryDeleteByProjectExceptIDsClearAllOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	// orgA owns two grants on its own project — both should be
	// removed.
	upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "a1"), orgA.ID, projA.ID,
		"usr_a1", "usr", "developer", nil, nil)
	upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "a2"), orgA.ID, projA.ID,
		"usr_a2", "usr", "viewer", nil, nil)
	// orgB owns one grant on its own project — must survive
	// byte-identical.
	grantB := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "bystander"), orgB.ID, projB.ID,
		"usr_b", "usr", "developer", nil, nil)
	baselineB := getGrantFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, grantB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptIDs(ctx, tx, orgA.ID, projA.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptIDs(orgA, projA, nil): %v", err)
	}

	// orgA's project is now empty.
	if remaining := listGrantsOrFail(ctx, t, s, repo, orgA.ID, projA.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByProjectExceptIDs(orgA, projA, nil) %d rows remain on orgA, want 0", len(remaining))
	}

	// orgB's project still has its row AND is byte-identical to its
	// baseline.
	afterB := getGrantFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, grantB.ID, "after orgA DeleteByProjectExceptIDs(nil)")
	assertGrantByteIdentical(t, "DeleteByProjectExceptIDs(orgA, nil) bystander orgB", baselineB, afterB)
}

// TestProjectGrantRepositoryDeleteByProjectExceptIDsKeepSubsetOnOrgADoesNotTouchOrgB
// is the byte-identical snapshot proof for the conditional-DELETE
// codepath of DeleteByProjectExceptIDs (len(keepIDs)>0 -> DELETE WHERE
// id NOT IN ANY): when orgA keeps a subset of its own grants and
// deletes the rest, orgB's bystander grant row on its own project
// must be byte-identical to its baseline. The id NOT IN ANY filter is
// the only thing that selects WHICH of orgA's rows survive, and a
// regression that dropped the tenant predicate would let the DELETE
// reach into orgB's grants (whose ids are NOT in keepIDs and would
// therefore become eligible for deletion).
func TestProjectGrantRepositoryDeleteByProjectExceptIDsKeepSubsetOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	keepA := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "keep"), orgA.ID, projA.ID,
		"usr_a1", "usr", "developer", nil, nil)
	dropA := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "drop"), orgA.ID, projA.ID,
		"usr_a2", "usr", "viewer", nil, nil)
	// orgB owns one grant on its own project — its id is deliberately
	// NOT in keepIDs (so a regression that lost the tenant predicate
	// would delete it through the "NOT IN ANY" branch).
	grantB := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "bystander"), orgB.ID, projB.ID,
		"usr_b", "usr", "developer", nil, nil)
	baselineB := getGrantFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, grantB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptIDs(ctx, tx, orgA.ID, projA.ID, []string{keepA.ID})
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptIDs(orgA, projA, [keepA]): %v", err)
	}

	// orgA's project now has exactly keepA — dropA was deleted.
	remaining := listGrantsOrFail(ctx, t, s, repo, orgA.ID, projA.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByProjectExceptIDs(orgA, projA, [keepA]) %d rows remain on orgA, want 1", len(remaining))
	}
	if remaining[0].ID != keepA.ID {
		t.Errorf("survivor on orgA = %q, want keepA=%q", remaining[0].ID, keepA.ID)
	}
	if remaining[0].ID == dropA.ID {
		t.Errorf("dropA (%q) was retained; expected deletion", dropA.ID)
	}

	// orgB's project still has its row AND is byte-identical to its
	// baseline — even though orgB's id is NOT in keepIDs and would
	// have been eligible for deletion if the tenant predicate had
	// been dropped.
	afterB := getGrantFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, grantB.ID, "after orgA DeleteByProjectExceptIDs([keepA])")
	assertGrantByteIdentical(t, "DeleteByProjectExceptIDs(orgA, [keepA]) bystander orgB", baselineB, afterB)
}

// TestProjectGrantRepositoryUpsertSameScopeTupleInTwoTenantsBothSucceed
// proves the (organization_id, project_id, principal_id,
// COALESCE(environment_id, ”), COALESCE(service_id, ”)) UNIQUE
// constraint is per-tenant, not global: two tenants can legitimately
// each have a row with the SAME (principal_id, env, svc) tuple on
// their own respective projects, and neither Upsert collides with the
// other. The flip side is the load-bearing reason every byte-
// identical-bystander test above asserts BOTH version and updated_at
// — if the scope tuple alone were the UNIQUE key, two tenants could
// not share it, and the WHERE filter would be redundant.
//
// The (env, svc) pointers are non-nil here so the COALESCE(...,”)
// branch of the conflict target is exercised (not just the
// NULL-COALESCE-to-empty-string fallback).
func TestProjectGrantRepositoryUpsertSameScopeTupleInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	envID := "env_e1"
	svcID := "svc_web"
	grantA := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "alpha"), orgA.ID, projA.ID,
		"usr_shared", "usr", "developer", &envID, &svcID)
	grantB := upsertProjectGrant(ctx, t, s, repo,
		newProjectGrantID(f, "beta"), orgB.ID, projB.ID,
		"usr_shared", "usr", "developer", &envID, &svcID)

	if grantA.ID == grantB.ID {
		t.Fatalf("two tenants minted the same grant id %q — the id generator collided, the byte-identical-bystander tests in this file are invalid", grantA.ID)
	}
	if grantA.OrganizationID == grantB.OrganizationID {
		t.Errorf("two grant rows landed under the SAME organization_id: %+v vs %+v", grantA, grantB)
	}
	if grantA.ProjectID == grantB.ProjectID {
		t.Errorf("two grant rows landed under the SAME project_id: %+v vs %+v", grantA, grantB)
	}
	if grantA.PrincipalID != "usr_shared" || grantB.PrincipalID != "usr_shared" {
		t.Errorf("principal_id drifted between Upsert calls: orgA=%q orgB=%q, want both 'usr_shared'", grantA.PrincipalID, grantB.PrincipalID)
	}
	if grantA.EnvironmentID == nil || *grantA.EnvironmentID != envID ||
		grantB.EnvironmentID == nil || *grantB.EnvironmentID != envID {
		t.Errorf("environment_id pointer did not round-trip across tenants: orgA=%v orgB=%v, want both *=%q", grantA.EnvironmentID, grantB.EnvironmentID, envID)
	}
	if grantA.ServiceID == nil || *grantA.ServiceID != svcID ||
		grantB.ServiceID == nil || *grantB.ServiceID != svcID {
		t.Errorf("service_id pointer did not round-trip across tenants: orgA=%v orgB=%v, want both *=%q", grantA.ServiceID, grantB.ServiceID, svcID)
	}
}

// --- shared helpers ---
//
// getGrantFromListOrFail observes a single project_grants row through
// the repository's ListByProject surface — the ONLY read path the
// repository exposes for grants — and returns the entry whose id
// matches the caller's. It fails the test on any error AND on the
// row's absence from the list; both are setup failures (the seeded
// row went missing) and not legs under proof in the byte-identical
// bystander cases.
//
// The api_key_scope tenant-isolation file uses a per-id Get for its
// equivalent helper; project_grants has no per-id Get on the
// repository surface, so the read is necessarily a list scan. The
// implementation favours correctness over efficiency — the lists are
// small (one or two rows) by construction.
func getGrantFromListOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.ProjectGrantRepository, organizationID, projectID, grantID, label string) store.ProjectGrant {
	t.Helper()
	rows := listGrantsOrFail(ctx, t, s, repo, organizationID, projectID)
	for _, row := range rows {
		if row.ID == grantID {
			return row
		}
	}
	t.Fatalf("%s: grant %q missing from ListByProject(%q, %q): got %d rows", label, grantID, organizationID, projectID, len(rows))
	return store.ProjectGrant{}
}

// assertGrantByteIdentical asserts every observable column on a
// bystander project_grants row is byte-identical to its baseline. The
// trigger-managed updated_at AND the trigger-bumped version are both
// load-bearing here: the BEFORE-UPDATE project_grants_set_updated_at
// trigger refreshes updated_at on every matched UPDATE, and the
// project_grants_bump_version trigger increments version — either
// drifting independently surfaces a missing tenant predicate even
// when the column writes themselves look correct.
//
// EnvironmentID and ServiceID are nullable *string pointers; the
// equality check matches "both nil" OR "both non-nil and equal", so a
// regression that resolved one of those pointers incorrectly on the
// bystander surface would be caught regardless of the original
// nullability.
func assertGrantByteIdentical(t *testing.T, label string, baseline, after store.ProjectGrant) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.ProjectID != baseline.ProjectID {
		t.Errorf("%s: bystander.project_id = %q, want %q", label, after.ProjectID, baseline.ProjectID)
	}
	if after.PrincipalID != baseline.PrincipalID {
		t.Errorf("%s: bystander.principal_id = %q, want %q", label, after.PrincipalID, baseline.PrincipalID)
	}
	if after.PrincipalKind != baseline.PrincipalKind {
		t.Errorf("%s: bystander.principal_kind = %q, want %q", label, after.PrincipalKind, baseline.PrincipalKind)
	}
	if after.Role != baseline.Role {
		t.Errorf("%s: bystander.role = %q, want %q", label, after.Role, baseline.Role)
	}
	if !stringPtrEqual(after.EnvironmentID, baseline.EnvironmentID) {
		t.Errorf("%s: bystander.environment_id = %s, want %s", label, fmtStringPtr(after.EnvironmentID), fmtStringPtr(baseline.EnvironmentID))
	}
	if !stringPtrEqual(after.ServiceID, baseline.ServiceID) {
		t.Errorf("%s: bystander.service_id = %s, want %s", label, fmtStringPtr(after.ServiceID), fmtStringPtr(baseline.ServiceID))
	}
	if after.Version != baseline.Version {
		t.Errorf("%s: bystander.version = %d, want %d — the project_grants_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE project_grants_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}

// stringPtrEqual reports whether two *string values point to the same
// string content, treating two nil pointers as equal. It is a local
// helper for assertGrantByteIdentical's nullable-pointer column
// comparisons (environment_id, service_id).
func stringPtrEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// fmtStringPtr renders a *string for a t.Errorf format — either
// "<nil>" or the quoted value — so a failing assertion shows the
// nullability and the value side by side.
func fmtStringPtr(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return `"` + *p + `"`
}
