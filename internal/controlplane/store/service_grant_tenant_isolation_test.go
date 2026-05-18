package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Repository-layer tenant-isolation tests for the service_grants table
// (BE-0448). service_grants is a tenant-scoped grandchild table (service
// grants are parented to services, which are parented to environments,
// projects, and organizations) whose row body is anchored to a single
// tenant by THREE load-bearing schema facts:
//
//	(a) every column carries organization_id explicitly, and the
//	    composite FK (organization_id, service_id) -> services
//	    (organization_id, id) is MATCH SIMPLE — so a row whose service
//	    belongs to one tenant is structurally unrepresentable as another
//	    tenant's grant at the database layer. The BE-0447 invariants file
//	    already proves Upsert rejects the cross-tenant FK violation with
//	    a typed apierr.Conflict, so this file does not re-prove it.
//	(b) every repository method (ListByService / Upsert /
//	    DeleteByServiceExceptIDs) carries organization_id as the first
//	    SQL predicate, ahead of the service identifier. The cross-tenant
//	    guarantee at this layer is therefore the byte-identical-bystander
//	    invariant every other tenant-scoped table is held to.
//	(c) the unique index service_grants_principal_scope_idx targets the
//	    COMPOSITE tuple (organization_id, service_id, principal_id) —
//	    organization_id is in the conflict target itself, so two tenants
//	    can legitimately each own a row with the SAME principal_id on
//	    their OWN services. The shared-scope-tuple safety net below pins
//	    this and makes the byte-identical-bystander projection on Upsert
//	    load-bearing (a regression that resolved the conflict by the
//	    (service_id, principal_id) pair alone would have hit the peer
//	    tenant's row).
//
// service_grants is a STRUCTURAL SIMPLIFICATION of environment_grants:
// the service is the leaf of the Organization -> Project -> Environment
// -> Service hierarchy, so there is NO further nested scope pointer on
// the row (no service_id *string here — the service IS the scope). The
// UNIQUE conflict target therefore drops the COALESCE(service_id, '')
// leg and is a clean (organization_id, service_id, principal_id) triple.
// Every leg of the env_grant template that exercised the nullable
// pointer (round-trip pointer, NULL-COALESCE branch, bystander
// stringPtrEqual check) collapses to direct string equality on the row.
//
// The service_grants row body carries NO secret-bearing column — the
// principal_id / role triple is the capability the wire layer surfaces
// in clear text — so the BE-0434 raw-secret_hash probe has no analogue
// here. The row body is fully observable through the typed
// ListByService read path (there is no per-id Get for grants); the
// byte-identical-bystander assertion below covers every observable
// column (id, organization_id, service_id, principal_id, principal_kind,
// role, version, created_at, updated_at).
//
// The BEFORE-UPDATE service_grants_set_updated_at trigger refreshes
// updated_at on every matched UPDATE — including a WHERE-less or
// WHERE-on-scope-tuple-only UPDATE that touched the wrong tenant's row —
// and the service_grants_bump_version trigger increments version on the
// same path. Either of those two columns drifting on the bystander is
// independently sufficient to catch a missing tenant predicate even
// when the column writes themselves look correct, and every byte-
// identical-bystander test below asserts BOTH against the baseline.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Upsert INSERT RETURNING shape, Upsert UPDATE-branch dual-anchor
//     (updated_at refreshed, created_at preserved, version bumped,
//     caller-id ignored, principal_kind preserved), cross-tenant
//     service_id FK Conflict, duplicate-PK Conflict, ON DELETE CASCADE
//     from services, Upsert tx-rollback, and nil-Tx guards are proved by
//     service_grant_repository_invariants_test.go (BE-0447).
//   - ListByService deterministic ordering, non-nil empty slice, and the
//     basic ListByService tenant-scoping property (cross-tenant
//     serviceID returns an empty slice) are proved by
//     service_grant_test.go (BE-0445/0446's siblings for the service_grant
//     read surface).
//   - The HTTP-layer "another tenant's grant id is a 404, not a 403" rule
//     is proved by the per-endpoint policy matrix and contract tests in
//     httpapi.
//   - service_grants exposes NO per-id Get and NO per-id Delete on the
//     repository surface — the only mutation paths are Upsert (which
//     either INSERTs or fires the ON CONFLICT DO UPDATE branch) and
//     DeleteByServiceExceptIDs (bulk delete by exclusion). The byte-
//     identical-bystander projection is therefore observed through
//     ListByService (the only read surface for a grant row).
//   - service_grants has no deletion_scheduled_at / soft-delete column —
//     rows are hard-deleted in a single statement, and the cross-tenant
//     cascade behaviour (services deletion removing child grant rows)
//     belongs to the parent table. The acceptance-criteria mention of
//     "soft-deleted rows where applicable" therefore has no surface here;
//     documenting the deliberate absence keeps a future reader from
//     looking for a missing test (mirrors
//     environment_grant_tenant_isolation_test.go's no-soft-delete note
//     for environment_grants and api_key_scope_tenant_isolation_test.go
//     for api_key_scopes).
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.

// TestServiceGrantRepositoryListByServiceReturnsCorrectRowsAcrossTenants
// proves ListByService is keyed strictly by BOTH organization_id AND
// service_id: each tenant has its own service and its own grant row, and
// ListByService(orgA, svcA) / ListByService(orgB, svcB) must each return
// their own row — never a swapped or merged response. The two fixtures
// use different principal ids and roles per tenant so a
// WHERE-on-service_id-only mistake would diverge from the expected
// per-tenant values.
func TestServiceGrantRepositoryListByServiceReturnsCorrectRowsAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	grantA := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "alpha"), orgA.ID, svcA.ID,
		"usr_a", "usr", "developer")
	grantB := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "beta"), orgB.ID, svcB.ID,
		"usr_b", "usr", "viewer")

	listA := listServiceGrantsOrFail(ctx, t, s, repo, orgA.ID, svcA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByService(orgA, svcA) returned %d rows, want exactly 1 — orgB grant rows leaked", len(listA))
	}
	if listA[0].ID != grantA.ID || listA[0].OrganizationID != orgA.ID || listA[0].ServiceID != svcA.ID || listA[0].PrincipalID != "usr_a" || listA[0].Role != "developer" {
		t.Errorf("ListByService(orgA, svcA)[0] = %+v, want orgA/svcA/usr_a/developer", listA[0])
	}

	listB := listServiceGrantsOrFail(ctx, t, s, repo, orgB.ID, svcB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByService(orgB, svcB) returned %d rows, want exactly 1 — orgA grant rows leaked", len(listB))
	}
	if listB[0].ID != grantB.ID || listB[0].OrganizationID != orgB.ID || listB[0].ServiceID != svcB.ID || listB[0].PrincipalID != "usr_b" || listB[0].Role != "viewer" {
		t.Errorf("ListByService(orgB, svcB)[0] = %+v, want orgB/svcB/usr_b/viewer", listB[0])
	}

	// The two reads MUST have returned distinct rows on EVERY anchor —
	// id, organization_id, service_id, principal_id, role. A
	// WHERE-on-service_id-only or WHERE-less SELECT would have collapsed
	// both lookups onto the same response, and an overlap on any single
	// anchor would surface here.
	if listA[0].ID == listB[0].ID || listA[0].OrganizationID == listB[0].OrganizationID ||
		listA[0].ServiceID == listB[0].ServiceID || listA[0].PrincipalID == listB[0].PrincipalID ||
		listA[0].Role == listB[0].Role {
		t.Errorf("ListByService returned overlapping rows across two tenants: %+v vs %+v", listA[0], listB[0])
	}
}

// TestServiceGrantRepositoryListByServiceCrossTenantServiceIDReturnsEmpty
// proves ListByService is tenant scoped at the SQL predicate: a
// cross-tenant service_id (a real service in another organization)
// matches no rows and yields a non-nil empty slice, and an unknown
// service_id under the same organization lands on the same empty-slice
// shape. A probing caller cannot infer the existence of a peer tenant's
// service from the response either.
//
// The basic "cross-tenant serviceID returns empty" property is also
// asserted by service_grant_test.go's
// TestServiceGrantRepoListByServiceIsTenantScoped; this file's
// contribution is the indistinguishability projection: cross-tenant
// serviceID and unknown-id-under-own-tenant render the SAME response
// shape (non-nil empty slice) so the cross-tenant probe is not a
// "does this serviceID exist?" oracle.
func TestServiceGrantRepositoryListByServiceCrossTenantServiceIDReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web-b")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcB := seedService(t, db, f, envB, "api-b")
	// orgB owns two grants on its own service — exactly what a
	// regression would have leaked through if the WHERE-on-service_id-
	// only mistake resolved against the orgA call.
	upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "leak1"), orgB.ID, svcB.ID,
		"usr_x", "usr", "developer")
	upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "leak2"), orgB.ID, svcB.ID,
		"usr_y", "usr", "viewer")

	// orgA passes orgB's real service_id. The composite predicate
	// (organization_id = orgA AND service_id = orgB's svc) matches no
	// rows and returns an empty (non-nil) slice — never another
	// tenant's grants.
	crossTenant := listServiceGrantsOrFail(ctx, t, s, repo, orgA.ID, svcB.ID)
	if len(crossTenant) != 0 {
		t.Errorf("ListByService(orgA, svcB) returned %d rows, want 0 — orgB grants leaked through a cross-tenant service_id", len(crossTenant))
	}
	if crossTenant == nil {
		t.Error("ListByService(orgA, svcB) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice so callers can iterate without a nil check")
	}

	// And an unknown service_id under orgA lands on the same empty-
	// slice shape — the cross-tenant probe must not be distinguishable
	// from "no such service at all".
	unknown := listServiceGrantsOrFail(ctx, t, s, repo, orgA.ID, "svc_never_existed")
	if len(unknown) != 0 {
		t.Errorf("ListByService(orgA, unknown) returned %d rows, want 0", len(unknown))
	}
	if unknown == nil {
		t.Error("ListByService(orgA, unknown) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice")
	}
}

// TestServiceGrantRepositoryListByServiceIsolatesSharedPrincipal proves
// that when both tenants have a grant row whose principal_id and role
// are IDENTICAL — but on their OWN respective services — each
// ListByService call renders only THIS tenant's row, never the other's,
// never a duplicate. principal_id is a string field that can
// legitimately repeat across tenants (the principal could be the same
// human / service-account-id-string referenced under both tenants from
// the customer's perspective, or a coincidentally identical string),
// and a regression that resolved the WHERE filter by principal_id alone
// — without organization_id — would surface here as a leak.
func TestServiceGrantRepositoryListByServiceIsolatesSharedPrincipal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")
	// Same principal_id + role on two tenants' OWN services. The
	// (organization_id, service_id, principal_id) UNIQUE conflict
	// target is per-tenant, so both rows coexist.
	grantA := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "shared-a"), orgA.ID, svcA.ID,
		"usr_shared", "usr", "developer")
	grantB := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "shared-b"), orgB.ID, svcB.ID,
		"usr_shared", "usr", "developer")

	listA := listServiceGrantsOrFail(ctx, t, s, repo, orgA.ID, svcA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByService(orgA, svcA) returned %d rows, want exactly 1 — orgB row for the same principal_id leaked or duplicated", len(listA))
	}
	if listA[0].ID != grantA.ID || listA[0].OrganizationID != orgA.ID {
		t.Errorf("ListByService(orgA, svcA)[0] = %+v, want id=%q org=%q", listA[0], grantA.ID, orgA.ID)
	}

	listB := listServiceGrantsOrFail(ctx, t, s, repo, orgB.ID, svcB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByService(orgB, svcB) returned %d rows, want exactly 1 — orgA row for the same principal_id leaked or duplicated", len(listB))
	}
	if listB[0].ID != grantB.ID || listB[0].OrganizationID != orgB.ID {
		t.Errorf("ListByService(orgB, svcB)[0] = %+v, want id=%q org=%q", listB[0], grantB.ID, orgB.ID)
	}

	// The two responses must not overlap on grant id — if any id
	// appeared in both lists, the WHERE filter is the only thing
	// keeping them apart and the only way for both calls to share a
	// row is a WHERE-less SELECT.
	if listA[0].ID == listB[0].ID {
		t.Errorf("grant id %q appears in both List(orgA, svcA) and List(orgB, svcB) responses", listA[0].ID)
	}
}

// TestServiceGrantRepositoryUpsertInsertOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for the Upsert INSERT branch: when orgA
// inserts a fresh grant on its own service, orgB's bystander grant row —
// which legitimately shares the SAME principal_id on its own service —
// must be byte-identical to its baseline across EVERY observable column,
// including the trigger-managed updated_at and the trigger-bumped
// version (which would have stamped if the INSERT statement had somehow
// matched orgB's row).
//
// The fixture is the load-bearing case: BOTH tenants share the SAME
// principal_id on their OWN services, so a regression that resolved the
// ON CONFLICT branch by (service_id, principal_id) alone — without
// organization_id in the conflict target — would have UPDATEd orgB's
// row instead of INSERTing orgA's.
func TestServiceGrantRepositoryUpsertInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	// orgB's bystander row lands FIRST so the baseline timestamps and
	// version are stable before orgA mutates.
	grantB := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "bystander"), orgB.ID, svcB.ID,
		"usr_shared", "usr", "developer")
	baselineB := getServiceGrantFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, grantB.ID, "baseline")

	// orgA INSERTs a row with the IDENTICAL principal_id on its own
	// service. If the conflict target leaked across tenants this would
	// fire the UPDATE branch on orgB's row and refresh both updated_at
	// and version on the peer.
	insertedA := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "alpha"), orgA.ID, svcA.ID,
		"usr_shared", "usr", "developer")
	if insertedA.OrganizationID != orgA.ID || insertedA.ServiceID != svcA.ID || insertedA.Version != 1 {
		t.Errorf("Upsert(orgA, svcA) inserted row = %+v, want orgA/svcA/version=1", insertedA)
	}
	if insertedA.ID == grantB.ID {
		t.Fatalf("orgA's freshly inserted grant id %q collides with orgB's bystander id — the id mint is unsound and the bystander test below is invalid", insertedA.ID)
	}

	afterB := getServiceGrantFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, grantB.ID, "after orgA Upsert INSERT")
	assertServiceGrantByteIdentical(t, "Upsert INSERT(orgA) bystander orgB", baselineB, afterB)
}

// TestServiceGrantRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for the Upsert UPDATE branch: when orgA
// re-upserts its own grant (firing the ON CONFLICT DO UPDATE branch on
// its own row), orgB's bystander grant row — which legitimately shares
// the SAME principal_id on its own service — must be byte-identical to
// its baseline across EVERY observable column, including the trigger-
// managed updated_at and the trigger-bumped version, which are the
// independent anchors that catch a WHERE-on-scope-tuple-only UPDATE
// even when the column writes themselves happened to look correct.
//
// The fixture is the load-bearing case: BOTH tenants share the SAME
// principal_id on their OWN services, so a regression that resolved the
// ON CONFLICT branch by (service_id, principal_id) alone would have
// UPDATEd orgB's row in addition to (or instead of) orgA's.
func TestServiceGrantRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	// Both tenants seed an identical-principal grant first so the
	// re-upsert below fires the ON CONFLICT DO UPDATE branch on orgA's
	// row.
	grantA := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "alpha"), orgA.ID, svcA.ID,
		"usr_shared", "usr", "developer")
	grantB := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "bystander"), orgB.ID, svcB.ID,
		"usr_shared", "usr", "developer")

	baselineB := getServiceGrantFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, grantB.ID, "baseline")

	// orgA re-upserts the SAME principal_id with a different role. The
	// ON CONFLICT DO UPDATE branch fires on orgA's row only — the
	// per-tenant conflict target rules out orgB.
	updatedA := upsertServiceGrant(ctx, t, s, repo,
		// Caller-supplied id is IGNORED on the conflict branch — pass a
		// fresh one to prove that.
		newServiceGrantID(f, "alpha-rebump"), orgA.ID, svcA.ID,
		"usr_shared", "usr", "viewer")
	// orgA's row must have actually changed — a no-op repository
	// cannot silently pass the byte-identical-orgB check below.
	if updatedA.ID != grantA.ID {
		t.Errorf("UpdatedA.ID = %q, want %q (caller-id should be ignored on the conflict branch)", updatedA.ID, grantA.ID)
	}
	if updatedA.Role != "viewer" || updatedA.Version != grantA.Version+1 {
		t.Errorf("UpdatedA = %+v, want role=viewer version=%d", updatedA, grantA.Version+1)
	}

	afterB := getServiceGrantFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, grantB.ID, "after orgA Upsert UPDATE")
	assertServiceGrantByteIdentical(t, "Upsert UPDATE(orgA) bystander orgB", baselineB, afterB)
}

// TestServiceGrantRepositoryDeleteByServiceExceptIDsClearAllOnOrgADoesNotTouchOrgB
// is the byte-identical snapshot proof for the unconditional-DELETE
// codepath of DeleteByServiceExceptIDs: when orgA clears every grant on
// its own service (nil keepIDs), orgB's bystander grant row on its own
// service must be byte-identical to its baseline. The trigger would
// refresh updated_at if the DELETE statement had matched orgB's row
// even momentarily, even though a successful DELETE removes the row —
// the invariant is that orgB's stamps are untouched.
//
// DeleteByServiceExceptIDs has TWO codepaths in the repository
// (len(keepIDs)==0 -> unconditional DELETE; len>0 -> DELETE WHERE id
// NOT IN ANY); this test exercises the first one. The paired test below
// exercises the second.
func TestServiceGrantRepositoryDeleteByServiceExceptIDsClearAllOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	// orgA owns two grants on its own service — both should be
	// removed.
	upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "a1"), orgA.ID, svcA.ID,
		"usr_a1", "usr", "developer")
	upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "a2"), orgA.ID, svcA.ID,
		"usr_a2", "usr", "viewer")
	// orgB owns one grant on its own service — must survive
	// byte-identical.
	grantB := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "bystander"), orgB.ID, svcB.ID,
		"usr_b", "usr", "developer")
	baselineB := getServiceGrantFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, grantB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptIDs(ctx, tx, orgA.ID, svcA.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptIDs(orgA, svcA, nil): %v", err)
	}

	// orgA's service is now empty.
	if remaining := listServiceGrantsOrFail(ctx, t, s, repo, orgA.ID, svcA.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByServiceExceptIDs(orgA, svcA, nil) %d rows remain on orgA, want 0", len(remaining))
	}

	// orgB's service still has its row AND is byte-identical to its
	// baseline.
	afterB := getServiceGrantFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, grantB.ID, "after orgA DeleteByServiceExceptIDs(nil)")
	assertServiceGrantByteIdentical(t, "DeleteByServiceExceptIDs(orgA, nil) bystander orgB", baselineB, afterB)
}

// TestServiceGrantRepositoryDeleteByServiceExceptIDsKeepSubsetOnOrgADoesNotTouchOrgB
// is the byte-identical snapshot proof for the conditional-DELETE
// codepath of DeleteByServiceExceptIDs (len(keepIDs)>0 -> DELETE WHERE
// id NOT IN ANY): when orgA keeps a subset of its own grants and
// deletes the rest, orgB's bystander grant row on its own service must
// be byte-identical to its baseline. The id NOT IN ANY filter is the
// only thing that selects WHICH of orgA's rows survive, and a
// regression that dropped the tenant predicate would let the DELETE
// reach into orgB's grants (whose ids are NOT in keepIDs and would
// therefore become eligible for deletion).
func TestServiceGrantRepositoryDeleteByServiceExceptIDsKeepSubsetOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	keepA := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "keep"), orgA.ID, svcA.ID,
		"usr_a1", "usr", "developer")
	dropA := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "drop"), orgA.ID, svcA.ID,
		"usr_a2", "usr", "viewer")
	// orgB owns one grant on its own service — its id is deliberately
	// NOT in keepIDs (so a regression that lost the tenant predicate
	// would delete it through the "NOT IN ANY" branch).
	grantB := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "bystander"), orgB.ID, svcB.ID,
		"usr_b", "usr", "developer")
	baselineB := getServiceGrantFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, grantB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptIDs(ctx, tx, orgA.ID, svcA.ID, []string{keepA.ID})
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptIDs(orgA, svcA, [keepA]): %v", err)
	}

	// orgA's service now has exactly keepA — dropA was deleted.
	remaining := listServiceGrantsOrFail(ctx, t, s, repo, orgA.ID, svcA.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByServiceExceptIDs(orgA, svcA, [keepA]) %d rows remain on orgA, want 1", len(remaining))
	}
	if remaining[0].ID != keepA.ID {
		t.Errorf("survivor on orgA = %q, want keepA=%q", remaining[0].ID, keepA.ID)
	}
	if remaining[0].ID == dropA.ID {
		t.Errorf("dropA (%q) was retained; expected deletion", dropA.ID)
	}

	// orgB's service still has its row AND is byte-identical to its
	// baseline — even though orgB's id is NOT in keepIDs and would have
	// been eligible for deletion if the tenant predicate had been
	// dropped.
	afterB := getServiceGrantFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, grantB.ID, "after orgA DeleteByServiceExceptIDs([keepA])")
	assertServiceGrantByteIdentical(t, "DeleteByServiceExceptIDs(orgA, [keepA]) bystander orgB", baselineB, afterB)
}

// TestServiceGrantRepositoryUpsertSameScopeTupleInTwoTenantsBothSucceed
// proves the (organization_id, service_id, principal_id) UNIQUE
// constraint is per-tenant, not global: two tenants can legitimately
// each have a row with the SAME principal_id on their own respective
// services, and neither Upsert collides with the other. The flip side
// is the load-bearing reason every byte-identical-bystander test above
// asserts BOTH version and updated_at — if the (service_id,
// principal_id) pair alone were the UNIQUE key, two tenants could not
// share it, and the WHERE filter would be redundant.
func TestServiceGrantRepositoryUpsertSameScopeTupleInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	grantA := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "alpha"), orgA.ID, svcA.ID,
		"usr_shared", "usr", "developer")
	grantB := upsertServiceGrant(ctx, t, s, repo,
		newServiceGrantID(f, "beta"), orgB.ID, svcB.ID,
		"usr_shared", "usr", "developer")

	if grantA.ID == grantB.ID {
		t.Fatalf("two tenants minted the same grant id %q — the id generator collided, the byte-identical-bystander tests in this file are invalid", grantA.ID)
	}
	if grantA.OrganizationID == grantB.OrganizationID {
		t.Errorf("two grant rows landed under the SAME organization_id: %+v vs %+v", grantA, grantB)
	}
	if grantA.ServiceID == grantB.ServiceID {
		t.Errorf("two grant rows landed under the SAME service_id: %+v vs %+v", grantA, grantB)
	}
	if grantA.PrincipalID != "usr_shared" || grantB.PrincipalID != "usr_shared" {
		t.Errorf("principal_id drifted between Upsert calls: orgA=%q orgB=%q, want both 'usr_shared'", grantA.PrincipalID, grantB.PrincipalID)
	}
	if grantA.Role != "developer" || grantB.Role != "developer" {
		t.Errorf("role drifted between Upsert calls: orgA=%q orgB=%q, want both 'developer'", grantA.Role, grantB.Role)
	}
}

// --- shared helpers ---
//
// getServiceGrantFromListOrFail observes a single service_grants row
// through the repository's ListByService surface — the ONLY read path
// the repository exposes for grants — and returns the entry whose id
// matches the caller's. It fails the test on any error AND on the row's
// absence from the list; both are setup failures (the seeded row went
// missing) and not legs under proof in the byte-identical bystander
// cases.
//
// The api_key_scope tenant-isolation file uses a per-id Get for its
// equivalent helper; service_grants has no per-id Get on the repository
// surface, so the read is necessarily a list scan. The implementation
// favours correctness over efficiency — the lists are small (one or two
// rows) by construction.
//
// The name is intentionally distinct from
// environment_grant_tenant_isolation_test.go's
// getEnvironmentGrantFromListOrFail and from
// project_grant_tenant_isolation_test.go's getGrantFromListOrFail to
// avoid a same-package collision — every *_test.go file under
// internal/controlplane/store/ shares the same store_test package.
func getServiceGrantFromListOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceGrantRepository, organizationID, serviceID, grantID, label string) store.ServiceGrant {
	t.Helper()
	rows := listServiceGrantsOrFail(ctx, t, s, repo, organizationID, serviceID)
	for _, row := range rows {
		if row.ID == grantID {
			return row
		}
	}
	t.Fatalf("%s: grant %q missing from ListByService(%q, %q): got %d rows", label, grantID, organizationID, serviceID, len(rows))
	return store.ServiceGrant{}
}

// assertServiceGrantByteIdentical asserts every observable column on a
// bystander service_grants row is byte-identical to its baseline. The
// trigger-managed updated_at AND the trigger-bumped version are both
// load-bearing here: the BEFORE-UPDATE service_grants_set_updated_at
// trigger refreshes updated_at on every matched UPDATE, and the
// service_grants_bump_version trigger increments version — either
// drifting independently surfaces a missing tenant predicate even when
// the column writes themselves look correct.
//
// Unlike environment_grants and project_grants, service_grants has NO
// nullable scope pointer on the row body — the service IS the leaf
// scope — so the bystander check uses direct string equality on
// ServiceID and the package-level stringPtrEqual/fmtStringPtr helpers
// (defined in project_grant_tenant_isolation_test.go) are not needed
// here.
func assertServiceGrantByteIdentical(t *testing.T, label string, baseline, after store.ServiceGrant) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.ServiceID != baseline.ServiceID {
		t.Errorf("%s: bystander.service_id = %q, want %q", label, after.ServiceID, baseline.ServiceID)
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
	if after.Version != baseline.Version {
		t.Errorf("%s: bystander.version = %d, want %d — the service_grants_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE service_grants_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}
