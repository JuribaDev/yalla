package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Repository-layer tenant-isolation tests for the environment_grants
// table (BE-0444). environment_grants is a tenant-scoped grandchild table
// (env_grants are parented to environments, which are parented to
// projects, which are parented to organizations) whose row body is
// anchored to a single tenant by THREE load-bearing schema facts:
//
//	(a) every column carries organization_id explicitly, and the
//	    composite FK (organization_id, environment_id) -> environments
//	    (organization_id, id) is MATCH SIMPLE — so a row whose
//	    environment belongs to one tenant is structurally unrepresentable
//	    as another tenant's grant at the database layer. The BE-0443
//	    invariants file already proves Upsert rejects the cross-tenant
//	    FK violation with a typed apierr.Conflict, so this file does not
//	    re-prove it.
//	(b) every repository method (ListByEnvironment / Upsert /
//	    DeleteByEnvironmentExceptIDs) carries organization_id as the
//	    first SQL predicate, ahead of the environment identifier. The
//	    cross-tenant guarantee at this layer is therefore the byte-
//	    identical-bystander invariant every other tenant-scoped table is
//	    held to.
//	(c) the unique index environment_grants_principal_scope_idx targets
//	    the COMPOSITE tuple (organization_id, environment_id, principal_id,
//	    COALESCE(service_id, '')) — organization_id is in the conflict
//	    target itself, so two tenants can legitimately each own a row
//	    with the SAME (principal_id, service_id) tuple on their OWN
//	    environments. The shared-scope-tuple safety net below pins this
//	    and makes the byte-identical-bystander projection on Upsert
//	    load-bearing (a regression that resolved the conflict by the
//	    scope tuple alone would have hit the peer tenant's row).
//
// The environment_grants row body carries NO secret-bearing column — the
// principal_id / role / service_id triple is the capability the wire
// layer surfaces in clear text — so the BE-0434 raw-secret_hash probe
// has no analogue here. The row body is fully observable through the
// typed ListByEnvironment read path (there is no per-id Get for grants);
// the byte-identical-bystander assertion below covers every observable
// column (id, organization_id, environment_id, principal_id,
// principal_kind, role, service_id, version, created_at, updated_at).
//
// The BEFORE-UPDATE environment_grants_set_updated_at trigger refreshes
// updated_at on every matched UPDATE — including a WHERE-less or
// WHERE-on-scope-tuple-only UPDATE that touched the wrong tenant's row —
// and the environment_grants_bump_version trigger increments version on
// the same path. Either of those two columns drifting on the bystander
// is independently sufficient to catch a missing tenant predicate even
// when the column writes themselves look correct, and every byte-
// identical-bystander test below asserts BOTH against the baseline.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Upsert INSERT RETURNING shape, Upsert UPDATE-branch dual-anchor
//     (updated_at refreshed, created_at preserved, version bumped,
//     caller-id ignored, principal_kind preserved), cross-tenant
//     environment_id FK Conflict, duplicate-PK Conflict, ON DELETE
//     CASCADE from environments, Upsert tx-rollback, and nil-Tx guards
//     are proved by environment_grant_repository_invariants_test.go
//     (BE-0443).
//   - ListByEnvironment deterministic ordering, non-nil empty slice, the
//     basic ListByEnvironment tenant-scoping property (cross-tenant
//     environmentID returns an empty slice), and the
//     EnvironmentGrantReader's environment-existence-check -> typed
//     NotFound contract are proved by environment_grant_test.go.
//   - The HTTP-layer "another tenant's grant id is a 404, not a 403"
//     rule is proved by the per-endpoint policy matrix and contract
//     tests in httpapi.
//   - environment_grants exposes NO per-id Get and NO per-id Delete on
//     the repository surface — the only mutation paths are Upsert (which
//     either INSERTs or fires the ON CONFLICT DO UPDATE branch) and
//     DeleteByEnvironmentExceptIDs (bulk delete by exclusion). The
//     byte-identical-bystander projection is therefore observed through
//     ListByEnvironment (the only read surface for a grant row).
//   - environment_grants has no deletion_scheduled_at / soft-delete
//     column — rows are hard-deleted in a single statement, and the
//     cross-tenant cascade behaviour (environments deletion removing
//     child grant rows) belongs to the parent table. The acceptance-
//     criteria mention of "soft-deleted rows where applicable"
//     therefore has no surface here; documenting the deliberate absence
//     keeps a future reader from looking for a missing test (mirrors
//     project_grant_tenant_isolation_test.go's no-soft-delete note for
//     project_grants and api_key_scope_tenant_isolation_test.go for
//     api_key_scopes).
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.

// TestEnvironmentGrantRepositoryListByEnvironmentReturnsCorrectRowsAcrossTenants
// proves ListByEnvironment is keyed strictly by BOTH organization_id AND
// environment_id: each tenant has its own environment and its own grant
// row, and ListByEnvironment(orgA, envA) / ListByEnvironment(orgB, envB)
// must each return their own row — never a swapped or merged response.
// The two fixtures use different principal ids and roles per tenant so a
// WHERE-on-environment_id-only mistake would diverge from the expected
// per-tenant values.
func TestEnvironmentGrantRepositoryListByEnvironmentReturnsCorrectRowsAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	grantA := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "alpha"), orgA.ID, envA.ID,
		"usr_a", "usr", "developer", nil)
	grantB := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "beta"), orgB.ID, envB.ID,
		"usr_b", "usr", "viewer", nil)

	listA := listEnvironmentGrantsOrFail(ctx, t, s, repo, orgA.ID, envA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByEnvironment(orgA, envA) returned %d rows, want exactly 1 — orgB grant rows leaked", len(listA))
	}
	if listA[0].ID != grantA.ID || listA[0].OrganizationID != orgA.ID || listA[0].EnvironmentID != envA.ID || listA[0].PrincipalID != "usr_a" || listA[0].Role != "developer" {
		t.Errorf("ListByEnvironment(orgA, envA)[0] = %+v, want orgA/envA/usr_a/developer", listA[0])
	}

	listB := listEnvironmentGrantsOrFail(ctx, t, s, repo, orgB.ID, envB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByEnvironment(orgB, envB) returned %d rows, want exactly 1 — orgA grant rows leaked", len(listB))
	}
	if listB[0].ID != grantB.ID || listB[0].OrganizationID != orgB.ID || listB[0].EnvironmentID != envB.ID || listB[0].PrincipalID != "usr_b" || listB[0].Role != "viewer" {
		t.Errorf("ListByEnvironment(orgB, envB)[0] = %+v, want orgB/envB/usr_b/viewer", listB[0])
	}

	// The two reads MUST have returned distinct rows on EVERY anchor —
	// id, organization_id, environment_id, principal_id, role. A
	// WHERE-on-environment_id-only or WHERE-less SELECT would have
	// collapsed both lookups onto the same response, and an overlap on
	// any single anchor would surface here.
	if listA[0].ID == listB[0].ID || listA[0].OrganizationID == listB[0].OrganizationID ||
		listA[0].EnvironmentID == listB[0].EnvironmentID || listA[0].PrincipalID == listB[0].PrincipalID ||
		listA[0].Role == listB[0].Role {
		t.Errorf("ListByEnvironment returned overlapping rows across two tenants: %+v vs %+v", listA[0], listB[0])
	}
}

// TestEnvironmentGrantRepositoryListByEnvironmentCrossTenantEnvironmentIDReturnsEmpty
// proves ListByEnvironment is tenant scoped at the SQL predicate: a
// cross-tenant environment_id (a real environment in another
// organization) matches no rows and yields a non-nil empty slice, and an
// unknown environment_id under the same organization lands on the same
// empty-slice shape. A probing caller cannot infer the existence of a
// peer tenant's environment from the response either.
//
// The basic "cross-tenant environmentID returns empty" property is also
// asserted by environment_grant_test.go's
// TestEnvironmentGrantRepoListByEnvironmentIsTenantScoped; this file's
// contribution is the indistinguishability projection: cross-tenant
// environmentID and unknown-id-under-own-tenant render the SAME response
// shape (non-nil empty slice) so the cross-tenant probe is not a
// "does this environmentID exist?" oracle.
func TestEnvironmentGrantRepositoryListByEnvironmentCrossTenantEnvironmentIDReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web-b")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	// orgB owns two grants on its own environment — exactly what a
	// regression would have leaked through if the WHERE-on-environment_id-
	// only mistake resolved against the orgA call.
	upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "leak1"), orgB.ID, envB.ID,
		"usr_x", "usr", "developer", nil)
	upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "leak2"), orgB.ID, envB.ID,
		"usr_y", "usr", "viewer", nil)

	// orgA passes orgB's real environment_id. The composite predicate
	// (organization_id = orgA AND environment_id = orgB's env) matches
	// no rows and returns an empty (non-nil) slice — never another
	// tenant's grants.
	crossTenant := listEnvironmentGrantsOrFail(ctx, t, s, repo, orgA.ID, envB.ID)
	if len(crossTenant) != 0 {
		t.Errorf("ListByEnvironment(orgA, envB) returned %d rows, want 0 — orgB grants leaked through a cross-tenant environment_id", len(crossTenant))
	}
	if crossTenant == nil {
		t.Error("ListByEnvironment(orgA, envB) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice so callers can iterate without a nil check")
	}

	// And an unknown environment_id under orgA lands on the same empty-
	// slice shape — the cross-tenant probe must not be distinguishable
	// from "no such environment at all".
	unknown := listEnvironmentGrantsOrFail(ctx, t, s, repo, orgA.ID, "env_never_existed")
	if len(unknown) != 0 {
		t.Errorf("ListByEnvironment(orgA, unknown) returned %d rows, want 0", len(unknown))
	}
	if unknown == nil {
		t.Error("ListByEnvironment(orgA, unknown) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice")
	}
}

// TestEnvironmentGrantRepositoryListByEnvironmentIsolatesSharedPrincipal
// proves that when both tenants have a grant row whose principal_id and
// role are IDENTICAL — but on their OWN respective environments — each
// ListByEnvironment call renders only THIS tenant's row, never the
// other's, never a duplicate. principal_id is a string field that can
// legitimately repeat across tenants (the principal could be the same
// human / service-account-id-string referenced under both tenants from
// the customer's perspective, or a coincidentally identical string),
// and a regression that resolved the WHERE filter by principal_id alone
// — without organization_id — would surface here as a leak.
func TestEnvironmentGrantRepositoryListByEnvironmentIsolatesSharedPrincipal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	// Same principal_id + role on two tenants' OWN environments. The
	// (organization_id, environment_id, principal_id, ...) UNIQUE
	// conflict target is per-tenant, so both rows coexist.
	grantA := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "shared-a"), orgA.ID, envA.ID,
		"usr_shared", "usr", "developer", nil)
	grantB := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "shared-b"), orgB.ID, envB.ID,
		"usr_shared", "usr", "developer", nil)

	listA := listEnvironmentGrantsOrFail(ctx, t, s, repo, orgA.ID, envA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByEnvironment(orgA, envA) returned %d rows, want exactly 1 — orgB row for the same principal_id leaked or duplicated", len(listA))
	}
	if listA[0].ID != grantA.ID || listA[0].OrganizationID != orgA.ID {
		t.Errorf("ListByEnvironment(orgA, envA)[0] = %+v, want id=%q org=%q", listA[0], grantA.ID, orgA.ID)
	}

	listB := listEnvironmentGrantsOrFail(ctx, t, s, repo, orgB.ID, envB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByEnvironment(orgB, envB) returned %d rows, want exactly 1 — orgA row for the same principal_id leaked or duplicated", len(listB))
	}
	if listB[0].ID != grantB.ID || listB[0].OrganizationID != orgB.ID {
		t.Errorf("ListByEnvironment(orgB, envB)[0] = %+v, want id=%q org=%q", listB[0], grantB.ID, orgB.ID)
	}

	// The two responses must not overlap on grant id — if any id
	// appeared in both lists, the WHERE filter is the only thing
	// keeping them apart and the only way for both calls to share a
	// row is a WHERE-less SELECT.
	if listA[0].ID == listB[0].ID {
		t.Errorf("grant id %q appears in both List(orgA, envA) and List(orgB, envB) responses", listA[0].ID)
	}
}

// TestEnvironmentGrantRepositoryUpsertInsertOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for the Upsert INSERT branch: when orgA
// inserts a fresh grant on its own environment, orgB's bystander grant
// row — which legitimately shares the SAME scope tuple (principal_id,
// service_id) on its own environment — must be byte-identical to its
// baseline across EVERY observable column, including the trigger-
// managed updated_at and the trigger-bumped version (which would have
// stamped if the INSERT statement had somehow matched orgB's row).
//
// The fixture is the load-bearing case: BOTH tenants share the SAME
// (principal_id, svc) tuple on their OWN environments, so a regression
// that resolved the ON CONFLICT branch by the scope tuple alone —
// without organization_id and environment_id in the conflict target —
// would have UPDATEd orgB's row instead of INSERTing orgA's.
func TestEnvironmentGrantRepositoryUpsertInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	// orgB's bystander row lands FIRST so the baseline timestamps and
	// version are stable before orgA mutates.
	grantB := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "bystander"), orgB.ID, envB.ID,
		"usr_shared", "usr", "developer", nil)
	baselineB := getEnvironmentGrantFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, grantB.ID, "baseline")

	// orgA INSERTs a row with the IDENTICAL scope tuple on its own
	// environment. If the conflict target leaked across tenants this
	// would fire the UPDATE branch on orgB's row and refresh both
	// updated_at and version on the peer.
	insertedA := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "alpha"), orgA.ID, envA.ID,
		"usr_shared", "usr", "developer", nil)
	if insertedA.OrganizationID != orgA.ID || insertedA.EnvironmentID != envA.ID || insertedA.Version != 1 {
		t.Errorf("Upsert(orgA, envA) inserted row = %+v, want orgA/envA/version=1", insertedA)
	}
	if insertedA.ID == grantB.ID {
		t.Fatalf("orgA's freshly inserted grant id %q collides with orgB's bystander id — the id mint is unsound and the bystander test below is invalid", insertedA.ID)
	}

	afterB := getEnvironmentGrantFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, grantB.ID, "after orgA Upsert INSERT")
	assertEnvironmentGrantByteIdentical(t, "Upsert INSERT(orgA) bystander orgB", baselineB, afterB)
}

// TestEnvironmentGrantRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for the Upsert UPDATE branch: when orgA
// re-upserts its own grant (firing the ON CONFLICT DO UPDATE branch on
// its own row), orgB's bystander grant row — which legitimately shares
// the SAME scope tuple (principal_id, service_id) on its own
// environment — must be byte-identical to its baseline across EVERY
// observable column, including the trigger-managed updated_at and the
// trigger-bumped version, which are the independent anchors that catch a
// WHERE-on-scope-tuple-only UPDATE even when the column writes
// themselves happened to look correct.
//
// The fixture is the load-bearing case: BOTH tenants share the SAME
// (principal_id, svc) tuple on their OWN environments, so a regression
// that resolved the ON CONFLICT branch by the scope tuple alone would
// have UPDATEd orgB's row in addition to (or instead of) orgA's. The
// service_id pointer is non-nil here so the COALESCE(service_id, ”)
// branch of the conflict target is exercised (not just the
// NULL-COALESCE-to-empty-string fallback).
func TestEnvironmentGrantRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	// Both tenants seed an identical-scope-tuple grant first so the
	// re-upsert below fires the ON CONFLICT DO UPDATE branch on orgA's
	// row.
	svcID := "svc_web"
	grantA := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "alpha"), orgA.ID, envA.ID,
		"usr_shared", "usr", "developer", &svcID)
	grantB := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "bystander"), orgB.ID, envB.ID,
		"usr_shared", "usr", "developer", &svcID)

	baselineB := getEnvironmentGrantFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, grantB.ID, "baseline")

	// orgA re-upserts the SAME scope tuple with a different role. The
	// ON CONFLICT DO UPDATE branch fires on orgA's row only — the
	// per-tenant conflict target rules out orgB.
	updatedA := upsertEnvironmentGrant(ctx, t, s, repo,
		// Caller-supplied id is IGNORED on the conflict branch — pass a
		// fresh one to prove that.
		newEnvironmentGrantID(f, "alpha-rebump"), orgA.ID, envA.ID,
		"usr_shared", "usr", "viewer", &svcID)
	// orgA's row must have actually changed — a no-op repository
	// cannot silently pass the byte-identical-orgB check below.
	if updatedA.ID != grantA.ID {
		t.Errorf("UpdatedA.ID = %q, want %q (caller-id should be ignored on the conflict branch)", updatedA.ID, grantA.ID)
	}
	if updatedA.Role != "viewer" || updatedA.Version != grantA.Version+1 {
		t.Errorf("UpdatedA = %+v, want role=viewer version=%d", updatedA, grantA.Version+1)
	}

	afterB := getEnvironmentGrantFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, grantB.ID, "after orgA Upsert UPDATE")
	assertEnvironmentGrantByteIdentical(t, "Upsert UPDATE(orgA) bystander orgB", baselineB, afterB)
}

// TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsClearAllOnOrgADoesNotTouchOrgB
// is the byte-identical snapshot proof for the unconditional-DELETE
// codepath of DeleteByEnvironmentExceptIDs: when orgA clears every grant
// on its own environment (nil keepIDs), orgB's bystander grant row on
// its own environment must be byte-identical to its baseline. The
// trigger would refresh updated_at if the DELETE statement had matched
// orgB's row even momentarily, even though a successful DELETE removes
// the row — the invariant is that orgB's stamps are untouched.
//
// DeleteByEnvironmentExceptIDs has TWO codepaths in the repository
// (len(keepIDs)==0 -> unconditional DELETE; len>0 -> DELETE WHERE id
// NOT IN ANY); this test exercises the first one. The paired test below
// exercises the second.
func TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsClearAllOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	// orgA owns two grants on its own environment — both should be
	// removed.
	upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "a1"), orgA.ID, envA.ID,
		"usr_a1", "usr", "developer", nil)
	upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "a2"), orgA.ID, envA.ID,
		"usr_a2", "usr", "viewer", nil)
	// orgB owns one grant on its own environment — must survive
	// byte-identical.
	grantB := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "bystander"), orgB.ID, envB.ID,
		"usr_b", "usr", "developer", nil)
	baselineB := getEnvironmentGrantFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, grantB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptIDs(ctx, tx, orgA.ID, envA.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptIDs(orgA, envA, nil): %v", err)
	}

	// orgA's environment is now empty.
	if remaining := listEnvironmentGrantsOrFail(ctx, t, s, repo, orgA.ID, envA.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByEnvironmentExceptIDs(orgA, envA, nil) %d rows remain on orgA, want 0", len(remaining))
	}

	// orgB's environment still has its row AND is byte-identical to
	// its baseline.
	afterB := getEnvironmentGrantFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, grantB.ID, "after orgA DeleteByEnvironmentExceptIDs(nil)")
	assertEnvironmentGrantByteIdentical(t, "DeleteByEnvironmentExceptIDs(orgA, nil) bystander orgB", baselineB, afterB)
}

// TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsKeepSubsetOnOrgADoesNotTouchOrgB
// is the byte-identical snapshot proof for the conditional-DELETE
// codepath of DeleteByEnvironmentExceptIDs (len(keepIDs)>0 -> DELETE
// WHERE id NOT IN ANY): when orgA keeps a subset of its own grants and
// deletes the rest, orgB's bystander grant row on its own environment
// must be byte-identical to its baseline. The id NOT IN ANY filter is
// the only thing that selects WHICH of orgA's rows survive, and a
// regression that dropped the tenant predicate would let the DELETE
// reach into orgB's grants (whose ids are NOT in keepIDs and would
// therefore become eligible for deletion).
func TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsKeepSubsetOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	keepA := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "keep"), orgA.ID, envA.ID,
		"usr_a1", "usr", "developer", nil)
	dropA := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "drop"), orgA.ID, envA.ID,
		"usr_a2", "usr", "viewer", nil)
	// orgB owns one grant on its own environment — its id is
	// deliberately NOT in keepIDs (so a regression that lost the tenant
	// predicate would delete it through the "NOT IN ANY" branch).
	grantB := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "bystander"), orgB.ID, envB.ID,
		"usr_b", "usr", "developer", nil)
	baselineB := getEnvironmentGrantFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, grantB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptIDs(ctx, tx, orgA.ID, envA.ID, []string{keepA.ID})
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptIDs(orgA, envA, [keepA]): %v", err)
	}

	// orgA's environment now has exactly keepA — dropA was deleted.
	remaining := listEnvironmentGrantsOrFail(ctx, t, s, repo, orgA.ID, envA.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByEnvironmentExceptIDs(orgA, envA, [keepA]) %d rows remain on orgA, want 1", len(remaining))
	}
	if remaining[0].ID != keepA.ID {
		t.Errorf("survivor on orgA = %q, want keepA=%q", remaining[0].ID, keepA.ID)
	}
	if remaining[0].ID == dropA.ID {
		t.Errorf("dropA (%q) was retained; expected deletion", dropA.ID)
	}

	// orgB's environment still has its row AND is byte-identical to
	// its baseline — even though orgB's id is NOT in keepIDs and would
	// have been eligible for deletion if the tenant predicate had been
	// dropped.
	afterB := getEnvironmentGrantFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, grantB.ID, "after orgA DeleteByEnvironmentExceptIDs([keepA])")
	assertEnvironmentGrantByteIdentical(t, "DeleteByEnvironmentExceptIDs(orgA, [keepA]) bystander orgB", baselineB, afterB)
}

// TestEnvironmentGrantRepositoryUpsertSameScopeTupleInTwoTenantsBothSucceed
// proves the (organization_id, environment_id, principal_id,
// COALESCE(service_id, ”)) UNIQUE constraint is per-tenant, not global:
// two tenants can legitimately each have a row with the SAME
// (principal_id, svc) tuple on their own respective environments, and
// neither Upsert collides with the other. The flip side is the load-
// bearing reason every byte-identical-bystander test above asserts BOTH
// version and updated_at — if the scope tuple alone were the UNIQUE
// key, two tenants could not share it, and the WHERE filter would be
// redundant.
//
// The service_id pointer is non-nil here so the COALESCE(..., ”)
// branch of the conflict target is exercised (not just the
// NULL-COALESCE-to-empty-string fallback).
func TestEnvironmentGrantRepositoryUpsertSameScopeTupleInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	svcID := "svc_web"
	grantA := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "alpha"), orgA.ID, envA.ID,
		"usr_shared", "usr", "developer", &svcID)
	grantB := upsertEnvironmentGrant(ctx, t, s, repo,
		newEnvironmentGrantID(f, "beta"), orgB.ID, envB.ID,
		"usr_shared", "usr", "developer", &svcID)

	if grantA.ID == grantB.ID {
		t.Fatalf("two tenants minted the same grant id %q — the id generator collided, the byte-identical-bystander tests in this file are invalid", grantA.ID)
	}
	if grantA.OrganizationID == grantB.OrganizationID {
		t.Errorf("two grant rows landed under the SAME organization_id: %+v vs %+v", grantA, grantB)
	}
	if grantA.EnvironmentID == grantB.EnvironmentID {
		t.Errorf("two grant rows landed under the SAME environment_id: %+v vs %+v", grantA, grantB)
	}
	if grantA.PrincipalID != "usr_shared" || grantB.PrincipalID != "usr_shared" {
		t.Errorf("principal_id drifted between Upsert calls: orgA=%q orgB=%q, want both 'usr_shared'", grantA.PrincipalID, grantB.PrincipalID)
	}
	if grantA.ServiceID == nil || *grantA.ServiceID != svcID ||
		grantB.ServiceID == nil || *grantB.ServiceID != svcID {
		t.Errorf("service_id pointer did not round-trip across tenants: orgA=%v orgB=%v, want both *=%q", grantA.ServiceID, grantB.ServiceID, svcID)
	}
}

// --- shared helpers ---
//
// getEnvironmentGrantFromListOrFail observes a single environment_grants
// row through the repository's ListByEnvironment surface — the ONLY
// read path the repository exposes for grants — and returns the entry
// whose id matches the caller's. It fails the test on any error AND on
// the row's absence from the list; both are setup failures (the seeded
// row went missing) and not legs under proof in the byte-identical
// bystander cases.
//
// The api_key_scope tenant-isolation file uses a per-id Get for its
// equivalent helper; environment_grants has no per-id Get on the
// repository surface, so the read is necessarily a list scan. The
// implementation favours correctness over efficiency — the lists are
// small (one or two rows) by construction.
//
// The name is intentionally distinct from
// project_grant_tenant_isolation_test.go's getGrantFromListOrFail to
// avoid a same-package collision — every *_test.go file under
// internal/controlplane/store/ shares the same store_test package.
func getEnvironmentGrantFromListOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.EnvironmentGrantRepository, organizationID, environmentID, grantID, label string) store.EnvironmentGrant {
	t.Helper()
	rows := listEnvironmentGrantsOrFail(ctx, t, s, repo, organizationID, environmentID)
	for _, row := range rows {
		if row.ID == grantID {
			return row
		}
	}
	t.Fatalf("%s: grant %q missing from ListByEnvironment(%q, %q): got %d rows", label, grantID, organizationID, environmentID, len(rows))
	return store.EnvironmentGrant{}
}

// assertEnvironmentGrantByteIdentical asserts every observable column on
// a bystander environment_grants row is byte-identical to its baseline.
// The trigger-managed updated_at AND the trigger-bumped version are
// both load-bearing here: the BEFORE-UPDATE
// environment_grants_set_updated_at trigger refreshes updated_at on
// every matched UPDATE, and the environment_grants_bump_version trigger
// increments version — either drifting independently surfaces a missing
// tenant predicate even when the column writes themselves look correct.
//
// ServiceID is a nullable *string pointer; the equality check matches
// "both nil" OR "both non-nil and equal" (delegated to the package-
// level stringPtrEqual helper defined in
// project_grant_tenant_isolation_test.go), so a regression that
// resolved that pointer incorrectly on the bystander surface would be
// caught regardless of the original nullability.
func assertEnvironmentGrantByteIdentical(t *testing.T, label string, baseline, after store.EnvironmentGrant) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.EnvironmentID != baseline.EnvironmentID {
		t.Errorf("%s: bystander.environment_id = %q, want %q", label, after.EnvironmentID, baseline.EnvironmentID)
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
	if !stringPtrEqual(after.ServiceID, baseline.ServiceID) {
		t.Errorf("%s: bystander.service_id = %s, want %s", label, fmtStringPtr(after.ServiceID), fmtStringPtr(baseline.ServiceID))
	}
	if after.Version != baseline.Version {
		t.Errorf("%s: bystander.version = %d, want %d — the environment_grants_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE environment_grants_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}
