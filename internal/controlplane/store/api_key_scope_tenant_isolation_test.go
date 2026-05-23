package store_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the api_key_scopes table
// (BE-0436). api_key_scopes is a tenant-scoped child table whose row body
// is anchored to a single tenant by TWO load-bearing schema facts:
//
//	(a) every column carries organization_id explicitly, and the
//	    composite FK (organization_id, api_key_id) -> api_keys
//	    (organization_id, id) makes a row whose api_key belongs to one
//	    tenant structurally unrepresentable as another tenant's scope at
//	    the database layer — the BE-0435 invariants file already proves
//	    Insert rejects the cross-tenant FK violation with a typed
//	    Conflict, so this file does not re-prove it;
//	(b) every repository method (Get / ListByAPIKey / ListByOrganization /
//	    UpdateScope / Delete) carries organization_id as the first SQL
//	    predicate, ahead of the row identifier. The cross-tenant guarantee
//	    at this layer is therefore the byte-identical-bystander invariant
//	    every other tenant-scoped table is held to.
//
// The api_key_scopes row body carries NO secret-bearing column — the
// scope text itself is the capability the wire layer surfaces in clear
// text — so the BE-0434 raw-secret_hash probe has no analogue here. The
// row body is fully observable through the typed Get / List read paths,
// and the byte-identical-bystander assertion below covers every
// observable column (id, organization_id, api_key_id, scope, version,
// created_at, updated_at).
//
// The BEFORE-UPDATE api_key_scopes_set_updated_at trigger refreshes
// updated_at on every matched UPDATE — including a WHERE-less or
// WHERE-on-id-only UPDATE that touched the wrong tenant's row — and the
// api_key_scopes_bump_version trigger increments version on the same
// path. Either of those two columns drifting on the bystander is
// independently sufficient to catch a missing tenant predicate even
// when the column writes themselves look correct, and every byte-
// identical-bystander test below asserts BOTH against the baseline.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Insert RETURNING shape, duplicate-tuple Conflict, cross-tenant FK
//     Conflict, UpdateScope dual-anchor (updated_at refreshed,
//     created_at preserved, version bumped), Delete RowsAffected()==0
//     NotFound, ON DELETE CASCADE from api_keys, Insert tx-rollback,
//     and nil-Tx guards are proved by
//     api_key_scope_repository_invariants_test.go (BE-0435).
//   - The HTTP-layer "another tenant's scope id is a 404, not a 403"
//     rule is proved by the per-endpoint policy matrix and contract
//     tests in httpapi.
//   - api_key_scopes has no deletion_scheduled_at / soft-delete column —
//     rows are hard-deleted in a single statement, and the cross-tenant
//     cascade behaviour (api_keys deletion removing child scope rows)
//     belongs to the parent table. The acceptance-criteria mention of
//     "soft-deleted rows where applicable" therefore has no surface
//     here; documenting the deliberate absence keeps a future reader
//     from looking for a missing test (mirrors
//     api_key_tenant_isolation_test.go's no-soft-delete note for
//     api_keys and membership_tenant_isolation_test.go's note for
//     memberships).
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.

// TestAPIKeyScopeRepositoryGetReturnsCorrectRowAcrossTenants proves Get is
// keyed strictly by BOTH organization_id AND id: each tenant has its own
// api_keys row and its own api_key_scopes row, and Get(orgA, scopeAID) /
// Get(orgB, scopeBID) must each return their own row — never a swapped
// or merged response.
func TestAPIKeyScopeRepositoryGetReturnsCorrectRowAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyAID, _, _ := seedAPIKeyForScopes(t, db, f, orgA, "ci-a")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci-b")
	// Distinct scope text per tenant so a WHERE-on-id-only mistake
	// (which would resolve to whichever row the planner found first)
	// would diverge from the expected per-tenant value.
	scopeA := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "projects:read"))
	scopeB := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "services:deploy"))

	var gotA store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.Get(ctx, q, orgA.ID, scopeA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgA, scopeA): %v", err)
	}
	if gotA.OrganizationID != orgA.ID || gotA.ID != scopeA.ID || gotA.APIKeyID != keyAID || gotA.Scope != "projects:read" {
		t.Errorf("Get(orgA, scopeA) = %+v, want orgA/scopeA/keyA/projects:read", gotA)
	}

	var gotB store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.Get(ctx, q, orgB.ID, scopeB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgB, scopeB): %v", err)
	}
	if gotB.OrganizationID != orgB.ID || gotB.ID != scopeB.ID || gotB.APIKeyID != keyBID || gotB.Scope != "services:deploy" {
		t.Errorf("Get(orgB, scopeB) = %+v, want orgB/scopeB/keyB/services:deploy", gotB)
	}

	// The two reads MUST have returned distinct rows on EVERY anchor —
	// id, organization_id, api_key_id, scope. A WHERE-on-id-only mistake
	// would collapse both lookups onto the same row, and an overlap on
	// any single anchor would surface here.
	if gotA.ID == gotB.ID || gotA.OrganizationID == gotB.OrganizationID || gotA.APIKeyID == gotB.APIKeyID || gotA.Scope == gotB.Scope {
		t.Errorf("Get returned overlapping rows across two tenants: %+v vs %+v", gotA, gotB)
	}
}

// TestAPIKeyScopeRepositoryGetCrossTenantIsIndistinguishableFromUnknown
// proves the cross-tenant NotFound shape — Code AND Hint — is the SAME
// shape an unknown scope id produces. A probing caller who guesses a
// peer tenant's scope id cannot infer that the scope id IS a real row
// in another tenant from the response: both surfaces emit
// yerr.CodeNotFound with matching Hint values.
func TestAPIKeyScopeRepositoryGetCrossTenantIsIndistinguishableFromUnknown(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci-b")
	scopeB := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "projects:read"))

	// Cross-tenant probe: (orgA, scopeB.ID). The id is real and belongs
	// to a different tenant.
	crossTenantErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, scopeB.ID)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Get error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	// Wholly unknown id under orgA.
	unknownErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, "aks_never_existed")
		return err
	})
	var yeUnknown *yerr.Error
	if !stderrors.As(unknownErr, &yeUnknown) || yeUnknown.Code != yerr.CodeNotFound {
		t.Fatalf("unknown-id Get error = %v, want a typed E_NOT_FOUND", unknownErr)
	}

	// The two shapes must be indistinguishable on Code AND Hint — a
	// caller who diffed the response surfaces could otherwise enumerate
	// peers by probing scope ids. The cross-tenant NotFound MUST NOT
	// echo the foreign scope id either.
	if yeCross.Code != yeUnknown.Code {
		t.Errorf("cross-tenant Code = %s, unknown-id Code = %s — existence leaks via Code", yeCross.Code, yeUnknown.Code)
	}
	if yeCross.Hint != yeUnknown.Hint {
		t.Errorf("cross-tenant Hint = %q, unknown-id Hint = %q — existence leaks via Hint", yeCross.Hint, yeUnknown.Hint)
	}
}

// TestAPIKeyScopeRepositoryListByAPIKeyIsTenantScoped proves
// ListByAPIKey is tenant scoped at the SQL predicate: a cross-tenant
// api_key_id (a real key in another organization) matches no rows and
// yields an empty slice, and an unknown api_key_id under the same
// organization lands on the same empty-slice shape. A probing caller
// cannot infer the existence of a peer tenant's api key from the
// response either.
func TestAPIKeyScopeRepositoryListByAPIKeyCrossTenantReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci-b")
	// orgB owns two scope rows on its own key — exactly what a regression
	// would have leaked through if the WHERE-on-api_key_id-only mistake
	// resolved against the orgA call.
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "projects:read"))
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "services:deploy"))

	// orgA passes orgB's real api_key_id. The composite predicate
	// (organization_id = orgA AND api_key_id = orgB's key) matches no
	// rows and returns an empty (non-nil) slice — never another tenant's
	// scopes.
	var crossTenant []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		crossTenant, readErr = repo.ListByAPIKey(ctx, q, orgA.ID, keyBID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByAPIKey(orgA, keyB) error = %v, want nil error and empty slice", err)
	}
	if len(crossTenant) != 0 {
		t.Errorf("ListByAPIKey(orgA, keyB) returned %d rows, want 0 — orgB scopes leaked through a cross-tenant api_key_id", len(crossTenant))
	}
	if crossTenant == nil {
		t.Error("ListByAPIKey(orgA, keyB) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice so callers can iterate without a nil check")
	}

	// And an unknown api_key_id under orgA lands on the same empty-slice
	// shape — the cross-tenant probe must not be distinguishable from
	// "no such key at all".
	var unknown []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		unknown, readErr = repo.ListByAPIKey(ctx, q, orgA.ID, "key_never_existed")
		return readErr
	}); err != nil {
		t.Fatalf("ListByAPIKey(orgA, unknown) error = %v, want nil error and empty slice", err)
	}
	if len(unknown) != 0 {
		t.Errorf("ListByAPIKey(orgA, unknown) returned %d rows, want 0", len(unknown))
	}
}

// TestAPIKeyScopeRepositoryListByOrganizationCountsAreIsolated proves the
// rendered length of ListByOrganization is local to the queried tenant
// — never the global count, never a sum across tenants. orgA owns one
// scope; orgB owns three. List(orgA) must return exactly 1 row;
// List(orgB) must return exactly 3. A SELECT without the WHERE
// organization_id filter would have returned 4 for both calls.
func TestAPIKeyScopeRepositoryListByOrganizationCountsAreIsolated(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyAID, _, _ := seedAPIKeyForScopes(t, db, f, orgA, "ci-a")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci-b")
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "projects:read"))
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "projects:read"))
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "services:deploy"))
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "deployments:read"))

	var gotA []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.ListByOrganization(ctx, q, orgA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(gotA) != 1 {
		t.Errorf("ListByOrganization(orgA) returned %d rows, want 1 — orgB scope rows leaked", len(gotA))
	}
	for _, sc := range gotA {
		if sc.OrganizationID != orgA.ID {
			t.Errorf("ListByOrganization(orgA) returned a foreign row: %+v", sc)
		}
	}

	var gotB []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.ListByOrganization(ctx, q, orgB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB): %v", err)
	}
	if len(gotB) != 3 {
		t.Errorf("ListByOrganization(orgB) returned %d rows, want 3", len(gotB))
	}
	for _, sc := range gotB {
		if sc.OrganizationID != orgB.ID {
			t.Errorf("ListByOrganization(orgB) returned a foreign row: %+v", sc)
		}
	}

	// The two responses must not overlap on scope id — if any id appeared
	// in both lists, the WHERE filter is the only thing keeping them
	// apart and the only way for both calls to share a row is a
	// WHERE-less SELECT.
	seenInB := make(map[string]struct{}, len(gotB))
	for _, sc := range gotB {
		seenInB[sc.ID] = struct{}{}
	}
	for _, sc := range gotA {
		if _, overlap := seenInB[sc.ID]; overlap {
			t.Errorf("scope id %q appears in both List(orgA) and List(orgB) responses", sc.ID)
		}
	}
}

// TestAPIKeyScopeRepositoryListByOrganizationIsolatesSharedScopeName
// proves that when both tenants have a scope row with the SAME scope
// text on their OWN respective api_keys row, each ListByOrganization
// call renders only THIS tenant's row — never the other's, never a
// duplicate. This is the shared-row safety net analogous to the
// shared-user-row test for memberships: the (organization_id,
// api_key_id, scope) UNIQUE constraint is per-tenant, so two tenants
// CAN legitimately share scope text — and a regression that resolved
// the WHERE filter by scope text alone would surface here as a leak.
func TestAPIKeyScopeRepositoryListByOrganizationIsolatesSharedScopeName(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyAID, _, _ := seedAPIKeyForScopes(t, db, f, orgA, "ci-a")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci-b")
	// Same scope text, two tenants, two distinct keys — proves the
	// UNIQUE (organization_id, api_key_id, scope) constraint allows both
	// rows to coexist AND each List sees only its own.
	scopeA := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "projects:read"))
	scopeB := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "projects:read"))

	var gotA []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.ListByOrganization(ctx, q, orgA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(gotA) != 1 {
		t.Fatalf("ListByOrganization(orgA) returned %d rows, want exactly 1 — orgB's row for the same scope text leaked or duplicated", len(gotA))
	}
	if gotA[0].ID != scopeA.ID || gotA[0].OrganizationID != orgA.ID || gotA[0].APIKeyID != keyAID || gotA[0].Scope != "projects:read" {
		t.Errorf("ListByOrganization(orgA)[0] = %+v, want orgA/scopeA/keyA/projects:read", gotA[0])
	}

	var gotB []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.ListByOrganization(ctx, q, orgB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB): %v", err)
	}
	if len(gotB) != 1 {
		t.Fatalf("ListByOrganization(orgB) returned %d rows, want exactly 1 — orgA's row for the same scope text leaked or duplicated", len(gotB))
	}
	if gotB[0].ID != scopeB.ID || gotB[0].OrganizationID != orgB.ID || gotB[0].APIKeyID != keyBID || gotB[0].Scope != "projects:read" {
		t.Errorf("ListByOrganization(orgB)[0] = %+v, want orgB/scopeB/keyB/projects:read", gotB[0])
	}
}

// TestAPIKeyScopeRepositoryUpdateScopeOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for UpdateScope: when orgA UPDATEs its
// own scope row, orgB's bystander scope row must be byte-identical to
// its baseline across EVERY observable column — including the
// trigger-managed updated_at and the trigger-bumped version, which are
// the independent anchors that catch a WHERE-on-id-only UPDATE even
// when the column writes themselves happened to look correct.
//
// The fixture has BOTH tenants share the SAME scope text on their OWN
// respective keys, so a regression that resolved the WHERE clause by
// scope text alone — or by id alone — would have hit orgB's row.
func TestAPIKeyScopeRepositoryUpdateScopeOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyAID, _, _ := seedAPIKeyForScopes(t, db, f, orgA, "ci-a")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci-b")
	scopeA := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "projects:read"))
	scopeB := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "projects:read"))

	baselineB := getScopeOrFail(ctx, t, s, repo, orgB.ID, scopeB.ID, "baseline")

	// orgA mutates its own row to a new scope text.
	var updatedA store.APIKeyScope
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updatedA, writeErr = repo.UpdateScope(ctx, tx, orgA.ID, scopeA.ID, "services:deploy")
		return writeErr
	}); err != nil {
		t.Fatalf("UpdateScope(orgA, scopeA): %v", err)
	}
	// orgA must have actually changed — a no-op repository cannot
	// silently pass the byte-identical-orgB check below.
	if updatedA.OrganizationID != orgA.ID || updatedA.ID != scopeA.ID || updatedA.Scope != "services:deploy" || updatedA.Version != 2 {
		t.Errorf("UpdateScope(orgA, scopeA) = %+v, want orgA/scopeA/services:deploy/version=2", updatedA)
	}

	afterB := getScopeOrFail(ctx, t, s, repo, orgB.ID, scopeB.ID, "after orgA UpdateScope")
	assertScopeByteIdentical(t, "UpdateScope(orgA) bystander orgB", baselineB, afterB)
}

// TestAPIKeyScopeRepositoryUpdateScopeCrossTenantReturnsNotFound proves
// UpdateScope with another tenant's scope id surfaces as the same typed
// NotFound shape an unknown id would produce, AND leaves the bystander
// tenant's row byte-identical — the trigger would otherwise refresh
// updated_at and bump version if the UPDATE statement had matched orgB's
// row even momentarily.
func TestAPIKeyScopeRepositoryUpdateScopeCrossTenantReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci-b")
	scopeB := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "projects:read"))
	baselineB := getScopeOrFail(ctx, t, s, repo, orgB.ID, scopeB.ID, "baseline")

	crossTenantErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.UpdateScope(ctx, tx, orgA.ID, scopeB.ID, "services:deploy")
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant UpdateScope error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	// And the bystander row is byte-identical — including updated_at
	// and version, which the BEFORE-UPDATE trigger would have stamped
	// if the statement had matched orgB's row.
	afterB := getScopeOrFail(ctx, t, s, repo, orgB.ID, scopeB.ID, "after cross-tenant UpdateScope")
	assertScopeByteIdentical(t, "cross-tenant UpdateScope bystander orgB", baselineB, afterB)
}

// TestAPIKeyScopeRepositoryDeleteOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for Delete: when orgA Deletes its own
// scope row, orgB's bystander row survives AND is byte-identical to its
// baseline across EVERY observable column. The trigger would refresh
// updated_at if the DELETE statement had matched orgB's row even
// momentarily, even though a successful DELETE removes the row — the
// invariant is that orgB's stamps are untouched.
func TestAPIKeyScopeRepositoryDeleteOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyAID, _, _ := seedAPIKeyForScopes(t, db, f, orgA, "ci-a")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci-b")
	scopeA := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "projects:read"))
	scopeB := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "projects:read"))

	baselineB := getScopeOrFail(ctx, t, s, repo, orgB.ID, scopeB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, orgA.ID, scopeA.ID)
	}); err != nil {
		t.Fatalf("Delete(orgA, scopeA): %v", err)
	}

	// orgA's row is gone — the follow-up Get is the typed NotFound the
	// read path produces, the same shape an unknown id would produce
	// (no Forbidden / no AlreadyDeleted leak).
	gotAErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, scopeA.ID)
		return err
	})
	var yeA *yerr.Error
	if !stderrors.As(gotAErr, &yeA) || yeA.Code != yerr.CodeNotFound {
		t.Fatalf("Get(orgA, scopeA) after Delete = %v, want a typed E_NOT_FOUND", gotAErr)
	}

	// orgB's row survives AND is byte-identical to its baseline.
	afterB := getScopeOrFail(ctx, t, s, repo, orgB.ID, scopeB.ID, "after orgA Delete")
	assertScopeByteIdentical(t, "Delete(orgA) bystander orgB", baselineB, afterB)
}

// TestAPIKeyScopeRepositoryDeleteCrossTenantReturnsNotFound proves Delete
// with another tenant's scope id surfaces as the same typed NotFound
// shape (RowsAffected() == 0 -> apierr.NotFound) an unknown id would
// produce, AND leaves the bystander tenant's row byte-identical — the
// query's tenant predicate is what makes the DELETE a no-op, and a
// WHERE-on-id-only mistake would scrub the bystander's row instead.
func TestAPIKeyScopeRepositoryDeleteCrossTenantReturnsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci-b")
	scopeB := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "projects:read"))
	baselineB := getScopeOrFail(ctx, t, s, repo, orgB.ID, scopeB.ID, "baseline")

	crossTenantErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, orgA.ID, scopeB.ID)
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Delete error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	// The bystander row is byte-identical AND still readable — the
	// DELETE was a no-op, not a "matched then rolled back" mutation.
	afterB := getScopeOrFail(ctx, t, s, repo, orgB.ID, scopeB.ID, "after cross-tenant Delete")
	assertScopeByteIdentical(t, "cross-tenant Delete bystander orgB", baselineB, afterB)
}

// TestAPIKeyScopeRepositoryInsertSameScopeNameInTwoTenantsBothSucceed
// proves the (organization_id, api_key_id, scope) UNIQUE constraint is
// per-tenant, not global: two tenants can legitimately each have a
// "projects:read" scope on their own respective api_keys row, and
// neither Insert collides with the other. The flip side is the
// load-bearing reason every read above asserts byte-identical bystander
// rows — if scope text alone were the UNIQUE key, two tenants could not
// share it, and the WHERE filter would be redundant.
func TestAPIKeyScopeRepositoryInsertSameScopeNameInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyAID, _, _ := seedAPIKeyForScopes(t, db, f, orgA, "ci-a")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci-b")

	scopeA := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "projects:read"))
	scopeB := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "projects:read"))

	if scopeA.ID == scopeB.ID {
		t.Fatalf("two tenants minted the same scope id %q — the id generator collided, the byte-identical-bystander tests below are invalid", scopeA.ID)
	}
	if scopeA.OrganizationID == scopeB.OrganizationID {
		t.Errorf("two scope rows landed under the SAME organization_id: %+v vs %+v", scopeA, scopeB)
	}
	if scopeA.APIKeyID == scopeB.APIKeyID {
		t.Errorf("two scope rows landed under the SAME api_key_id: %+v vs %+v", scopeA, scopeB)
	}
	if scopeA.Scope != "projects:read" || scopeB.Scope != "projects:read" {
		t.Errorf("scope text drifted between Insert calls: orgA=%q orgB=%q, want both 'projects:read'", scopeA.Scope, scopeB.Scope)
	}
}

// --- shared helpers ---
//
// getScopeOrFail reads a scope through the typed repository surface and
// fails the test on any error — the test cases use this exclusively for
// reads that are EXPECTED to succeed, so a NotFound here is a setup
// failure (the seeded row went missing) and not a leg under proof.
func getScopeOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.APIKeyScopeRepository, organizationID, scopeID, label string) store.APIKeyScope {
	t.Helper()
	var got store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		got, readErr = repo.Get(ctx, q, organizationID, scopeID)
		return readErr
	}); err != nil {
		t.Fatalf("%s Get(%q, %q): %v", label, organizationID, scopeID, err)
	}
	return got
}

// assertScopeByteIdentical asserts every observable column on a
// bystander api_key_scopes row is byte-identical to its baseline. The
// trigger-managed updated_at AND the trigger-bumped version are both
// load-bearing here: the BEFORE-UPDATE api_key_scopes_set_updated_at
// trigger refreshes updated_at on every matched UPDATE, and the
// api_key_scopes_bump_version trigger increments version — either
// drifting independently surfaces a missing tenant predicate even when
// the column writes themselves look correct.
func assertScopeByteIdentical(t *testing.T, label string, baseline, after store.APIKeyScope) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.APIKeyID != baseline.APIKeyID {
		t.Errorf("%s: bystander.api_key_id = %q, want %q", label, after.APIKeyID, baseline.APIKeyID)
	}
	if after.Scope != baseline.Scope {
		t.Errorf("%s: bystander.scope = %q, want %q", label, after.Scope, baseline.Scope)
	}
	if after.Version != baseline.Version {
		t.Errorf("%s: bystander.version = %d, want %d — the api_key_scopes_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE api_key_scopes_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}
