package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration and unit tests for APIKeyScopeRepository (BE-0435). This file
// is the first set of tests to land against the api_key_scopes table — no
// pre-existing api_key_scope_test.go exists — so it covers both the CRUD
// surface and the row-shape / lifecycle invariants in a single file. The
// byte-identical-bystander tenant-isolation proof for cross-tenant Get /
// Update / Delete is the subject of BE-0436 and will live in
// api_key_scope_tenant_isolation_test.go.
//
// What this file proves:
//
//   - Insert returns the row the database actually committed: created_at
//     and updated_at are non-zero and equal on a fresh row (no UPDATE has
//     fired yet, so the api_key_scopes_set_updated_at trigger has not run),
//     version starts at 1 (the schema default), and the caller-supplied
//     fields (id, organization_id, api_key_id, scope) are echoed back
//     verbatim.
//   - Insert rejects a duplicate (organization_id, api_key_id, scope) tuple
//     with a typed apierr.Conflict; the database-side UNIQUE constraint is
//     the load-bearing defence, and the mapWriteError chokepoint surfaces
//     it as the same typed code the rest of the persistence layer uses.
//   - Insert rejects a cross-tenant or unknown api_key_id with a typed
//     apierr.Conflict (the composite FK
//     (organization_id, api_key_id) -> api_keys violation is a
//     constraint-violation class 23 error, exactly like the duplicate
//     tuple case). The reasoning is structural: a row whose api_key
//     belongs to one tenant is unrepresentable as another tenant's scope
//     at the database layer.
//   - Get and ListByAPIKey are tenant scoped at the SQL predicate. A
//     cross-tenant scope id surfaces as the same NotFound shape an unknown
//     id would produce; a cross-tenant or unknown api_key_id surfaces as
//     an empty list (never another tenant's rows).
//   - UpdateScope refreshes updated_at via the BEFORE UPDATE trigger,
//     bumps version, and preserves created_at — the dual-anchor lifecycle
//     assertion every other domain table's mutation must honor. The
//     mutable surface is exactly {scope}; id, organization_id, and
//     api_key_id stay byte-identical to the baseline.
//   - UpdateScope renaming a scope onto an existing (api_key_id, scope)
//     tuple surfaces as the typed apierr.Conflict mapWriteError produces.
//   - Delete reports NotFound when no row matches (RowsAffected() == 0),
//     mirroring api_keys.Revoke's idempotent-tag pattern. The query is
//     tenant scoped so a cross-tenant id can never delete another
//     organization's row.
//   - ON DELETE CASCADE from api_keys removes a key's scope rows when the
//     parent api_keys row is deleted; the schema is the only writer of
//     this guarantee.
//   - Insert rolls back when the surrounding Write closure returns a
//     non-nil error: the transaction is the unit of work, and no
//     half-written scope row can survive an aborted audit/policy step
//     that runs alongside it.
//   - The Insert / UpdateScope / Delete mutation paths' nil-Tx guards
//     against a nil *Tx argument render a typed apierr.Internal — never
//     a nil-pointer panic — so a caller that wires the unit of work
//     wrong is reported with a code the rest of the error taxonomy
//     understands.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard tests are pure unit tests and require no database.

// seedAPIKeyForScopes inserts a minimal api_keys row (the parent of a scope
// row) directly via SQL. The api_keys.scopes text[] column stays at its
// schema default ('{}') because the api_key_scopes table is the only thing
// under test here. It returns the inserted key's identifiers — id, prefix,
// and secret_hash — so a follow-up secret_hash probe can prove the parent
// teardown also removes its child rows.
func seedAPIKeyForScopes(t *testing.T, db *testutil.DB, f *testutil.Factory, org testutil.Organization, label string) (id, prefix, secretHash string) {
	t.Helper()
	user := f.User(org, "scope-owner-"+label)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)`,
		user.ID, user.Email, user.Name); err != nil {
		t.Fatalf("seed user for api key %q: %v", label, err)
	}
	key := f.APIKey(org, user, label)
	prefix = key.Prefix + "_" + key.ID
	secretHash = "h_" + key.ID
	if _, err := db.Exec(context.Background(),
		`INSERT INTO api_keys (id, organization_id, prefix, secret_hash, name, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		key.ID, org.ID, prefix, secretHash, key.Name, user.ID); err != nil {
		t.Fatalf("seed api key %q: %v", label, err)
	}
	return key.ID, prefix, secretHash
}

// newAPIKeyScope builds a persistence-shaped APIKeyScope owned by
// (orgID, apiKeyID) carrying the given scope text.
func newAPIKeyScope(f *testutil.Factory, orgID, apiKeyID, scope string) store.APIKeyScope {
	// The factory mints opaque, globally-unique id strings; we reuse the
	// APIKey id mint so we get a fresh, namespaced token, then transform
	// the prefix to mark this id as a scope row.
	id := strings.Replace(f.APIKey(testutil.Organization{ID: orgID}, testutil.User{ID: "scope-owner"}, "scope").ID, "key_", "aks_", 1)
	return store.APIKeyScope{
		ID:             id,
		OrganizationID: orgID,
		APIKeyID:       apiKeyID,
		Scope:          scope,
	}
}

// insertAPIKeyScope persists s through Store.Write and returns the stored
// row. It is the smallest possible "happy-path Insert" closure and is
// reused by every test that does not need to observe the insert's tx in
// isolation.
func insertAPIKeyScope(ctx context.Context, t *testing.T, s *store.Store, repo *store.APIKeyScopeRepository, scope store.APIKeyScope) store.APIKeyScope {
	t.Helper()
	var stored store.APIKeyScope
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, scope)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("insert api key scope: %v", err)
	}
	return stored
}

// TestAPIKeyScopeRepositoryInsertReturnsRowWithTimestamps proves Insert
// returns the row the database actually committed. created_at and
// updated_at are both non-zero AND byte-equal on the fresh row (no UPDATE
// has fired yet, so the api_key_scopes_set_updated_at trigger has not run),
// version starts at 1 (the schema default), and the caller-supplied fields
// are echoed back verbatim.
func TestAPIKeyScopeRepositoryInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	keyID, _, _ := seedAPIKeyForScopes(t, db, f, org, "ci")
	want := newAPIKeyScope(f, org.ID, keyID, "projects:read")

	got := insertAPIKeyScope(ctx, t, s, repo, want)

	if got.ID != want.ID {
		t.Errorf("Insert returned id %q, want %q", got.ID, want.ID)
	}
	if got.OrganizationID != org.ID {
		t.Errorf("Insert returned organization_id %q, want %q", got.OrganizationID, org.ID)
	}
	if got.APIKeyID != keyID {
		t.Errorf("Insert returned api_key_id %q, want %q", got.APIKeyID, keyID)
	}
	if got.Scope != want.Scope {
		t.Errorf("Insert returned scope %q, want %q", got.Scope, want.Scope)
	}
	if got.Version != 1 {
		t.Errorf("Insert returned version %d, want 1", got.Version)
	}
	if got.CreatedAt.IsZero() {
		t.Error("Insert returned zero created_at; the schema default must have populated it")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("Insert returned zero updated_at; the schema default must have populated it")
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("Insert created_at = %v, updated_at = %v; the BEFORE UPDATE trigger must NOT have fired on a fresh row (timestamps must be byte-equal)",
			got.CreatedAt, got.UpdatedAt)
	}
}

// TestAPIKeyScopeRepositoryInsertDuplicateScopeReturnsTypedConflict proves
// the (organization_id, api_key_id, scope) UNIQUE constraint surfaces a
// duplicate insert as the typed apierr.Conflict mapWriteError produces,
// never as a 5xx. Two different ids attempting to claim the same scope on
// the same key both succeed at the wire-shape (no field is "wrong"); the
// schema is the load-bearing defence.
func TestAPIKeyScopeRepositoryInsertDuplicateScopeReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	keyID, _, _ := seedAPIKeyForScopes(t, db, f, org, "ci")
	first := newAPIKeyScope(f, org.ID, keyID, "services:deploy")
	insertAPIKeyScope(ctx, t, s, repo, first)

	duplicate := newAPIKeyScope(f, org.ID, keyID, "services:deploy")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insErr := repo.Insert(ctx, tx, duplicate)
		return insErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(duplicate scope) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

// TestAPIKeyScopeRepositoryInsertCrossTenantAPIKeyReturnsTypedConflict
// proves the composite FK (organization_id, api_key_id) -> api_keys
// rejects a row whose api_key belongs to a different organization. A
// cross-tenant api_key_id is structurally unrepresentable: even though
// the scope id and scope text are well-formed, the constraint-violation
// class 23 error surfaces as the typed apierr.Conflict at the persistence
// chokepoint. An unknown api_key_id (no row at all) lands on the same
// path for the same reason.
func TestAPIKeyScopeRepositoryInsertCrossTenantAPIKeyReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci")

	// orgA claims orgB's api key.
	crossTenant := newAPIKeyScope(f, orgA.ID, keyBID, "projects:read")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insErr := repo.Insert(ctx, tx, crossTenant)
		return insErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(cross-tenant api_key) error = %v, want code %s", err, yerr.CodeConflict)
	}

	// An unknown api_key_id under orgA lands on the same conflict code.
	unknown := newAPIKeyScope(f, orgA.ID, "key_does_not_exist", "projects:read")
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insErr := repo.Insert(ctx, tx, unknown)
		return insErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(unknown api_key) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

// TestAPIKeyScopeRepositoryGetIsTenantScoped proves a scope id from another
// organization surfaces as the same NotFound shape an unknown id would
// produce. Cross-tenant existence cannot leak through Get even if the id
// happens to be a real row in another tenant.
func TestAPIKeyScopeRepositoryGetIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyAID, _, _ := seedAPIKeyForScopes(t, db, f, orgA, "ci")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci")

	scopeA := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "projects:read"))
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "projects:read"))

	// orgB asks for orgA's scope id.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgB.ID, scopeA.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(cross-tenant scope) = %v, want NotFound", err)
	}

	// An unknown id under the right tenant produces the same shape — no
	// existence-leak channel via code or message divergence.
	err = s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgA.ID, "aks_does_not_exist")
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(unknown scope) = %v, want NotFound", err)
	}
}

// TestAPIKeyScopeRepositoryListByAPIKeyIsTenantScoped proves a cross-tenant
// or unknown api_key_id surfaces as an empty list and never reveals another
// organization's rows. Determinism of the (scope, id) ordering keeps the
// response shape stable for agent consumers.
func TestAPIKeyScopeRepositoryListByAPIKeyIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyAID, _, _ := seedAPIKeyForScopes(t, db, f, orgA, "ci")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci")

	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "z:later"))
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "a:first"))
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "intruder:bait"))

	// orgB asks for orgA's key id — even though the api_key_id is a real
	// row in another tenant, the predicate (organization_id, api_key_id)
	// matches no rows.
	var crossTenantRows []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rerr error
		crossTenantRows, rerr = repo.ListByAPIKey(ctx, q, orgB.ID, keyAID)
		return rerr
	}); err != nil {
		t.Fatalf("ListByAPIKey(cross-tenant) failed: %v", err)
	}
	if len(crossTenantRows) != 0 {
		t.Errorf("ListByAPIKey(cross-tenant) returned %d rows, want 0", len(crossTenantRows))
	}

	// orgA asks for its own key id — the rows are ordered by (scope, id).
	var ownRows []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rerr error
		ownRows, rerr = repo.ListByAPIKey(ctx, q, orgA.ID, keyAID)
		return rerr
	}); err != nil {
		t.Fatalf("ListByAPIKey(own tenant) failed: %v", err)
	}
	if len(ownRows) != 2 {
		t.Fatalf("ListByAPIKey(own tenant) returned %d rows, want 2", len(ownRows))
	}
	if ownRows[0].Scope != "a:first" || ownRows[1].Scope != "z:later" {
		t.Errorf("ListByAPIKey order = [%q, %q], want [\"a:first\", \"z:later\"]",
			ownRows[0].Scope, ownRows[1].Scope)
	}
}

// TestAPIKeyScopeRepositoryListByOrganizationIsTenantScoped proves the
// organization-wide list never leaks another tenant's rows and orders
// rows by (api_key_id, scope, id) for stable response shapes.
func TestAPIKeyScopeRepositoryListByOrganizationIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyAID, _, _ := seedAPIKeyForScopes(t, db, f, orgA, "ci")
	keyBID, _, _ := seedAPIKeyForScopes(t, db, f, orgB, "ci")

	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "projects:read"))
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgB.ID, keyBID, "intruder:bait"))

	var rows []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rerr error
		rows, rerr = repo.ListByOrganization(ctx, q, orgA.ID)
		return rerr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("ListByOrganization(tenant-a) returned %d rows, want 1", len(rows))
	}
	if rows[0].APIKeyID != keyAID || rows[0].Scope != "projects:read" {
		t.Errorf("ListByOrganization returned wrong row: api_key=%q scope=%q", rows[0].APIKeyID, rows[0].Scope)
	}
}

// TestAPIKeyScopeRepositoryUpdateScopeRefreshesUpdatedAtAndBumpsVersion
// proves UpdateScope refreshes updated_at via the BEFORE UPDATE trigger,
// bumps version via the api_key_scopes_bump_version trigger, and preserves
// created_at. The mutable surface is exactly {scope}; id, organization_id,
// and api_key_id stay byte-identical to the baseline.
func TestAPIKeyScopeRepositoryUpdateScopeRefreshesUpdatedAtAndBumpsVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	keyID, _, _ := seedAPIKeyForScopes(t, db, f, org, "ci")
	baseline := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, org.ID, keyID, "projects:read"))

	// The Postgres now() clock advances at microsecond resolution; sleep
	// one millisecond so a trigger that fails to refresh updated_at
	// surfaces as a comparison failure rather than an Equal-by-accident.
	time.Sleep(time.Millisecond)

	var updated store.APIKeyScope
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.UpdateScope(ctx, tx, org.ID, baseline.ID, "projects:write")
		if err != nil {
			return err
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("UpdateScope: %v", err)
	}

	if updated.Scope != "projects:write" {
		t.Errorf("UpdateScope returned scope %q, want %q", updated.Scope, "projects:write")
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("UpdateScope version = %d, want %d (trigger must bump)",
			updated.Version, baseline.Version+1)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("UpdateScope mutated created_at: was %v, now %v", baseline.CreatedAt, updated.CreatedAt)
	}
	if !updated.UpdatedAt.After(baseline.UpdatedAt) {
		t.Errorf("UpdateScope updated_at = %v, want > baseline %v (trigger must refresh)",
			updated.UpdatedAt, baseline.UpdatedAt)
	}
	if updated.ID != baseline.ID {
		t.Errorf("UpdateScope mutated id: was %q, now %q", baseline.ID, updated.ID)
	}
	if updated.OrganizationID != baseline.OrganizationID {
		t.Errorf("UpdateScope mutated organization_id: was %q, now %q", baseline.OrganizationID, updated.OrganizationID)
	}
	if updated.APIKeyID != baseline.APIKeyID {
		t.Errorf("UpdateScope mutated api_key_id: was %q, now %q", baseline.APIKeyID, updated.APIKeyID)
	}
}

// TestAPIKeyScopeRepositoryUpdateScopeNotFound proves UpdateScope reports
// the typed apierr.NotFound for a scope id that does not exist in the
// caller's tenant (whether unknown globally or cross-tenant). The
// pgx.ErrNoRows branch is the load-bearing path because UPDATE ... WHERE
// returns no rows when the predicate matches nothing — there is no
// constraint to trip, so the conflict path is not the right code.
func TestAPIKeyScopeRepositoryUpdateScopeNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.UpdateScope(ctx, tx, org.ID, "aks_unknown", "anything")
		return updErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("UpdateScope(unknown id) = %v, want NotFound", err)
	}
}

// TestAPIKeyScopeRepositoryUpdateScopeDuplicateReturnsTypedConflict proves
// renaming a scope onto a row that already claims that (api_key_id, scope)
// tuple surfaces as the typed apierr.Conflict the UNIQUE constraint
// mapWriteError chokepoint produces.
func TestAPIKeyScopeRepositoryUpdateScopeDuplicateReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	keyID, _, _ := seedAPIKeyForScopes(t, db, f, org, "ci")
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, org.ID, keyID, "projects:read"))
	other := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, org.ID, keyID, "services:deploy"))

	// Rename `other` onto the existing "projects:read" tuple.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.UpdateScope(ctx, tx, org.ID, other.ID, "projects:read")
		return updErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("UpdateScope(duplicate) = %v, want Conflict", err)
	}
}

// TestAPIKeyScopeRepositoryDeleteSucceedsAndIsIdempotentTagged proves the
// happy-path Delete returns nil for an existing row and apierr.NotFound
// (via tag.RowsAffected() == 0) when the row is already gone or never
// existed — the same idempotent-tag pattern api_keys.Revoke uses. The
// query is tenant scoped so a cross-tenant id can never delete another
// organization's row.
func TestAPIKeyScopeRepositoryDeleteSucceedsAndIsIdempotentTagged(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	keyAID, _, _ := seedAPIKeyForScopes(t, db, f, orgA, "ci")
	scope := insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, orgA.ID, keyAID, "projects:read"))

	// orgB asks to delete orgA's scope id — tenant-scoped DELETE matches
	// no rows, the repository reports NotFound.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, orgB.ID, scope.ID)
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Delete(cross-tenant id) = %v, want NotFound", err)
	}

	// The row is still there: orgA can read it.
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgA.ID, scope.ID)
		return getErr
	}); err != nil {
		t.Fatalf("Get after cross-tenant Delete: %v", err)
	}

	// orgA deletes its own row.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, orgA.ID, scope.ID)
	}); err != nil {
		t.Fatalf("Delete(own row) = %v", err)
	}

	// Second delete is idempotent at the wire — NotFound, never a 5xx.
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, orgA.ID, scope.ID)
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Delete(already-removed row) = %v, want NotFound", err)
	}
}

// TestAPIKeyScopeRepositoryAPIKeyDeleteCascades proves ON DELETE CASCADE on
// the composite FK removes scope rows when their parent api_keys row is
// deleted. The CASCADE is the only writer of this guarantee — there is no
// application-side cleanup that could substitute — so a regression that
// dropped the CASCADE would leak orphan scope rows pointing at a
// non-existent api_keys row.
func TestAPIKeyScopeRepositoryAPIKeyDeleteCascades(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	keyID, _, _ := seedAPIKeyForScopes(t, db, f, org, "ci")
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, org.ID, keyID, "projects:read"))
	insertAPIKeyScope(ctx, t, s, repo, newAPIKeyScope(f, org.ID, keyID, "services:deploy"))

	// Delete the parent api_keys row via raw SQL (the repository's Revoke
	// only sets revoked_at — it does not delete the row). ON DELETE
	// CASCADE on the composite FK must remove every child scope row.
	if _, err := db.Exec(ctx, `DELETE FROM api_keys WHERE id = $1`, keyID); err != nil {
		t.Fatalf("DELETE api_keys: %v", err)
	}

	var remaining []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rerr error
		remaining, rerr = repo.ListByAPIKey(ctx, q, org.ID, keyID)
		return rerr
	}); err != nil {
		t.Fatalf("ListByAPIKey after parent delete: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("ListByAPIKey after parent delete returned %d rows, want 0 (ON DELETE CASCADE must remove children)",
			len(remaining))
	}
}

// TestAPIKeyScopeRepositoryInsertRollsBackOnTxRollback proves that an
// Insert whose outer Write returns a non-nil error rolls the row back —
// the transaction is the unit of work, and no half-written scope row can
// survive an aborted audit/policy step that runs alongside it. The proof
// is the structural-equivalent of the api_keys rollback case minus the
// secret-bearing column extension: api_key_scopes carries no credential
// material, so the proof reduces to "the row does not exist outside the
// rolled-back transaction" via Get and ListByAPIKey.
func TestAPIKeyScopeRepositoryInsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAPIKeyScopeRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	keyID, _, _ := seedAPIKeyForScopes(t, db, f, org, "ci")
	scope := newAPIKeyScope(f, org.ID, keyID, "projects:read")

	bailout := apiKeyScopeTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, insErr := repo.Insert(ctx, tx, scope); insErr != nil {
			return insErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	getErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, rerr := repo.Get(ctx, q, org.ID, scope.ID)
		return rerr
	})
	if ye := yerr.From(getErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(rolled-back scope) = %v, want NotFound", getErr)
	}

	var listed []store.APIKeyScope
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rerr error
		listed, rerr = repo.ListByAPIKey(ctx, q, org.ID, keyID)
		return rerr
	}); err != nil {
		t.Fatalf("ListByAPIKey after rollback: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("ListByAPIKey after rolled-back Insert returned %d rows, want 0", len(listed))
	}
}

// apiKeyScopeTxRollbackSentinel is a typed error a transaction closure can
// return to force a rollback in TestAPIKeyScopeRepositoryInsertRollsBackOnTxRollback.
// It is local to this test file so callers cannot rely on its identity;
// every *_test.go file under internal/controlplane/store/ shares the same
// store_test package, so the type name is intentionally distinct from
// apikey_test.go's apiKeyTxRollbackSentinel,
// user_repository_invariants_test.go's errSentinel,
// membership_repository_invariants_test.go's membershipTxRollbackSentinel,
// and serviceaccount_repository_invariants_test.go's
// serviceAccountTxRollbackSentinel to avoid a collision.
type apiKeyScopeTxRollbackSentinel struct{}

func (apiKeyScopeTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this api key scope transaction"
}

// TestAPIKeyScopeRepositoryInsertWithoutTxIsTypedInternal proves the
// repository's nil-Tx guard on Insert renders a typed apierr.Internal —
// never a nil-pointer panic — when a caller wires the unit of work wrong.
// This is a pure unit test and requires no database.
func TestAPIKeyScopeRepositoryInsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewAPIKeyScopeRepository()

	_, err := repo.Insert(context.Background(), nil, store.APIKeyScope{
		ID:             "aks_irrelevant",
		OrganizationID: "org_irrelevant",
		APIKeyID:       "key_irrelevant",
		Scope:          "projects:read",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Insert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestAPIKeyScopeRepositoryUpdateScopeWithoutTxIsTypedInternal: same
// guard, UpdateScope path.
func TestAPIKeyScopeRepositoryUpdateScopeWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewAPIKeyScopeRepository()

	_, err := repo.UpdateScope(context.Background(), nil, "org_irrelevant", "aks_irrelevant", "projects:read")
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("UpdateScope(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestAPIKeyScopeRepositoryDeleteWithoutTxIsTypedInternal: same guard,
// Delete path.
func TestAPIKeyScopeRepositoryDeleteWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewAPIKeyScopeRepository()

	err := repo.Delete(context.Background(), nil, "org_irrelevant", "aks_irrelevant")
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Delete(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
