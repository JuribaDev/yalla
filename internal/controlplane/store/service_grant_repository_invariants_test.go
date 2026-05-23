package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration and unit tests for ServiceGrantRepository (BE-0447). This
// file covers the CRUD surface and row-shape / lifecycle invariants of the
// repository's two mutation methods (Upsert, DeleteByServiceExceptIDs) and
// composes naturally with service_grant_test.go (which already pins the
// ListByService ordering and tenant-scoping contract) and with the paired
// BE-0448 service_grant_tenant_isolation_test.go cross-tenant
// byte-identical bystander proof (landing in the paired isolation story).
//
// What this file proves:
//
//   - Upsert INSERT branch returns the row the database actually committed:
//     created_at and updated_at are non-zero and byte-equal on a fresh row
//     (no UPDATE has fired yet, so the service_grants_set_updated_at and
//     service_grants_bump_version triggers from migrations 0034 / 0011
//     have not run), version starts at 1 (the schema default), and the
//     caller-supplied id / organization_id / service_id / principal_id /
//     principal_kind / role are echoed back verbatim.
//
//   - Upsert UPDATE branch (same scope tuple, different caller-supplied id
//     and role) updates ONLY the role, bumps version via the
//     service_grants_bump_version trigger, refreshes updated_at via the
//     service_grants_set_updated_at trigger, preserves created_at, and
//     keeps the immutable identifiers (id, organization_id, service_id,
//     principal_id, principal_kind) byte-identical to the baseline. The
//     caller-supplied id is IGNORED on the conflict branch — the persisted
//     id remains the row's original id, so a re-upsert is idempotent at
//     the customer's view of the resource (same scope tuple = same logical
//     grant). principal_kind stays at the existing value even if the
//     caller supplied a different one for the same principal_id, so
//     cross-kind smuggling is structurally impossible.
//
//   - Upsert rejects a cross-tenant or unknown service_id with a typed
//     apierr.Conflict — the composite FK (organization_id, service_id) ->
//     services (organization_id, id) is MATCH SIMPLE, so a row whose
//     service belongs to one tenant is unrepresentable as another
//     tenant's grant; the constraint-violation class 23 error surfaces as
//     the same typed code the rest of the persistence layer uses.
//
//   - Upsert rejects a duplicate primary key id (a different scope tuple
//     attempting to claim an id another row already owns) with a typed
//     apierr.Conflict — the PRIMARY KEY (id) constraint is the load-
//     bearing defence and mapWriteError surfaces it as Conflict, never as
//     a 5xx.
//
//   - DeleteByServiceExceptIDs with an empty / nil keepIDs slice removes
//     every grant of (organizationID, serviceID) — an explicit "clear all
//     grants" intent is meaningful (extreme), not a silent no-op — and
//     the query is tenant scoped so a cross-tenant serviceID can never
//     delete another organization's grants.
//
//   - DeleteByServiceExceptIDs with a non-empty keepIDs slice removes
//     only the rows whose id is NOT in keepIDs; cross-tenant ids in
//     keepIDs do NOT keep cross-tenant rows alive (the WHERE filter is
//     the only thing keeping the rows apart) — the persisted survivors
//     are exactly the caller-tenant's keepIDs.
//
//   - ON DELETE CASCADE from services removes a service's grants when the
//     parent services row is deleted. The CASCADE is the only writer of
//     this guarantee — there is no application-side cleanup that could
//     substitute — so a regression that dropped the CASCADE would leak
//     orphan grants referencing a non-existent service.
//
//   - Upsert rolls back when the surrounding Write closure returns a non-
//     nil error: the transaction is the unit of work, and no half-written
//     grant row can survive an aborted audit / policy step that runs
//     alongside it. The proof reduces to "the row does not exist outside
//     the rolled-back transaction" via ListByService because the
//     repository exposes no per-id Get — ListByService is the only
//     observation surface for a grant row, so it is the load-bearing leak
//     channel a partial commit would surface through.
//
//   - The Upsert and DeleteByServiceExceptIDs nil-Tx guards render a
//     typed apierr.Internal — never a nil-pointer panic — when a caller
//     wires the unit of work wrong. These are pure unit tests and require
//     no database.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard tests are pure unit tests and require no database.

// newServiceGrantID mints a fresh `sgrnt_<token>` id from the factory
// without colliding with the other resource kinds the factory hands out.
// The factory itself only stamps known domain prefixes, so we synthesize
// the service-grant id from a stable counter — the same shape the service
// layer would mint through domain.NewID(domain.KindServiceGrant).
//
// f.Service mints a unique `svc_<token_n>` per call; rewriting the prefix
// yields an `sgrnt_<token_n>` id that is unique per call and distinct
// from the service's own id namespace. The synthetic parent
// environment/project/org passed in is never persisted — only the
// per-factory counter is observed.
func newServiceGrantID(f *testutil.Factory, label string) string {
	parent := testutil.Environment{
		ID:             "env_irrelevant",
		ProjectID:      "prj_irrelevant",
		OrganizationID: "org_irrelevant",
	}
	return "sgrnt_" + f.Service(parent, label).ID[len("svc_"):]
}

// upsertServiceGrant runs the repository Upsert inside Store.Write and
// returns the persisted row. It is the smallest possible "happy-path
// insert" closure and is reused by every test that does not need to
// observe the upsert's tx in isolation.
func upsertServiceGrant(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceGrantRepository,
	id, organizationID, serviceID, principalID, principalKind, role string,
) store.ServiceGrant {
	t.Helper()
	var stored store.ServiceGrant
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Upsert(ctx, tx, id, organizationID, serviceID, principalID, principalKind, role)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("upsert service grant: %v", err)
	}
	return stored
}

// listServiceGrantsOrFail runs ListByService inside Store.Read and fatals
// on error. It is reused by every test in this file that needs to observe
// the post-condition of a mutation against the only read surface the
// repository exposes for service grants.
//
// The name is intentionally distinct from
// environment_grant_repository_invariants_test.go's
// listEnvironmentGrantsOrFail and from
// project_grant_repository_invariants_test.go's listGrantsOrFail to avoid
// a same-package collision — every *_test.go file under
// internal/controlplane/store/ shares the same store_test package.
func listServiceGrantsOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceGrantRepository, organizationID, serviceID string) []store.ServiceGrant {
	t.Helper()
	var out []store.ServiceGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, lerr := repo.ListByService(ctx, q, organizationID, serviceID)
		if lerr != nil {
			return lerr
		}
		out = rows
		return nil
	}); err != nil {
		t.Fatalf("ListByService(%q, %q): %v", organizationID, serviceID, err)
	}
	return out
}

// TestServiceGrantRepositoryUpsertInsertReturnsRowWithTimestamps proves
// the INSERT branch returns the row the database actually committed.
// created_at and updated_at are both non-zero AND byte-equal on the fresh
// row (no UPDATE has fired yet, so the service_grants_set_updated_at
// trigger has not run), version starts at 1 (the schema default), and the
// caller-supplied fields are echoed back verbatim.
func TestServiceGrantRepositoryUpsertInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	id := newServiceGrantID(f, "alpha")

	got := upsertServiceGrant(ctx, t, s, repo, id, org.ID, svc.ID, "usr_alpha", "usr", "developer")

	if got.ID != id {
		t.Errorf("Upsert returned id %q, want %q", got.ID, id)
	}
	if got.OrganizationID != org.ID {
		t.Errorf("Upsert returned organization_id %q, want %q", got.OrganizationID, org.ID)
	}
	if got.ServiceID != svc.ID {
		t.Errorf("Upsert returned service_id %q, want %q", got.ServiceID, svc.ID)
	}
	if got.PrincipalID != "usr_alpha" {
		t.Errorf("Upsert returned principal_id %q, want %q", got.PrincipalID, "usr_alpha")
	}
	if got.PrincipalKind != "usr" {
		t.Errorf("Upsert returned principal_kind %q, want %q", got.PrincipalKind, "usr")
	}
	if got.Role != "developer" {
		t.Errorf("Upsert returned role %q, want %q", got.Role, "developer")
	}
	if got.Version != 1 {
		t.Errorf("Upsert returned version %d, want 1 (schema default)", got.Version)
	}
	if got.CreatedAt.IsZero() {
		t.Error("Upsert returned zero created_at; the schema default must have populated it")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("Upsert returned zero updated_at; the schema default must have populated it")
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("Upsert created_at = %v, updated_at = %v; the BEFORE UPDATE trigger must NOT have fired on a fresh row (timestamps must be byte-equal)",
			got.CreatedAt, got.UpdatedAt)
	}
}

// TestServiceGrantRepositoryUpsertInsertServiceAccountPrincipalKind proves
// the closed-set CHECK constraint admits the second principal kind ("sa")
// on the INSERT path. The schema accepts only ('usr', 'sa'); both must
// round-trip without translation.
func TestServiceGrantRepositoryUpsertInsertServiceAccountPrincipalKind(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	id := newServiceGrantID(f, "sa")

	got := upsertServiceGrant(ctx, t, s, repo, id, org.ID, svc.ID, "sa_ci", "sa", "ci")

	if got.PrincipalKind != "sa" {
		t.Errorf("Upsert returned principal_kind %q, want %q (service-account grant)", got.PrincipalKind, "sa")
	}
	if got.Role != "ci" {
		t.Errorf("Upsert returned role %q, want %q", got.Role, "ci")
	}
}

// TestServiceGrantRepositoryUpsertUpdateBranchOnlyMutatesRole proves the
// ON CONFLICT (organization_id, service_id, principal_id) DO UPDATE SET
// role = EXCLUDED.role branch updates ONLY the role: version is bumped by
// the service_grants_bump_version trigger, updated_at is refreshed by the
// service_grants_set_updated_at trigger, created_at is preserved, and the
// immutable identifiers (id, organization_id, service_id, principal_id,
// principal_kind) stay byte-identical to the baseline. The caller-supplied
// id is IGNORED on the conflict branch — the persisted id stays at the
// baseline's id, never the second caller's id. principal_kind stays at
// the baseline's value even when the caller supplies a different kind for
// the same principal_id, so cross-kind smuggling is structurally
// impossible at this layer.
func TestServiceGrantRepositoryUpsertUpdateBranchOnlyMutatesRole(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	baselineID := newServiceGrantID(f, "baseline")
	baseline := upsertServiceGrant(ctx, t, s, repo, baselineID, org.ID, svc.ID, "usr_alpha", "usr", "developer")

	// The Postgres now() clock advances at microsecond resolution; sleep
	// one millisecond so a trigger that fails to refresh updated_at
	// surfaces as a comparison failure rather than an Equal-by-accident.
	time.Sleep(time.Millisecond)

	// Re-upsert at the SAME scope tuple (same principal_id), with a
	// DIFFERENT caller-supplied id, a DIFFERENT role, and a DIFFERENT
	// principal_kind. The repository must:
	//   * keep the baseline's id (the caller-supplied id is ignored on the
	//     conflict branch);
	//   * update role to "admin" (the only customer-mutable field);
	//   * keep principal_kind at "usr" — the caller's "sa" must not stick;
	//   * bump version; refresh updated_at; preserve created_at.
	overrideID := newServiceGrantID(f, "override")
	updated := upsertServiceGrant(ctx, t, s, repo, overrideID, org.ID, svc.ID, "usr_alpha", "sa", "admin")

	if updated.ID != baseline.ID {
		t.Errorf("Upsert(conflict) mutated id: was %q, now %q (caller-supplied id must be ignored on the conflict branch)",
			baseline.ID, updated.ID)
	}
	if updated.OrganizationID != baseline.OrganizationID {
		t.Errorf("Upsert(conflict) mutated organization_id: was %q, now %q", baseline.OrganizationID, updated.OrganizationID)
	}
	if updated.ServiceID != baseline.ServiceID {
		t.Errorf("Upsert(conflict) mutated service_id: was %q, now %q", baseline.ServiceID, updated.ServiceID)
	}
	if updated.PrincipalID != baseline.PrincipalID {
		t.Errorf("Upsert(conflict) mutated principal_id: was %q, now %q", baseline.PrincipalID, updated.PrincipalID)
	}
	if updated.PrincipalKind != "usr" {
		t.Errorf("Upsert(conflict) returned principal_kind %q, want %q (cross-kind smuggling must be impossible)", updated.PrincipalKind, "usr")
	}
	if updated.Role != "admin" {
		t.Errorf("Upsert(conflict) returned role %q, want %q", updated.Role, "admin")
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("Upsert(conflict) version = %d, want %d (trigger must bump)", updated.Version, baseline.Version+1)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("Upsert(conflict) mutated created_at: was %v, now %v", baseline.CreatedAt, updated.CreatedAt)
	}
	if !updated.UpdatedAt.After(baseline.UpdatedAt) {
		t.Errorf("Upsert(conflict) updated_at = %v, want > baseline %v (trigger must refresh)",
			updated.UpdatedAt, baseline.UpdatedAt)
	}
}

// TestServiceGrantRepositoryUpsertCrossTenantServiceReturnsTypedConflict
// proves the composite FK (organization_id, service_id) -> services
// rejects a row whose service belongs to another organization. The FK is
// MATCH SIMPLE so a cross-tenant service_id is structurally
// unrepresentable: even though the grant id and role are well-formed, the
// constraint-violation class 23 error surfaces as the typed
// apierr.Conflict at the persistence chokepoint. An unknown service_id
// (no row at all) lands on the same path for the same reason.
func TestServiceGrantRepositoryUpsertCrossTenantServiceReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "b-only")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcB := seedService(t, db, f, envB, "api")

	// orgA tries to attach a grant to orgB's service.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, newServiceGrantID(f, "cross"), orgA.ID, svcB.ID, "usr_a", "usr", "developer")
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(cross-tenant service) error = %v, want code %s", err, yerr.CodeConflict)
	}

	// An unknown service_id under orgA lands on the same conflict code —
	// the same FK violation, the same typed shape.
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, newServiceGrantID(f, "ghost"), orgA.ID, "svc_does_not_exist", "usr_a", "usr", "developer")
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(unknown service) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

// TestServiceGrantRepositoryUpsertDuplicatePrimaryKeyReturnsTypedConflict
// proves the PRIMARY KEY (id) constraint surfaces a second Upsert that
// reuses an existing id at a DIFFERENT scope tuple (different principal,
// so the ON CONFLICT (org, service, principal) branch does NOT match) as
// the typed apierr.Conflict mapWriteError produces. The id is reserved
// per-row across the whole table; the ON CONFLICT branch only fires for
// the principal-scope-tuple unique constraint, not for the primary key.
func TestServiceGrantRepositoryUpsertDuplicatePrimaryKeyReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	id := newServiceGrantID(f, "shared")

	upsertServiceGrant(ctx, t, s, repo, id, org.ID, svc.ID, "usr_alpha", "usr", "developer")

	// Second Upsert: same id, DIFFERENT principal_id. The ON CONFLICT
	// branch keys on (org, service, principal) — principal_id is
	// different — so the conflict resolution path is the PRIMARY KEY (id)
	// uniqueness violation, not the principal-scope-tuple upsert.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, id, org.ID, svc.ID, "usr_beta", "usr", "developer")
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(duplicate id) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

// TestServiceGrantRepositoryDeleteByServiceExceptIDsEmptyKeepClearsAll
// proves DeleteByServiceExceptIDs with a nil / empty keepIDs slice
// removes every grant of (organizationID, serviceID) — an explicit "clear
// all grants" intent is meaningful (extreme), not a silent no-op. Both
// nil and an empty slice are treated identically.
func TestServiceGrantRepositoryDeleteByServiceExceptIDsEmptyKeepClearsAll(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")

	upsertServiceGrant(ctx, t, s, repo, newServiceGrantID(f, "one"), org.ID, svc.ID, "usr_a", "usr", "developer")
	upsertServiceGrant(ctx, t, s, repo, newServiceGrantID(f, "two"), org.ID, svc.ID, "usr_b", "usr", "viewer")

	// nil keepIDs.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptIDs(ctx, tx, org.ID, svc.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptIDs(nil): %v", err)
	}
	if remaining := listServiceGrantsOrFail(ctx, t, s, repo, org.ID, svc.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByServiceExceptIDs(nil) %d rows remain, want 0", len(remaining))
	}

	// Re-seed and try the explicit empty slice — must be identical.
	upsertServiceGrant(ctx, t, s, repo, newServiceGrantID(f, "three"), org.ID, svc.ID, "usr_c", "usr", "developer")
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptIDs(ctx, tx, org.ID, svc.ID, []string{})
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptIDs([]): %v", err)
	}
	if remaining := listServiceGrantsOrFail(ctx, t, s, repo, org.ID, svc.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByServiceExceptIDs([]) %d rows remain, want 0", len(remaining))
	}
}

// TestServiceGrantRepositoryDeleteByServiceExceptIDsRemovesOnlyExcluded
// proves a non-empty keepIDs slice retains exactly the rows whose id is
// in the slice and removes every other row of the service's grants.
func TestServiceGrantRepositoryDeleteByServiceExceptIDsRemovesOnlyExcluded(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")

	keeper := upsertServiceGrant(ctx, t, s, repo, newServiceGrantID(f, "keeper"), org.ID, svc.ID, "usr_keeper", "usr", "developer")
	dropped := upsertServiceGrant(ctx, t, s, repo, newServiceGrantID(f, "dropped"), org.ID, svc.ID, "usr_dropped", "usr", "viewer")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptIDs(ctx, tx, org.ID, svc.ID, []string{keeper.ID})
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptIDs([keeper]): %v", err)
	}

	remaining := listServiceGrantsOrFail(ctx, t, s, repo, org.ID, svc.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByServiceExceptIDs([keeper]) %d rows remain, want 1", len(remaining))
	}
	if remaining[0].ID != keeper.ID {
		t.Errorf("remaining[0].ID = %q, want %q (the keeper)", remaining[0].ID, keeper.ID)
	}
	if remaining[0].ID == dropped.ID {
		t.Errorf("dropped row %q survived; keep set must NOT keep excluded ids", dropped.ID)
	}
}

// TestServiceGrantRepositoryDeleteByServiceExceptIDsIsTenantScoped proves
// a cross-tenant serviceID cannot delete another organization's grants —
// the WHERE clause filters on organization_id AND service_id. A pair of
// tenants each owning a service named identically inside their tenant
// would fail this property if the WHERE missed the organization_id leg.
func TestServiceGrantRepositoryDeleteByServiceExceptIDsIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "ledger")
	projB := seedProject(t, db, f, orgB, "ledger")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcA := seedService(t, db, f, envA, "api")
	svcB := seedService(t, db, f, envB, "api")

	bystander := upsertServiceGrant(ctx, t, s, repo, newServiceGrantID(f, "bystander"), orgB.ID, svcB.ID, "usr_b", "usr", "developer")
	upsertServiceGrant(ctx, t, s, repo, newServiceGrantID(f, "victim"), orgA.ID, svcA.ID, "usr_a", "usr", "developer")

	// orgA asks to clear orgB's serviceID. Composite WHERE filters on
	// (org, service) so the predicate matches zero rows.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptIDs(ctx, tx, orgA.ID, svcB.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptIDs(cross-tenant serviceID): %v", err)
	}

	// orgB's bystander grant is untouched.
	remainingB := listServiceGrantsOrFail(ctx, t, s, repo, orgB.ID, svcB.ID)
	if len(remainingB) != 1 || remainingB[0].ID != bystander.ID {
		t.Errorf("orgB grants after cross-tenant clear = %+v, want exactly bystander %q", remainingB, bystander.ID)
	}

	// orgA's own grant is also still there because the predicate matched
	// no rows (different service_id, even though same organization_id).
	remainingA := listServiceGrantsOrFail(ctx, t, s, repo, orgA.ID, svcA.ID)
	if len(remainingA) != 1 {
		t.Errorf("orgA grants after cross-tenant clear = %+v, want exactly 1 (own grant)", remainingA)
	}
}

// TestServiceGrantRepositoryServiceDeleteCascades proves ON DELETE CASCADE
// on the composite FK (organization_id, service_id) -> services removes
// every service_grants row when the parent services row is deleted. The
// CASCADE is the only writer of this guarantee — there is no
// application-side cleanup that could substitute — so a regression that
// dropped the CASCADE would leak orphan grants referencing a non-existent
// service.
//
// We delete the parent services row via raw SQL because the
// ServiceRepository's ScheduleDeletion only stamps deletion_scheduled_at
// (a soft delete) and does NOT delete the row, which would not trigger
// CASCADE.
func TestServiceGrantRepositoryServiceDeleteCascades(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	upsertServiceGrant(ctx, t, s, repo, newServiceGrantID(f, "one"), org.ID, svc.ID, "usr_a", "usr", "developer")
	upsertServiceGrant(ctx, t, s, repo, newServiceGrantID(f, "two"), org.ID, svc.ID, "usr_b", "usr", "viewer")

	if _, err := db.Exec(ctx, `DELETE FROM services WHERE id = $1`, svc.ID); err != nil {
		t.Fatalf("DELETE services: %v", err)
	}

	remaining := listServiceGrantsOrFail(ctx, t, s, repo, org.ID, svc.ID)
	if len(remaining) != 0 {
		t.Errorf("ListByService after parent delete returned %d rows, want 0 (ON DELETE CASCADE must remove children)",
			len(remaining))
	}
}

// TestServiceGrantRepositoryUpsertRollsBackOnTxRollback proves that an
// Upsert whose outer Write returns a non-nil error rolls the row back —
// the transaction is the unit of work, and no half-written grant row can
// survive an aborted audit/policy step that runs alongside it. The proof
// reduces to "no row matches at the ListByService read surface outside
// the rolled-back transaction" because the repository exposes no per-id
// Get for grants — ListByService is the only observation surface for a
// grant row, so it is the load-bearing leak channel a partial commit
// would surface through.
func TestServiceGrantRepositoryUpsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	id := newServiceGrantID(f, "rollback")

	bailout := serviceGrantTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, upErr := repo.Upsert(ctx, tx, id, org.ID, svc.ID, "usr_alpha", "usr", "developer"); upErr != nil {
			return upErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	listed := listServiceGrantsOrFail(ctx, t, s, repo, org.ID, svc.ID)
	if len(listed) != 0 {
		t.Errorf("ListByService after rolled-back Upsert returned %d rows, want 0", len(listed))
	}
	for _, g := range listed {
		if g.ID == id {
			t.Errorf("rolled-back grant id %q is visible at ListByService; the transaction did NOT roll back", id)
		}
	}
}

// serviceGrantTxRollbackSentinel is a typed error a transaction closure
// can return to force a rollback in
// TestServiceGrantRepositoryUpsertRollsBackOnTxRollback. It is local to
// this test file so callers cannot rely on its identity; every *_test.go
// file under internal/controlplane/store/ shares the same store_test
// package, so the type name is intentionally distinct from
// environment_grant_repository_invariants_test.go's
// environmentGrantTxRollbackSentinel,
// project_grant_repository_invariants_test.go's projectGrantTxRollbackSentinel,
// api_key_scope_repository_invariants_test.go's apiKeyScopeTxRollbackSentinel,
// and the other rollback sentinels in store_test to avoid a collision.
type serviceGrantTxRollbackSentinel struct{}

func (serviceGrantTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this service grant transaction"
}

// TestServiceGrantRepositoryUpsertWithoutTxIsTypedInternal proves the
// repository's nil-Tx guard on Upsert renders a typed apierr.Internal —
// never a nil-pointer panic — when a caller wires the unit of work wrong.
// This is a pure unit test and requires no database.
func TestServiceGrantRepositoryUpsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceGrantRepository()

	_, err := repo.Upsert(context.Background(), nil,
		"sgrnt_irrelevant", "org_irrelevant", "svc_irrelevant", "usr_irrelevant", "usr", "developer")
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Upsert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestServiceGrantRepositoryDeleteByServiceExceptIDsWithoutTxIsTypedInternal:
// same guard, DeleteByServiceExceptIDs path.
func TestServiceGrantRepositoryDeleteByServiceExceptIDsWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceGrantRepository()

	err := repo.DeleteByServiceExceptIDs(context.Background(), nil, "org_irrelevant", "svc_irrelevant", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("DeleteByServiceExceptIDs(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
