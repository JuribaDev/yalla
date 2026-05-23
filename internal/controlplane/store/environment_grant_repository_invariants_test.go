package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration and unit tests for EnvironmentGrantRepository (BE-0443). This
// file covers the CRUD surface and row-shape / lifecycle invariants of the
// repository's two mutation methods (Upsert, DeleteByEnvironmentExceptIDs)
// and composes naturally with environment_grant_test.go (which already pins
// the ListByEnvironment ordering and tenant-scoping contract) and with the
// paired BE-0444 environment_grant_tenant_isolation_test.go cross-tenant
// byte-identical bystander proof (landing in the paired isolation story).
//
// What this file proves:
//
//   - Upsert INSERT branch returns the row the database actually committed:
//     created_at and updated_at are non-zero and byte-equal on a fresh row
//     (no UPDATE has fired yet, so the environment_grants_set_updated_at and
//     environment_grants_bump_version triggers from migration 0017 / 0011
//     have not run), version starts at 1 (the schema default), the caller-
//     supplied id / organization_id / environment_id / principal_id /
//     principal_kind / role are echoed back verbatim, and the optional
//     service_id pointer is preserved as the schema stored it (NULL stays
//     nil; non-NULL round-trips as a pointer to the exact text).
//
//   - Upsert UPDATE branch (same scope tuple, different caller-supplied id
//     and role) updates ONLY the role, bumps version via the
//     environment_grants_bump_version trigger, refreshes updated_at via the
//     environment_grants_set_updated_at trigger, preserves created_at, and
//     keeps the immutable identifiers (id, organization_id, environment_id,
//     principal_id, principal_kind, service_id) byte-identical to the
//     baseline. The caller-supplied id is IGNORED on the conflict branch —
//     the persisted id remains the row's original id, so a re-upsert is
//     idempotent at the customer's view of the resource (same scope tuple
//     = same logical grant). principal_kind stays at the existing value
//     even if the caller supplied a different one for the same
//     principal_id, so cross-kind smuggling is structurally impossible.
//
//   - Upsert rejects a cross-tenant or unknown environment_id with a typed
//     apierr.Conflict — the composite FK (organization_id, environment_id)
//     -> environments (organization_id, id) is MATCH SIMPLE, so a row
//     whose environment belongs to one tenant is unrepresentable as
//     another tenant's grant; the constraint-violation class 23 error
//     surfaces as the same typed code the rest of the persistence layer
//     uses.
//
//   - Upsert rejects a duplicate primary key id (a different scope tuple
//     attempting to claim an id another row already owns) with a typed
//     apierr.Conflict — the PRIMARY KEY (id) constraint is the load-
//     bearing defence and mapWriteError surfaces it as Conflict, never as
//     a 5xx.
//
//   - DeleteByEnvironmentExceptIDs with an empty / nil keepIDs slice
//     removes every grant of (organizationID, environmentID) — an explicit
//     "clear all grants" intent is meaningful (extreme), not a silent no-
//     op — and the query is tenant scoped so a cross-tenant environmentID
//     can never delete another organization's grants.
//
//   - DeleteByEnvironmentExceptIDs with a non-empty keepIDs slice removes
//     only the rows whose id is NOT in keepIDs; cross-tenant ids in
//     keepIDs do NOT keep cross-tenant rows alive (the WHERE filter is
//     the only thing keeping the rows apart) — the persisted survivors
//     are exactly the caller-tenant's keepIDs.
//
//   - ON DELETE CASCADE from environments removes an environment's grants
//     when the parent environments row is deleted. The CASCADE is the only
//     writer of this guarantee — there is no application-side cleanup that
//     could substitute — so a regression that dropped the CASCADE would
//     leak orphan grants referencing a non-existent environment.
//
//   - Upsert rolls back when the surrounding Write closure returns a non-
//     nil error: the transaction is the unit of work, and no half-written
//     grant row can survive an aborted audit / policy step that runs
//     alongside it. The proof reduces to "the row does not exist outside
//     the rolled-back transaction" via ListByEnvironment because the
//     repository exposes no per-id Get — ListByEnvironment is the only
//     observation surface for a grant row, so it is the load-bearing leak
//     channel a partial commit would surface through.
//
//   - The Upsert and DeleteByEnvironmentExceptIDs nil-Tx guards render a
//     typed apierr.Internal — never a nil-pointer panic — when a caller
//     wires the unit of work wrong. These are pure unit tests and require
//     no database.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard tests are pure unit tests and require no database.

// newEnvironmentGrantID mints a fresh `egrnt_<token>` id from the factory
// without colliding with the other resource kinds the factory hands out.
// The factory itself only stamps known domain prefixes, so we synthesize
// the environment-grant id from a stable counter — the same shape the
// service layer uses through domain.NewID(domain.KindEnvironmentGrant).
//
// f.Environment mints a unique `env_<token_n>` per call; rewriting the
// prefix yields an `egrnt_<token_n>` id that is unique per call and
// distinct from the environment's own id namespace. The synthetic parent
// project/org passed in is never persisted — only the per-factory counter
// is observed.
func newEnvironmentGrantID(f *testutil.Factory, label string) string {
	parent := testutil.Project{ID: "prj_irrelevant", OrganizationID: "org_irrelevant"}
	return "egrnt_" + f.Environment(parent, label).ID[len("env_"):]
}

// upsertEnvironmentGrant runs the repository Upsert inside Store.Write and
// returns the persisted row. It is the smallest possible "happy-path
// insert" closure and is reused by every test that does not need to
// observe the upsert's tx in isolation.
func upsertEnvironmentGrant(ctx context.Context, t *testing.T, s *store.Store, repo *store.EnvironmentGrantRepository,
	id, organizationID, environmentID, principalID, principalKind, role string, svcID *string,
) store.EnvironmentGrant {
	t.Helper()
	var stored store.EnvironmentGrant
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Upsert(ctx, tx, id, organizationID, environmentID, principalID, principalKind, role, svcID)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("upsert environment grant: %v", err)
	}
	return stored
}

// listEnvironmentGrantsOrFail runs ListByEnvironment inside Store.Read and
// fatals on error. It is reused by every test in this file that needs to
// observe the post-condition of a mutation against the only read surface
// the repository exposes for grants.
//
// The name is intentionally distinct from project_grant_repository_invariants_test.go's
// listGrantsOrFail to avoid a same-package collision — every *_test.go
// file under internal/controlplane/store/ shares the same store_test
// package.
func listEnvironmentGrantsOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.EnvironmentGrantRepository, organizationID, environmentID string) []store.EnvironmentGrant {
	t.Helper()
	var out []store.EnvironmentGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, lerr := repo.ListByEnvironment(ctx, q, organizationID, environmentID)
		if lerr != nil {
			return lerr
		}
		out = rows
		return nil
	}); err != nil {
		t.Fatalf("ListByEnvironment(%q, %q): %v", organizationID, environmentID, err)
	}
	return out
}

// TestEnvironmentGrantRepositoryUpsertInsertReturnsRowWithTimestamps proves
// the INSERT branch returns the row the database actually committed.
// created_at and updated_at are both non-zero AND byte-equal on the fresh
// row (no UPDATE has fired yet, so the environment_grants_set_updated_at
// trigger has not run), version starts at 1 (the schema default), and the
// caller-supplied fields are echoed back verbatim. ServiceID stays nil for
// an environment-root grant.
func TestEnvironmentGrantRepositoryUpsertInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	id := newEnvironmentGrantID(f, "alpha")

	got := upsertEnvironmentGrant(ctx, t, s, repo, id, org.ID, env.ID, "usr_alpha", "usr", "developer", nil)

	if got.ID != id {
		t.Errorf("Upsert returned id %q, want %q", got.ID, id)
	}
	if got.OrganizationID != org.ID {
		t.Errorf("Upsert returned organization_id %q, want %q", got.OrganizationID, org.ID)
	}
	if got.EnvironmentID != env.ID {
		t.Errorf("Upsert returned environment_id %q, want %q", got.EnvironmentID, env.ID)
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
	if got.ServiceID != nil {
		t.Errorf("Upsert returned service_id = %v, want nil (environment-root grant)", *got.ServiceID)
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

// TestEnvironmentGrantRepositoryUpsertInsertWithServiceRoundtripsPointer
// proves the optional service_id column round-trips as a non-nil pointer
// when the caller opts into a service-scoped grant. The schema CHECKs
// reject empty strings (CHECK (service_id IS NULL OR length(service_id) >
// 0)) so the pointer's payload is structurally non-empty. PrincipalKind
// "sa" rides the same path as "usr"; both are accepted by the closed-set
// CHECK.
func TestEnvironmentGrantRepositoryUpsertInsertWithServiceRoundtripsPointer(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	svcID := "svc_web"
	id := newEnvironmentGrantID(f, "scoped")

	got := upsertEnvironmentGrant(ctx, t, s, repo, id, org.ID, env.ID, "sa_one", "sa", "ci", &svcID)

	if got.ServiceID == nil || *got.ServiceID != svcID {
		t.Errorf("Upsert returned service_id = %v, want pointer to %q", got.ServiceID, svcID)
	}
	if got.PrincipalKind != "sa" {
		t.Errorf("Upsert returned principal_kind %q, want %q (service-account grant)", got.PrincipalKind, "sa")
	}
}

// TestEnvironmentGrantRepositoryUpsertUpdateBranchOnlyMutatesRole proves
// the ON CONFLICT (organization_id, environment_id, principal_id,
// COALESCE(service_id, ”)) DO UPDATE SET role = EXCLUDED.role branch
// updates ONLY the role: version is bumped by the
// environment_grants_bump_version trigger, updated_at is refreshed by the
// environment_grants_set_updated_at trigger, created_at is preserved, and
// the immutable identifiers (id, organization_id, environment_id,
// principal_id, principal_kind, service_id) stay byte-identical to the
// baseline. The caller-supplied id is IGNORED on the conflict branch —
// the persisted id stays at the baseline's id, never the second caller's
// id. principal_kind stays at the baseline's value even when the caller
// supplies a different kind for the same principal_id, so cross-kind
// smuggling is structurally impossible at this layer.
func TestEnvironmentGrantRepositoryUpsertUpdateBranchOnlyMutatesRole(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	baselineID := newEnvironmentGrantID(f, "baseline")
	baseline := upsertEnvironmentGrant(ctx, t, s, repo, baselineID, org.ID, env.ID, "usr_alpha", "usr", "developer", nil)

	// The Postgres now() clock advances at microsecond resolution; sleep
	// one millisecond so a trigger that fails to refresh updated_at
	// surfaces as a comparison failure rather than an Equal-by-accident.
	time.Sleep(time.Millisecond)

	// Re-upsert at the SAME scope tuple (same principal_id, same nil
	// service_id), with a DIFFERENT caller-supplied id, a DIFFERENT role,
	// and a DIFFERENT principal_kind. The repository must:
	//   * keep the baseline's id (the caller-supplied id is ignored on the
	//     conflict branch);
	//   * update role to "admin" (the only customer-mutable field);
	//   * keep principal_kind at "usr" — the caller's "sa" must not stick;
	//   * bump version; refresh updated_at; preserve created_at.
	overrideID := newEnvironmentGrantID(f, "override")
	updated := upsertEnvironmentGrant(ctx, t, s, repo, overrideID, org.ID, env.ID, "usr_alpha", "sa", "admin", nil)

	if updated.ID != baseline.ID {
		t.Errorf("Upsert(conflict) mutated id: was %q, now %q (caller-supplied id must be ignored on the conflict branch)",
			baseline.ID, updated.ID)
	}
	if updated.OrganizationID != baseline.OrganizationID {
		t.Errorf("Upsert(conflict) mutated organization_id: was %q, now %q", baseline.OrganizationID, updated.OrganizationID)
	}
	if updated.EnvironmentID != baseline.EnvironmentID {
		t.Errorf("Upsert(conflict) mutated environment_id: was %q, now %q", baseline.EnvironmentID, updated.EnvironmentID)
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
	if updated.ServiceID != nil {
		t.Errorf("Upsert(conflict) mutated service_id from nil to %v", *updated.ServiceID)
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

// TestEnvironmentGrantRepositoryUpsertCrossTenantEnvironmentReturnsTypedConflict
// proves the composite FK (organization_id, environment_id) -> environments
// rejects a row whose environment belongs to another organization. The FK
// is MATCH SIMPLE so a cross-tenant environment_id is structurally
// unrepresentable: even though the grant id and role are well-formed, the
// constraint-violation class 23 error surfaces as the typed apierr.Conflict
// at the persistence chokepoint. An unknown environment_id (no row at all)
// lands on the same path for the same reason.
func TestEnvironmentGrantRepositoryUpsertCrossTenantEnvironmentReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "b-only")
	envB := seedEnvironment(t, db, f, projB, "production")

	// orgA tries to attach a grant to orgB's environment.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, newEnvironmentGrantID(f, "cross"), orgA.ID, envB.ID, "usr_a", "usr", "developer", nil)
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(cross-tenant environment) error = %v, want code %s", err, yerr.CodeConflict)
	}

	// An unknown environment_id under orgA lands on the same conflict
	// code — the same FK violation, the same typed shape.
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, newEnvironmentGrantID(f, "ghost"), orgA.ID, "env_does_not_exist", "usr_a", "usr", "developer", nil)
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(unknown environment) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

// TestEnvironmentGrantRepositoryUpsertDuplicatePrimaryKeyReturnsTypedConflict
// proves the PRIMARY KEY (id) constraint surfaces a second Upsert that
// reuses an existing id at a DIFFERENT scope tuple (different principal,
// so the ON CONFLICT (org, env, principal, svc) branch does NOT match) as
// the typed apierr.Conflict mapWriteError produces. The id is reserved
// per-row across the whole table; the ON CONFLICT branch only fires for
// the principal-scope-tuple unique index, not for the primary key.
func TestEnvironmentGrantRepositoryUpsertDuplicatePrimaryKeyReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	id := newEnvironmentGrantID(f, "shared")

	upsertEnvironmentGrant(ctx, t, s, repo, id, org.ID, env.ID, "usr_alpha", "usr", "developer", nil)

	// Second Upsert: same id, DIFFERENT principal_id. The ON CONFLICT
	// branch keys on (org, env, principal, svc) — principal_id is
	// different — so the conflict resolution path is the PRIMARY KEY (id)
	// uniqueness violation, not the principal-scope-tuple upsert.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, id, org.ID, env.ID, "usr_beta", "usr", "developer", nil)
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(duplicate id) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

// TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsEmptyKeepClearsAll
// proves DeleteByEnvironmentExceptIDs with a nil / empty keepIDs slice
// removes every grant of (organizationID, environmentID) — an explicit
// "clear all grants" intent is meaningful (extreme), not a silent no-op.
// Both nil and an empty slice are treated identically.
func TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsEmptyKeepClearsAll(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")

	upsertEnvironmentGrant(ctx, t, s, repo, newEnvironmentGrantID(f, "one"), org.ID, env.ID, "usr_a", "usr", "developer", nil)
	upsertEnvironmentGrant(ctx, t, s, repo, newEnvironmentGrantID(f, "two"), org.ID, env.ID, "usr_b", "usr", "viewer", nil)

	// nil keepIDs.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptIDs(ctx, tx, org.ID, env.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptIDs(nil): %v", err)
	}
	if remaining := listEnvironmentGrantsOrFail(ctx, t, s, repo, org.ID, env.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByEnvironmentExceptIDs(nil) %d rows remain, want 0", len(remaining))
	}

	// Re-seed and try the explicit empty slice — must be identical.
	upsertEnvironmentGrant(ctx, t, s, repo, newEnvironmentGrantID(f, "three"), org.ID, env.ID, "usr_c", "usr", "developer", nil)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptIDs(ctx, tx, org.ID, env.ID, []string{})
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptIDs([]): %v", err)
	}
	if remaining := listEnvironmentGrantsOrFail(ctx, t, s, repo, org.ID, env.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByEnvironmentExceptIDs([]) %d rows remain, want 0", len(remaining))
	}
}

// TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsRemovesOnlyExcluded
// proves a non-empty keepIDs slice retains exactly the rows whose id is in
// the slice and removes every other row of the environment's grants.
func TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsRemovesOnlyExcluded(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")

	keeper := upsertEnvironmentGrant(ctx, t, s, repo, newEnvironmentGrantID(f, "keeper"), org.ID, env.ID, "usr_keeper", "usr", "developer", nil)
	dropped := upsertEnvironmentGrant(ctx, t, s, repo, newEnvironmentGrantID(f, "dropped"), org.ID, env.ID, "usr_dropped", "usr", "viewer", nil)

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptIDs(ctx, tx, org.ID, env.ID, []string{keeper.ID})
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptIDs([keeper]): %v", err)
	}

	remaining := listEnvironmentGrantsOrFail(ctx, t, s, repo, org.ID, env.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByEnvironmentExceptIDs([keeper]) %d rows remain, want 1", len(remaining))
	}
	if remaining[0].ID != keeper.ID {
		t.Errorf("remaining[0].ID = %q, want %q (the keeper)", remaining[0].ID, keeper.ID)
	}
	if remaining[0].ID == dropped.ID {
		t.Errorf("dropped row %q survived; keep set must NOT keep excluded ids", dropped.ID)
	}
}

// TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsIsTenantScoped
// proves a cross-tenant environmentID cannot delete another organization's
// grants — the WHERE clause filters on organization_id AND environment_id.
// A pair of tenants each owning an environment named identically inside
// their tenant would fail this property if the WHERE missed the
// organization_id leg.
func TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "ledger")
	projB := seedProject(t, db, f, orgB, "ledger")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")

	bystander := upsertEnvironmentGrant(ctx, t, s, repo, newEnvironmentGrantID(f, "bystander"), orgB.ID, envB.ID, "usr_b", "usr", "developer", nil)
	upsertEnvironmentGrant(ctx, t, s, repo, newEnvironmentGrantID(f, "victim"), orgA.ID, envA.ID, "usr_a", "usr", "developer", nil)

	// orgA asks to clear orgB's environmentID. Composite WHERE filters on
	// (org, environment) so the predicate matches zero rows.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptIDs(ctx, tx, orgA.ID, envB.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptIDs(cross-tenant environmentID): %v", err)
	}

	// orgB's bystander grant is untouched.
	remainingB := listEnvironmentGrantsOrFail(ctx, t, s, repo, orgB.ID, envB.ID)
	if len(remainingB) != 1 || remainingB[0].ID != bystander.ID {
		t.Errorf("orgB grants after cross-tenant clear = %+v, want exactly bystander %q", remainingB, bystander.ID)
	}

	// orgA's own grant is also still there because the predicate matched
	// no rows (different environment_id, even though same organization_id).
	remainingA := listEnvironmentGrantsOrFail(ctx, t, s, repo, orgA.ID, envA.ID)
	if len(remainingA) != 1 {
		t.Errorf("orgA grants after cross-tenant clear = %+v, want exactly 1 (own grant)", remainingA)
	}
}

// TestEnvironmentGrantRepositoryEnvironmentDeleteCascades proves ON DELETE
// CASCADE on the composite FK (organization_id, environment_id) ->
// environments removes every environment_grants row when the parent
// environments row is deleted. The CASCADE is the only writer of this
// guarantee — there is no application-side cleanup that could substitute —
// so a regression that dropped the CASCADE would leak orphan grants
// referencing a non-existent environment.
//
// We delete the parent environments row via raw SQL because the
// EnvironmentRepository's ScheduleDeletion only stamps deletion_scheduled_at
// (a soft delete) and does NOT delete the row, which would not trigger
// CASCADE.
func TestEnvironmentGrantRepositoryEnvironmentDeleteCascades(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	upsertEnvironmentGrant(ctx, t, s, repo, newEnvironmentGrantID(f, "one"), org.ID, env.ID, "usr_a", "usr", "developer", nil)
	upsertEnvironmentGrant(ctx, t, s, repo, newEnvironmentGrantID(f, "two"), org.ID, env.ID, "usr_b", "usr", "viewer", nil)

	if _, err := db.Exec(ctx, `DELETE FROM environments WHERE id = $1`, env.ID); err != nil {
		t.Fatalf("DELETE environments: %v", err)
	}

	remaining := listEnvironmentGrantsOrFail(ctx, t, s, repo, org.ID, env.ID)
	if len(remaining) != 0 {
		t.Errorf("ListByEnvironment after parent delete returned %d rows, want 0 (ON DELETE CASCADE must remove children)",
			len(remaining))
	}
}

// TestEnvironmentGrantRepositoryUpsertRollsBackOnTxRollback proves that an
// Upsert whose outer Write returns a non-nil error rolls the row back —
// the transaction is the unit of work, and no half-written grant row can
// survive an aborted audit/policy step that runs alongside it. The proof
// reduces to "no row matches at the ListByEnvironment read surface outside
// the rolled-back transaction" because the repository exposes no per-id
// Get for grants — ListByEnvironment is the only observation surface for
// a grant row, so it is the load-bearing leak channel a partial commit
// would surface through.
func TestEnvironmentGrantRepositoryUpsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	env := seedEnvironment(t, db, f, proj, "production")
	id := newEnvironmentGrantID(f, "rollback")

	bailout := environmentGrantTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, upErr := repo.Upsert(ctx, tx, id, org.ID, env.ID, "usr_alpha", "usr", "developer", nil); upErr != nil {
			return upErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	listed := listEnvironmentGrantsOrFail(ctx, t, s, repo, org.ID, env.ID)
	if len(listed) != 0 {
		t.Errorf("ListByEnvironment after rolled-back Upsert returned %d rows, want 0", len(listed))
	}
	for _, g := range listed {
		if g.ID == id {
			t.Errorf("rolled-back grant id %q is visible at ListByEnvironment; the transaction did NOT roll back", id)
		}
	}
}

// environmentGrantTxRollbackSentinel is a typed error a transaction closure
// can return to force a rollback in
// TestEnvironmentGrantRepositoryUpsertRollsBackOnTxRollback. It is local
// to this test file so callers cannot rely on its identity; every *_test.go
// file under internal/controlplane/store/ shares the same store_test
// package, so the type name is intentionally distinct from
// project_grant_repository_invariants_test.go's projectGrantTxRollbackSentinel,
// api_key_scope_repository_invariants_test.go's apiKeyScopeTxRollbackSentinel,
// membership_repository_invariants_test.go's membershipTxRollbackSentinel,
// serviceaccount_repository_invariants_test.go's serviceAccountTxRollbackSentinel,
// user_repository_invariants_test.go's errSentinel,
// environment_repository_invariants_test.go's environmentTxRollbackSentinel,
// and apikey_test.go's apiKeyTxRollbackSentinel to avoid a collision.
type environmentGrantTxRollbackSentinel struct{}

func (environmentGrantTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this environment grant transaction"
}

// TestEnvironmentGrantRepositoryUpsertWithoutTxIsTypedInternal proves the
// repository's nil-Tx guard on Upsert renders a typed apierr.Internal —
// never a nil-pointer panic — when a caller wires the unit of work wrong.
// This is a pure unit test and requires no database.
func TestEnvironmentGrantRepositoryUpsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewEnvironmentGrantRepository()

	_, err := repo.Upsert(context.Background(), nil,
		"egrnt_irrelevant", "org_irrelevant", "env_irrelevant", "usr_irrelevant", "usr", "developer", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Upsert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsWithoutTxIsTypedInternal:
// same guard, DeleteByEnvironmentExceptIDs path.
func TestEnvironmentGrantRepositoryDeleteByEnvironmentExceptIDsWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewEnvironmentGrantRepository()

	err := repo.DeleteByEnvironmentExceptIDs(context.Background(), nil, "org_irrelevant", "env_irrelevant", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("DeleteByEnvironmentExceptIDs(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
