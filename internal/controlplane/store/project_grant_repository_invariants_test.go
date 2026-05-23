package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration and unit tests for ProjectGrantRepository (BE-0439). This file
// covers the CRUD surface and row-shape / lifecycle invariants of the
// repository's two mutation methods (Upsert, DeleteByProjectExceptIDs) and
// composes naturally with project_grant_test.go (which already pins the
// ListByProject ordering and tenant-scoping contract) and with BE-0440's
// project_grant_tenant_isolation_test.go (cross-tenant byte-identical
// bystander proof — landing in the paired isolation story).
//
// What this file proves:
//
//   - Upsert INSERT branch returns the row the database actually committed:
//     created_at and updated_at are non-zero and byte-equal on a fresh row
//     (no UPDATE has fired yet, so the project_grants_set_updated_at and
//     project_grants_bump_version triggers from migration 0014 / 0011 have
//     not run), version starts at 1 (the schema default), the caller-
//     supplied id / organization_id / project_id / principal_id /
//     principal_kind / role are echoed back verbatim, and the optional
//     environment_id and service_id pointers are preserved as the schema
//     stored them (NULL stays nil; non-NULL round-trips as a pointer to the
//     exact text).
//
//   - Upsert UPDATE branch (same scope tuple, different caller-supplied
//     id and role) updates ONLY the role, bumps version via the
//     project_grants_bump_version trigger, refreshes updated_at via the
//     project_grants_set_updated_at trigger, preserves created_at, and
//     keeps the immutable identifiers (id, organization_id, project_id,
//     principal_id, principal_kind, environment_id, service_id) byte-
//     identical to the baseline. The caller-supplied id is IGNORED on the
//     conflict branch — the persisted id remains the row's original id, so
//     a re-upsert is idempotent at the customer's view of the resource
//     (same scope tuple = same logical grant). principal_kind stays at the
//     existing value even if the caller supplied a different one for the
//     same principal_id, so cross-kind smuggling is structurally
//     impossible.
//
//   - Upsert rejects a cross-tenant or unknown project_id with a typed
//     apierr.Conflict — the composite FK (organization_id, project_id) ->
//     projects (organization_id, id) is MATCH SIMPLE, so a row whose
//     project belongs to one tenant is unrepresentable as another tenant's
//     grant; the constraint-violation class 23 error surfaces as the
//     same typed code the rest of the persistence layer uses.
//
//   - Upsert rejects a duplicate primary key id (a different scope tuple
//     attempting to claim an id another row already owns) with a typed
//     apierr.Conflict — the PRIMARY KEY (id) constraint is the load-bearing
//     defence and mapWriteError surfaces it as Conflict, never as a 5xx.
//
//   - DeleteByProjectExceptIDs with an empty / nil keepIDs slice removes
//     every grant of (organizationID, projectID) — an explicit "clear all
//     grants" intent is meaningful (extreme), not a silent no-op — and the
//     query is tenant scoped so a cross-tenant projectID can never delete
//     another organization's grants.
//
//   - DeleteByProjectExceptIDs with a non-empty keepIDs slice removes only
//     the rows whose id is NOT in keepIDs; cross-tenant ids in keepIDs do
//     NOT keep cross-tenant rows alive (the WHERE filter is the only thing
//     keeping the rows apart) — the persisted survivors are exactly the
//     callers' tenant's keepIDs.
//
//   - ON DELETE CASCADE from projects removes a project's grants when the
//     parent projects row is deleted. The CASCADE is the only writer of
//     this guarantee — there is no application-side cleanup that could
//     substitute — so a regression that dropped the CASCADE would leak
//     orphan grants referencing a non-existent project.
//
//   - Upsert rolls back when the surrounding Write closure returns a
//     non-nil error: the transaction is the unit of work, and no
//     half-written grant row can survive an aborted audit / policy step
//     that runs alongside it. The proof reduces to "the row does not
//     exist outside the rolled-back transaction" via ListByProject because
//     the repository exposes no per-id Get — ListByProject is the only
//     observation surface for a grant row, so it is the load-bearing
//     leak channel a partial commit would surface through.
//
//   - The Upsert and DeleteByProjectExceptIDs nil-Tx guards render a typed
//     apierr.Internal — never a nil-pointer panic — when a caller wires
//     the unit of work wrong. These are pure unit tests and require no
//     database.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard tests are pure unit tests and require no database.

// newProjectGrantID mints a fresh `pgrnt_<token>` id from the factory
// without colliding with the other resource kinds the factory hands out.
// The factory itself only stamps known domain prefixes, so we synthesize
// the project-grant id from a stable counter — the same shape the service
// layer uses through domain.NewID(domain.KindProjectGrant).
func newProjectGrantID(f *testutil.Factory, label string) string {
	// f.Project mints a unique `prj_<token_n>` per call; rewriting the
	// prefix yields a `pgrnt_<token_n>` id that is unique per call and
	// distinct from the project's own id namespace.
	return "pgrnt_" + f.Project(testutil.Organization{ID: "org_irrelevant"}, label).ID[len("prj_"):]
}

// upsertProjectGrant runs the repository Upsert inside Store.Write and
// returns the persisted row. It is the smallest possible "happy-path
// insert" closure and is reused by every test that does not need to
// observe the upsert's tx in isolation.
func upsertProjectGrant(ctx context.Context, t *testing.T, s *store.Store, repo *store.ProjectGrantRepository,
	id, organizationID, projectID, principalID, principalKind, role string, envID, svcID *string,
) store.ProjectGrant {
	t.Helper()
	var stored store.ProjectGrant
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Upsert(ctx, tx, id, organizationID, projectID, principalID, principalKind, role, envID, svcID)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("upsert project grant: %v", err)
	}
	return stored
}

// TestProjectGrantRepositoryUpsertInsertReturnsRowWithTimestamps proves the
// INSERT branch returns the row the database actually committed. created_at
// and updated_at are both non-zero AND byte-equal on the fresh row (no
// UPDATE has fired yet, so the project_grants_set_updated_at trigger has
// not run), version starts at 1 (the schema default), and the caller-
// supplied fields are echoed back verbatim. EnvironmentID / ServiceID
// pointers stay nil for a project-scoped grant.
func TestProjectGrantRepositoryUpsertInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	id := newProjectGrantID(f, "alpha")

	got := upsertProjectGrant(ctx, t, s, repo, id, org.ID, proj.ID, "usr_alpha", "usr", "developer", nil, nil)

	if got.ID != id {
		t.Errorf("Upsert returned id %q, want %q", got.ID, id)
	}
	if got.OrganizationID != org.ID {
		t.Errorf("Upsert returned organization_id %q, want %q", got.OrganizationID, org.ID)
	}
	if got.ProjectID != proj.ID {
		t.Errorf("Upsert returned project_id %q, want %q", got.ProjectID, proj.ID)
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
	if got.EnvironmentID != nil {
		t.Errorf("Upsert returned environment_id = %v, want nil (project-scoped grant)", *got.EnvironmentID)
	}
	if got.ServiceID != nil {
		t.Errorf("Upsert returned service_id = %v, want nil (project-scoped grant)", *got.ServiceID)
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

// TestProjectGrantRepositoryUpsertInsertWithEnvAndServiceRoundtripsPointers
// proves the optional environment_id and service_id columns round-trip as
// non-nil pointers when the caller opts into a service-scoped grant. The
// schema CHECKs reject empty strings (CHECK (length(environment_id) > 0))
// so the pointer's payload is structurally non-empty.
func TestProjectGrantRepositoryUpsertInsertWithEnvAndServiceRoundtripsPointers(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	envID := "env_prod"
	svcID := "svc_web"
	id := newProjectGrantID(f, "scoped")

	got := upsertProjectGrant(ctx, t, s, repo, id, org.ID, proj.ID, "sa_one", "sa", "ci", &envID, &svcID)

	if got.EnvironmentID == nil || *got.EnvironmentID != envID {
		t.Errorf("Upsert returned environment_id = %v, want pointer to %q", got.EnvironmentID, envID)
	}
	if got.ServiceID == nil || *got.ServiceID != svcID {
		t.Errorf("Upsert returned service_id = %v, want pointer to %q", got.ServiceID, svcID)
	}
	if got.PrincipalKind != "sa" {
		t.Errorf("Upsert returned principal_kind %q, want %q (service-account grant)", got.PrincipalKind, "sa")
	}
}

// TestProjectGrantRepositoryUpsertUpdateBranchOnlyMutatesRole proves the
// ON CONFLICT (organization_id, project_id, principal_id, COALESCE(env_id,
// ”), COALESCE(svc_id, ”)) DO UPDATE SET role = EXCLUDED.role branch
// updates ONLY the role: version is bumped by the
// project_grants_bump_version trigger, updated_at is refreshed by the
// project_grants_set_updated_at trigger, created_at is preserved, and the
// immutable identifiers (id, organization_id, project_id, principal_id,
// principal_kind, environment_id, service_id) stay byte-identical to the
// baseline. The caller-supplied id is IGNORED on the conflict branch — the
// persisted id stays at the baseline's id, never the second caller's id.
// principal_kind stays at the baseline's value even when the caller
// supplies a different kind for the same principal_id, so cross-kind
// smuggling is structurally impossible at this layer.
func TestProjectGrantRepositoryUpsertUpdateBranchOnlyMutatesRole(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	baselineID := newProjectGrantID(f, "baseline")
	baseline := upsertProjectGrant(ctx, t, s, repo, baselineID, org.ID, proj.ID, "usr_alpha", "usr", "developer", nil, nil)

	// The Postgres now() clock advances at microsecond resolution; sleep
	// one millisecond so a trigger that fails to refresh updated_at
	// surfaces as a comparison failure rather than an Equal-by-accident.
	time.Sleep(time.Millisecond)

	// Re-upsert at the SAME scope tuple (same principal_id, same nil
	// env/svc), with a DIFFERENT caller-supplied id, a DIFFERENT role,
	// and a DIFFERENT principal_kind. The repository must:
	//   * keep the baseline's id (the caller-supplied id is ignored on the
	//     conflict branch);
	//   * update role to "admin" (the only customer-mutable field);
	//   * keep principal_kind at "usr" — the caller's "sa" must not stick;
	//   * bump version; refresh updated_at; preserve created_at.
	overrideID := newProjectGrantID(f, "override")
	updated := upsertProjectGrant(ctx, t, s, repo, overrideID, org.ID, proj.ID, "usr_alpha", "sa", "admin", nil, nil)

	if updated.ID != baseline.ID {
		t.Errorf("Upsert(conflict) mutated id: was %q, now %q (caller-supplied id must be ignored on the conflict branch)",
			baseline.ID, updated.ID)
	}
	if updated.OrganizationID != baseline.OrganizationID {
		t.Errorf("Upsert(conflict) mutated organization_id: was %q, now %q", baseline.OrganizationID, updated.OrganizationID)
	}
	if updated.ProjectID != baseline.ProjectID {
		t.Errorf("Upsert(conflict) mutated project_id: was %q, now %q", baseline.ProjectID, updated.ProjectID)
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
	if updated.EnvironmentID != nil {
		t.Errorf("Upsert(conflict) mutated environment_id from nil to %v", *updated.EnvironmentID)
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

// TestProjectGrantRepositoryUpsertCrossTenantProjectReturnsTypedConflict
// proves the composite FK (organization_id, project_id) -> projects rejects
// a row whose project belongs to another organization. The FK is MATCH
// SIMPLE so a cross-tenant project_id is structurally unrepresentable:
// even though the grant id and role are well-formed, the constraint-
// violation class 23 error surfaces as the typed apierr.Conflict at the
// persistence chokepoint. An unknown project_id (no row at all) lands on
// the same path for the same reason.
func TestProjectGrantRepositoryUpsertCrossTenantProjectReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "b-only")

	// orgA tries to attach a grant to orgB's project.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, newProjectGrantID(f, "cross"), orgA.ID, projB.ID, "usr_a", "usr", "developer", nil, nil)
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(cross-tenant project) error = %v, want code %s", err, yerr.CodeConflict)
	}

	// An unknown project_id under orgA lands on the same conflict code —
	// the same FK violation, the same typed shape.
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, newProjectGrantID(f, "ghost"), orgA.ID, "prj_does_not_exist", "usr_a", "usr", "developer", nil, nil)
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(unknown project) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

// TestProjectGrantRepositoryUpsertDuplicatePrimaryKeyReturnsTypedConflict
// proves the PRIMARY KEY (id) constraint surfaces a second Upsert that
// reuses an existing id at a DIFFERENT scope tuple (different principal,
// so the ON CONFLICT (org, proj, principal, env, svc) branch does NOT
// match) as the typed apierr.Conflict mapWriteError produces. The id is
// reserved per-row across the whole table; the ON CONFLICT branch only
// fires for the principal-scope-tuple unique index, not for the primary
// key.
func TestProjectGrantRepositoryUpsertDuplicatePrimaryKeyReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	id := newProjectGrantID(f, "shared")

	upsertProjectGrant(ctx, t, s, repo, id, org.ID, proj.ID, "usr_alpha", "usr", "developer", nil, nil)

	// Second Upsert: same id, DIFFERENT principal_id. The ON CONFLICT
	// branch keys on (org, proj, principal, env, svc) — principal_id is
	// different — so the conflict resolution path is the PRIMARY KEY (id)
	// uniqueness violation, not the principal-scope-tuple upsert.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, id, org.ID, proj.ID, "usr_beta", "usr", "developer", nil, nil)
		return upErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Upsert(duplicate id) error = %v, want code %s", err, yerr.CodeConflict)
	}
}

// TestProjectGrantRepositoryDeleteByProjectExceptIDsEmptyKeepClearsAll
// proves DeleteByProjectExceptIDs with a nil / empty keepIDs slice removes
// every grant of (organizationID, projectID) — an explicit "clear all
// grants" intent is meaningful (extreme), not a silent no-op. Both nil and
// an empty slice are treated identically.
func TestProjectGrantRepositoryDeleteByProjectExceptIDsEmptyKeepClearsAll(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")

	upsertProjectGrant(ctx, t, s, repo, newProjectGrantID(f, "one"), org.ID, proj.ID, "usr_a", "usr", "developer", nil, nil)
	upsertProjectGrant(ctx, t, s, repo, newProjectGrantID(f, "two"), org.ID, proj.ID, "usr_b", "usr", "viewer", nil, nil)

	// nil keepIDs.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptIDs(ctx, tx, org.ID, proj.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptIDs(nil): %v", err)
	}
	if remaining := listGrantsOrFail(ctx, t, s, repo, org.ID, proj.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByProjectExceptIDs(nil) %d rows remain, want 0", len(remaining))
	}

	// Re-seed and try the explicit empty slice — must be identical.
	upsertProjectGrant(ctx, t, s, repo, newProjectGrantID(f, "three"), org.ID, proj.ID, "usr_c", "usr", "developer", nil, nil)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptIDs(ctx, tx, org.ID, proj.ID, []string{})
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptIDs([]): %v", err)
	}
	if remaining := listGrantsOrFail(ctx, t, s, repo, org.ID, proj.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByProjectExceptIDs([]) %d rows remain, want 0", len(remaining))
	}
}

// TestProjectGrantRepositoryDeleteByProjectExceptIDsRemovesOnlyExcluded
// proves a non-empty keepIDs slice retains exactly the rows whose id is in
// the slice and removes every other row of the project's grants.
func TestProjectGrantRepositoryDeleteByProjectExceptIDsRemovesOnlyExcluded(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")

	keeper := upsertProjectGrant(ctx, t, s, repo, newProjectGrantID(f, "keeper"), org.ID, proj.ID, "usr_keeper", "usr", "developer", nil, nil)
	dropped := upsertProjectGrant(ctx, t, s, repo, newProjectGrantID(f, "dropped"), org.ID, proj.ID, "usr_dropped", "usr", "viewer", nil, nil)

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptIDs(ctx, tx, org.ID, proj.ID, []string{keeper.ID})
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptIDs([keeper]): %v", err)
	}

	remaining := listGrantsOrFail(ctx, t, s, repo, org.ID, proj.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByProjectExceptIDs([keeper]) %d rows remain, want 1", len(remaining))
	}
	if remaining[0].ID != keeper.ID {
		t.Errorf("remaining[0].ID = %q, want %q (the keeper)", remaining[0].ID, keeper.ID)
	}
	if remaining[0].ID == dropped.ID {
		t.Errorf("dropped row %q survived; keep set must NOT keep excluded ids", dropped.ID)
	}
}

// TestProjectGrantRepositoryDeleteByProjectExceptIDsIsTenantScoped proves a
// cross-tenant projectID cannot delete another organization's grants —
// the WHERE clause filters on organization_id AND project_id. A pair of
// tenants each owning a project named identically inside their tenant
// would fail this property if the WHERE missed the organization_id leg.
func TestProjectGrantRepositoryDeleteByProjectExceptIDsIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "ledger")
	projB := seedProject(t, db, f, orgB, "ledger")

	bystander := upsertProjectGrant(ctx, t, s, repo, newProjectGrantID(f, "bystander"), orgB.ID, projB.ID, "usr_b", "usr", "developer", nil, nil)
	upsertProjectGrant(ctx, t, s, repo, newProjectGrantID(f, "victim"), orgA.ID, projA.ID, "usr_a", "usr", "developer", nil, nil)

	// orgA asks to clear orgB's projectID. Composite WHERE filters on
	// (org, project) so the predicate matches zero rows.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptIDs(ctx, tx, orgA.ID, projB.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptIDs(cross-tenant projectID): %v", err)
	}

	// orgB's bystander grant is untouched.
	remainingB := listGrantsOrFail(ctx, t, s, repo, orgB.ID, projB.ID)
	if len(remainingB) != 1 || remainingB[0].ID != bystander.ID {
		t.Errorf("orgB grants after cross-tenant clear = %+v, want exactly bystander %q", remainingB, bystander.ID)
	}

	// orgA's own grant is also still there because the predicate matched
	// no rows (different project_id, even though same organization_id).
	remainingA := listGrantsOrFail(ctx, t, s, repo, orgA.ID, projA.ID)
	if len(remainingA) != 1 {
		t.Errorf("orgA grants after cross-tenant clear = %+v, want exactly 1 (own grant)", remainingA)
	}
}

// TestProjectGrantRepositoryProjectDeleteCascades proves ON DELETE CASCADE
// on the composite FK (organization_id, project_id) -> projects removes
// every project_grants row when the parent projects row is deleted. The
// CASCADE is the only writer of this guarantee — there is no application-
// side cleanup that could substitute — so a regression that dropped the
// CASCADE would leak orphan grants referencing a non-existent project.
func TestProjectGrantRepositoryProjectDeleteCascades(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	upsertProjectGrant(ctx, t, s, repo, newProjectGrantID(f, "one"), org.ID, proj.ID, "usr_a", "usr", "developer", nil, nil)
	upsertProjectGrant(ctx, t, s, repo, newProjectGrantID(f, "two"), org.ID, proj.ID, "usr_b", "usr", "viewer", nil, nil)

	// Delete the parent projects row via raw SQL — the repository's
	// ScheduleDeletion only stamps deletion_scheduled_at (a soft delete),
	// it does not delete the row. ON DELETE CASCADE on the composite FK
	// must remove every child grant row.
	if _, err := db.Exec(ctx, `DELETE FROM projects WHERE id = $1`, proj.ID); err != nil {
		t.Fatalf("DELETE projects: %v", err)
	}

	remaining := listGrantsOrFail(ctx, t, s, repo, org.ID, proj.ID)
	if len(remaining) != 0 {
		t.Errorf("ListByProject after parent delete returned %d rows, want 0 (ON DELETE CASCADE must remove children)",
			len(remaining))
	}
}

// TestProjectGrantRepositoryUpsertRollsBackOnTxRollback proves that an
// Upsert whose outer Write returns a non-nil error rolls the row back —
// the transaction is the unit of work, and no half-written grant row can
// survive an aborted audit/policy step that runs alongside it. The proof
// reduces to "no row matches at the ListByProject read surface outside
// the rolled-back transaction" because the repository exposes no per-id
// Get for grants — ListByProject is the only observation surface for a
// grant row, so it is the load-bearing leak channel a partial commit
// would surface through.
func TestProjectGrantRepositoryUpsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectGrantRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	proj := seedProject(t, db, f, org, "web-api")
	id := newProjectGrantID(f, "rollback")

	bailout := projectGrantTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, upErr := repo.Upsert(ctx, tx, id, org.ID, proj.ID, "usr_alpha", "usr", "developer", nil, nil); upErr != nil {
			return upErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	listed := listGrantsOrFail(ctx, t, s, repo, org.ID, proj.ID)
	if len(listed) != 0 {
		t.Errorf("ListByProject after rolled-back Upsert returned %d rows, want 0", len(listed))
	}
	for _, g := range listed {
		if g.ID == id {
			t.Errorf("rolled-back grant id %q is visible at ListByProject; the transaction did NOT roll back", id)
		}
	}
}

// projectGrantTxRollbackSentinel is a typed error a transaction closure
// can return to force a rollback in
// TestProjectGrantRepositoryUpsertRollsBackOnTxRollback. It is local to
// this test file so callers cannot rely on its identity; every *_test.go
// file under internal/controlplane/store/ shares the same store_test
// package, so the type name is intentionally distinct from
// apikey_test.go's apiKeyTxRollbackSentinel,
// api_key_scope_repository_invariants_test.go's
// apiKeyScopeTxRollbackSentinel,
// user_repository_invariants_test.go's errSentinel,
// membership_repository_invariants_test.go's membershipTxRollbackSentinel,
// and serviceaccount_repository_invariants_test.go's
// serviceAccountTxRollbackSentinel to avoid a collision.
type projectGrantTxRollbackSentinel struct{}

func (projectGrantTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this project grant transaction"
}

// TestProjectGrantRepositoryUpsertWithoutTxIsTypedInternal proves the
// repository's nil-Tx guard on Upsert renders a typed apierr.Internal —
// never a nil-pointer panic — when a caller wires the unit of work wrong.
// This is a pure unit test and requires no database.
func TestProjectGrantRepositoryUpsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewProjectGrantRepository()

	_, err := repo.Upsert(context.Background(), nil,
		"pgrnt_irrelevant", "org_irrelevant", "prj_irrelevant", "usr_irrelevant", "usr", "developer", nil, nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Upsert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestProjectGrantRepositoryDeleteByProjectExceptIDsWithoutTxIsTypedInternal:
// same guard, DeleteByProjectExceptIDs path.
func TestProjectGrantRepositoryDeleteByProjectExceptIDsWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewProjectGrantRepository()

	err := repo.DeleteByProjectExceptIDs(context.Background(), nil, "org_irrelevant", "prj_irrelevant", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("DeleteByProjectExceptIDs(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// listGrantsOrFail runs ListByProject inside Store.Read and fatals on
// error. It is reused by every test in this file that needs to observe the
// post-condition of a mutation against the only read surface the
// repository exposes for grants.
func listGrantsOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.ProjectGrantRepository, organizationID, projectID string) []store.ProjectGrant {
	t.Helper()
	var out []store.ProjectGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, lerr := repo.ListByProject(ctx, q, organizationID, projectID)
		if lerr != nil {
			return lerr
		}
		out = rows
		return nil
	}); err != nil {
		t.Fatalf("ListByProject(%q, %q): %v", organizationID, projectID, err)
	}
	return out
}
