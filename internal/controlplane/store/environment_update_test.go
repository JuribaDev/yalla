package store_test

import (
	"context"
	"errors"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Integration tests for EnvironmentRepository.Update — the persistence
// half of PATCH /v1/environments/{environment_id}. They run against an
// isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset. The tests prove the version-checked
// UPDATE bumps the trigger-managed version column, surfaces a stale
// view as ConflictStale with the row's authoritative version, reports
// cross-tenant ids as NotFound, and treats a slug collision inside the
// same project as a typed Conflict.

// TestEnvironmentRepoUpdateBumpsVersion proves a successful Update
// returns the row with its new slug/display_name and a version bumped
// by the environments_bump_version trigger (migration 0011). The
// trigger is the only writer of the version column; callers must
// observe its value rather than guessing.
func TestEnvironmentRepoUpdateBumpsVersion(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvUpdAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")

	repo := store.NewEnvironmentRepository()

	var before store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		before, getErr = repo.GetByID(ctx, q, org.ID, env.ID)
		return getErr
	}); err != nil {
		t.Fatalf("GetByID before update: %v", err)
	}

	var updated store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		desired := before
		desired.Slug = "preview"
		desired.DisplayName = "Preview"
		var updErr error
		updated, updErr = repo.Update(ctx, tx, desired, nil)
		return updErr
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if updated.Slug != "preview" {
		t.Errorf("updated.Slug = %q, want preview", updated.Slug)
	}
	if updated.DisplayName != "Preview" {
		t.Errorf("updated.DisplayName = %q, want Preview", updated.DisplayName)
	}
	if updated.Version <= before.Version {
		t.Errorf("version not bumped: %d <= %d", updated.Version, before.Version)
	}
	if updated.OrganizationID != before.OrganizationID || updated.ProjectID != before.ProjectID {
		t.Errorf("composite tenant key changed across UPDATE: %+v -> %+v", before, updated)
	}
}

// TestEnvironmentRepoUpdateIfMatchHonoured proves the optional
// optimistic-concurrency precondition: an update with a stale version
// is rejected as ConflictStale carrying the current authoritative
// version, never silently overwriting another writer's change. An
// update with the correct version succeeds.
func TestEnvironmentRepoUpdateIfMatchHonoured(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvUpdMatchAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")

	repo := store.NewEnvironmentRepository()
	var before store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		before, getErr = repo.GetByID(ctx, q, org.ID, env.ID)
		return getErr
	}); err != nil {
		t.Fatalf("GetByID before update: %v", err)
	}

	stale := before.Version + 1
	staleErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		desired := before
		desired.DisplayName = "New Display"
		_, updErr := repo.Update(ctx, tx, desired, &stale)
		return updErr
	})
	if staleErr == nil {
		t.Fatalf("Update with stale ifMatch returned nil; want ConflictStale")
	}
	var ye *yerr.Error
	if !errors.As(staleErr, &ye) || ye.Code != yerr.CodeConflict {
		t.Fatalf("err = %v (%T); want yerr CodeConflict", staleErr, staleErr)
	}

	// Sanity: with the correct version the update succeeds.
	var updated store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		desired := before
		desired.DisplayName = "New Display"
		row, updErr := repo.Update(ctx, tx, desired, &before.Version)
		updated = row
		return updErr
	}); err != nil {
		t.Fatalf("Update with current ifMatch: %v", err)
	}
	if updated.DisplayName != "New Display" {
		t.Errorf("updated.DisplayName = %q, want New Display", updated.DisplayName)
	}
}

// TestEnvironmentRepoUpdateUnknownIDIsNotFound proves an unknown
// environment id with no version precondition surfaces as NotFound,
// the same way GET-by-id does. The repository must not invent a row.
func TestEnvironmentRepoUpdateUnknownIDIsNotFound(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvUpdMissAcme")
	_ = seedProject(t, db, f, org, "Web")

	repo := store.NewEnvironmentRepository()
	desired := store.Environment{
		ID:             "env_ghost",
		OrganizationID: org.ID,
		Slug:           "preview",
		DisplayName:    "Preview",
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.Update(ctx, tx, desired, nil)
		return updErr
	})
	if err == nil {
		t.Fatalf("Update(unknown id) returned no error; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestEnvironmentRepoUpdateCrossTenantIsNotFound proves an environment
// id that lives in another tenant simply does not match — the
// composite (organization_id, id) predicate is tenant-scoped at the
// SQL leg, so the foreign row is invisible to this caller and
// surfaces as the same NotFound an unknown id would.
func TestEnvironmentRepoUpdateCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "EnvUpdAcmeA")
	orgB := seedOrg(t, db, f, "EnvUpdAcmeB")
	projB := seedProject(t, db, f, orgB, "Web")
	envB := seedEnvironment(t, db, f, projB, "production")

	repo := store.NewEnvironmentRepository()
	desired := store.Environment{
		ID:             envB.ID,
		OrganizationID: orgA.ID,
		Slug:           "preview",
		DisplayName:    "Preview",
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.Update(ctx, tx, desired, nil)
		return updErr
	})
	if err == nil {
		t.Fatalf("Update(cross-tenant id) returned no error; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}

	// And the other tenant's row is unchanged — proving the failed
	// update did not bleed across the tenant boundary.
	var current store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		current, getErr = repo.GetByID(ctx, q, orgB.ID, envB.ID)
		return getErr
	}); err != nil {
		t.Fatalf("GetByID(other tenant after cross-tenant attempt): %v", err)
	}
	if current.Slug != envB.Slug || current.DisplayName != envB.Name {
		t.Errorf("cross-tenant attempt mutated the other tenant's row: got %+v, want slug=%q display=%q", current, envB.Slug, envB.Name)
	}
}

// TestEnvironmentRepoUpdateSlugConflictIsTypedConflict proves a slug
// already in use by another environment in the SAME project is a
// typed Conflict, not a 500 leaking the constraint name. Slug
// uniqueness scope is (project_id, slug).
func TestEnvironmentRepoUpdateSlugConflictIsTypedConflict(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvUpdSlugAcme")
	proj := seedProject(t, db, f, org, "Web")
	envProd := seedEnvironment(t, db, f, proj, "production")
	envPreview := seedEnvironment(t, db, f, proj, "preview")

	repo := store.NewEnvironmentRepository()
	var prod store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		prod, getErr = repo.GetByID(ctx, q, org.ID, envProd.ID)
		return getErr
	}); err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		desired := prod
		// Collide with the preview environment's slug — both live under
		// the same parent project. The factory mints unique slugs per
		// seed, so we collide against the actual stored value rather
		// than a literal "preview".
		desired.Slug = envPreview.Slug
		_, updErr := repo.Update(ctx, tx, desired, nil)
		return updErr
	})
	if err == nil {
		t.Fatalf("Update with duplicate slug returned no error; want Conflict")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeConflict {
		t.Fatalf("err = %v (%T); want yerr CodeConflict", err, err)
	}
}

// TestEnvironmentRepoUpdateRejectsNilTx proves a wiring error
// (forgetting to open a transaction) is reported as a typed Internal
// rather than silently dropping the mutation.
func TestEnvironmentRepoUpdateRejectsNilTx(t *testing.T) {
	t.Parallel()

	repo := store.NewEnvironmentRepository()
	_, err := repo.Update(context.Background(), nil, store.Environment{}, nil)
	if err == nil {
		t.Fatalf("Update(nil tx) returned no error; want Internal")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Fatalf("err = %v (%T); want yerr CodeInternal", err, err)
	}
}
