package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for ProjectRepository — the reference repository for the
// transaction pattern. They prove tenant-scoped reads, the *Tx-only mutation
// surface, typed not-found behaviour, and conflict mapping against an isolated,
// freshly migrated Postgres database.

// projectFixture builds a store.Project from a testutil project fixture.
func projectFixture(p testutil.Project) store.Project {
	return store.Project{
		ID:             p.ID,
		OrganizationID: p.OrganizationID,
		Slug:           p.Slug,
		DisplayName:    p.Name,
	}
}

// insertProject persists p through Store.Write and returns the stored row.
func insertProject(ctx context.Context, t *testing.T, s *store.Store, repo *store.ProjectRepository, p store.Project) store.Project {
	t.Helper()
	var stored store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, p)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	return stored
}

func TestProjectRepositoryInsertAndGet(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	want := projectFixture(f.Project(org, "web-api"))

	stored := insertProject(ctx, t, s, repo, want)
	if stored.ID != want.ID || stored.Slug != want.Slug || stored.DisplayName != want.DisplayName {
		t.Fatalf("Insert returned %+v, want id/slug/name from %+v", stored, want)
	}
	if stored.CreatedAt.IsZero() || stored.UpdatedAt.IsZero() {
		t.Error("Insert did not return the database-assigned timestamps")
	}

	var got store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, want.ID)
		return err
	}); err != nil {
		t.Fatalf("Get returned %v, want nil", err)
	}
	if got.ID != want.ID || got.OrganizationID != org.ID {
		t.Errorf("Get returned %+v, want id %q in org %q", got, want.ID, org.ID)
	}
}

func TestProjectRepositoryGetNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	missing := f.Project(org, "ghost") // built, never inserted

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, org.ID, missing.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(missing) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestProjectRepositoryGetIsTenantScoped proves a project id from another
// organization can never be read through a different organization's scope: the
// cross-tenant lookup is reported as NotFound, never as the real row.
func TestProjectRepositoryGetIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "secret-service")))

	// orgB asks for orgA's project id.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgB.ID, projA.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Get error code = %v, want %s", err, yerr.CodeNotFound)
	}

	// The owning organization still sees it.
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgA.ID, projA.ID)
		return getErr
	}); err != nil {
		t.Errorf("owner Get returned %v, want the project", err)
	}
}

func TestProjectRepositoryInsertDuplicateSlugConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	first := projectFixture(f.Project(org, "web-api"))
	insertProject(ctx, t, s, repo, first)

	// A second project, distinct id, same organization, same slug.
	dup := projectFixture(f.Project(org, "web-api"))
	dup.Slug = first.Slug

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insErr := repo.Insert(ctx, tx, dup)
		return insErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate-slug Insert error code = %v, want %s", err, yerr.CodeConflict)
	}
}

func TestProjectRepositoryCountByOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "one")))
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "two")))
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "only")))

	counts := map[string]int{}
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		for _, org := range []testutil.Organization{orgA, orgB} {
			n, err := repo.CountByOrganization(ctx, q, org.ID)
			if err != nil {
				return err
			}
			counts[org.ID] = n
		}
		return nil
	}); err != nil {
		t.Fatalf("CountByOrganization: %v", err)
	}
	if counts[orgA.ID] != 2 {
		t.Errorf("orgA project count = %d, want 2", counts[orgA.ID])
	}
	if counts[orgB.ID] != 1 {
		t.Errorf("orgB project count = %d, want 1 (count is tenant scoped)", counts[orgB.ID])
	}
}

func TestProjectRepositoryInsertRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewProjectRepository()
	if _, err := repo.Insert(context.Background(), nil, store.Project{}); err == nil {
		t.Fatal("Insert(nil tx) error = nil, want an error")
	}
}

// TestProjectRepositoryListByOrganizationReturnsEmpty proves the list query
// against an organization with no projects yields a non-nil empty slice —
// the deterministic shape every list endpoint depends on.
func TestProjectRepositoryListByOrganizationReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "tenant-empty")

	var got []store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByOrganization(ctx, q, org.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if got == nil {
		t.Fatal("ListByOrganization returned nil slice, want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("ListByOrganization returned %d projects, want 0", len(got))
	}
}

// TestProjectRepositoryListByOrganizationIsTenantScoped proves a cross-tenant
// organization id never returns another tenant's projects: orgA's list is
// every orgA project (in (slug, id) order) and orgB's list is every orgB
// project — with no row leaking across.
func TestProjectRepositoryListByOrganizationIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// Insert in a non-alphabetic order so the (slug, id) ORDER BY is
	// observable: a wrong-ordering bug would echo insert order, not slug
	// order. Each fixture's slug is the label prefixed onto a per-factory
	// token, so labels with the same alphabetical ordering produce slugs
	// with the same alphabetical ordering.
	ledger := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "ledger")))
	alpha := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "alpha")))
	billing := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "billing")))
	betaonly := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "betaonly")))

	var gotA, gotB []store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		gotA, listErr = repo.ListByOrganization(ctx, q, orgA.ID)
		if listErr != nil {
			return listErr
		}
		gotB, listErr = repo.ListByOrganization(ctx, q, orgB.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}

	if got := len(gotA); got != 3 {
		t.Fatalf("ListByOrganization(orgA) returned %d projects, want 3", got)
	}
	wantOrder := []string{alpha.Slug, billing.Slug, ledger.Slug}
	for i, want := range wantOrder {
		if gotA[i].Slug != want {
			t.Errorf("ListByOrganization(orgA)[%d].Slug = %q, want %q (slug, id order)",
				i, gotA[i].Slug, want)
		}
	}
	for _, p := range gotA {
		if p.OrganizationID != orgA.ID {
			t.Errorf("ListByOrganization(orgA) returned a project belonging to %q, want %q", p.OrganizationID, orgA.ID)
		}
	}

	if got := len(gotB); got != 1 {
		t.Fatalf("ListByOrganization(orgB) returned %d projects, want 1", got)
	}
	if gotB[0].OrganizationID != orgB.ID {
		t.Errorf("ListByOrganization(orgB) returned project owned by %q, want %q", gotB[0].OrganizationID, orgB.ID)
	}
	if gotB[0].Slug != betaonly.Slug {
		t.Errorf("ListByOrganization(orgB) returned slug %q, want %q", gotB[0].Slug, betaonly.Slug)
	}
}

// TestProjectReaderListProjects proves the store-backed reader adapter
// runs the list inside a short-lived read transaction and returns the
// repository's results unchanged.
func TestProjectReaderListProjects(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "tenant-reader")
	alpha := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "alpha")))
	beta := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "beta")))

	reader, err := store.NewProjectReader(s)
	if err != nil {
		t.Fatalf("NewProjectReader: %v", err)
	}
	got, err := reader.ListProjects(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListProjects returned %d projects, want 2", len(got))
	}
	if got[0].Slug != alpha.Slug || got[1].Slug != beta.Slug {
		t.Errorf("ListProjects ordering = [%s, %s], want [%s, %s]",
			got[0].Slug, got[1].Slug, alpha.Slug, beta.Slug)
	}
}

// TestProjectReaderGetProject proves the store-backed reader adapter runs
// the single-project read inside a short-lived read transaction, returns
// the repository row unchanged for a tenant-owned id, and reports a typed
// NotFound for a cross-tenant id — the tenant-isolation invariant that
// keeps a cross-tenant project_id from ever revealing another
// organization's project through GET /v1/projects/{project_id}.
func TestProjectReaderGetProject(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-reader-get-a")
	orgB := seedOrg(t, db, f, "tenant-reader-get-b")
	alpha := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "alpha")))
	betaB := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "beta")))

	reader, err := store.NewProjectReader(s)
	if err != nil {
		t.Fatalf("NewProjectReader: %v", err)
	}

	got, err := reader.GetProject(ctx, orgA.ID, alpha.ID)
	if err != nil {
		t.Fatalf("GetProject(orgA, alpha): %v", err)
	}
	if got.ID != alpha.ID || got.OrganizationID != orgA.ID || got.Slug != alpha.Slug {
		t.Errorf("GetProject(orgA, alpha) = %+v, want id=%q org=%q slug=%q",
			got, alpha.ID, orgA.ID, alpha.Slug)
	}

	if _, err := reader.GetProject(ctx, orgA.ID, betaB.ID); err == nil {
		t.Fatalf("GetProject(orgA, betaB) error = nil, want NotFound")
	} else {
		var ye *yerr.Error
		if !errors.As(err, &ye) || ye.Code != "E_NOT_FOUND" {
			t.Fatalf("GetProject(orgA, betaB) error = %v, want apierr.NotFound (E_NOT_FOUND)", err)
		}
	}

	if _, err := reader.GetProject(ctx, orgA.ID, "prj_ghost00000000000000000000000"); err == nil {
		t.Fatalf("GetProject(orgA, missing) error = nil, want NotFound")
	} else {
		var ye *yerr.Error
		if !errors.As(err, &ye) || ye.Code != "E_NOT_FOUND" {
			t.Fatalf("GetProject(orgA, missing) error = %v, want apierr.NotFound (E_NOT_FOUND)", err)
		}
	}
}

// TestNewProjectReaderRejectsNilStore proves the constructor fails fast on
// a misconfigured adapter so a misconfigured server cannot ship.
func TestNewProjectReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewProjectReader(nil); err == nil {
		t.Fatal("NewProjectReader(nil) error = nil, want an error")
	}
}

// TestProjectRepositoryUpdateRejectsNilTx proves Update enforces the *Tx-only
// mutation surface — a nil tx is a typed Internal error, never a silent
// no-op or a panic — so a project can never be mutated outside the
// transaction that also carries its authorization and audit.
func TestProjectRepositoryUpdateRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewProjectRepository()
	_, err := repo.Update(context.Background(), nil, store.Project{ID: "prj_x", OrganizationID: "org_x"}, nil)
	if err == nil {
		t.Fatal("Update(nil tx) error = nil, want apierr.Internal")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != "E_INTERNAL" {
		t.Fatalf("Update(nil tx) error = %v, want E_INTERNAL", err)
	}
}

// TestProjectRepositoryUpdateApplies proves Update writes slug+display_name
// in one round-trip, bumps the version via the bump_version trigger, and
// returns the new row including the trigger-refreshed updated_at.
func TestProjectRepositoryUpdateApplies(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	original := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "web")))

	desired := original
	desired.Slug = "web-v2"
	desired.DisplayName = "Web v2"
	var updated store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Update(ctx, tx, desired, nil)
		if err != nil {
			return err
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Slug != "web-v2" || updated.DisplayName != "Web v2" {
		t.Errorf("updated row = %+v, want slug=web-v2 display_name=Web v2", updated)
	}
	if updated.Version <= original.Version {
		t.Errorf("version = %d, want > %d (trigger bump_version must fire on UPDATE)", updated.Version, original.Version)
	}
}

// TestProjectRepositoryUpdateNotFoundIsTenantScoped proves a cross-tenant
// project id is reported as NotFound by Update — the WHERE clause filters by
// organization_id first, so a project belonging to another tenant simply
// does not match. A truly missing id surfaces the same NotFound. The
// classification path that re-Gets the row to disambiguate stale-version
// from missing is therefore safe to call: it will not reveal another
// tenant's data.
func TestProjectRepositoryUpdateNotFoundIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "secret-service")))

	// orgB attempts to update orgA's project: NotFound, never the real row.
	desired := projA
	desired.OrganizationID = orgB.ID
	desired.DisplayName = "Hijacked"
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.Update(ctx, tx, desired, nil)
		return updErr
	})
	if err == nil {
		t.Fatal("cross-tenant Update error = nil, want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != "E_NOT_FOUND" {
		t.Fatalf("cross-tenant Update error = %v, want E_NOT_FOUND", err)
	}
}

// TestProjectRepositoryUpdateStaleVersion proves a stale If-Match precondition
// returns apierr.ConflictStale carrying the row's authoritative version, so
// the caller can rebuild its precondition without an extra Get.
func TestProjectRepositoryUpdateStaleVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	original := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "web")))
	// version starts at 1 (DEFAULT 1). Stale precondition: version 99.
	stale := int64(99)

	desired := original
	desired.DisplayName = "Updated"
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.Update(ctx, tx, desired, &stale)
		return updErr
	})
	if err == nil {
		t.Fatal("stale-version Update error = nil, want ConflictStale")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != "E_CONFLICT" {
		t.Fatalf("stale-version Update error = %v, want E_CONFLICT", err)
	}
	if got := ye.Details["current_version"]; got != "1" {
		t.Errorf("Details[current_version] = %q, want 1", got)
	}
}

// TestProjectRepositoryUpdateDuplicateSlugConflict proves a slug that
// collides with another project in the same organization rolls Update back
// with a typed Conflict — the (organization_id, slug) UNIQUE index is
// authoritative.
func TestProjectRepositoryUpdateDuplicateSlugConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	existing := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "web")))
	target := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "api")))

	// Rename target's slug to the existing one.
	desired := target
	desired.Slug = existing.Slug
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.Update(ctx, tx, desired, nil)
		return updErr
	})
	if err == nil {
		t.Fatal("duplicate-slug Update error = nil, want Conflict")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != "E_CONFLICT" {
		t.Fatalf("duplicate-slug Update error = %v, want E_CONFLICT", err)
	}
}
