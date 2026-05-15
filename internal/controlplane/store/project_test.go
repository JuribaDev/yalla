package store_test

import (
	"context"
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

// TestNewProjectReaderRejectsNilStore proves the constructor fails fast on
// a misconfigured adapter so a misconfigured server cannot ship.
func TestNewProjectReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewProjectReader(nil); err == nil {
		t.Fatal("NewProjectReader(nil) error = nil, want an error")
	}
}
