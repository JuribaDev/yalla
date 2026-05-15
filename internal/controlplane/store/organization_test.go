package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for OrganizationRepository and OrganizationReader — the
// read surface behind GET /v1/organizations. They prove id-scoped reads, typed
// not-found behaviour, that one tenant's row is never returned for another
// tenant's id, and that the Store.Read-backed reader inherits all of it. They
// run against an isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset.

func TestOrganizationRepositoryGet(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")

	var got store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID)
		return err
	}); err != nil {
		t.Fatalf("Get returned %v, want nil", err)
	}
	if got.ID != org.ID || got.Slug != org.Slug || got.DisplayName != org.Name {
		t.Errorf("Get returned %+v, want id/slug/name from %+v", got, org)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("Get did not return the database-assigned timestamps")
	}
}

func TestOrganizationRepositoryGetNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	missing := f.Organization("ghost") // built, never inserted

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, missing.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(missing) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestOrganizationRepositoryGetIsTenantScoped proves a Get is keyed by the
// organization's own id: it returns exactly that organization's row and never
// another tenant's, and an id that belongs to no organization is NotFound — the
// same shape one tenant sees for another tenant's (unknown-to-it) id.
func TestOrganizationRepositoryGetIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	var gotA, gotB store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		if gotA, err = repo.Get(ctx, q, orgA.ID); err != nil {
			return err
		}
		gotB, err = repo.Get(ctx, q, orgB.ID)
		return err
	}); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotA.ID != orgA.ID || gotA.Slug != orgA.Slug {
		t.Errorf("Get(orgA) = %+v, want orgA's own row", gotA)
	}
	if gotB.ID != orgB.ID || gotB.Slug != orgB.Slug {
		t.Errorf("Get(orgB) = %+v, want orgB's own row", gotB)
	}
	if gotA.ID == gotB.ID {
		t.Error("Get returned the same row for two distinct organization ids")
	}
}

func TestOrganizationReaderGetOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	reader, err := store.NewOrganizationReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationReader: %v", err)
	}

	org := seedOrg(t, db, f, "acme")

	got, err := reader.GetOrganization(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrganization returned %v, want nil", err)
	}
	if got.ID != org.ID || got.Slug != org.Slug || got.DisplayName != org.Name {
		t.Errorf("GetOrganization returned %+v, want id/slug/name from %+v", got, org)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("GetOrganization did not return the database-assigned timestamps")
	}
}

func TestOrganizationReaderGetOrganizationNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	reader, err := store.NewOrganizationReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationReader: %v", err)
	}

	missing := f.Organization("ghost") // built, never inserted

	_, err = reader.GetOrganization(ctx, missing.ID)
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetOrganization(missing) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

func TestNewOrganizationReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewOrganizationReader(nil); err == nil {
		t.Fatal("NewOrganizationReader(nil) error = nil, want an error")
	}
}
