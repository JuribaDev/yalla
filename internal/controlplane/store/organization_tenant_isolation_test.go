package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the organizations source of
// truth (BE-0426). Organizations is the tenant root of Yalla's
// Organization -> Project -> Environment -> Service hierarchy, so the
// isolation guarantee at this layer is the strongest one in the codebase:
// every read and every write is keyed by the organization's own id, and a
// mutation made through one organization's id can never observe, alter, or
// soft-delete another organization's row. The tests run against an isolated,
// freshly migrated Postgres database and skip when YALLA_TEST_DATABASE_URL
// is unset.
//
// What is intentionally NOT exercised here, and where the proof lives instead:
//   - Cross-tenant LIST visibility for child tables (projects, environments,
//     services, etc.) is proven by the parent-scoped repository tests in
//     project_test.go and friends.
//   - The HTTP-layer "another tenant's id is a 404, not a 403" rule is
//     proven by the per-endpoint policy matrix and contract tests in httpapi.
//   - The cross-tenant cascade is proven by TestTenantHierarchyCascadeDelete
//     in schema_test.go.
//   - The optimistic-concurrency conflict surface is proven by
//     organization_concurrency_test.go.
//
// The OrganizationRepository deliberately exposes no list-by-parent method:
// the table has no parent, and authorization for "which organizations does a
// principal see" is membership-derived and handled at the httpapi layer
// (GET /v1/me/organizations). Asserting that absence is part of the contract.

// TestOrganizationRepositoryGetReturnsOnlyTheNamedTenant proves Get is keyed
// strictly by the row's own id: two organizations exist with very similar
// slugs and display names; reading either returns exactly that organization's
// own row, never the other's.
func TestOrganizationRepositoryGetReturnsOnlyTheNamedTenant(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	// Seed two organizations whose fixtures look superficially similar — the
	// factory makes each slug and id unique, but the labels overlap enough
	// that a careless query that ORed across rows would be hard to spot.
	orgA := seedOrg(t, db, f, "acme-co")
	orgB := seedOrg(t, db, f, "acme-co-other")

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

	if gotA.ID != orgA.ID || gotA.Slug != orgA.Slug || gotA.DisplayName != orgA.Name {
		t.Errorf("Get(orgA) = %+v, want orgA's own row (%+v)", gotA, orgA)
	}
	if gotB.ID != orgB.ID || gotB.Slug != orgB.Slug || gotB.DisplayName != orgB.Name {
		t.Errorf("Get(orgB) = %+v, want orgB's own row (%+v)", gotB, orgB)
	}
	if gotA.ID == gotB.ID || gotA.Slug == gotB.Slug {
		t.Error("Get returned overlapping rows for two distinct organization ids")
	}
}

// TestOrganizationRepositoryGetUnknownIdIsNotFound proves an id that belongs
// to no organization at all is the same typed NotFound a principal would see
// for another tenant's (unknown-to-it) id. The wire shape one tenant produces
// for "an org you cannot see" must be byte-identical to "no such org": the
// existence of an organization in the database is never revealed by the
// shape of the response alone.
func TestOrganizationRepositoryGetUnknownIdIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	// Seed an organization that exists, then try to read a fixture that was
	// built but never inserted: the second id has the same shape as the
	// first (same prefix, same length) but corresponds to no row.
	seedOrg(t, db, f, "acme-co")
	missing := f.Organization("ghost")

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, missing.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(missing) error = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestOrganizationRepositoryUpdateOnlyTouchesNamedTenant proves a successful
// Update on organization A leaves organization B's row byte-identical to its
// pre-update state: same slug, same display name, same version, same
// updated_at timestamp, same deletion stamp. A repository whose UPDATE
// statement was missing its WHERE clause — or named the wrong column — would
// quietly mutate B; this test makes that mutation visible.
func TestOrganizationRepositoryUpdateOnlyTouchesNamedTenant(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// Snapshot orgB before the update so any drift is caught precisely.
	var baselineB store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		baselineB, err = repo.Get(ctx, q, orgB.ID)
		return err
	}); err != nil {
		t.Fatalf("baseline Get(orgB): %v", err)
	}

	// Update orgA only: change slug AND display_name so a wrong-column WHERE
	// would be detected by either projection on orgB.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Update(ctx, tx, store.Organization{
			ID:          orgA.ID,
			Slug:        "tenant-a-renamed",
			DisplayName: "Tenant A Renamed",
		}, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Update(orgA): %v", err)
	}

	// orgB must be byte-identical to its baseline — slug, display name,
	// version, updated_at, and the deletion stamp.
	var afterB store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		afterB, err = repo.Get(ctx, q, orgB.ID)
		return err
	}); err != nil {
		t.Fatalf("after Get(orgB): %v", err)
	}
	if afterB.Slug != baselineB.Slug {
		t.Errorf("orgB.slug = %q, want %q — Update(orgA) leaked into orgB", afterB.Slug, baselineB.Slug)
	}
	if afterB.DisplayName != baselineB.DisplayName {
		t.Errorf("orgB.display_name = %q, want %q — Update(orgA) leaked into orgB", afterB.DisplayName, baselineB.DisplayName)
	}
	if afterB.Version != baselineB.Version {
		t.Errorf("orgB.version = %d, want %d — Update(orgA) bumped orgB's optimistic version", afterB.Version, baselineB.Version)
	}
	if !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) {
		t.Errorf("orgB.updated_at = %v, want %v — Update(orgA) refreshed orgB's timestamp", afterB.UpdatedAt, baselineB.UpdatedAt)
	}
	if afterB.DeletionScheduledAt != nil {
		t.Errorf("orgB.deletion_scheduled_at = %v, want nil — Update(orgA) must never stamp orgB", afterB.DeletionScheduledAt)
	}

	// And the orgA update itself actually landed — otherwise a no-op repository
	// would pass this test trivially.
	var afterA store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		afterA, err = repo.Get(ctx, q, orgA.ID)
		return err
	}); err != nil {
		t.Fatalf("after Get(orgA): %v", err)
	}
	if afterA.Slug != "tenant-a-renamed" || afterA.DisplayName != "Tenant A Renamed" {
		t.Errorf("Update(orgA) did not persist: got %+v, want slug/name tenant-a-renamed/Tenant A Renamed", afterA)
	}
}

// TestOrganizationRepositoryUpdateWithMismatchedIfMatchOnOrgADoesNotTouchOrgB
// proves a stale-If-Match Update against organization A — which fails with a
// typed Conflict — also leaves organization B byte-identical to its
// pre-attempt state. A handler that silently fell back to a no-WHERE UPDATE
// after a stale conflict would be caught here.
func TestOrganizationRepositoryUpdateWithMismatchedIfMatchOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	var baselineB store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		baselineB, err = repo.Get(ctx, q, orgB.ID)
		return err
	}); err != nil {
		t.Fatalf("baseline Get(orgB): %v", err)
	}

	// Deliberately use a version orgA was never at to force a conflict.
	stale := int64(99)
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Update(ctx, tx, store.Organization{
			ID:          orgA.ID,
			Slug:        "tenant-a-renamed",
			DisplayName: "Tenant A Renamed",
		}, &stale)
		return writeErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Update(orgA, stale) error = %v, want %s", err, yerr.CodeConflict)
	}

	// orgB still byte-identical to its baseline.
	var afterB store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		afterB, err = repo.Get(ctx, q, orgB.ID)
		return err
	}); err != nil {
		t.Fatalf("after Get(orgB): %v", err)
	}
	if afterB.Slug != baselineB.Slug || afterB.DisplayName != baselineB.DisplayName ||
		afterB.Version != baselineB.Version || !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) ||
		afterB.DeletionScheduledAt != nil {
		t.Errorf("orgB drifted across a failed orgA Update: before=%+v, after=%+v", baselineB, afterB)
	}
}

// TestOrganizationRepositoryScheduleDeletionOnlyTouchesNamedTenant proves a
// soft-delete on organization A stamps deletion_scheduled_at on exactly that
// row: organization B's row, read back through the same repository, still has
// no stamp. The HTTP layer's deletion endpoint relies on this property to
// keep one tenant's accidental destructive action from cascading another
// tenant out of existence.
func TestOrganizationRepositoryScheduleDeletionOnlyTouchesNamedTenant(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	var baselineB store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		baselineB, err = repo.Get(ctx, q, orgB.ID)
		return err
	}); err != nil {
		t.Fatalf("baseline Get(orgB): %v", err)
	}

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.ScheduleDeletion(ctx, tx, orgA.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion(orgA): %v", err)
	}

	// orgA must carry the stamp.
	var afterA store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		afterA, err = repo.Get(ctx, q, orgA.ID)
		return err
	}); err != nil {
		t.Fatalf("after Get(orgA): %v", err)
	}
	if afterA.DeletionScheduledAt == nil {
		t.Fatal("ScheduleDeletion(orgA) did not stamp deletion_scheduled_at on orgA")
	}

	// orgB must be byte-identical — including the absent deletion stamp.
	var afterB store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		afterB, err = repo.Get(ctx, q, orgB.ID)
		return err
	}); err != nil {
		t.Fatalf("after Get(orgB): %v", err)
	}
	if afterB.DeletionScheduledAt != nil {
		t.Errorf("orgB.deletion_scheduled_at = %v, want nil — ScheduleDeletion(orgA) must never stamp orgB", afterB.DeletionScheduledAt)
	}
	if afterB.Slug != baselineB.Slug || afterB.DisplayName != baselineB.DisplayName ||
		afterB.Version != baselineB.Version || !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) {
		t.Errorf("orgB drifted across ScheduleDeletion(orgA): before=%+v, after=%+v", baselineB, afterB)
	}
}

// TestOrganizationRepositoryGetOfSoftDeletedTenantDoesNotMaskOther proves a
// scheduled-for-deletion organization is still readable as its own row, and
// the stamp on it never bleeds into another tenant's row. This pins the
// invariant that the soft-delete column is a per-row flag, not a globally
// visible state: a destructive teardown worker (BE-0203+) that crashes after
// scheduling orgA must not corrupt orgB.
func TestOrganizationRepositoryGetOfSoftDeletedTenantDoesNotMaskOther(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.ScheduleDeletion(ctx, tx, orgA.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion(orgA): %v", err)
	}

	// orgA still readable, with the stamp visible — soft-delete is not a
	// SQL-level hide; visibility decisions live in the policy/handler layer.
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
	if gotA.DeletionScheduledAt == nil {
		t.Error("Get(orgA scheduled) returned no stamp, want the persisted deletion_scheduled_at")
	}
	if gotB.DeletionScheduledAt != nil {
		t.Errorf("Get(orgB) returned a stamp = %v, want nil — orgA's stamp must not bleed into orgB", gotB.DeletionScheduledAt)
	}
	if gotA.ID == gotB.ID || gotA.Slug == gotB.Slug {
		t.Error("Get returned the same row for the soft-deleted tenant and the live tenant")
	}
}

// TestOrganizationRepositoryInsertEnforcesGlobalSlugUniqueness proves the
// organizations table treats slug as a globally unique identifier across
// every tenant — there is no parent to scope by, since organizations IS the
// tenant root. A second Insert with the same slug as an existing organization
// is a typed Conflict; the slug of the first organization is never altered.
// This is the load-bearing reason GET /v1/organizations/{slug} can be a stable
// public-facing identifier: a customer never has to disambiguate it.
func TestOrganizationRepositoryInsertEnforcesGlobalSlugUniqueness(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	// Seed orgA with a known slug via the repository (not the seed helper)
	// so the test exercises Insert's own conflict mapping.
	built := f.Organization("acme-co")
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Insert(ctx, tx, store.Organization{
			ID:          built.ID,
			Slug:        built.Slug,
			DisplayName: built.Name,
		})
		return writeErr
	}); err != nil {
		t.Fatalf("Insert(orgA): %v", err)
	}

	// Now try to insert a second, independently-built organization that
	// happens to reuse orgA's slug.
	other := f.Organization("acme-co-other")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Insert(ctx, tx, store.Organization{
			ID:          other.ID,
			Slug:        built.Slug, // intentional collision
			DisplayName: other.Name,
		})
		return writeErr
	})
	conflict := yerr.From(err)
	if conflict.Code != yerr.CodeConflict {
		t.Fatalf("Insert(orgB, dup slug) error = %v, want %s", err, yerr.CodeConflict)
	}

	// The conflict carries the typed user-facing message the repository
	// supplied — never the raw driver detail or constraint name.
	if conflict.Message == "" {
		t.Fatalf("Insert error rendered empty user-facing message: %v", err)
	}

	// The first organization's slug is unchanged, no orgB row exists.
	var gotA store.Organization
	if rerr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		gotA, err = repo.Get(ctx, q, built.ID)
		return err
	}); rerr != nil {
		t.Fatalf("Get(orgA): %v", rerr)
	}
	if gotA.Slug != built.Slug {
		t.Errorf("orgA.slug = %q, want %q after failed orgB Insert", gotA.Slug, built.Slug)
	}

	// orgB's row never landed: a Get by its id is NotFound.
	getErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, e := repo.Get(ctx, q, other.ID)
		return e
	})
	if ye := yerr.From(getErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(orgB) after failed Insert: error = %v, want %s", getErr, yerr.CodeNotFound)
	}
}
