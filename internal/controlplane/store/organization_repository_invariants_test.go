package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for OrganizationRepository's own CRUD invariants
// (BE-0425). The repository's tenant-scoping contract is proved in
// organization_tenant_isolation_test.go; the optimistic-concurrency
// contract on top of it is proved in organization_concurrency_test.go.
// What this file proves are the row-shape invariants the source-of-truth
// table owes its callers regardless of who else is around:
//
//   - Insert returns the row at version 1, with database-assigned timestamps
//     where created_at and updated_at agree, and with deletion_scheduled_at
//     unset.
//   - Update bumps the row's version by exactly one and refreshes
//     updated_at while preserving created_at.
//   - Update with a matching If-Match version succeeds — the positive
//     companion to the stale-If-Match conflict path.
//   - Update with another row's slug renders a typed apierr.Conflict from
//     the repository, never a 500 leaking the constraint name.
//   - ScheduleDeletion bumps version, refreshes updated_at, preserves
//     created_at, and stamps deletion_scheduled_at on or after the
//     update boundary.
//   - The Insert / Update / ScheduleDeletion guards against a nil *Tx
//     argument render a typed apierr.Internal — never a nil-pointer
//     panic — so a caller that forgets to open a write transaction is
//     caught by the typed-error contract instead of by SIGSEGV.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard tests are pure unit tests and require no database.

// TestOrganizationRepositoryInsertReturnsRowAtVersion1WithTimestamps proves
// Insert returns the row the table actually committed: version starts at 1
// (the optimistic-concurrency baseline every caller is allowed to assume),
// created_at and updated_at are both non-zero and equal to each other
// (no UPDATE has fired yet, so the bump-version trigger has not run), and
// deletion_scheduled_at is nil (a live organization, not a scheduled one).
func TestOrganizationRepositoryInsertReturnsRowAtVersion1WithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	built := f.Organization("acme-co")

	var created store.Organization
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		created, writeErr = repo.Insert(ctx, tx, store.Organization{
			ID:          built.ID,
			Slug:        built.Slug,
			DisplayName: built.Name,
		})
		return writeErr
	}); err != nil {
		t.Fatalf("Insert returned %v, want nil", err)
	}

	if created.ID != built.ID || created.Slug != built.Slug || created.DisplayName != built.Name {
		t.Errorf("Insert returned %+v, want id/slug/name from %+v", created, built)
	}
	if created.Version != 1 {
		t.Errorf("Insert version = %d, want 1 (the optimistic-concurrency baseline)", created.Version)
	}
	if created.CreatedAt.IsZero() {
		t.Error("Insert returned a zero created_at")
	}
	if created.UpdatedAt.IsZero() {
		t.Error("Insert returned a zero updated_at")
	}
	if !created.CreatedAt.Equal(created.UpdatedAt) {
		t.Errorf("Insert created_at=%v updated_at=%v: want equal on a fresh row (no UPDATE has fired)", created.CreatedAt, created.UpdatedAt)
	}
	if created.DeletionScheduledAt != nil {
		t.Errorf("Insert returned deletion_scheduled_at=%v, want nil on a live row", created.DeletionScheduledAt)
	}

	// And the returned row must match what a subsequent Get reads back —
	// the source of truth is the database, not the in-memory value Insert
	// returned.
	var got store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, created.ID)
		return err
	}); err != nil {
		t.Fatalf("Get(created): %v", err)
	}
	if got.Version != created.Version || !got.CreatedAt.Equal(created.CreatedAt) || !got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("Get(created) = %+v, want the row Insert returned %+v", got, created)
	}
}

// TestOrganizationRepositoryUpdateBumpsVersionAndUpdatedAt proves a
// successful Update advances version by exactly one (the bump-version
// trigger fired once, no more) and refreshes updated_at to a value at or
// after the original — the same property the version trigger gives us, but
// projected through a different column, so a missing WHERE clause that
// avoids both anchors must be very lucky. created_at is preserved.
func TestOrganizationRepositoryUpdateBumpsVersionAndUpdatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme-co")

	var baseline store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		baseline, err = repo.Get(ctx, q, org.ID)
		return err
	}); err != nil {
		t.Fatalf("baseline Get: %v", err)
	}
	if baseline.Version != 1 {
		t.Fatalf("baseline Version = %d, want 1 on a freshly inserted row", baseline.Version)
	}

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at or
	// after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	var updated store.Organization
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updated, writeErr = repo.Update(ctx, tx, store.Organization{
			ID:          org.ID,
			Slug:        "acme-renamed",
			DisplayName: "Acme Renamed",
		}, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}

	if updated.Slug != "acme-renamed" || updated.DisplayName != "Acme Renamed" {
		t.Errorf("Update returned %+v, want slug=acme-renamed display_name=Acme Renamed", updated)
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("Update version = %d, want %d (baseline+1)", updated.Version, baseline.Version+1)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("Update mutated created_at: was %v, now %v", baseline.CreatedAt, updated.CreatedAt)
	}
	if updated.UpdatedAt.Before(baseline.UpdatedAt) {
		t.Errorf("Update updated_at = %v, want >= baseline %v (trigger must refresh)", updated.UpdatedAt, baseline.UpdatedAt)
	}
	if updated.DeletionScheduledAt != nil {
		t.Errorf("Update set deletion_scheduled_at=%v on a live row, want nil", updated.DeletionScheduledAt)
	}
}

// TestOrganizationRepositoryUpdateWithMatchingIfMatchSucceeds proves the
// positive side of the optimistic-concurrency contract: a caller that
// presents the row's current version in ifMatchVersion gets a successful
// Update, not a false ConflictStale. The stale-If-Match path is covered
// elsewhere; this one anchors the happy path so a regression that always
// classified version-checked UPDATEs as stale would be caught here.
func TestOrganizationRepositoryUpdateWithMatchingIfMatchSucceeds(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme-co")

	var baseline store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		baseline, err = repo.Get(ctx, q, org.ID)
		return err
	}); err != nil {
		t.Fatalf("baseline Get: %v", err)
	}

	current := baseline.Version
	var updated store.Organization
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updated, writeErr = repo.Update(ctx, tx, store.Organization{
			ID:          org.ID,
			Slug:        "acme-current",
			DisplayName: "Acme Current",
		}, &current)
		return writeErr
	}); err != nil {
		t.Fatalf("Update(matching If-Match) returned %v, want nil", err)
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("Update version = %d, want %d", updated.Version, baseline.Version+1)
	}
	if updated.Slug != "acme-current" {
		t.Errorf("Update slug = %q, want acme-current", updated.Slug)
	}
}

// TestOrganizationRepositoryUpdateSlugConflictReturnsTypedConflict proves
// the repository maps a slug-uniqueness collision on Update to a typed
// apierr.Conflict with a non-empty user-facing message — the same shape
// Insert returns for the same collision, so the audit/policy layers
// upstream don't have to special-case which mutation rendered the
// conflict. The raw driver detail (constraint name) is never the
// user-facing message.
func TestOrganizationRepositoryUpdateSlugConflictReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")

	// Snapshot orgA so we can prove its slug is unchanged after the
	// failed Update.
	var baselineA store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		baselineA, err = repo.Get(ctx, q, orgA.ID)
		return err
	}); err != nil {
		t.Fatalf("baseline Get(orgA): %v", err)
	}

	// Try to rename orgB to orgA's slug.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Update(ctx, tx, store.Organization{
			ID:          orgB.ID,
			Slug:        orgA.Slug, // intentional collision
			DisplayName: "Tenant B Renamed",
		}, nil)
		return writeErr
	})
	conflict := yerr.From(err)
	if conflict.Code != yerr.CodeConflict {
		t.Fatalf("Update(orgB, dup slug) error = %v, want %s", err, yerr.CodeConflict)
	}
	if conflict.Message == "" {
		t.Errorf("Update slug-conflict rendered an empty user-facing message")
	}

	// orgA's slug is untouched.
	var afterA store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		afterA, err = repo.Get(ctx, q, orgA.ID)
		return err
	}); err != nil {
		t.Fatalf("after Get(orgA): %v", err)
	}
	if afterA.Slug != baselineA.Slug {
		t.Errorf("orgA.slug = %q, want %q — failed Update on orgB must not touch orgA", afterA.Slug, baselineA.Slug)
	}

	// orgB still has its original slug too — the failed Update rolled back.
	var afterB store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		afterB, err = repo.Get(ctx, q, orgB.ID)
		return err
	}); err != nil {
		t.Fatalf("after Get(orgB): %v", err)
	}
	if afterB.Slug != orgB.Slug {
		t.Errorf("orgB.slug = %q, want %q — failed Update must roll back", afterB.Slug, orgB.Slug)
	}
}

// TestOrganizationRepositoryScheduleDeletionBumpsVersionAndUpdatedAt proves
// a successful ScheduleDeletion bumps version by exactly one, refreshes
// updated_at, preserves created_at, and stamps deletion_scheduled_at at or
// after baseline.UpdatedAt. The "version + updated_at both move" property
// is the same dual-anchor we anchor every other mutation against —
// scheduling a deletion is just another UPDATE statement and the trigger
// must treat it identically.
func TestOrganizationRepositoryScheduleDeletionBumpsVersionAndUpdatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme-co")

	var baseline store.Organization
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		baseline, err = repo.Get(ctx, q, org.ID)
		return err
	}); err != nil {
		t.Fatalf("baseline Get: %v", err)
	}
	if baseline.DeletionScheduledAt != nil {
		t.Fatalf("baseline DeletionScheduledAt = %v, want nil on a freshly seeded row", baseline.DeletionScheduledAt)
	}

	time.Sleep(time.Millisecond)

	var scheduled store.Organization
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		scheduled, writeErr = repo.ScheduleDeletion(ctx, tx, org.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion returned %v, want nil", err)
	}

	if scheduled.Version != baseline.Version+1 {
		t.Errorf("ScheduleDeletion version = %d, want %d", scheduled.Version, baseline.Version+1)
	}
	if !scheduled.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("ScheduleDeletion mutated created_at: was %v, now %v", baseline.CreatedAt, scheduled.CreatedAt)
	}
	if scheduled.UpdatedAt.Before(baseline.UpdatedAt) {
		t.Errorf("ScheduleDeletion updated_at = %v, want >= baseline %v", scheduled.UpdatedAt, baseline.UpdatedAt)
	}
	if scheduled.DeletionScheduledAt == nil {
		t.Fatal("ScheduleDeletion did not stamp deletion_scheduled_at")
	}
	if scheduled.DeletionScheduledAt.Before(baseline.UpdatedAt) {
		t.Errorf("DeletionScheduledAt = %v, want >= baseline.UpdatedAt %v", *scheduled.DeletionScheduledAt, baseline.UpdatedAt)
	}
	// Slug and display name must be preserved — ScheduleDeletion is a
	// soft-delete stamp, not a rename.
	if scheduled.Slug != baseline.Slug || scheduled.DisplayName != baseline.DisplayName {
		t.Errorf("ScheduleDeletion mutated identity fields: baseline=%+v, after=%+v", baseline, scheduled)
	}
}

// TestOrganizationRepositoryInsertWithoutTxIsTypedInternal proves the
// repository's nil-Tx guard renders a typed apierr.Internal — never a
// nil-pointer panic — when a caller wires the unit of work wrong. The
// caller is the policy/service layer; a missing transaction is a coding
// bug, not a user-recoverable condition, but it must still surface as the
// typed-error contract a panic would bypass.
func TestOrganizationRepositoryInsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewOrganizationRepository()

	_, err := repo.Insert(context.Background(), nil, store.Organization{
		ID:          "org_irrelevant",
		Slug:        "irrelevant",
		DisplayName: "Irrelevant",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Insert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestOrganizationRepositoryUpdateWithoutTxIsTypedInternal: same guard,
// Update path.
func TestOrganizationRepositoryUpdateWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewOrganizationRepository()

	_, err := repo.Update(context.Background(), nil, store.Organization{
		ID:          "org_irrelevant",
		Slug:        "irrelevant",
		DisplayName: "Irrelevant",
	}, nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Update(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestOrganizationRepositoryScheduleDeletionWithoutTxIsTypedInternal: same
// guard, ScheduleDeletion path.
func TestOrganizationRepositoryScheduleDeletionWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewOrganizationRepository()

	_, err := repo.ScheduleDeletion(context.Background(), nil, "org_irrelevant", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("ScheduleDeletion(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
