package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for ProjectRepository's own CRUD invariants (BE-0437).
// The repository's tenant-scoping contract (Get / ListByOrganization /
// Update / UpdateDisplayName / ScheduleDeletion / Restore filter by
// organization_id before id) and slug-uniqueness conflict mapping are
// proved in project_test.go / project_delete_test.go / project_restore_test.go
// alongside the ProjectRepository unit-of-work tests. The optimistic-concurrency
// classifyProjectConcurrencyMiss path on Update is anchored by
// TestProjectRepositoryUpdateStaleVersion in project_test.go. What this file
// proves are the row-shape and lifecycle invariants the projects table owes
// its callers regardless of who else is around:
//
//   - Insert returns the row at version 1, with database-assigned timestamps
//     where created_at and updated_at agree byte-for-byte (no UPDATE has
//     fired yet, so the projects_bump_version trigger has not run), and
//     with deletion_scheduled_at unset.
//   - Update bumps the row's version by exactly one and refreshes
//     updated_at while preserving created_at. The "version + updated_at
//     both advance, created_at does not" dual-anchor is the property a
//     missing WHERE clause or a forgotten trigger would silently violate.
//   - Update with a matching If-Match version succeeds — the positive
//     companion to the stale-If-Match conflict path covered elsewhere.
//   - UpdateDisplayName runs the dual-anchor too (it is a distinct UPDATE
//     statement with its own SET clause) and additionally must leave slug
//     untouched; only display_name is allowed to move on this path.
//   - ScheduleDeletion bumps version, refreshes updated_at, preserves
//     created_at, preserves identity fields (slug and display_name), and
//     stamps deletion_scheduled_at on or after the update boundary.
//   - Restore bumps version, refreshes updated_at, preserves created_at,
//     and clears deletion_scheduled_at back to NULL — the inverse of
//     ScheduleDeletion projected through the same dual-anchor.
//   - Insert participates in the surrounding transaction as the unit of
//     work: a closure that succeeds in writing the row but returns an
//     error must leave no row behind, so an audit/policy/quota step that
//     fails alongside an Insert cannot leak a half-created project.
//   - The UpdateDisplayName nil-Tx guard renders a typed apierr.Internal
//     so a caller that wires the unit of work wrong is caught by the
//     typed-error contract instead of by a nil-pointer panic. The
//     Insert / Update / ScheduleDeletion / Restore nil-Tx guards are
//     already covered by project_test.go, project_delete_test.go, and
//     project_restore_test.go respectively.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard test is a pure unit test and requires no database.

// TestProjectRepositoryInsertReturnsRowAtVersion1WithTimestamps proves
// Insert returns the row the table actually committed: version starts at 1
// (the optimistic-concurrency baseline every caller is allowed to assume),
// created_at and updated_at are both non-zero AND byte-equal on the fresh
// row (no UPDATE has fired yet, so the projects_bump_version trigger has
// not run), and deletion_scheduled_at is nil (a live project, not a
// scheduled one).
func TestProjectRepositoryInsertReturnsRowAtVersion1WithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	built := projectFixture(f.Project(org, "web"))

	var created store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		created, writeErr = repo.Insert(ctx, tx, built)
		return writeErr
	}); err != nil {
		t.Fatalf("Insert returned %v, want nil", err)
	}

	if created.ID != built.ID || created.OrganizationID != built.OrganizationID || created.Slug != built.Slug || created.DisplayName != built.DisplayName {
		t.Errorf("Insert returned %+v, want id/org/slug/name from %+v", created, built)
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
	var got store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("Get(created): %v", err)
	}
	if got.Version != created.Version || !got.CreatedAt.Equal(created.CreatedAt) || !got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("Get(created) = %+v, want the row Insert returned %+v", got, created)
	}
}

// TestProjectRepositoryUpdateBumpsVersionAndRefreshesUpdatedAt proves a
// successful Update advances version by exactly one (the
// projects_bump_version trigger fired once, no more), refreshes updated_at
// to a value at or after the original — the same property the version
// trigger gives us, but projected through a different column, so a missing
// WHERE clause that avoids both anchors must be very lucky — and preserves
// created_at. deletion_scheduled_at must remain nil on a live row.
func TestProjectRepositoryUpdateBumpsVersionAndRefreshesUpdatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	baseline := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "web")))
	if baseline.Version != 1 {
		t.Fatalf("baseline Version = %d, want 1 on a freshly inserted row", baseline.Version)
	}

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at or
	// after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	desired := baseline
	desired.Slug = "web-v2"
	desired.DisplayName = "Web v2"
	var updated store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updated, writeErr = repo.Update(ctx, tx, desired, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}

	if updated.Slug != "web-v2" || updated.DisplayName != "Web v2" {
		t.Errorf("Update returned %+v, want slug=web-v2 display_name=Web v2", updated)
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

// TestProjectRepositoryUpdateWithMatchingIfMatchSucceeds proves the
// positive side of the optimistic-concurrency contract: a caller that
// presents the row's current version in ifMatchVersion gets a successful
// Update, not a false ConflictStale. The stale-If-Match path is covered by
// TestProjectRepositoryUpdateStaleVersion in project_test.go; this case
// anchors the happy path so a regression that always classified
// version-checked UPDATEs as stale would be caught here.
func TestProjectRepositoryUpdateWithMatchingIfMatchSucceeds(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	baseline := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "web")))

	current := baseline.Version
	desired := baseline
	desired.Slug = "web-current"
	desired.DisplayName = "Web Current"
	var updated store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updated, writeErr = repo.Update(ctx, tx, desired, &current)
		return writeErr
	}); err != nil {
		t.Fatalf("Update(matching If-Match) returned %v, want nil", err)
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("Update version = %d, want %d", updated.Version, baseline.Version+1)
	}
	if updated.Slug != "web-current" || updated.DisplayName != "Web Current" {
		t.Errorf("Update returned %+v, want slug=web-current display_name=Web Current", updated)
	}
}

// TestProjectRepositoryUpdateDisplayNameBumpsVersionAndPreservesSlug proves
// the UpdateDisplayName path — a distinct UPDATE statement with its own
// `SET display_name = $3` clause — runs the same dual-anchor as Update
// (version+1, updated_at refreshed, created_at preserved) AND that slug is
// untouched. This is the property a regression that copy-pasted the Update
// SET list into UpdateDisplayName would silently violate: the row would
// still pass the version/timestamp anchors but the user's display-name-only
// PATCH would also clobber their slug.
func TestProjectRepositoryUpdateDisplayNameBumpsVersionAndPreservesSlug(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	baseline := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "web")))

	time.Sleep(time.Millisecond)

	var updated store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updated, writeErr = repo.UpdateDisplayName(ctx, tx, org.ID, baseline.ID, "Web Renamed", nil)
		return writeErr
	}); err != nil {
		t.Fatalf("UpdateDisplayName returned %v, want nil", err)
	}

	if updated.DisplayName != "Web Renamed" {
		t.Errorf("UpdateDisplayName display_name = %q, want Web Renamed", updated.DisplayName)
	}
	if updated.Slug != baseline.Slug {
		t.Errorf("UpdateDisplayName mutated slug: was %q, now %q (the path must SET display_name only)", baseline.Slug, updated.Slug)
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("UpdateDisplayName version = %d, want %d (baseline+1)", updated.Version, baseline.Version+1)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("UpdateDisplayName mutated created_at: was %v, now %v", baseline.CreatedAt, updated.CreatedAt)
	}
	if updated.UpdatedAt.Before(baseline.UpdatedAt) {
		t.Errorf("UpdateDisplayName updated_at = %v, want >= baseline %v", updated.UpdatedAt, baseline.UpdatedAt)
	}
	if updated.DeletionScheduledAt != nil {
		t.Errorf("UpdateDisplayName set deletion_scheduled_at=%v on a live row, want nil", updated.DeletionScheduledAt)
	}

	// And the returned row must match what a subsequent Get reads back —
	// the source of truth is the database, not the in-memory value
	// UpdateDisplayName returned.
	var got store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, baseline.ID)
		return err
	}); err != nil {
		t.Fatalf("Get(updated): %v", err)
	}
	if got.Slug != baseline.Slug {
		t.Errorf("Get after UpdateDisplayName: slug=%q, want unchanged %q", got.Slug, baseline.Slug)
	}
	if got.DisplayName != "Web Renamed" {
		t.Errorf("Get after UpdateDisplayName: display_name=%q, want Web Renamed", got.DisplayName)
	}
}

// TestProjectRepositoryScheduleDeletionBumpsVersionAndStampsDeletionScheduledAt
// proves a successful ScheduleDeletion bumps version by exactly one,
// refreshes updated_at, preserves created_at, preserves the row's identity
// fields (slug and display_name — scheduling a deletion is a soft-delete
// stamp, not a rename), and stamps deletion_scheduled_at at or after
// baseline.UpdatedAt. The "version + updated_at both move" property is the
// same dual-anchor every other mutation is held to — scheduling a deletion
// is just another UPDATE statement and the trigger must treat it
// identically.
func TestProjectRepositoryScheduleDeletionBumpsVersionAndStampsDeletionScheduledAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	baseline := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "web")))
	if baseline.DeletionScheduledAt != nil {
		t.Fatalf("baseline DeletionScheduledAt = %v, want nil on a freshly inserted row", baseline.DeletionScheduledAt)
	}

	time.Sleep(time.Millisecond)

	var scheduled store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		scheduled, writeErr = repo.ScheduleDeletion(ctx, tx, org.ID, baseline.ID, nil)
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

// TestProjectRepositoryRestoreBumpsVersionAndClearsDeletionScheduledAt
// proves a successful Restore is the inverse of ScheduleDeletion projected
// through the same dual-anchor: it bumps version by exactly one, refreshes
// updated_at, preserves created_at, preserves identity fields, and clears
// deletion_scheduled_at back to NULL. A regression that forgot the `SET
// deletion_scheduled_at = NULL` clause would still pass the version /
// updated_at anchors — the trigger fires on any UPDATE — so the
// "deletion_scheduled_at is nil after Restore" assertion is the load-bearing
// one for this path.
func TestProjectRepositoryRestoreBumpsVersionAndClearsDeletionScheduledAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	inserted := insertProject(ctx, t, s, repo, projectFixture(f.Project(org, "web")))

	// Schedule deletion first so Restore has a non-nil stamp to clear.
	var scheduled store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		scheduled, writeErr = repo.ScheduleDeletion(ctx, tx, org.ID, inserted.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion(setup) returned %v, want nil", err)
	}
	if scheduled.DeletionScheduledAt == nil {
		t.Fatal("setup ScheduleDeletion did not stamp deletion_scheduled_at; cannot test Restore")
	}

	time.Sleep(time.Millisecond)

	var restored store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		restored, writeErr = repo.Restore(ctx, tx, org.ID, inserted.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Restore returned %v, want nil", err)
	}

	if restored.Version != scheduled.Version+1 {
		t.Errorf("Restore version = %d, want %d (scheduled+1)", restored.Version, scheduled.Version+1)
	}
	if !restored.CreatedAt.Equal(inserted.CreatedAt) {
		t.Errorf("Restore mutated created_at: original %v, now %v", inserted.CreatedAt, restored.CreatedAt)
	}
	if restored.UpdatedAt.Before(scheduled.UpdatedAt) {
		t.Errorf("Restore updated_at = %v, want >= scheduled %v", restored.UpdatedAt, scheduled.UpdatedAt)
	}
	if restored.DeletionScheduledAt != nil {
		t.Errorf("Restore deletion_scheduled_at = %v, want nil (cleared)", restored.DeletionScheduledAt)
	}
	// Slug and display name must be preserved — Restore is a soft-delete
	// unstamp, not a rename.
	if restored.Slug != inserted.Slug || restored.DisplayName != inserted.DisplayName {
		t.Errorf("Restore mutated identity fields: original=%+v, after=%+v", inserted, restored)
	}

	// And the returned row must match what a subsequent Get reads back —
	// the source of truth is the database, not the in-memory value Restore
	// returned.
	var got store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, inserted.ID)
		return err
	}); err != nil {
		t.Fatalf("Get(restored): %v", err)
	}
	if got.DeletionScheduledAt != nil {
		t.Errorf("Get after Restore: deletion_scheduled_at = %v, want nil", got.DeletionScheduledAt)
	}
	if got.Version != restored.Version {
		t.Errorf("Get after Restore: version = %d, want %d", got.Version, restored.Version)
	}
}

// TestProjectRepositoryInsertRollsBackOnTxRollback proves that an Insert
// whose outer Write returns a non-nil error rolls the row back — the
// transaction is the unit of work, and no half-written project can survive
// an aborted audit/policy/quota step that runs alongside it. A future
// refactor that switched Insert to a SAVEPOINT or autonomous transaction
// would let the row escape the rollback and this test would catch it.
func TestProjectRepositoryInsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	built := projectFixture(f.Project(org, "web"))

	// Insert succeeds inside the tx, but the closure returns an error, so
	// the entire transaction is rolled back.
	bailout := projectTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, insErr := repo.Insert(ctx, tx, built); insErr != nil {
			return insErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	// The row must not exist outside the rolled-back transaction — Get
	// must surface NotFound.
	getErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, rerr := repo.Get(ctx, q, org.ID, built.ID)
		return rerr
	})
	if ye := yerr.From(getErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(rolled-back project) = %v, want NotFound", getErr)
	}

	// And the list view from the owning organization must not see it
	// either — the row is gone everywhere, not just behind the by-id path.
	var listed []store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listed, listErr = repo.ListByOrganization(ctx, q, org.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByOrganization(after rollback): %v", err)
	}
	for _, p := range listed {
		if p.ID == built.ID {
			t.Fatalf("ListByOrganization still sees rolled-back project %q", built.ID)
		}
	}

	// And the count the quota layer reads must also reflect the rollback —
	// a quota check that ran alongside the failed Insert must not see the
	// row.
	var count int
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var cerr error
		count, cerr = repo.CountByOrganization(ctx, q, org.ID)
		return cerr
	}); err != nil {
		t.Fatalf("CountByOrganization(after rollback): %v", err)
	}
	if count != 0 {
		t.Errorf("CountByOrganization after rollback = %d, want 0 (the rolled-back row must not count)", count)
	}
}

// projectTxRollbackSentinel is a typed error a transaction closure can
// return to force a rollback in TestProjectRepositoryInsertRollsBackOnTxRollback.
// It is local to this test file so callers cannot rely on its identity —
// every *_test.go file under internal/controlplane/store/ shares the same
// store_test package, so the type name is intentionally distinct from
// api_key_repository_invariants_test.go's apiKeyTxRollbackSentinel,
// api_key_scope_repository_invariants_test.go's apiKeyScopeTxRollbackSentinel,
// membership_repository_invariants_test.go's membershipTxRollbackSentinel,
// serviceaccount_repository_invariants_test.go's serviceAccountTxRollbackSentinel,
// and user_repository_invariants_test.go's errSentinel to avoid a collision.
type projectTxRollbackSentinel struct{}

func (projectTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this project transaction"
}

// TestProjectRepositoryUpdateDisplayNameWithoutTxIsTypedInternal proves the
// repository's nil-Tx guard on UpdateDisplayName renders a typed
// apierr.Internal — never a nil-pointer panic — when a caller wires the
// unit of work wrong. The Insert / Update / ScheduleDeletion / Restore
// nil-Tx guards are already covered by TestProjectRepositoryInsertRejectsNilTx
// (project_test.go), TestProjectRepositoryUpdateRejectsNilTx (project_test.go),
// TestProjectRepositoryScheduleDeletionRejectsNilTx (project_delete_test.go),
// and TestProjectRepositoryRestoreRejectsNilTx (project_restore_test.go);
// UpdateDisplayName is the one mutation path that did not yet have a
// typed-code assertion, so this case closes the matrix.
func TestProjectRepositoryUpdateDisplayNameWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewProjectRepository()

	_, err := repo.UpdateDisplayName(context.Background(), nil, "org_irrelevant", "prj_irrelevant", "Irrelevant", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("UpdateDisplayName(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
