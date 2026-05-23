package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for EnvironmentRepository's own CRUD invariants
// (BE-0441). The repository's tenant-scoping contract (Get / ListByProject /
// Update / ScheduleDeletion filter by organization_id before id), slug
// uniqueness conflict mapping inside a project, and optimistic-concurrency
// classifyEnvironmentConcurrencyMiss path on Update are proved in
// environment_test.go / environment_update_test.go / environment_delete_test.go
// alongside the EnvironmentRepository unit-of-work tests. The Update and
// ScheduleDeletion nil-Tx guards are anchored by
// TestEnvironmentRepoUpdateRejectsNilTx (environment_update_test.go) and
// TestEnvironmentRepositoryScheduleDeletionRejectsNilTx
// (environment_delete_test.go) respectively. What this file proves are the
// row-shape and lifecycle invariants the environments table owes its
// callers regardless of who else is around:
//
//   - Insert returns the row at version 1, with database-assigned timestamps
//     where created_at and updated_at agree byte-for-byte (no UPDATE has
//     fired yet, so the environments_bump_version trigger has not run),
//     and with deletion_scheduled_at unset.
//   - Update bumps the row's version by exactly one and refreshes
//     updated_at while preserving created_at. The "version + updated_at
//     both advance, created_at does not" dual-anchor is the property a
//     missing WHERE clause or a forgotten trigger would silently violate.
//     Kind, organization_id, and project_id are preserved — Update is a
//     slug/display_name PATCH, not a re-parenting or a re-classification.
//   - Update with a matching If-Match version succeeds — the positive
//     companion to the stale-If-Match conflict path covered elsewhere.
//   - ScheduleDeletion bumps version, refreshes updated_at, preserves
//     created_at, preserves identity fields (slug, display_name, kind), and
//     stamps deletion_scheduled_at on or after the update boundary.
//   - Insert participates in the surrounding transaction as the unit of
//     work: a closure that succeeds in writing the row but returns an
//     error must leave no row behind, so an audit/policy/quota step that
//     fails alongside an Insert cannot leak a half-created environment.
//   - The Insert nil-Tx guard renders a typed apierr.Internal so a caller
//     that wires the unit of work wrong is caught by the typed-error
//     contract instead of by a nil-pointer panic. The Update and
//     ScheduleDeletion nil-Tx guards are already covered in
//     environment_update_test.go and environment_delete_test.go
//     respectively; this case closes the matrix.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard test is a pure unit test and requires no database.
//
// EnvironmentRepository exposes no UpdateDisplayName and no Restore path
// (unlike ProjectRepository): the only mutation surface is Insert /
// Update / ScheduleDeletion, so the invariants matrix is correspondingly
// smaller than project_repository_invariants_test.go's. Adding a new
// mutation path here is the cue to extend the dual-anchor coverage to
// match.

// environmentFixture lifts a testutil.Environment into the store.Environment
// shape the EnvironmentRepository accepts. Kind defaults to
// EnvironmentKindStandard — the long-lived staging / production /
// ad-hoc taxonomy member that the CHECK constraint in migration 0025
// requires every persisted environments row to live in.
func environmentFixture(env testutil.Environment) store.Environment {
	return store.Environment{
		ID:             env.ID,
		OrganizationID: env.OrganizationID,
		ProjectID:      env.ProjectID,
		Slug:           env.Slug,
		DisplayName:    env.Name,
		Kind:           store.EnvironmentKindStandard,
	}
}

// insertEnvironment persists e through Store.Write and returns the stored
// row, including the database-assigned timestamps and the initial version.
// Tests use this to seed a baseline before exercising Update or
// ScheduleDeletion, so the baseline carries the same trigger-managed
// shape that production INSERTs commit.
func insertEnvironment(ctx context.Context, t *testing.T, s *store.Store, repo *store.EnvironmentRepository, e store.Environment) store.Environment {
	t.Helper()
	var stored store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, e)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("insert environment: %v", err)
	}
	return stored
}

// TestEnvironmentRepositoryInsertReturnsRowAtVersion1WithTimestamps proves
// Insert returns the row the table actually committed: version starts at 1
// (the optimistic-concurrency baseline every caller is allowed to assume),
// created_at and updated_at are both non-zero AND byte-equal on the fresh
// row (no UPDATE has fired yet, so the environments_bump_version trigger
// has not run), and deletion_scheduled_at is nil (a live environment, not
// a scheduled one).
func TestEnvironmentRepositoryInsertReturnsRowAtVersion1WithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvInvInsAcme")
	proj := seedProject(t, db, f, org, "Web")
	built := environmentFixture(f.Environment(proj, "production"))

	var created store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		created, writeErr = repo.Insert(ctx, tx, built)
		return writeErr
	}); err != nil {
		t.Fatalf("Insert returned %v, want nil", err)
	}

	if created.ID != built.ID ||
		created.OrganizationID != built.OrganizationID ||
		created.ProjectID != built.ProjectID ||
		created.Slug != built.Slug ||
		created.DisplayName != built.DisplayName ||
		created.Kind != built.Kind {
		t.Errorf("Insert returned %+v, want id/org/project/slug/name/kind from %+v", created, built)
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
	var got store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.GetByID(ctx, q, org.ID, created.ID)
		return err
	}); err != nil {
		t.Fatalf("GetByID(created): %v", err)
	}
	if got.Version != created.Version ||
		!got.CreatedAt.Equal(created.CreatedAt) ||
		!got.UpdatedAt.Equal(created.UpdatedAt) ||
		got.Kind != created.Kind {
		t.Errorf("GetByID(created) = %+v, want the row Insert returned %+v", got, created)
	}
}

// TestEnvironmentRepositoryUpdateBumpsVersionAndRefreshesUpdatedAt proves a
// successful Update advances version by exactly one (the
// environments_bump_version trigger fired once, no more), refreshes
// updated_at to a value at or after the original — the same property the
// version trigger gives us, but projected through a different column, so
// a missing WHERE clause that avoids both anchors must be very lucky —
// and preserves created_at. Kind, organization_id, and project_id are
// preserved (Update is a slug/display_name PATCH, not a re-parenting or
// re-classification); deletion_scheduled_at remains nil on a live row.
func TestEnvironmentRepositoryUpdateBumpsVersionAndRefreshesUpdatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvInvUpdAcme")
	proj := seedProject(t, db, f, org, "Web")
	baseline := insertEnvironment(ctx, t, s, repo, environmentFixture(f.Environment(proj, "production")))
	if baseline.Version != 1 {
		t.Fatalf("baseline Version = %d, want 1 on a freshly inserted row", baseline.Version)
	}

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at or
	// after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	desired := baseline
	desired.Slug = "production-v2"
	desired.DisplayName = "Production v2"
	var updated store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updated, writeErr = repo.Update(ctx, tx, desired, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}

	if updated.Slug != "production-v2" || updated.DisplayName != "Production v2" {
		t.Errorf("Update returned %+v, want slug=production-v2 display_name=Production v2", updated)
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
	if updated.Kind != baseline.Kind {
		t.Errorf("Update mutated kind: was %q, now %q (the SET clause must touch slug/display_name only)", baseline.Kind, updated.Kind)
	}
	if updated.OrganizationID != baseline.OrganizationID || updated.ProjectID != baseline.ProjectID {
		t.Errorf("Update mutated tenant key: baseline=%+v, after=%+v", baseline, updated)
	}
	if updated.DeletionScheduledAt != nil {
		t.Errorf("Update set deletion_scheduled_at=%v on a live row, want nil", updated.DeletionScheduledAt)
	}
}

// TestEnvironmentRepositoryUpdateWithMatchingIfMatchSucceeds proves the
// positive side of the optimistic-concurrency contract: a caller that
// presents the row's current version in ifMatchVersion gets a successful
// Update, not a false ConflictStale. The stale-If-Match path is covered
// by TestEnvironmentRepoUpdateIfMatchHonoured in environment_update_test.go;
// this case anchors the happy path so a regression that always classified
// version-checked UPDATEs as stale would be caught here.
func TestEnvironmentRepositoryUpdateWithMatchingIfMatchSucceeds(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvInvIfMatchAcme")
	proj := seedProject(t, db, f, org, "Web")
	baseline := insertEnvironment(ctx, t, s, repo, environmentFixture(f.Environment(proj, "production")))

	current := baseline.Version
	desired := baseline
	desired.Slug = "production-current"
	desired.DisplayName = "Production Current"
	var updated store.Environment
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
	if updated.Slug != "production-current" || updated.DisplayName != "Production Current" {
		t.Errorf("Update returned %+v, want slug=production-current display_name=Production Current", updated)
	}
}

// TestEnvironmentRepositoryScheduleDeletionBumpsVersionAndPreservesIdentity
// proves a successful ScheduleDeletion bumps version by exactly one,
// refreshes updated_at, preserves created_at, preserves the row's identity
// fields (slug, display_name, kind — scheduling a deletion is a soft-delete
// stamp, not a rename or re-classification), and stamps
// deletion_scheduled_at at or after baseline.UpdatedAt. The "version +
// updated_at both move" property is the same dual-anchor every other
// mutation is held to — scheduling a deletion is just another UPDATE
// statement and the trigger must treat it identically. The baseline
// stamp-only behavior is partially covered by
// TestEnvironmentRepositoryScheduleDeletion in environment_delete_test.go;
// this case adds the dual-anchor and identity-preservation proofs that
// file did not assert.
func TestEnvironmentRepositoryScheduleDeletionBumpsVersionAndPreservesIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvInvSchedDelAcme")
	proj := seedProject(t, db, f, org, "Web")
	baseline := insertEnvironment(ctx, t, s, repo, environmentFixture(f.Environment(proj, "production")))
	if baseline.DeletionScheduledAt != nil {
		t.Fatalf("baseline DeletionScheduledAt = %v, want nil on a freshly inserted row", baseline.DeletionScheduledAt)
	}

	time.Sleep(time.Millisecond)

	var scheduled store.Environment
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
	// Identity fields must be preserved — ScheduleDeletion is a
	// soft-delete stamp, not a rename or re-classification, and the
	// composite tenant key is structural so it must not move either.
	if scheduled.Slug != baseline.Slug ||
		scheduled.DisplayName != baseline.DisplayName ||
		scheduled.Kind != baseline.Kind {
		t.Errorf("ScheduleDeletion mutated identity fields: baseline=%+v, after=%+v", baseline, scheduled)
	}
	if scheduled.OrganizationID != baseline.OrganizationID || scheduled.ProjectID != baseline.ProjectID {
		t.Errorf("ScheduleDeletion mutated tenant key: baseline=%+v, after=%+v", baseline, scheduled)
	}
}

// TestEnvironmentRepositoryInsertRollsBackOnTxRollback proves that an
// Insert whose outer Write returns a non-nil error rolls the row back —
// the transaction is the unit of work, and no half-written environment
// can survive an aborted audit/policy/quota step that runs alongside it.
// A future refactor that switched Insert to a SAVEPOINT or autonomous
// transaction would let the row escape the rollback and this test would
// catch it.
func TestEnvironmentRepositoryInsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvInvRollbackAcme")
	proj := seedProject(t, db, f, org, "Web")
	built := environmentFixture(f.Environment(proj, "production"))

	// Insert succeeds inside the tx, but the closure returns an error, so
	// the entire transaction is rolled back.
	bailout := environmentTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, insErr := repo.Insert(ctx, tx, built); insErr != nil {
			return insErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	// The row must not exist outside the rolled-back transaction —
	// GetByID must surface NotFound.
	getErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, rerr := repo.GetByID(ctx, q, org.ID, built.ID)
		return rerr
	})
	if ye := yerr.From(getErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(rolled-back environment) = %v, want NotFound", getErr)
	}

	// And the list view from the owning project must not see it either —
	// the row is gone everywhere, not just behind the by-id path.
	var listed []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listed, listErr = repo.ListByProject(ctx, q, org.ID, proj.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByProject(after rollback): %v", err)
	}
	for _, e := range listed {
		if e.ID == built.ID {
			t.Fatalf("ListByProject still sees rolled-back environment %q", built.ID)
		}
	}
}

// environmentTxRollbackSentinel is a typed error a transaction closure
// can return to force a rollback in
// TestEnvironmentRepositoryInsertRollsBackOnTxRollback. It is local to
// this test file so callers cannot rely on its identity — every *_test.go
// file under internal/controlplane/store/ shares the same store_test
// package, so the type name is intentionally distinct from
// api_key_repository_invariants_test.go's apiKeyTxRollbackSentinel,
// api_key_scope_repository_invariants_test.go's
// apiKeyScopeTxRollbackSentinel, membership_repository_invariants_test.go's
// membershipTxRollbackSentinel,
// serviceaccount_repository_invariants_test.go's
// serviceAccountTxRollbackSentinel, project_repository_invariants_test.go's
// projectTxRollbackSentinel, and user_repository_invariants_test.go's
// errSentinel to avoid a collision.
type environmentTxRollbackSentinel struct{}

func (environmentTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this environment transaction"
}

// TestEnvironmentRepositoryInsertRejectsNilTx proves the repository's
// nil-Tx guard on Insert renders a typed apierr.Internal — never a
// nil-pointer panic — when a caller wires the unit of work wrong. The
// Update and ScheduleDeletion nil-Tx guards are already covered by
// TestEnvironmentRepoUpdateRejectsNilTx (environment_update_test.go) and
// TestEnvironmentRepositoryScheduleDeletionRejectsNilTx
// (environment_delete_test.go); Insert is the one mutation path that did
// not yet have a typed-code assertion, so this case closes the matrix.
func TestEnvironmentRepositoryInsertRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewEnvironmentRepository()

	_, err := repo.Insert(context.Background(), nil, store.Environment{
		ID:             "env_irrelevant",
		OrganizationID: "org_irrelevant",
		ProjectID:      "prj_irrelevant",
		Slug:           "irrelevant",
		DisplayName:    "Irrelevant",
		Kind:           store.EnvironmentKindStandard,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Insert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
