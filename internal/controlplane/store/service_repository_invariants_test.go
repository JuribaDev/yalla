package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for ServiceRepository's own CRUD invariants (BE-0445).
// The repository's tenant-scoping contract (Get / ListByEnvironment /
// Update / ScheduleDeletion / Restore filter by organization_id before
// id), slug uniqueness conflict mapping inside an environment, and
// optimistic-concurrency classifyServiceConcurrencyMiss path on Update
// are proved in service_test.go / service_restore_test.go alongside the
// ServiceRepository unit-of-work tests. The Restore nil-Tx guard is
// anchored by TestServiceRepositoryRestoreRejectsNilTx
// (service_restore_test.go). What this file proves are the row-shape
// and lifecycle invariants the services table owes its callers
// regardless of who else is around:
//
//   - Insert returns the row at version 1, with database-assigned
//     timestamps where created_at and updated_at agree byte-for-byte
//     (no UPDATE has fired yet, so the services_bump_version trigger
//     has not run), and with deletion_scheduled_at unset.
//   - Update bumps the row's version by exactly one and refreshes
//     updated_at while preserving created_at. The "version + updated_at
//     both advance, created_at does not" dual-anchor is the property a
//     missing WHERE clause or a forgotten trigger would silently
//     violate. Kind, organization_id, project_id, and environment_id
//     are preserved — Update is a slug/display_name PATCH, not a
//     re-parenting or a re-classification (the Dokploy service
//     taxonomy is immutable once provisioning has started).
//   - Update with a matching If-Match version succeeds — the positive
//     companion to the stale-If-Match conflict path covered elsewhere.
//   - ScheduleDeletion bumps version, refreshes updated_at, preserves
//     created_at, preserves identity fields (slug, display_name, kind),
//     preserves the composite (organization_id, project_id,
//     environment_id) tenant key, and stamps deletion_scheduled_at on
//     or after the update boundary.
//   - Restore bumps version, refreshes updated_at, preserves
//     created_at, preserves identity fields, preserves the composite
//     tenant key, and clears deletion_scheduled_at back to NULL — the
//     inverse of ScheduleDeletion projected through the same dual
//     anchor. A regression that forgot the `SET deletion_scheduled_at
//     = NULL` clause would still pass the version / updated_at
//     anchors — the trigger fires on any UPDATE — so the
//     "deletion_scheduled_at is nil after Restore" assertion is the
//     load-bearing one for this path.
//   - Insert participates in the surrounding transaction as the unit
//     of work: a closure that succeeds in writing the row but returns
//     an error must leave no row behind, so an audit/policy/quota
//     step that fails alongside an Insert cannot leak a half-created
//     service.
//   - The Insert, Update, and ScheduleDeletion nil-Tx guards render a
//     typed apierr.Internal so a caller that wires the unit of work
//     wrong is caught by the typed-error contract instead of by a
//     nil-pointer panic. The Restore nil-Tx guard is already covered
//     in service_restore_test.go; these cases close the matrix for
//     the remaining three mutation paths.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset.
// The nil-tx guard tests are pure unit tests and require no database.

// serviceFixture lifts a testutil.Service into the store.Service shape
// the ServiceRepository accepts. Kind is carried through verbatim from
// the testutil fixture (which defaults to ServiceKindApplication, the
// most common member of the Dokploy taxonomy enforced by the kind
// CHECK constraint in migration 0002).
func serviceFixture(svc testutil.Service) store.Service {
	return store.Service{
		ID:             svc.ID,
		OrganizationID: svc.OrganizationID,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		Slug:           svc.Slug,
		DisplayName:    svc.Name,
		Kind:           svc.Kind,
	}
}

// insertService persists svc through Store.Write and returns the stored
// row, including the database-assigned timestamps and the initial
// version. Tests use this to seed a baseline before exercising Update,
// ScheduleDeletion, or Restore, so the baseline carries the same
// trigger-managed shape that production INSERTs commit. This wraps the
// repository's own Insert path (not the raw-SQL seedService helper
// from schema_test.go) so the baseline reflects exactly what the
// production code path writes.
func insertService(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceRepository, svc store.Service) store.Service {
	t.Helper()
	var stored store.Service
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, svc)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("insert service: %v", err)
	}
	return stored
}

// TestServiceRepositoryInsertReturnsRowAtVersion1WithTimestamps proves
// Insert returns the row the table actually committed: version starts
// at 1 (the optimistic-concurrency baseline every caller is allowed to
// assume), created_at and updated_at are both non-zero AND byte-equal
// on the fresh row (no UPDATE has fired yet, so the
// services_bump_version trigger has not run), and
// deletion_scheduled_at is nil (a live service, not a scheduled one).
func TestServiceRepositoryInsertReturnsRowAtVersion1WithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcInvInsAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	built := serviceFixture(f.Service(env, "api"))

	var created store.Service
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
		created.EnvironmentID != built.EnvironmentID ||
		created.Slug != built.Slug ||
		created.DisplayName != built.DisplayName ||
		created.Kind != built.Kind {
		t.Errorf("Insert returned %+v, want id/org/project/env/slug/name/kind from %+v", created, built)
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

	// And the returned row must match what a subsequent Get reads
	// back — the source of truth is the database, not the in-memory
	// value Insert returned.
	var got store.Service
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

// TestServiceRepositoryUpdateBumpsVersionAndRefreshesUpdatedAt proves a
// successful Update advances version by exactly one (the
// services_bump_version trigger fired once, no more), refreshes
// updated_at to a value at or after the original — the same property
// the version trigger gives us, but projected through a different
// column, so a missing WHERE clause that avoids both anchors must be
// very lucky — and preserves created_at. Kind, organization_id,
// project_id, and environment_id are preserved (Update is a
// slug/display_name PATCH, not a re-parenting or re-classification);
// deletion_scheduled_at remains nil on a live row.
func TestServiceRepositoryUpdateBumpsVersionAndRefreshesUpdatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcInvUpdAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	baseline := insertService(ctx, t, s, repo, serviceFixture(f.Service(env, "api")))
	if baseline.Version != 1 {
		t.Fatalf("baseline Version = %d, want 1 on a freshly inserted row", baseline.Version)
	}

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at
	// or after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	desired := baseline
	desired.Slug = "api-v2"
	desired.DisplayName = "API v2"
	// Try to smuggle a re-classification through the desired row —
	// Update must ignore Kind in its SET clause and the persisted row
	// must keep the baseline kind.
	desired.Kind = testutil.ServiceKindDatabase
	var updated store.Service
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updated, writeErr = repo.Update(ctx, tx, desired, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}

	if updated.Slug != "api-v2" || updated.DisplayName != "API v2" {
		t.Errorf("Update returned %+v, want slug=api-v2 display_name=API v2", updated)
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
		t.Errorf("Update mutated kind: was %q, now %q (the SET clause must touch slug/display_name only — kind is immutable Dokploy taxonomy)", baseline.Kind, updated.Kind)
	}
	if updated.OrganizationID != baseline.OrganizationID ||
		updated.ProjectID != baseline.ProjectID ||
		updated.EnvironmentID != baseline.EnvironmentID {
		t.Errorf("Update mutated tenant key: baseline=%+v, after=%+v", baseline, updated)
	}
	if updated.DeletionScheduledAt != nil {
		t.Errorf("Update set deletion_scheduled_at=%v on a live row, want nil", updated.DeletionScheduledAt)
	}
}

// TestServiceRepositoryUpdateWithMatchingIfMatchSucceeds proves the
// positive side of the optimistic-concurrency contract: a caller that
// presents the row's current version in ifMatchVersion gets a
// successful Update, not a false ConflictStale. The stale-If-Match
// path runs through classifyServiceConcurrencyMiss and surfaces as
// apierr.ConflictStale carrying the row's authoritative version —
// covered indirectly through the higher-level service tests; this
// case anchors the happy path so a regression that always classified
// version-checked UPDATEs as stale would be caught here.
func TestServiceRepositoryUpdateWithMatchingIfMatchSucceeds(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcInvIfMatchAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	baseline := insertService(ctx, t, s, repo, serviceFixture(f.Service(env, "api")))

	current := baseline.Version
	desired := baseline
	desired.Slug = "api-current"
	desired.DisplayName = "API Current"
	var updated store.Service
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
	if updated.Slug != "api-current" || updated.DisplayName != "API Current" {
		t.Errorf("Update returned %+v, want slug=api-current display_name=API Current", updated)
	}
}

// TestServiceRepositoryScheduleDeletionBumpsVersionAndPreservesIdentity
// proves a successful ScheduleDeletion bumps version by exactly one,
// refreshes updated_at, preserves created_at, preserves the row's
// identity fields (slug, display_name, kind — scheduling a deletion
// is a soft-delete stamp, not a rename or a re-classification), and
// stamps deletion_scheduled_at at or after baseline.UpdatedAt. The
// "version + updated_at both move" property is the same dual-anchor
// every other mutation is held to — scheduling a deletion is just
// another UPDATE statement and the trigger must treat it identically.
// The composite (organization_id, project_id, environment_id) tenant
// key must also be preserved: ScheduleDeletion is a stamp on
// deletion_scheduled_at, never a re-parenting.
func TestServiceRepositoryScheduleDeletionBumpsVersionAndPreservesIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcInvSchedDelAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	baseline := insertService(ctx, t, s, repo, serviceFixture(f.Service(env, "api")))
	if baseline.DeletionScheduledAt != nil {
		t.Fatalf("baseline DeletionScheduledAt = %v, want nil on a freshly inserted row", baseline.DeletionScheduledAt)
	}

	time.Sleep(time.Millisecond)

	var scheduled store.Service
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
	// soft-delete stamp, not a rename or a re-classification, and the
	// composite tenant key is structural so it must not move either.
	if scheduled.Slug != baseline.Slug ||
		scheduled.DisplayName != baseline.DisplayName ||
		scheduled.Kind != baseline.Kind {
		t.Errorf("ScheduleDeletion mutated identity fields: baseline=%+v, after=%+v", baseline, scheduled)
	}
	if scheduled.OrganizationID != baseline.OrganizationID ||
		scheduled.ProjectID != baseline.ProjectID ||
		scheduled.EnvironmentID != baseline.EnvironmentID {
		t.Errorf("ScheduleDeletion mutated tenant key: baseline=%+v, after=%+v", baseline, scheduled)
	}
}

// TestServiceRepositoryRestoreBumpsVersionAndClearsDeletionScheduledAt
// proves a successful Restore is the inverse of ScheduleDeletion
// projected through the same dual-anchor: it bumps version by exactly
// one, refreshes updated_at, preserves created_at, preserves identity
// fields, preserves the composite (organization_id, project_id,
// environment_id) tenant key, and clears deletion_scheduled_at back
// to NULL. A regression that forgot the `SET deletion_scheduled_at =
// NULL` clause would still pass the version / updated_at anchors —
// the trigger fires on any UPDATE — so the "deletion_scheduled_at is
// nil after Restore" assertion is the load-bearing one for this path.
// The clear-stamp happy path is covered by TestServiceRepositoryRestore
// in service_restore_test.go; this case adds the dual-anchor and
// identity-preservation proofs that file did not assert.
func TestServiceRepositoryRestoreBumpsVersionAndClearsDeletionScheduledAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcInvRestoreAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	inserted := insertService(ctx, t, s, repo, serviceFixture(f.Service(env, "api")))

	// Schedule deletion first so Restore has a non-nil stamp to clear.
	var scheduled store.Service
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

	var restored store.Service
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
	// Identity fields must be preserved — Restore is a soft-delete
	// unstamp, not a rename or a re-classification.
	if restored.Slug != inserted.Slug ||
		restored.DisplayName != inserted.DisplayName ||
		restored.Kind != inserted.Kind {
		t.Errorf("Restore mutated identity fields: original=%+v, after=%+v", inserted, restored)
	}
	if restored.OrganizationID != inserted.OrganizationID ||
		restored.ProjectID != inserted.ProjectID ||
		restored.EnvironmentID != inserted.EnvironmentID {
		t.Errorf("Restore mutated tenant key: original=%+v, after=%+v", inserted, restored)
	}

	// And the returned row must match what a subsequent Get reads
	// back — the source of truth is the database, not the in-memory
	// value Restore returned.
	var got store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.GetByID(ctx, q, org.ID, inserted.ID)
		return err
	}); err != nil {
		t.Fatalf("GetByID(restored): %v", err)
	}
	if got.DeletionScheduledAt != nil {
		t.Errorf("GetByID after Restore: deletion_scheduled_at = %v, want nil", got.DeletionScheduledAt)
	}
	if got.Version != restored.Version {
		t.Errorf("GetByID after Restore: version = %d, want %d", got.Version, restored.Version)
	}
}

// TestServiceRepositoryInsertRollsBackOnTxRollback proves that an
// Insert whose outer Write returns a non-nil error rolls the row
// back — the transaction is the unit of work, and no half-written
// service can survive an aborted audit/policy/quota step that runs
// alongside it. A future refactor that switched Insert to a
// SAVEPOINT or autonomous transaction would let the row escape the
// rollback and this test would catch it.
func TestServiceRepositoryInsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcInvRollbackAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	built := serviceFixture(f.Service(env, "api"))

	// Insert succeeds inside the tx, but the closure returns an
	// error, so the entire transaction is rolled back.
	bailout := serviceTxRollbackSentinel{}
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
		t.Fatalf("GetByID(rolled-back service) = %v, want NotFound", getErr)
	}

	// And the list view from the owning environment must not see it
	// either — the row is gone everywhere, not just behind the by-id
	// path.
	var listed []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listed, listErr = repo.ListByEnvironment(ctx, q, org.ID, env.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(after rollback): %v", err)
	}
	for _, svc := range listed {
		if svc.ID == built.ID {
			t.Fatalf("ListByEnvironment still sees rolled-back service %q", built.ID)
		}
	}
}

// serviceTxRollbackSentinel is a typed error a transaction closure can
// return to force a rollback in
// TestServiceRepositoryInsertRollsBackOnTxRollback. It is local to
// this test file so callers cannot rely on its identity — every
// *_test.go file under internal/controlplane/store/ shares the same
// store_test package, so the type name is intentionally distinct from
// api_key_repository_invariants_test.go's apiKeyTxRollbackSentinel,
// api_key_scope_repository_invariants_test.go's
// apiKeyScopeTxRollbackSentinel,
// membership_repository_invariants_test.go's
// membershipTxRollbackSentinel,
// serviceaccount_repository_invariants_test.go's
// serviceAccountTxRollbackSentinel,
// project_repository_invariants_test.go's projectTxRollbackSentinel,
// environment_repository_invariants_test.go's
// environmentTxRollbackSentinel,
// environment_grant_repository_invariants_test.go's
// environmentGrantTxRollbackSentinel, and
// user_repository_invariants_test.go's errSentinel to avoid a
// collision.
type serviceTxRollbackSentinel struct{}

func (serviceTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this service transaction"
}

// TestServiceRepositoryInsertRejectsNilTx proves the repository's
// nil-Tx guard on Insert renders a typed apierr.Internal — never a
// nil-pointer panic — when a caller wires the unit of work wrong.
func TestServiceRepositoryInsertRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceRepository()

	_, err := repo.Insert(context.Background(), nil, store.Service{
		ID:             "svc_irrelevant",
		OrganizationID: "org_irrelevant",
		ProjectID:      "prj_irrelevant",
		EnvironmentID:  "env_irrelevant",
		Slug:           "irrelevant",
		DisplayName:    "Irrelevant",
		Kind:           testutil.ServiceKindApplication,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Insert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestServiceRepositoryUpdateRejectsNilTx proves the repository's
// nil-Tx guard on Update renders a typed apierr.Internal — never a
// nil-pointer panic — when a caller wires the unit of work wrong.
func TestServiceRepositoryUpdateRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceRepository()

	_, err := repo.Update(context.Background(), nil, store.Service{
		ID:             "svc_irrelevant",
		OrganizationID: "org_irrelevant",
		ProjectID:      "prj_irrelevant",
		EnvironmentID:  "env_irrelevant",
		Slug:           "irrelevant",
		DisplayName:    "Irrelevant",
		Kind:           testutil.ServiceKindApplication,
	}, nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Update(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestServiceRepositoryScheduleDeletionRejectsNilTx proves the
// repository's nil-Tx guard on ScheduleDeletion renders a typed
// apierr.Internal — never a nil-pointer panic — when a caller wires
// the unit of work wrong. The Restore nil-Tx guard is already covered
// by TestServiceRepositoryRestoreRejectsNilTx in
// service_restore_test.go; this case closes the matrix for the
// remaining mutation paths.
func TestServiceRepositoryScheduleDeletionRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceRepository()

	_, err := repo.ScheduleDeletion(context.Background(), nil, "org_irrelevant", "svc_irrelevant", nil)
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("ScheduleDeletion(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
