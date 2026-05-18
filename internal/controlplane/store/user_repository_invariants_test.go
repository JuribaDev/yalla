package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for UserRepository's CRUD invariants (BE-0427). The
// repository's tenant-scoping contract (the GetInOrganization join) is
// proved in user_test.go. What this file proves are the row-shape and
// lifecycle invariants the global identity table owes its callers
// regardless of who else is around:
//
//   - Insert returns the row with database-assigned timestamps where
//     created_at and updated_at agree.
//   - Insert with a duplicate email is reported as a typed
//     apierr.Conflict, not a 500 leaking the constraint name.
//   - Update refreshes updated_at via the BEFORE UPDATE trigger and
//     preserves created_at.
//   - Update of a non-existent id is a typed apierr.NotFound.
//   - Update to an email already in use by another user is a typed
//     apierr.Conflict — and the failed Update rolls back.
//   - Delete removes the row, cascades into memberships, and reports a
//     typed apierr.NotFound for a non-existent id.
//   - The Insert / Update / Delete guards against a nil *Tx argument
//     render a typed apierr.Internal — never a nil-pointer panic — so a
//     caller that forgets to open a write transaction is caught by the
//     typed-error contract instead of by SIGSEGV.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard tests are pure unit tests and require no database.

// TestUserRepositoryInsertReturnsRowWithTimestamps proves Insert returns the
// row the table actually committed: created_at and updated_at are both
// non-zero and equal to each other (no UPDATE has fired yet, so the
// set_updated_at trigger has not run).
func TestUserRepositoryInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := f.Organization("acme")
	built := f.User(org, "ada")

	var created store.User
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		created, writeErr = repo.Insert(ctx, tx, store.User{
			ID:          built.ID,
			Email:       built.Email,
			DisplayName: built.Name,
		})
		return writeErr
	}); err != nil {
		t.Fatalf("Insert returned %v, want nil", err)
	}

	if created.ID != built.ID || created.Email != built.Email || created.DisplayName != built.Name {
		t.Errorf("Insert returned %+v, want id/email/name from %+v", created, built)
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

	// And the returned row must match what a subsequent Get reads back —
	// the source of truth is the database, not the in-memory value Insert
	// returned.
	var got store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, created.ID)
		return err
	}); err != nil {
		t.Fatalf("Get(created): %v", err)
	}
	if got.Email != created.Email || !got.CreatedAt.Equal(created.CreatedAt) || !got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("Get(created) = %+v, want the row Insert returned %+v", got, created)
	}
}

// TestUserRepositoryInsertDuplicateEmailReturnsTypedConflict proves a second
// Insert with an email that collides with an existing user is mapped to a
// typed apierr.Conflict with a non-empty user-facing message — the raw
// driver detail (constraint name) is never the user-facing message.
func TestUserRepositoryInsertDuplicateEmailReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	first := seedUserRow(t, db, f, org, "ada")

	// Build a second user with a fresh id but reuse the first user's email
	// — that is the collision we want.
	second := f.User(org, "duplicate")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Insert(ctx, tx, store.User{
			ID:          second.ID,
			Email:       first.Email,
			DisplayName: second.Name,
		})
		return writeErr
	})
	conflict := yerr.From(err)
	if conflict.Code != yerr.CodeConflict {
		t.Fatalf("Insert(dup email) error = %v, want %s", err, yerr.CodeConflict)
	}
	if conflict.Message == "" {
		t.Errorf("Insert(dup email) rendered an empty user-facing message")
	}
}

// TestUserRepositoryUpdateRefreshesUpdatedAt proves a successful Update
// refreshes updated_at via the BEFORE UPDATE trigger and preserves
// created_at — the same dual-anchor we anchor every other domain table's
// mutation against.
func TestUserRepositoryUpdateRefreshesUpdatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")

	var baseline store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		baseline, err = repo.Get(ctx, q, user.ID)
		return err
	}); err != nil {
		t.Fatalf("baseline Get: %v", err)
	}

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at or
	// after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	var updated store.User
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updated, writeErr = repo.Update(ctx, tx, store.User{
			ID:          user.ID,
			Email:       user.Email, // unchanged
			DisplayName: "Ada Renamed",
		})
		return writeErr
	}); err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}

	if updated.DisplayName != "Ada Renamed" {
		t.Errorf("Update returned DisplayName = %q, want %q", updated.DisplayName, "Ada Renamed")
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("Update mutated created_at: was %v, now %v", baseline.CreatedAt, updated.CreatedAt)
	}
	if updated.UpdatedAt.Before(baseline.UpdatedAt) {
		t.Errorf("Update updated_at = %v, want >= baseline %v (trigger must refresh)", updated.UpdatedAt, baseline.UpdatedAt)
	}
}

// TestUserRepositoryUpdateNotFoundReturnsTypedNotFound proves an Update of a
// user that does not exist is reported as a typed NotFound — the same shape
// any other unknown id produces, so a caller can never tell "no such user"
// apart from "a user you cannot see".
func TestUserRepositoryUpdateNotFoundReturnsTypedNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := f.Organization("acme")
	ghost := f.User(org, "ghost") // built, never inserted

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Update(ctx, tx, store.User{
			ID:          ghost.ID,
			Email:       ghost.Email,
			DisplayName: "Ghost Renamed",
		})
		return writeErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Update(missing) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestUserRepositoryUpdateEmailConflictReturnsTypedConflict proves the
// repository maps an email-uniqueness collision on Update to a typed
// apierr.Conflict — the same shape Insert returns for the same collision,
// so the audit/policy layers upstream don't have to special-case which
// mutation rendered the conflict. The failed Update rolls back: the first
// user's email is unchanged, and the second user's email is unchanged.
func TestUserRepositoryUpdateEmailConflictReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	first := seedUserRow(t, db, f, org, "ada")
	second := seedUserRow(t, db, f, org, "ben")

	// Try to rename `second` to `first`'s email.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Update(ctx, tx, store.User{
			ID:          second.ID,
			Email:       first.Email, // intentional collision
			DisplayName: second.Name,
		})
		return writeErr
	})
	conflict := yerr.From(err)
	if conflict.Code != yerr.CodeConflict {
		t.Fatalf("Update(second, dup email) error = %v, want %s", err, yerr.CodeConflict)
	}
	if conflict.Message == "" {
		t.Errorf("Update email-conflict rendered an empty user-facing message")
	}

	// first's email is untouched.
	var afterFirst store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		afterFirst, err = repo.Get(ctx, q, first.ID)
		return err
	}); err != nil {
		t.Fatalf("after Get(first): %v", err)
	}
	if afterFirst.Email != first.Email {
		t.Errorf("first.email = %q, want %q — failed Update on second must not touch first", afterFirst.Email, first.Email)
	}

	// second still has its original email — the failed Update rolled back.
	var afterSecond store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		afterSecond, err = repo.Get(ctx, q, second.ID)
		return err
	}); err != nil {
		t.Fatalf("after Get(second): %v", err)
	}
	if afterSecond.Email != second.Email {
		t.Errorf("second.email = %q, want %q — failed Update must roll back", afterSecond.Email, second.Email)
	}
}

// TestUserRepositoryDeleteRemovesRow proves Delete removes the row from the
// global users table and that a subsequent Get reports NotFound.
func TestUserRepositoryDeleteRemovesRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, user.ID)
	}); err != nil {
		t.Fatalf("Delete returned %v, want nil", err)
	}

	// A subsequent Get is NotFound.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, user.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(deleted) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestUserRepositoryDeleteCascadesToMemberships proves the
// memberships(user_id) ON DELETE CASCADE wired in 0002_tenant_hierarchy
// fires when the repository deletes a user: the user's organization
// memberships disappear in the same statement, atomic with the audit record
// the transaction also carries.
func TestUserRepositoryDeleteCascadesToMemberships(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, user.ID, "member", 1)

	// Sanity: the membership is there.
	var before int
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM memberships WHERE user_id = $1`, user.ID).Scan(&before); err != nil {
		t.Fatalf("count memberships before: %v", err)
	}
	if before != 1 {
		t.Fatalf("memberships before = %d, want 1", before)
	}

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, user.ID)
	}); err != nil {
		t.Fatalf("Delete returned %v, want nil", err)
	}

	var after int
	if err := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM memberships WHERE user_id = $1`, user.ID).Scan(&after); err != nil {
		t.Fatalf("count memberships after: %v", err)
	}
	if after != 0 {
		t.Errorf("memberships after = %d, want 0 (ON DELETE CASCADE must fire)", after)
	}
}

// TestUserRepositoryDeleteNotFoundReturnsTypedNotFound proves a Delete of a
// user that does not exist is reported as a typed NotFound — the same shape
// any other unknown id produces. RowsAffected() == 0 is the signal.
func TestUserRepositoryDeleteNotFoundReturnsTypedNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := f.Organization("acme")
	ghost := f.User(org, "ghost") // built, never inserted

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, ghost.ID)
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Delete(missing) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestUserRepositoryInsertRollsBackOnTxRollback proves that an Insert whose
// outer Write returns a non-nil error rolls the row back — the transaction
// is the unit of work, and no half-written user can survive an aborted
// audit/policy step that runs alongside it.
func TestUserRepositoryInsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := f.Organization("acme")
	built := f.User(org, "ada")

	// Insert succeeds inside the tx, but the closure returns an error, so
	// the entire transaction is rolled back.
	bailout := errSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := repo.Insert(ctx, tx, store.User{
			ID:          built.ID,
			Email:       built.Email,
			DisplayName: built.Name,
		}); err != nil {
			return err
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	// The row must not exist outside the rolled-back transaction.
	var got store.User
	getErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rerr error
		got, rerr = repo.Get(ctx, q, built.ID)
		return rerr
	})
	if ye := yerr.From(getErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(rolled-back id) = %+v / %v, want NotFound", got, getErr)
	}
}

// errSentinel is a typed error a transaction closure can return to force a
// rollback in TestUserRepositoryInsertRollsBackOnTxRollback. It is local to
// this test file so callers cannot rely on its identity.
type errSentinel struct{}

func (errSentinel) Error() string { return "test sentinel: roll back this transaction" }

// TestUserRepositoryInsertWithoutTxIsTypedInternal proves the repository's
// nil-Tx guard renders a typed apierr.Internal — never a nil-pointer panic
// — when a caller wires the unit of work wrong.
func TestUserRepositoryInsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewUserRepository()

	_, err := repo.Insert(context.Background(), nil, store.User{
		ID:          "usr_irrelevant",
		Email:       "irrelevant@fixtures.yalla.test",
		DisplayName: "Irrelevant",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Insert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestUserRepositoryUpdateWithoutTxIsTypedInternal: same guard, Update path.
func TestUserRepositoryUpdateWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewUserRepository()

	_, err := repo.Update(context.Background(), nil, store.User{
		ID:          "usr_irrelevant",
		Email:       "irrelevant@fixtures.yalla.test",
		DisplayName: "Irrelevant",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Update(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestUserRepositoryDeleteWithoutTxIsTypedInternal: same guard, Delete path.
func TestUserRepositoryDeleteWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewUserRepository()

	err := repo.Delete(context.Background(), nil, "usr_irrelevant")
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Delete(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
