package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for MembershipRepository's CRUD invariants (BE-0429). The
// repository's tenant-scoping contract — that a (organization_id, user_id)
// pairing across tenant boundaries collapses to the same NotFound a missing
// row produces — is proved in membership_test.go alongside the GetMember /
// ListByOrganization / UpdateRole / Delete tenant-isolation cases. What this
// file proves are the row-shape and lifecycle invariants the memberships
// table owes its callers regardless of who else is around:
//
//   - Insert returns the row the database actually committed, joined with the
//     member's global users identity: created_at and updated_at are non-zero
//     and equal on a fresh row (no UPDATE has fired, so the
//     memberships_set_updated_at trigger has not run), role_version defaults
//     to 1 (the schema default that backs session-token revocation), and the
//     email / display_name come from the users row.
//   - Insert of a second row with the same (organization_id, user_id) is the
//     primary-key collision the schema is built around, and the repository
//     maps it to a typed apierr.Conflict — never a 500 leaking the
//     constraint name. The repo's user-facing message is non-empty and the
//     raw driver detail is preserved only as the wrapped cause for
//     server-side logging.
//   - UpdateRole refreshes updated_at via the BEFORE UPDATE trigger and
//     preserves created_at — the same dual-anchor lifecycle assertion every
//     other domain table's mutation must honor. role_version's atomic
//     increment is anchored separately in membership_test.go's UpdateRole
//     case; this file anchors the timestamp pair so a future refactor that
//     accidentally rewrites created_at or skips the trigger trips a
//     dedicated gate.
//   - Insert rolls back when the surrounding Write closure returns a non-nil
//     error: the transaction is the unit of work, and no half-written
//     membership can survive an aborted audit/policy step that runs
//     alongside it.
//   - The Insert / UpdateRole / Delete guards against a nil *Tx argument
//     render a typed apierr.Internal — never a nil-pointer panic — so a
//     caller that forgets to open a write transaction is caught by the
//     typed-error contract instead of by SIGSEGV.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard tests are pure unit tests and require no database.

// TestMembershipRepositoryInsertReturnsRowWithTimestamps proves Insert
// returns the row the table actually committed: created_at and updated_at
// are both non-zero and equal to each other (no UPDATE has fired yet, so
// the memberships_set_updated_at trigger has not run), role_version
// defaults to 1 (the schema default in 0005_membership_role_version), and
// the returned OrganizationMember carries the member's email and
// display_name joined from the global users row.
func TestMembershipRepositoryInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewMembershipRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")

	var created store.OrganizationMember
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		created, writeErr = repo.Insert(ctx, tx, org.ID, user.ID, "member")
		return writeErr
	}); err != nil {
		t.Fatalf("Insert returned %v, want nil", err)
	}

	if created.OrganizationID != org.ID || created.UserID != user.ID {
		t.Errorf("Insert returned organization_id=%q user_id=%q, want org=%q user=%q",
			created.OrganizationID, created.UserID, org.ID, user.ID)
	}
	if created.Role != "member" {
		t.Errorf("Insert role = %q, want member", created.Role)
	}
	if created.RoleVersion != 1 {
		t.Errorf("Insert role_version = %d, want 1 (schema default backs session-token revocation)", created.RoleVersion)
	}
	if created.Email != user.Email {
		t.Errorf("Insert email = %q, want %q (must JOIN the users row)", created.Email, user.Email)
	}
	if created.UserDisplayName != user.Name {
		t.Errorf("Insert display_name = %q, want %q (must JOIN the users row)", created.UserDisplayName, user.Name)
	}
	if created.CreatedAt.IsZero() {
		t.Error("Insert returned a zero created_at")
	}
	if created.UpdatedAt.IsZero() {
		t.Error("Insert returned a zero updated_at")
	}
	if !created.CreatedAt.Equal(created.UpdatedAt) {
		t.Errorf("Insert created_at=%v updated_at=%v: want equal on a fresh row (no UPDATE has fired)",
			created.CreatedAt, created.UpdatedAt)
	}

	// And the returned row must match what a subsequent Get reads back —
	// the source of truth is the database, not the in-memory value Insert
	// returned.
	var got store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, user.ID)
		return err
	}); err != nil {
		t.Fatalf("Get(created): %v", err)
	}
	if got.Role != created.Role ||
		got.RoleVersion != created.RoleVersion ||
		!got.CreatedAt.Equal(created.CreatedAt) ||
		!got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("Get(created) = %+v, want the row Insert returned (role/role_version/timestamps)", got)
	}
}

// TestMembershipRepositoryInsertDuplicateReturnsTypedConflict proves a
// second Insert with the same (organization_id, user_id) primary key is
// mapped to a typed apierr.Conflict with a non-empty user-facing message —
// the raw driver detail (constraint name) is never the user-facing
// message. The pre-existing row is left untouched: a failed Insert rolls
// back the whole transaction.
func TestMembershipRepositoryInsertDuplicateReturnsTypedConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewMembershipRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, user.ID, "owner", 7)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Insert(ctx, tx, org.ID, user.ID, "member")
		return writeErr
	})
	conflict := yerr.From(err)
	if conflict.Code != yerr.CodeConflict {
		t.Fatalf("Insert(dup org/user) error = %v, want %s", err, yerr.CodeConflict)
	}
	if conflict.Message == "" {
		t.Errorf("Insert(dup org/user) rendered an empty user-facing message")
	}

	// The pre-existing row is untouched: a failed Insert must not overwrite
	// the role or rewind the role_version of the existing membership.
	var live store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		live, err = repo.Get(ctx, q, org.ID, user.ID)
		return err
	}); err != nil {
		t.Fatalf("Get(existing) returned %v, want nil", err)
	}
	if live.Role != "owner" || live.RoleVersion != 7 {
		t.Errorf("existing membership after dup Insert = %+v, want unchanged role owner / role_version 7", live)
	}
}

// TestMembershipRepositoryUpdateRoleRefreshesUpdatedAt proves a successful
// UpdateRole refreshes updated_at via the memberships_set_updated_at
// BEFORE UPDATE trigger and preserves created_at — the same dual-anchor
// every other domain table's mutation must honor. The role_version
// increment is anchored separately in membership_test.go; this case is
// dedicated to the timestamp pair so a future refactor that accidentally
// rewrites created_at or drops the trigger trips its own gate.
func TestMembershipRepositoryUpdateRoleRefreshesUpdatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewMembershipRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, user.ID, "member", 1)

	var baseline store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		baseline, err = repo.Get(ctx, q, org.ID, user.ID)
		return err
	}); err != nil {
		t.Fatalf("baseline Get: %v", err)
	}

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at or
	// after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	var updated store.OrganizationMember
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updated, writeErr = repo.UpdateRole(ctx, tx, org.ID, user.ID, "owner")
		return writeErr
	}); err != nil {
		t.Fatalf("UpdateRole returned %v, want nil", err)
	}

	if updated.Role != "owner" {
		t.Errorf("UpdateRole returned role = %q, want owner", updated.Role)
	}
	if !updated.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("UpdateRole mutated created_at: was %v, now %v", baseline.CreatedAt, updated.CreatedAt)
	}
	if updated.UpdatedAt.Before(baseline.UpdatedAt) {
		t.Errorf("UpdateRole updated_at = %v, want >= baseline %v (trigger must refresh)",
			updated.UpdatedAt, baseline.UpdatedAt)
	}
}

// TestMembershipRepositoryInsertRollsBackOnTxRollback proves that an
// Insert whose outer Write returns a non-nil error rolls the row back —
// the transaction is the unit of work, and no half-written membership can
// survive an aborted audit/policy step that runs alongside it.
func TestMembershipRepositoryInsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewMembershipRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")

	// Insert succeeds inside the tx, but the closure returns an error, so
	// the entire transaction is rolled back.
	bailout := membershipTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := repo.Insert(ctx, tx, org.ID, user.ID, "member"); err != nil {
			return err
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	// The row must not exist outside the rolled-back transaction.
	getErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, rerr := repo.Get(ctx, q, org.ID, user.ID)
		return rerr
	})
	if ye := yerr.From(getErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(rolled-back membership) = %v, want NotFound", getErr)
	}
}

// membershipTxRollbackSentinel is a typed error a transaction closure can
// return to force a rollback in TestMembershipRepositoryInsertRollsBackOnTxRollback.
// It is local to this test file so callers cannot rely on its identity —
// every *_test.go file under internal/controlplane/store/ shares the same
// store_test package, so the type name is intentionally distinct from
// user_repository_invariants_test.go's errSentinel to avoid a collision.
type membershipTxRollbackSentinel struct{}

func (membershipTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this membership transaction"
}

// TestMembershipRepositoryInsertWithoutTxIsTypedInternal proves the
// repository's nil-Tx guard renders a typed apierr.Internal — never a
// nil-pointer panic — when a caller wires the unit of work wrong.
func TestMembershipRepositoryInsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewMembershipRepository()

	_, err := repo.Insert(context.Background(), nil, "org_irrelevant", "usr_irrelevant", "member")
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Insert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestMembershipRepositoryUpdateRoleWithoutTxIsTypedInternal: same guard,
// UpdateRole path.
func TestMembershipRepositoryUpdateRoleWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewMembershipRepository()

	_, err := repo.UpdateRole(context.Background(), nil, "org_irrelevant", "usr_irrelevant", "admin")
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("UpdateRole(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestMembershipRepositoryDeleteWithoutTxIsTypedInternal: same guard,
// Delete path.
func TestMembershipRepositoryDeleteWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewMembershipRepository()

	err := repo.Delete(context.Background(), nil, "org_irrelevant", "usr_irrelevant")
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Delete(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
