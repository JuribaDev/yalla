package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for ServiceAccountRepository's CRUD invariants (BE-0431).
// The repository's tenant-scoping contract (Get / ListByOrganization filter by
// organization_id before id) and slug-uniqueness conflict mapping are proved
// in serviceaccount_test.go alongside the ServiceAccountService unit-of-work
// tests. What this file proves are the row-shape and lifecycle invariants the
// service_accounts table owes its callers regardless of who else is around:
//
//   - Insert returns the row the database actually committed: created_at and
//     updated_at are non-zero and equal on a fresh row (no UPDATE has fired
//     yet, so the service_accounts_set_updated_at trigger has not run),
//     disabled_at is nil (a freshly minted service account is live, not
//     parked), and the slug / display_name round-trip from the input.
//   - Disable refreshes updated_at via the BEFORE UPDATE trigger and
//     preserves created_at — the same dual-anchor lifecycle assertion every
//     other domain table's mutation must honor. The idempotent-disable
//     semantics (COALESCE keeps the first disable timestamp) are anchored
//     separately in serviceaccount_test.go's
//     TestServiceAccountRepositoryDisableIsIdempotentAndTenantScoped; this
//     file anchors the timestamp pair so a future refactor that dropped the
//     trigger does not silently freeze updated_at while keeping every other
//     contract.
//   - Insert rolls back when the surrounding Write closure returns a non-nil
//     error: the transaction is the unit of work, and no half-written
//     service account can survive an aborted audit/policy step that runs
//     alongside it.
//   - The Insert / Disable guards against a nil *Tx argument render a typed
//     apierr.Internal — never a nil-pointer panic — so a caller that
//     forgets to open a write transaction is caught by the typed-error
//     contract instead of by SIGSEGV.
//
// Repository tenant isolation (cross-tenant Disable, cross-tenant Get, etc.)
// is the subject of BE-0432 and lives in serviceaccount_tenant_isolation_test.go.
//
// The database-backed cases run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// nil-tx guard tests are pure unit tests and require no database.

// TestServiceAccountRepositoryInsertReturnsRowWithTimestamps proves Insert
// returns the row the table actually committed: created_at and updated_at
// are both non-zero and equal to each other (no UPDATE has fired yet, so
// the service_accounts_set_updated_at trigger has not run), disabled_at is
// nil (a freshly minted service account is live), and the input slug /
// display_name are echoed back.
func TestServiceAccountRepositoryInsertReturnsRowWithTimestamps(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	built := f.ServiceAccount(org, "CI Deployer")

	created := insertServiceAccount(ctx, t, s, repo, store.ServiceAccount{
		ID:             built.ID,
		OrganizationID: built.OrganizationID,
		Slug:           built.Slug,
		DisplayName:    built.Name,
	})

	if created.ID != built.ID || created.OrganizationID != built.OrganizationID {
		t.Errorf("Insert returned %+v, want id/org from %+v", created, built)
	}
	if created.Slug != built.Slug {
		t.Errorf("Insert slug = %q, want %q", created.Slug, built.Slug)
	}
	if created.DisplayName != built.Name {
		t.Errorf("Insert display_name = %q, want %q", created.DisplayName, built.Name)
	}
	if created.DisabledAt != nil {
		t.Errorf("Insert disabled_at = %v, want nil (a freshly minted service account is live)", *created.DisabledAt)
	}
	if created.IsDisabled() {
		t.Error("Insert returned a service account where IsDisabled() reports true")
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
	var got store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, built.ID)
		return err
	}); err != nil {
		t.Fatalf("after-Insert Get returned %v, want nil", err)
	}
	if got.ID != created.ID ||
		got.OrganizationID != created.OrganizationID ||
		got.Slug != created.Slug ||
		got.DisplayName != created.DisplayName ||
		!got.CreatedAt.Equal(created.CreatedAt) ||
		!got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("Get after Insert = %+v, want byte-identical to Insert return %+v", got, created)
	}
	if got.DisabledAt != nil {
		t.Errorf("Get after Insert disabled_at = %v, want nil", *got.DisabledAt)
	}
}

// TestServiceAccountRepositoryDisableRefreshesUpdatedAtAndPreservesCreatedAt
// proves the BEFORE UPDATE trigger fires on a Disable: created_at is
// untouched, updated_at moves forward, and disabled_at is set. The
// idempotent-COALESCE behavior on a second Disable is anchored elsewhere;
// this test anchors the dual-anchor timestamp pair specifically.
func TestServiceAccountRepositoryDisableRefreshesUpdatedAtAndPreservesCreatedAt(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	built := f.ServiceAccount(org, "CI")
	created := insertServiceAccount(ctx, t, s, repo, store.ServiceAccount{
		ID:             built.ID,
		OrganizationID: built.OrganizationID,
		Slug:           built.Slug,
		DisplayName:    built.Name,
	})

	// Sleep a hair so the trigger's clock advances past created_at on
	// systems with coarse time resolution; the assertion below is "at or
	// after", so this is paranoia, not load-bearing.
	time.Sleep(time.Millisecond)

	disabledAt := time.Now().UTC()
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Disable(ctx, tx, org.ID, built.ID, disabledAt)
	}); err != nil {
		t.Fatalf("Disable returned %v, want nil", err)
	}

	var after store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		after, err = repo.Get(ctx, q, org.ID, built.ID)
		return err
	}); err != nil {
		t.Fatalf("post-Disable Get returned %v, want nil", err)
	}

	if !after.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("Disable mutated created_at: was %v, now %v", created.CreatedAt, after.CreatedAt)
	}
	if !after.UpdatedAt.After(created.UpdatedAt) {
		t.Errorf("Disable updated_at = %v, want > Insert updated_at %v (the BEFORE UPDATE trigger must refresh it)",
			after.UpdatedAt, created.UpdatedAt)
	}
	if after.DisabledAt == nil {
		t.Fatal("post-Disable disabled_at is nil, want a timestamp")
	}
	if !after.IsDisabled() {
		t.Error("post-Disable IsDisabled() = false, want true")
	}
}

// TestServiceAccountRepositoryInsertRollsBackOnTxRollback proves that an
// Insert whose outer Write returns a non-nil error rolls the row back —
// the transaction is the unit of work, and no half-written service account
// can survive an aborted audit/policy step that runs alongside it.
func TestServiceAccountRepositoryInsertRollsBackOnTxRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	built := f.ServiceAccount(org, "CI")

	// Insert succeeds inside the tx, but the closure returns an error, so
	// the entire transaction is rolled back.
	bailout := serviceAccountTxRollbackSentinel{}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, insErr := repo.Insert(ctx, tx, store.ServiceAccount{
			ID:             built.ID,
			OrganizationID: built.OrganizationID,
			Slug:           built.Slug,
			DisplayName:    built.Name,
		}); insErr != nil {
			return insErr
		}
		return bailout
	})
	if err == nil {
		t.Fatal("Write returned nil, want the closure's sentinel error")
	}

	// The row must not exist outside the rolled-back transaction.
	getErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, rerr := repo.Get(ctx, q, org.ID, built.ID)
		return rerr
	})
	if ye := yerr.From(getErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(rolled-back service account) = %v, want NotFound", getErr)
	}

	// The CountByOrganization read is the one the quota layer uses to gate
	// new service accounts; a rolled-back Insert must not inflate it.
	var n int
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rerr error
		n, rerr = repo.CountByOrganization(ctx, q, org.ID)
		return rerr
	}); err != nil {
		t.Fatalf("CountByOrganization: %v", err)
	}
	if n != 0 {
		t.Errorf("CountByOrganization after rolled-back Insert = %d, want 0", n)
	}
}

// serviceAccountTxRollbackSentinel is a typed error a transaction closure
// can return to force a rollback in
// TestServiceAccountRepositoryInsertRollsBackOnTxRollback. It is local to
// this test file so callers cannot rely on its identity — every *_test.go
// file under internal/controlplane/store/ shares the same store_test
// package, so the type name is intentionally distinct from
// user_repository_invariants_test.go's errSentinel and
// membership_repository_invariants_test.go's membershipTxRollbackSentinel
// to avoid a collision.
type serviceAccountTxRollbackSentinel struct{}

func (serviceAccountTxRollbackSentinel) Error() string {
	return "test sentinel: roll back this service account transaction"
}

// TestServiceAccountRepositoryInsertWithoutTxIsTypedInternal proves the
// repository's nil-Tx guard renders a typed apierr.Internal — never a
// nil-pointer panic — when a caller wires the unit of work wrong.
func TestServiceAccountRepositoryInsertWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceAccountRepository()

	_, err := repo.Insert(context.Background(), nil, store.ServiceAccount{
		ID:             "sa_irrelevant",
		OrganizationID: "org_irrelevant",
		Slug:           "ci",
		DisplayName:    "Irrelevant",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Insert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestServiceAccountRepositoryDisableWithoutTxIsTypedInternal: same guard,
// Disable path.
func TestServiceAccountRepositoryDisableWithoutTxIsTypedInternal(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceAccountRepository()

	err := repo.Disable(context.Background(), nil, "org_irrelevant", "sa_irrelevant", time.Now().UTC())
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Disable(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
