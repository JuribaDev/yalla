package store_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for MembershipRepository — the persistence layer for
// organization memberships and the role/revocation version that backs
// session-token revocation. They prove the tenant-scoped read, the schema
// default for role_version, the typed not-found result, and that a user id
// paired with the wrong organization can never reveal another tenant's
// membership. They run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.

// seedMembership inserts a memberships row joining userID to orgID with the
// given role and role version, using a direct INSERT.
func seedMembership(t *testing.T, db *testutil.DB, orgID, userID, role string, roleVersion int64) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO memberships (organization_id, user_id, role, role_version) VALUES ($1, $2, $3, $4)`,
		orgID, userID, role, roleVersion); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}

func TestMembershipRepositoryGet(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, userID, "admin", 4)

	var got store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, userID)
		return err
	}); err != nil {
		t.Fatalf("Get returned %v, want nil", err)
	}
	if got.OrganizationID != org.ID || got.UserID != userID {
		t.Errorf("Get returned %+v, want the membership of %q in %q", got, userID, org.ID)
	}
	if got.Role != "admin" || got.RoleVersion != 4 {
		t.Errorf("Get role/version = %q/%d, want admin/4", got.Role, got.RoleVersion)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("Get did not return the database-assigned timestamps")
	}
}

// TestMembershipRepositoryGetDefaultsRoleVersion proves the 0005 migration's
// DEFAULT 1: a membership inserted without an explicit role_version — the
// shape every pre-0005 insert path uses — still reads back with a valid
// starting version.
func TestMembershipRepositoryGetDefaultsRoleVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada")
	if _, err := db.Exec(ctx,
		`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')`,
		org.ID, userID); err != nil {
		t.Fatalf("seed membership without role_version: %v", err)
	}

	var got store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, org.ID, userID)
		return err
	}); err != nil {
		t.Fatalf("Get returned %v, want nil", err)
	}
	if got.RoleVersion != 1 {
		t.Errorf("RoleVersion = %d, want the schema default 1", got.RoleVersion)
	}
}

func TestMembershipRepositoryGetNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada") // the user exists, but has no membership row

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, org.ID, userID)
		return err
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get error = %v, want a typed E_NOT_FOUND", err)
	}
}

// TestMembershipRepositoryGetIsTenantScoped proves cross-tenant isolation: a
// user id from one organization, paired with another organization, must not
// reveal the first organization's membership.
func TestMembershipRepositoryGetIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "alpha")
	orgB := seedOrg(t, db, f, "beta")
	userID := seedUser(t, db, f, orgB, "ada")
	seedMembership(t, db, orgB.ID, userID, "owner", 2)

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, userID)
		return err
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Get error = %v, want E_NOT_FOUND — no membership leak", err)
	}
}
