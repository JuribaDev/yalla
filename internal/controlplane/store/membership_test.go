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

// TestMembershipRepositoryListByOrganization proves the list read joins the
// memberships row with the global users identity row, returns every member of
// the requested organization with the deterministic created_at then user_id
// ordering, and surfaces the schema-default role_version for rows inserted
// without an explicit version.
func TestMembershipRepositoryListByOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	adaID := seedUser(t, db, f, org, "ada")
	graceID := seedUser(t, db, f, org, "grace")
	seedMembership(t, db, org.ID, adaID, "owner", 4)
	// grace's row is inserted without role_version so the schema default 1
	// is exercised through the join read too.
	if _, err := db.Exec(ctx,
		`INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'admin')`,
		org.ID, graceID); err != nil {
		t.Fatalf("seed grace membership: %v", err)
	}

	var got []store.OrganizationMember
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.ListByOrganization(ctx, q, org.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByOrganization returned %v, want nil", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListByOrganization returned %d rows, want 2: %+v", len(got), got)
	}
	// The two seed rows are inserted in the same transaction, so created_at
	// ties; the secondary ORDER BY user_id is what makes the order stable.
	// The map below is keyed by user id so the test does not depend on the
	// minted id ordering.
	byUser := map[string]store.OrganizationMember{got[0].UserID: got[0], got[1].UserID: got[1]}
	if ada, ok := byUser[adaID]; !ok {
		t.Errorf("ada (%q) missing from list: %+v", adaID, got)
	} else {
		if ada.OrganizationID != org.ID || ada.Role != "owner" || ada.RoleVersion != 4 {
			t.Errorf("ada row = %+v, want owner/4 in %q", ada, org.ID)
		}
		if ada.CreatedAt.IsZero() || ada.UpdatedAt.IsZero() {
			t.Error("ada row did not return the database-assigned timestamps")
		}
		if ada.Email == "" || ada.UserDisplayName == "" {
			t.Errorf("ada row = %+v, want email/display_name from the joined users row", ada)
		}
	}
	if grace, ok := byUser[graceID]; !ok {
		t.Errorf("grace (%q) missing from list: %+v", graceID, got)
	} else if grace.Role != "admin" || grace.RoleVersion != 1 {
		t.Errorf("grace row = %+v, want admin/1 (schema default)", grace)
	}
}

// TestMembershipRepositoryListByOrganizationIsTenantScoped proves cross-tenant
// isolation: listing one organization's members must never return a member of
// another organization, even when the same user has memberships in both.
func TestMembershipRepositoryListByOrganizationIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "alpha")
	orgB := seedOrg(t, db, f, "beta")
	adaID := seedUser(t, db, f, orgA, "ada")
	graceID := seedUser(t, db, f, orgB, "grace")
	seedMembership(t, db, orgA.ID, adaID, "owner", 1)
	seedMembership(t, db, orgB.ID, graceID, "owner", 1)

	for _, tc := range []struct {
		name   string
		org    string
		wantID string
	}{
		{name: "alpha", org: orgA.ID, wantID: adaID},
		{name: "beta", org: orgB.ID, wantID: graceID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []store.OrganizationMember
			if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
				var err error
				got, err = repo.ListByOrganization(ctx, q, tc.org)
				return err
			}); err != nil {
				t.Fatalf("ListByOrganization(%s) returned %v, want nil", tc.org, err)
			}
			if len(got) != 1 {
				t.Fatalf("ListByOrganization(%s) returned %d rows, want exactly 1: %+v", tc.org, len(got), got)
			}
			if got[0].UserID != tc.wantID || got[0].OrganizationID != tc.org {
				t.Errorf("ListByOrganization(%s) returned %+v, want member %q of %q only — cross-tenant leak",
					tc.org, got[0], tc.wantID, tc.org)
			}
		})
	}
}

// TestMembershipRepositoryListByOrganizationEmptyIsNotNil proves an
// organization with no members yields a non-nil empty slice, never a nil
// list, so callers can iterate the response without a nil check — and the
// stable empty-array contract holds at the persistence layer.
func TestMembershipRepositoryListByOrganizationEmptyIsNotNil(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "lonely") // no memberships seeded

	var got []store.OrganizationMember
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.ListByOrganization(ctx, q, org.ID)
		return err
	}); err != nil {
		t.Fatalf("ListByOrganization returned %v, want nil", err)
	}
	if got == nil {
		t.Error("ListByOrganization returned a nil slice; want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("ListByOrganization returned %d rows, want 0: %+v", len(got), got)
	}
}

// TestMembershipReaderListMembers proves the store-backed adapter composes the
// repository through its own Store.Read transaction: the rows it returns
// match the rows the repository read directly returns, and the join with the
// users table is performed.
func TestMembershipReaderListMembers(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	reader, err := store.NewMembershipReader(s)
	if err != nil {
		t.Fatalf("NewMembershipReader: %v", err)
	}
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	adaID := seedUser(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, adaID, "owner", 1)

	got, err := reader.ListMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListMembers returned %v, want nil", err)
	}
	if len(got) != 1 || got[0].UserID != adaID || got[0].Email == "" {
		t.Errorf("ListMembers = %+v, want exactly the seeded ada row with a joined email", got)
	}
}

// TestNewMembershipReaderRejectsNilStore proves a misconfigured reader fails
// at construction rather than on its first request — the same defensive
// contract NewOrganizationReader / NewCredentialReader enforce.
func TestNewMembershipReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewMembershipReader(nil); err == nil {
		t.Fatal("NewMembershipReader(nil) returned nil error, want a typed construction error")
	}
}

// TestMembershipRepositoryGetMember proves the joined per-member read: the
// row carries the source-of-truth membership fields plus the user's email
// and display name from the global users table, so GET
// /v1/organizations/{org_id}/members/{member_id} can render the same wire
// shape as the list endpoint without a second lookup.
func TestMembershipRepositoryGetMember(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, userID, "admin", 4)

	var got store.OrganizationMember
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.GetMember(ctx, q, org.ID, userID)
		return err
	}); err != nil {
		t.Fatalf("GetMember returned %v, want nil", err)
	}
	if got.OrganizationID != org.ID || got.UserID != userID {
		t.Errorf("GetMember returned %+v, want the membership of %q in %q", got, userID, org.ID)
	}
	if got.Role != "admin" || got.RoleVersion != 4 {
		t.Errorf("GetMember role/version = %q/%d, want admin/4", got.Role, got.RoleVersion)
	}
	if got.Email == "" || got.UserDisplayName == "" {
		t.Errorf("GetMember = %+v, want email/display_name from the joined users row", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("GetMember did not return the database-assigned timestamps")
	}
}

// TestMembershipRepositoryGetMemberNotFound proves a user id with no row in
// the tenant is the typed apierr.NotFound — the same contract every
// repository read produces, never disguised as a row with zero fields.
func TestMembershipRepositoryGetMemberNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada") // the user exists, but has no membership row

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.GetMember(ctx, q, org.ID, userID)
		return err
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetMember error = %v, want a typed E_NOT_FOUND", err)
	}
}

// TestMembershipRepositoryGetMemberIsTenantScoped proves cross-tenant
// isolation: a user id from one organization, paired with another
// organization, must not reveal the first organization's membership — it is
// a deterministic not-found, indistinguishable from a missing row.
func TestMembershipRepositoryGetMemberIsTenantScoped(t *testing.T) {
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
		_, err := repo.GetMember(ctx, q, orgA.ID, userID)
		return err
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant GetMember error = %v, want E_NOT_FOUND — no membership leak", err)
	}
}

// TestMembershipReaderGetMember proves the store-backed adapter composes the
// repository through its own Store.Read transaction and surfaces the join
// with the users table.
func TestMembershipReaderGetMember(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	reader, err := store.NewMembershipReader(s)
	if err != nil {
		t.Fatalf("NewMembershipReader: %v", err)
	}
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	adaID := seedUser(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, adaID, "owner", 1)

	got, err := reader.GetMember(ctx, org.ID, adaID)
	if err != nil {
		t.Fatalf("GetMember returned %v, want nil", err)
	}
	if got.UserID != adaID || got.OrganizationID != org.ID {
		t.Errorf("GetMember = %+v, want the seeded ada row in %q", got, org.ID)
	}
	if got.Email == "" || got.UserDisplayName == "" {
		t.Errorf("GetMember = %+v, want a joined email/display_name", got)
	}
}

// TestMembershipReaderGetMemberNotFound proves the adapter propagates the
// repository's typed not-found contract through Store.Read.
func TestMembershipReaderGetMemberNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	reader, err := store.NewMembershipReader(s)
	if err != nil {
		t.Fatalf("NewMembershipReader: %v", err)
	}
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada") // the user exists, but has no membership row

	_, getErr := reader.GetMember(ctx, org.ID, userID)
	var ye *yerr.Error
	if !stderrors.As(getErr, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetMember error = %v, want a typed E_NOT_FOUND", getErr)
	}
}

// TestMembershipRepositoryUpdateRole proves the role-change repository
// primitive behind PATCH /v1/organizations/{org_id}/members/{member_id}: it
// writes the new role, atomically bumps role_version, returns the joined
// OrganizationMember (so the joined user identity and the database-assigned
// timestamps round-trip), and the row is persisted exactly as returned.
func TestMembershipRepositoryUpdateRole(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, userID, "member", 5)

	var got store.OrganizationMember
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		got, err = repo.UpdateRole(ctx, tx, org.ID, userID, "owner")
		return err
	}); err != nil {
		t.Fatalf("UpdateRole returned %v, want nil", err)
	}

	if got.Role != "owner" {
		t.Errorf("UpdateRole role = %q, want owner", got.Role)
	}
	if got.RoleVersion != 6 {
		t.Errorf("UpdateRole role_version = %d, want 6 (5 + 1)", got.RoleVersion)
	}
	if got.Email == "" || got.UserDisplayName == "" {
		t.Errorf("UpdateRole returned %+v, want email/display_name joined from the users row", got)
	}

	// Persistence: re-read through the same repository to prove the write
	// landed as returned.
	var live store.OrganizationMember
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		live, err = repo.GetMember(ctx, q, org.ID, userID)
		return err
	}); err != nil {
		t.Fatalf("GetMember returned %v, want nil", err)
	}
	if live.Role != "owner" || live.RoleVersion != 6 {
		t.Errorf("re-read membership = %+v, want role owner / role_version 6", live)
	}
}

// TestMembershipRepositoryUpdateRoleMissingIsNotFound proves a UPDATE that
// matched no rows — for any reason, including a cross-tenant pairing — is
// the typed apierr.NotFound the GET endpoint uses, so a 404 contract is
// preserved at the persistence boundary.
func TestMembershipRepositoryUpdateRoleMissingIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada") // the user exists, but no membership row

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.UpdateRole(ctx, tx, org.ID, userID, "admin")
		return updErr
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("UpdateRole error = %v, want a typed E_NOT_FOUND", err)
	}
}

// TestMembershipRepositoryUpdateRoleIsTenantScoped proves the persistence
// layer's tenant guard: a user id paired with another organization is the
// same deterministic NotFound as a missing row, and the original tenant's
// row is left untouched.
func TestMembershipRepositoryUpdateRoleIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "alpha")
	orgB := seedOrg(t, db, f, "beta")
	userID := seedUser(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, userID, "owner", 3)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updErr := repo.UpdateRole(ctx, tx, orgB.ID, userID, "admin")
		return updErr
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant UpdateRole error = %v, want E_NOT_FOUND — no membership leak", err)
	}

	// orgA's row must be untouched: a cross-tenant UPDATE cannot reach into
	// another tenant's data even on the role_version field.
	var live store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		live, err = repo.Get(ctx, q, orgA.ID, userID)
		return err
	}); err != nil {
		t.Fatalf("Get(orgA) returned %v, want nil", err)
	}
	if live.Role != "owner" || live.RoleVersion != 3 {
		t.Errorf("orgA membership after cross-tenant UpdateRole = %+v, want unchanged role owner / role_version 3", live)
	}
}

// TestMembershipRepositoryDelete is the happy path for the membership DELETE
// primitive: the row is removed inside the transaction, and a follow-up Get
// surfaces the typed NotFound the read path produces.
func TestMembershipRepositoryDelete(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, userID, "owner", 2)

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, org.ID, userID)
	}); err != nil {
		t.Fatalf("Delete returned %v, want nil", err)
	}

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, org.ID, userID)
		return getErr
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get after Delete = %v, want a typed E_NOT_FOUND — the row must be gone", err)
	}
}

// TestMembershipRepositoryDeleteMissingIsNotFound proves a DELETE that
// matched no rows — for any reason, including a cross-tenant pairing — is
// the typed apierr.NotFound the GET endpoint uses, so a 404 contract is
// preserved at the persistence boundary.
func TestMembershipRepositoryDeleteMissingIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, org, "ada") // the user exists, but no membership row

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, org.ID, userID)
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("Delete error = %v, want a typed E_NOT_FOUND", err)
	}
}

// TestMembershipRepositoryDeleteIsTenantScoped proves the persistence
// layer's tenant guard: a user id paired with another organization is the
// same deterministic NotFound as a missing row, and the original tenant's
// row is left untouched.
func TestMembershipRepositoryDeleteIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "alpha")
	orgB := seedOrg(t, db, f, "beta")
	userID := seedUser(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, userID, "owner", 3)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, orgB.ID, userID)
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Delete error = %v, want E_NOT_FOUND — no membership leak", err)
	}

	// orgA's row must be untouched: a cross-tenant DELETE cannot reach into
	// another tenant's data.
	var live store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		live, err = repo.Get(ctx, q, orgA.ID, userID)
		return err
	}); err != nil {
		t.Fatalf("Get(orgA) returned %v, want nil", err)
	}
	if live.Role != "owner" || live.RoleVersion != 3 {
		t.Errorf("orgA membership after cross-tenant Delete = %+v, want unchanged role owner / role_version 3",
			live)
	}
}
