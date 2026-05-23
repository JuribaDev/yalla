package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for UserRepository and UserReader — the read surface
// behind GET /v1/users and the member lookups behind organization-scoped
// endpoints. They prove id-scoped reads, citext email lookups, tenant-scoped
// membership joins, typed not-found behaviour, that one tenant's roster is
// never returned for another tenant's id, and that the Store.Read-backed
// reader inherits all of it. They run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset.

// seedUserRow inserts a global user row and returns the in-memory fixture so
// tests can assert against the email and display name they persisted.
// seedUser already exists in apikey_test.go for the API-key-foreign-key path
// (returns just the id); this helper hands back the full testutil.User so a
// user-repository test can assert email and display-name roundtrip.
func seedUserRow(t *testing.T, db *testutil.DB, f *testutil.Factory, org testutil.Organization, label string) testutil.User {
	t.Helper()
	user := f.User(org, label)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)`,
		user.ID, user.Email, user.Name); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return user
}

func TestUserRepositoryGet(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")

	var got store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.Get(ctx, q, user.ID)
		return err
	}); err != nil {
		t.Fatalf("Get returned %v, want nil", err)
	}
	if got.ID != user.ID || got.Email != user.Email || got.DisplayName != user.Name {
		t.Errorf("Get returned %+v, want id/email/name from %+v", got, user)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("Get did not return the database-assigned timestamps")
	}
}

func TestUserRepositoryGetNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	missing := f.User(org, "ghost") // built, never inserted

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, missing.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(missing) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestUserRepositoryGetByEmail proves the citext email lookup returns the
// user and that the lookup is case-insensitive — the same property the
// schema's citext UNIQUE constraint owes us, surfaced through the repository.
func TestUserRepositoryGetByEmail(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")

	// Lower-cased lookup.
	var got store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.GetByEmail(ctx, q, strings.ToLower(user.Email))
		return err
	}); err != nil {
		t.Fatalf("GetByEmail(lower) returned %v, want nil", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetByEmail(lower) = %+v, want id %q", got, user.ID)
	}

	// Upper-cased lookup must return the same row.
	var gotUpper store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		gotUpper, err = repo.GetByEmail(ctx, q, strings.ToUpper(user.Email))
		return err
	}); err != nil {
		t.Fatalf("GetByEmail(upper) returned %v, want nil", err)
	}
	if gotUpper.ID != user.ID {
		t.Errorf("GetByEmail(upper) returned %+v, want id %q (citext must be case-insensitive)", gotUpper, user.ID)
	}
}

func TestUserRepositoryGetByEmailNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	ctx := context.Background()

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.GetByEmail(ctx, q, "no-such-user@fixtures.yalla.test")
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetByEmail(missing) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestUserRepositoryGetInOrganization proves the membership-join read returns
// the user when they are a member of the given organization. This is the
// happy path for the tenant-scoped lookup; the cross-tenant case lives below.
func TestUserRepositoryGetInOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, user.ID, "member", 1)

	var got store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.GetInOrganization(ctx, q, org.ID, user.ID)
		return err
	}); err != nil {
		t.Fatalf("GetInOrganization returned %v, want nil", err)
	}
	if got.ID != user.ID || got.Email != user.Email {
		t.Errorf("GetInOrganization = %+v, want the seeded member", got)
	}
}

// TestUserRepositoryGetInOrganizationNonMemberIsNotFound proves the lookup
// returns NotFound when the user exists but has no membership in the target
// organization — the row is in the global users table but not on the join,
// so it must not be visible through a tenant-scoped read.
func TestUserRepositoryGetInOrganizationNonMemberIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme")
	outsider := seedUserRow(t, db, f, org, "outsider") // global user, no membership

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.GetInOrganization(ctx, q, org.ID, outsider.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetInOrganization(non-member) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestUserRepositoryGetInOrganizationIsTenantScoped proves a member of one
// organization is reported as NotFound by another organization's lookup —
// the same shape an unknown id produces, so a cross-tenant id can never
// reveal another organization's roster.
func TestUserRepositoryGetInOrganizationIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	memberOfA := seedUserRow(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, memberOfA.ID, "owner", 1)

	// orgB asks for orgA's member: must be NotFound.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.GetInOrganization(ctx, q, orgB.ID, memberOfA.ID)
		return getErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetInOrganization(cross-tenant) error code = %v, want %s", err, yerr.CodeNotFound)
	}

	// orgA's own lookup still works — the join is symmetric.
	var got store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.GetInOrganization(ctx, q, orgA.ID, memberOfA.ID)
		return err
	}); err != nil {
		t.Fatalf("GetInOrganization(orgA, own member): %v", err)
	}
	if got.ID != memberOfA.ID {
		t.Errorf("GetInOrganization(orgA, own member) = %+v, want id %q", got, memberOfA.ID)
	}
}

func TestUserReaderGetUser(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	reader, err := store.NewUserReader(s)
	if err != nil {
		t.Fatalf("NewUserReader: %v", err)
	}

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")

	got, err := reader.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser returned %v, want nil", err)
	}
	if got.ID != user.ID || got.Email != user.Email || got.DisplayName != user.Name {
		t.Errorf("GetUser returned %+v, want id/email/name from %+v", got, user)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Error("GetUser did not return the database-assigned timestamps")
	}
}

func TestUserReaderGetUserNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	reader, err := store.NewUserReader(s)
	if err != nil {
		t.Fatalf("NewUserReader: %v", err)
	}

	org := seedOrg(t, db, f, "acme")
	missing := f.User(org, "ghost") // built, never inserted

	_, err = reader.GetUser(ctx, missing.ID)
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetUser(missing) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

func TestUserReaderGetUserInOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	reader, err := store.NewUserReader(s)
	if err != nil {
		t.Fatalf("NewUserReader: %v", err)
	}

	org := seedOrg(t, db, f, "acme")
	user := seedUserRow(t, db, f, org, "ada")
	seedMembership(t, db, org.ID, user.ID, "member", 1)

	got, err := reader.GetUserInOrganization(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("GetUserInOrganization returned %v, want nil", err)
	}
	if got.ID != user.ID {
		t.Errorf("GetUserInOrganization returned %+v, want id %q", got, user.ID)
	}
}

func TestUserReaderGetUserInOrganizationCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	reader, err := store.NewUserReader(s)
	if err != nil {
		t.Fatalf("NewUserReader: %v", err)
	}

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	memberOfA := seedUserRow(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, memberOfA.ID, "owner", 1)

	_, err = reader.GetUserInOrganization(ctx, orgB.ID, memberOfA.ID)
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetUserInOrganization(cross-tenant) error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

func TestNewUserReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewUserReader(nil); err == nil {
		t.Fatal("NewUserReader(nil) error = nil, want an error")
	}
}
