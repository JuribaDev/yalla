package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the users source of truth
// (BE-0428). users is the GLOBAL identity table — there is no
// organization_id column on the row itself, so the cross-tenant guarantee
// at this layer is shaped differently from the BE-0426 organizations
// proof: instead of "a query keyed by organization_id never sees another
// tenant's row", the load-bearing rules are
//
//	(a) every mutation is keyed strictly by the row's own id, so a
//	    WHERE-less UPDATE / DELETE — or one that accidentally also matched
//	    on email — could never ripple across rows or tenants;
//	(b) the tenant-scoped read path (GetInOrganization) filters by
//	    memberships first, so a user that has no membership in this
//	    organization is the same typed NotFound an unknown id would
//	    produce;
//	(c) the global UNIQUE(email) citext constraint is enforced
//	    consistently across tenants — two independent organizations
//	    cannot each insert their own row claiming the same email.
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - The basic Get / GetByEmail / GetInOrganization read shapes and the
//     UserReader adapter are proven by user_test.go (BE-0427).
//   - Single-row CRUD invariants (Insert RETURNING shape, Update
//     RETURNING, rollback on Conflict, nil-tx guards, cascade-to-
//     memberships on a single id) are proven by
//     user_repository_invariants_test.go (BE-0427).
//   - The HTTP-layer "another tenant's id is a 404, not a 403" rule is
//     proven by per-endpoint policy matrix and contract tests in httpapi.
//   - The cross-tenant cascade for the broader hierarchy is proven by
//     TestTenantHierarchyCascadeDelete in schema_test.go.
//
// UserRepository has no version column and no If-Match path, so the
// stale-If-Match leak surface BE-0426 covers on organizations is absent
// here. The session-token-revocation invariant that fills that role for
// user identity lives on memberships.role_version instead and is covered
// by membership_test.go.
//
// UserRepository deliberately exposes no list-by-parent method: users is
// not a child of any tenant — the per-tenant roster is rendered by the
// memberships repository (membership_test.go), which is where the
// list-pagination tenant-isolation proof lives. Likewise users has no
// deletion_scheduled_at column: human identities are hard-deleted, with
// the cross-tenant cascade behaviour proven by Delete tests below.

// TestUserRepositoryGetByIdReturnsCorrectRowAcrossTenants proves Get is
// keyed strictly by the row's own id: two users seeded into two distinct
// tenants each return their own row when looked up by id, and the two
// rows are distinguishable from each other. A regression that ORed across
// rows — say, a "WHERE id = $1 OR email ILIKE $1" mistake — would surface
// here as a swapped or merged response.
func TestUserRepositoryGetByIdReturnsCorrectRowAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	userA := seedUserRow(t, db, f, orgA, "ada")
	userB := seedUserRow(t, db, f, orgB, "bea")

	var gotA store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.Get(ctx, q, userA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(userA): %v", err)
	}
	if gotA.ID != userA.ID || gotA.Email != userA.Email || gotA.DisplayName != userA.Name {
		t.Errorf("Get(userA) = %+v, want id/email/name from %+v", gotA, userA)
	}

	var gotB store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.Get(ctx, q, userB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(userB): %v", err)
	}
	if gotB.ID != userB.ID || gotB.Email != userB.Email || gotB.DisplayName != userB.Name {
		t.Errorf("Get(userB) = %+v, want id/email/name from %+v", gotB, userB)
	}

	// The two ids and the two emails are distinct, so a query that
	// silently returned the same row for both lookups would be caught.
	if gotA.ID == gotB.ID || gotA.Email == gotB.Email {
		t.Errorf("Get returned overlapping rows for two distinct user ids: %+v vs %+v", gotA, gotB)
	}
}

// TestUserRepositoryUpdateOnUserADoesNotTouchUserB is the byte-identical
// snapshot proof for Update. We seed two users in two tenants, snapshot
// userB's row, rename userA, then re-read userB and assert every field
// unchanged (id, email, display_name, created_at, updated_at). A
// WHERE-less UPDATE — or an UPDATE that accidentally matched both rows
// by collation accident — would refresh userB.updated_at via the
// set_updated_at trigger and fail this test. The trigger anchors
// "another row was touched" independently of the column writes themselves.
func TestUserRepositoryUpdateOnUserADoesNotTouchUserB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	userA := seedUserRow(t, db, f, orgA, "ada")
	userB := seedUserRow(t, db, f, orgB, "bea")

	// Snapshot userB before the mutation so any drift is caught precisely.
	var baselineB store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		baselineB, readErr = repo.Get(ctx, q, userB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("baseline Get(userB): %v", err)
	}

	// Rename userA with a fresh, deterministic email that cannot collide
	// with the factory-generated email userB carries.
	renamedEmail := "ada-renamed-" + strings.ToLower(userA.ID) + "@fixtures.yalla.test"
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Update(ctx, tx, store.User{
			ID:          userA.ID,
			Email:       renamedEmail,
			DisplayName: "Ada Renamed",
		})
		return writeErr
	}); err != nil {
		t.Fatalf("Update(userA): %v", err)
	}

	// userB must be byte-identical to its baseline — id, email, display
	// name, created_at AND updated_at. The set_updated_at trigger fires
	// on *the row being updated*, so a refreshed updated_at on userB
	// proves an unrelated row was touched even if the column writes
	// themselves look correct.
	var afterB store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterB, readErr = repo.Get(ctx, q, userB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(userB): %v", err)
	}
	if afterB.ID != baselineB.ID {
		t.Errorf("userB.id = %q, want %q — Update(userA) reassigned userB.id", afterB.ID, baselineB.ID)
	}
	if afterB.Email != baselineB.Email {
		t.Errorf("userB.email = %q, want %q — Update(userA) leaked into userB", afterB.Email, baselineB.Email)
	}
	if afterB.DisplayName != baselineB.DisplayName {
		t.Errorf("userB.display_name = %q, want %q — Update(userA) leaked into userB", afterB.DisplayName, baselineB.DisplayName)
	}
	if !afterB.CreatedAt.Equal(baselineB.CreatedAt) {
		t.Errorf("userB.created_at = %v, want %v — Update(userA) reset userB.created_at", afterB.CreatedAt, baselineB.CreatedAt)
	}
	if !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) {
		t.Errorf("userB.updated_at = %v, want %v — Update(userA) refreshed userB.updated_at via the trigger", afterB.UpdatedAt, baselineB.UpdatedAt)
	}

	// And the Update on userA actually landed — otherwise a no-op
	// repository would silently pass the byte-identical-userB check.
	var afterA store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterA, readErr = repo.Get(ctx, q, userA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(userA): %v", err)
	}
	if afterA.Email != renamedEmail {
		t.Errorf("userA.email = %q, want %q — Update did not land", afterA.Email, renamedEmail)
	}
	if afterA.DisplayName != "Ada Renamed" {
		t.Errorf("userA.display_name = %q, want %q — Update did not land", afterA.DisplayName, "Ada Renamed")
	}
}

// TestUserRepositoryUpdateUserAEmailCollidingWithUserBLeavesBothByteIdentical
// proves an Update on userA that tries to claim userB's email (under a
// different casing, so the citext UNIQUE constraint is what catches it)
// fails with a typed Conflict AND leaves BOTH users byte-identical. A
// regression where the UPDATE partially landed on userA before tripping
// the constraint — or where the transaction rolled back the userA write
// but the trigger had already refreshed updated_at on userB — would
// surface here.
func TestUserRepositoryUpdateUserAEmailCollidingWithUserBLeavesBothByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	userA := seedUserRow(t, db, f, orgA, "ada")
	userB := seedUserRow(t, db, f, orgB, "bea")

	var baselineA, baselineB store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		baselineA, readErr = repo.Get(ctx, q, userA.ID)
		if readErr != nil {
			return readErr
		}
		baselineB, readErr = repo.Get(ctx, q, userB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("baseline Get(both): %v", err)
	}

	// Use a different casing to also prove citext is what catches it —
	// a case-sensitive UNIQUE column would let this collision through.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Update(ctx, tx, store.User{
			ID:          userA.ID,
			Email:       strings.ToUpper(userB.Email),
			DisplayName: "Ada (Pretending)",
		})
		return writeErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Update(userA, dup email) error = %v, want %s", err, yerr.CodeConflict)
	}

	// userB must be byte-identical to its baseline — the conflicting
	// Update must not even have stamped userB's updated_at via the
	// trigger.
	var afterB store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterB, readErr = repo.Get(ctx, q, userB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(userB): %v", err)
	}
	if afterB.Email != baselineB.Email {
		t.Errorf("userB.email = %q, want %q — failed Update(userA) leaked into userB", afterB.Email, baselineB.Email)
	}
	if afterB.DisplayName != baselineB.DisplayName {
		t.Errorf("userB.display_name = %q, want %q — failed Update(userA) leaked into userB", afterB.DisplayName, baselineB.DisplayName)
	}
	if !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) {
		t.Errorf("userB.updated_at = %v, want %v — failed Update(userA) refreshed userB.updated_at", afterB.UpdatedAt, baselineB.UpdatedAt)
	}

	// userA must be byte-identical to its baseline — the conflicting
	// UPDATE rolled back without partial-write damage to the row that
	// was supposed to be the *target* of the write.
	var afterA store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterA, readErr = repo.Get(ctx, q, userA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(userA): %v", err)
	}
	if afterA.Email != baselineA.Email {
		t.Errorf("userA.email = %q, want %q — failed Update partial-wrote userA", afterA.Email, baselineA.Email)
	}
	if afterA.DisplayName != baselineA.DisplayName {
		t.Errorf("userA.display_name = %q, want %q — failed Update partial-wrote userA", afterA.DisplayName, baselineA.DisplayName)
	}
	if !afterA.UpdatedAt.Equal(baselineA.UpdatedAt) {
		t.Errorf("userA.updated_at = %v, want %v — failed Update partial-stamped userA via the trigger", afterA.UpdatedAt, baselineA.UpdatedAt)
	}
}

// TestUserRepositoryDeleteOnUserADoesNotTouchUserB proves Delete is
// strictly id-scoped: it removes userA AND every membership row tied to
// userA's id (memberships.user_id is ON DELETE CASCADE), but it never
// touches userB or any membership belonging to a different user. This is
// the cross-row safety net for the BE-0427 cascade behaviour — without
// it, a faulty DELETE could wipe an entire tenant's roster. The cascade
// is also asymmetric across tenants: userA's membership in orgA goes,
// userB's membership in orgB stays.
func TestUserRepositoryDeleteOnUserADoesNotTouchUserB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	userA := seedUserRow(t, db, f, orgA, "ada")
	userB := seedUserRow(t, db, f, orgB, "bea")
	seedMembership(t, db, orgA.ID, userA.ID, "owner", 1)
	seedMembership(t, db, orgB.ID, userB.ID, "owner", 1)

	var baselineB store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		baselineB, readErr = repo.Get(ctx, q, userB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("baseline Get(userB): %v", err)
	}

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, userA.ID)
	}); err != nil {
		t.Fatalf("Delete(userA): %v", err)
	}

	// userA is gone — a subsequent Get is the typed NotFound, the same
	// shape any other unknown id produces.
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, readErr := repo.Get(ctx, q, userA.ID)
		return readErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(userA) after Delete error = %v, want %s", err, yerr.CodeNotFound)
	}

	// userB is byte-identical to its baseline across every field —
	// id, email, display_name, created_at, AND updated_at (the trigger
	// would refresh updated_at if the DELETE statement had been
	// WHERE-less or had accidentally matched userB too).
	var afterB store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterB, readErr = repo.Get(ctx, q, userB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(userB): %v", err)
	}
	if afterB.ID != baselineB.ID || afterB.Email != baselineB.Email || afterB.DisplayName != baselineB.DisplayName {
		t.Errorf("userB drifted after Delete(userA): got %+v, want %+v", afterB, baselineB)
	}
	if !afterB.CreatedAt.Equal(baselineB.CreatedAt) {
		t.Errorf("userB.created_at = %v, want %v — Delete(userA) reset userB.created_at", afterB.CreatedAt, baselineB.CreatedAt)
	}
	if !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) {
		t.Errorf("userB.updated_at = %v, want %v — Delete(userA) refreshed userB.updated_at", afterB.UpdatedAt, baselineB.UpdatedAt)
	}

	// userB's membership in orgB survives — the cascade is scoped to
	// userA's id, not the whole memberships table. This is the
	// load-bearing distinction between "delete this user's identity"
	// and "wipe every membership row".
	var orgBMemberships int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE organization_id = $1 AND user_id = $2`,
		orgB.ID, userB.ID).Scan(&orgBMemberships); err != nil {
		t.Fatalf("count memberships(orgB, userB): %v", err)
	}
	if orgBMemberships != 1 {
		t.Errorf("memberships(orgB, userB) count = %d, want 1 — Delete(userA) cascaded into orgB", orgBMemberships)
	}

	// userA's membership in orgA was cascaded away by the
	// memberships.user_id ON DELETE CASCADE FK. The atomic teardown is
	// what makes "delete a user" safe to expose as a single statement.
	var userAMemberships int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE user_id = $1`,
		userA.ID).Scan(&userAMemberships); err != nil {
		t.Fatalf("count memberships(userA): %v", err)
	}
	if userAMemberships != 0 {
		t.Errorf("memberships(userA) count = %d, want 0 — Delete did not cascade", userAMemberships)
	}
}

// TestUserRepositoryInsertEnforcesGlobalEmailUniquenessAcrossTenants
// proves the email uniqueness constraint is GLOBAL — a second Insert
// reusing an existing email from a peer tenant is a typed Conflict, the
// intruder row never lands, and the original row is byte-identical
// afterwards. This is the load-bearing reason the auth layer can treat
// email as a stable global identifier: a customer never has to
// disambiguate it between two independent organizations, and a malicious
// second tenant cannot squat on a peer's identity.
func TestUserRepositoryInsertEnforcesGlobalEmailUniquenessAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	userA := seedUserRow(t, db, f, orgA, "ada")

	var baselineA store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		baselineA, readErr = repo.Get(ctx, q, userA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("baseline Get(userA): %v", err)
	}

	// The intruder builds a fresh in-memory fixture under orgB but
	// overrides its email with an upper-cased copy of userA's. citext
	// equality must catch it; a case-sensitive UNIQUE would let it slip.
	intruder := f.User(orgB, "intruder")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Insert(ctx, tx, store.User{
			ID:          intruder.ID,
			Email:       strings.ToUpper(userA.Email),
			DisplayName: intruder.Name,
		})
		return writeErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Insert(intruder, dup email) error = %v, want %s", err, yerr.CodeConflict)
	}

	// The intruder row never landed — a failed Insert must not have
	// committed a partial row that a later Get could surface.
	intruderErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, readErr := repo.Get(ctx, q, intruder.ID)
		return readErr
	})
	if ye := yerr.From(intruderErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Get(intruder) error = %v, want %s — failed Insert left a partial row", intruderErr, yerr.CodeNotFound)
	}

	// userA's row is byte-identical to its baseline. The failed Insert
	// targeted only the intruder id, but a WHERE-less INSERT-conflict
	// recovery path (e.g. an ON CONFLICT DO UPDATE that crept in) would
	// surface here as a refreshed updated_at on userA.
	var afterA store.User
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterA, readErr = repo.Get(ctx, q, userA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(userA): %v", err)
	}
	if afterA.Email != baselineA.Email {
		t.Errorf("userA.email = %q, want %q — failed Insert leaked into userA", afterA.Email, baselineA.Email)
	}
	if afterA.DisplayName != baselineA.DisplayName {
		t.Errorf("userA.display_name = %q, want %q — failed Insert leaked into userA", afterA.DisplayName, baselineA.DisplayName)
	}
	if !afterA.UpdatedAt.Equal(baselineA.UpdatedAt) {
		t.Errorf("userA.updated_at = %v, want %v — failed Insert refreshed userA.updated_at", afterA.UpdatedAt, baselineA.UpdatedAt)
	}
}

// TestUserRepositoryGetInOrganizationUnknownIdMatchesCrossTenantShape
// proves the typed-NotFound code an unknown user id produces through
// GetInOrganization is identical to the code a real-but-non-member id
// produces through the same path — the wire-existence of any user can
// never be inferred from the response code alone. The HTTP layer relies
// on this equivalence so that "this user does not exist" and "this user
// is not in your organization" are indistinguishable to a probing
// caller, which prevents a tenant from enumerating peers by guessing ids.
func TestUserRepositoryGetInOrganizationUnknownIdMatchesCrossTenantShape(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewUserRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	userOfA := seedUserRow(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, userOfA.ID, "owner", 1)

	// (1) An id that belongs to no user at all, scoped to orgB.
	unknownErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, readErr := repo.GetInOrganization(ctx, q, orgB.ID, "usr_neverexisted_00000000000")
		return readErr
	})
	if ye := yerr.From(unknownErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetInOrganization(orgB, unknown) error code = %v, want %s", unknownErr, yerr.CodeNotFound)
	}

	// (2) A real userId that simply has no membership in orgB.
	crossTenantErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, readErr := repo.GetInOrganization(ctx, q, orgB.ID, userOfA.ID)
		return readErr
	})
	if ye := yerr.From(crossTenantErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetInOrganization(orgB, userOfA) error code = %v, want %s", crossTenantErr, yerr.CodeNotFound)
	}

	// Both errors carry the same yerr.CodeNotFound, and both messages
	// follow the user-facing "user %q not found" shape — no flag, no
	// detail, no hint distinguishes the two cases. A handler that
	// leaked existence ("user exists but not in your organization")
	// would surface here as a divergent Code or a Hint that only the
	// real-id case sets.
	unknownYE := yerr.From(unknownErr)
	crossYE := yerr.From(crossTenantErr)
	if unknownYE.Code != crossYE.Code {
		t.Errorf("Code mismatch: unknown=%s, crossTenant=%s — existence leaked via Code", unknownYE.Code, crossYE.Code)
	}
	if unknownYE.Hint != crossYE.Hint {
		t.Errorf("Hint mismatch: unknown=%q, crossTenant=%q — existence leaked via Hint", unknownYE.Hint, crossYE.Hint)
	}
}
