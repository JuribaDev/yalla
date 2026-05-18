package store_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the memberships table
// (BE-0430). memberships is a tenant-scoped link table whose composite
// primary key is (organization_id, user_id); the row has no own id, no
// version column independent of role_version, and no soft-delete column.
// The cross-tenant guarantee at this layer is therefore shaped around
// three load-bearing rules that membership_test.go's tenant-scoped tests
// touch only partially:
//
//	(a) every Get / GetMember / UpdateRole / Delete is keyed strictly by
//	    BOTH columns of the composite primary key, so the SAME user can be
//	    a member of two different organizations with different roles and
//	    role_versions and neither row can swap with — or leak into — the
//	    other under any read or mutation;
//	(b) ListByOrganization returns exactly the rows whose organization_id
//	    matches, never inflating its count or rendered set by another
//	    tenant's membership rows that share a user_id;
//	(c) the cross-tenant error shape is indistinguishable from the
//	    unknown-pair error shape — both surfaces emit
//	    yerr.CodeNotFound with matching Hint values — so a probing caller
//	    cannot infer the existence of a peer tenant's membership from the
//	    response Code, Hint, or message.
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Basic single-tenant Get / GetMember / ListByOrganization /
//     UpdateRole / Delete read shapes and their plain cross-tenant
//     NotFound result are proved by membership_test.go (BE-0426).
//   - Single-row CRUD invariants (Insert RETURNING shape, role_version
//     schema default, UpdateRole timestamp dual-anchor, rollback on
//     conflict, nil-tx guards) are proved by
//     membership_repository_invariants_test.go (BE-0429).
//   - The HTTP-layer "another tenant's pair is a 404, not a 403" rule is
//     proved by per-endpoint policy matrix and contract tests in httpapi.
//   - The cross-tenant cascade-on-organization-delete is proved by
//     TestTenantHierarchyCascadeDelete in schema_test.go. The
//     cascade-on-user-delete is proved by
//     TestUserRepositoryDeleteCascadesToMemberships in
//     user_repository_invariants_test.go.
//
// memberships has no deletion_scheduled_at / soft-delete column — rows
// are hard-deleted in a single statement, and the cross-tenant cascade
// behaviour belongs to the parent tables, not the link table. The
// acceptance-criteria mention of "soft-deleted rows where applicable"
// therefore has no surface here; documenting the deliberate absence
// keeps a future reader from looking for a missing test (mirrors
// user_tenant_isolation_test.go's no-soft-delete note for users).

// TestMembershipRepositoryGetReturnsCorrectRowAcrossTenants proves Get is
// keyed strictly by BOTH columns of the composite primary key: the SAME
// user is seeded as a member of orgA and orgB with deliberately distinct
// (role, role_version) tuples, and Get(orgA, ada) / Get(orgB, ada) must
// each return their own row — never a swapped or merged response. The
// (role, role_version) values per tenant are intentionally non-default
// so a WHERE-on-user-only mistake (which would resolve to whichever row
// the planner found first) would diverge from the expected per-tenant
// tuple.
func TestMembershipRepositoryGetReturnsCorrectRowAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	adaID := seedUser(t, db, f, orgA, "ada")
	// Distinct role/role_version per tenant so a swapped row trips the
	// equality assertions below — not just the org_id field. The
	// memberships_role_check CHECK constraint restricts role to
	// {owner, admin, member}, so the contrast is on (role, role_version)
	// together: a WHERE-on-user-only mistake would return one of these
	// two rows for both Get calls and the disjoint role_version values
	// would catch it even when the role values happened to coincide.
	seedMembership(t, db, orgA.ID, adaID, "owner", 7)
	seedMembership(t, db, orgB.ID, adaID, "member", 2)

	var gotA store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.Get(ctx, q, orgA.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgA, ada): %v", err)
	}
	if gotA.OrganizationID != orgA.ID || gotA.UserID != adaID || gotA.Role != "owner" || gotA.RoleVersion != 7 {
		t.Errorf("Get(orgA, ada) = %+v, want orgA/ada/owner/7", gotA)
	}

	var gotB store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.Get(ctx, q, orgB.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgB, ada): %v", err)
	}
	if gotB.OrganizationID != orgB.ID || gotB.UserID != adaID || gotB.Role != "member" || gotB.RoleVersion != 2 {
		t.Errorf("Get(orgB, ada) = %+v, want orgB/ada/member/2", gotB)
	}

	// The two reads MUST have returned distinct rows. A WHERE-on-user-only
	// mistake would have collapsed both lookups onto the same row and
	// failed this guard even when each per-row equality check might have
	// drifted into a coincidental match.
	if gotA.OrganizationID == gotB.OrganizationID || gotA.Role == gotB.Role || gotA.RoleVersion == gotB.RoleVersion {
		t.Errorf("Get returned overlapping rows for the same user across two tenants: %+v vs %+v", gotA, gotB)
	}
}

// TestMembershipRepositoryGetMemberReturnsCorrectRowAcrossTenants is the
// same proof for the JOIN-bearing GetMember read: the same user has the
// same Email/UserDisplayName in every tenant (the user is global), but
// the Role / RoleVersion / OrganizationID / CreatedAt / UpdatedAt are
// per-row and must not swap when paired with a different organization.
func TestMembershipRepositoryGetMemberReturnsCorrectRowAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	adaID := seedUser(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, adaID, "owner", 5)
	seedMembership(t, db, orgB.ID, adaID, "member", 9)

	var gotA store.OrganizationMember
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.GetMember(ctx, q, orgA.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("GetMember(orgA, ada): %v", err)
	}
	if gotA.OrganizationID != orgA.ID || gotA.UserID != adaID || gotA.Role != "owner" || gotA.RoleVersion != 5 {
		t.Errorf("GetMember(orgA, ada) = %+v, want orgA/ada/owner/5", gotA)
	}
	if gotA.Email == "" || gotA.UserDisplayName == "" {
		t.Errorf("GetMember(orgA, ada) joined identity is empty: email=%q name=%q", gotA.Email, gotA.UserDisplayName)
	}

	var gotB store.OrganizationMember
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.GetMember(ctx, q, orgB.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("GetMember(orgB, ada): %v", err)
	}
	if gotB.OrganizationID != orgB.ID || gotB.UserID != adaID || gotB.Role != "member" || gotB.RoleVersion != 9 {
		t.Errorf("GetMember(orgB, ada) = %+v, want orgB/ada/member/9", gotB)
	}

	// The joined identity is the SAME global user across both reads —
	// a regression that disambiguated by email would mask the row-swap.
	if gotA.Email != gotB.Email || gotA.UserDisplayName != gotB.UserDisplayName {
		t.Errorf("GetMember joined identity drifted across tenants: A.email=%q B.email=%q / A.name=%q B.name=%q",
			gotA.Email, gotB.Email, gotA.UserDisplayName, gotB.UserDisplayName)
	}
	// The row-level fields are per-tenant and must diverge.
	if gotA.OrganizationID == gotB.OrganizationID || gotA.Role == gotB.Role || gotA.RoleVersion == gotB.RoleVersion {
		t.Errorf("GetMember returned overlapping per-row fields across tenants: %+v vs %+v", gotA, gotB)
	}
}

// TestMembershipRepositoryUpdateRoleOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for UpdateRole on a user who is a
// member of TWO tenants. membership_test.go's
// TestMembershipRepositoryUpdateRoleIsTenantScoped covers the inverse
// direction (UpdateRole(orgB) on a user who is only in orgA → NotFound,
// orgA row unchanged at role/role_version); this test covers the
// load-bearing case where the user IS a legitimate member of the
// untouched tenant — so a WHERE-less or WHERE-on-user-only UPDATE would
// silently bump the WRONG row, including its updated_at via the
// memberships_set_updated_at trigger.
func TestMembershipRepositoryUpdateRoleOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	adaID := seedUser(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, adaID, "member", 1)
	seedMembership(t, db, orgB.ID, adaID, "owner", 4)

	// Snapshot orgB's membership before the mutation so any drift is
	// caught precisely on EVERY field — including the trigger-managed
	// updated_at, which is the independent anchor that catches a
	// WHERE-on-user-only UPDATE even when the column writes themselves
	// happen to look correct.
	var baselineB store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		baselineB, readErr = repo.Get(ctx, q, orgB.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("baseline Get(orgB, ada): %v", err)
	}

	// UpdateRole on orgA only.
	var updatedA store.OrganizationMember
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updatedA, writeErr = repo.UpdateRole(ctx, tx, orgA.ID, adaID, "admin")
		return writeErr
	}); err != nil {
		t.Fatalf("UpdateRole(orgA, ada): %v", err)
	}

	// orgA must have actually changed — a no-op repository cannot
	// silently pass the byte-identical-orgB check below.
	if updatedA.Role != "admin" || updatedA.RoleVersion != 2 || updatedA.OrganizationID != orgA.ID {
		t.Errorf("UpdateRole(orgA, ada) = %+v, want orgA/admin/role_version=2", updatedA)
	}

	// orgB membership must be byte-identical to its baseline across
	// every field — including updated_at, which the BEFORE-UPDATE
	// trigger would stamp if the UPDATE statement had been WHERE-less
	// or had matched on user_id only.
	var afterB store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterB, readErr = repo.Get(ctx, q, orgB.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(orgB, ada): %v", err)
	}
	if afterB.OrganizationID != baselineB.OrganizationID || afterB.UserID != baselineB.UserID {
		t.Errorf("orgB key drifted after UpdateRole(orgA): got %+v, want %+v", afterB, baselineB)
	}
	if afterB.Role != baselineB.Role {
		t.Errorf("orgB.role = %q, want %q — UpdateRole(orgA) leaked into orgB's role", afterB.Role, baselineB.Role)
	}
	if afterB.RoleVersion != baselineB.RoleVersion {
		t.Errorf("orgB.role_version = %d, want %d — UpdateRole(orgA) bumped orgB's role_version", afterB.RoleVersion, baselineB.RoleVersion)
	}
	if !afterB.CreatedAt.Equal(baselineB.CreatedAt) {
		t.Errorf("orgB.created_at = %v, want %v — UpdateRole(orgA) reset orgB.created_at", afterB.CreatedAt, baselineB.CreatedAt)
	}
	if !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) {
		t.Errorf("orgB.updated_at = %v, want %v — UpdateRole(orgA) refreshed orgB.updated_at via the trigger", afterB.UpdatedAt, baselineB.UpdatedAt)
	}
}

// TestMembershipRepositoryDeleteOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for Delete on a user who is a member of
// TWO tenants. The composite-key DELETE must hit exactly one row — a
// WHERE-on-user-only mistake would scrub the user's membership in EVERY
// tenant they belong to, which is the worst possible cross-row failure
// mode for a tenant link table.
func TestMembershipRepositoryDeleteOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	adaID := seedUser(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, adaID, "owner", 3)
	seedMembership(t, db, orgB.ID, adaID, "member", 6)

	var baselineB store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		baselineB, readErr = repo.Get(ctx, q, orgB.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("baseline Get(orgB, ada): %v", err)
	}

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Delete(ctx, tx, orgA.ID, adaID)
	}); err != nil {
		t.Fatalf("Delete(orgA, ada): %v", err)
	}

	// orgA membership is gone — a follow-up Get is the typed NotFound
	// that the read path produces, the same shape an unknown pair
	// produces (no Forbidden / no AlreadyDeleted leak).
	gotAErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, adaID)
		return err
	})
	var yeA *yerr.Error
	if !stderrors.As(gotAErr, &yeA) || yeA.Code != yerr.CodeNotFound {
		t.Fatalf("Get(orgA, ada) after Delete = %v, want a typed E_NOT_FOUND", gotAErr)
	}

	// orgB membership survives AND is byte-identical to its baseline
	// across every field — the trigger would refresh updated_at if the
	// DELETE statement had matched orgB's row even momentarily.
	var afterB store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterB, readErr = repo.Get(ctx, q, orgB.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(orgB, ada): %v — Delete(orgA) wiped orgB's row too", err)
	}
	if afterB.OrganizationID != baselineB.OrganizationID || afterB.UserID != baselineB.UserID {
		t.Errorf("orgB key drifted after Delete(orgA): got %+v, want %+v", afterB, baselineB)
	}
	if afterB.Role != baselineB.Role || afterB.RoleVersion != baselineB.RoleVersion {
		t.Errorf("orgB row mutated after Delete(orgA): got role=%q version=%d, want role=%q version=%d",
			afterB.Role, afterB.RoleVersion, baselineB.Role, baselineB.RoleVersion)
	}
	if !afterB.CreatedAt.Equal(baselineB.CreatedAt) {
		t.Errorf("orgB.created_at = %v, want %v — Delete(orgA) reset orgB.created_at", afterB.CreatedAt, baselineB.CreatedAt)
	}
	if !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) {
		t.Errorf("orgB.updated_at = %v, want %v — Delete(orgA) refreshed orgB.updated_at via the trigger", afterB.UpdatedAt, baselineB.UpdatedAt)
	}

	// The global users row is untouched: Delete on a memberships pair
	// removes ONLY the link, never the identity. A regression that
	// dropped a cascade-the-other-way would surface here.
	var userExists bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, adaID).Scan(&userExists); err != nil {
		t.Fatalf("count users(ada): %v", err)
	}
	if !userExists {
		t.Error("users(ada) row was deleted as a side effect of Delete(orgA, ada) — the link should never cascade upward to the identity")
	}
}

// TestMembershipRepositoryInsertConflictOnOrgADoesNotTouchOrgB proves
// a primary-key duplicate Insert on (orgA, ada) — when Ada is also a
// legitimate member of orgB — fails with the typed Conflict AND leaves
// orgB's membership byte-identical. Conflict-path leaks are the
// load-bearing analogue here of the BE-0428 user-email-conflict proof:
// a constraint that fires AFTER any of the row's triggers could
// otherwise stamp orgB's updated_at before rolling back.
func TestMembershipRepositoryInsertConflictOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	adaID := seedUser(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, adaID, "owner", 4)
	seedMembership(t, db, orgB.ID, adaID, "member", 8)

	var baselineA, baselineB store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		baselineA, readErr = repo.Get(ctx, q, orgA.ID, adaID)
		if readErr != nil {
			return readErr
		}
		baselineB, readErr = repo.Get(ctx, q, orgB.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("baseline Get: %v", err)
	}

	// Try to re-Insert (orgA, ada) under a different (still-valid) role.
	// The composite PRIMARY KEY must catch it and the typed Conflict
	// must come back — never the raw driver error and never a silent
	// overwrite.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, writeErr := repo.Insert(ctx, tx, orgA.ID, adaID, "admin")
		return writeErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate Insert(orgA, ada) error code = %v, want %s", err, yerr.CodeConflict)
	}

	// orgA's existing row must be byte-identical to the baseline — the
	// conflicting INSERT rolled back without partial-write damage.
	var afterA store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterA, readErr = repo.Get(ctx, q, orgA.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(orgA, ada): %v", err)
	}
	if afterA.Role != baselineA.Role || afterA.RoleVersion != baselineA.RoleVersion {
		t.Errorf("orgA row mutated by failed duplicate Insert: got role=%q version=%d, want role=%q version=%d",
			afterA.Role, afterA.RoleVersion, baselineA.Role, baselineA.RoleVersion)
	}
	if !afterA.CreatedAt.Equal(baselineA.CreatedAt) || !afterA.UpdatedAt.Equal(baselineA.UpdatedAt) {
		t.Errorf("orgA timestamps drifted after failed duplicate Insert: got %+v, want %+v", afterA, baselineA)
	}

	// orgB's bystander row is the critical safety net — a regression
	// where the rolled-back Insert touched the wrong row would have
	// stamped orgB.updated_at via the trigger.
	var afterB store.Membership
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterB, readErr = repo.Get(ctx, q, orgB.ID, adaID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(orgB, ada): %v", err)
	}
	if afterB.Role != baselineB.Role || afterB.RoleVersion != baselineB.RoleVersion {
		t.Errorf("orgB row mutated by failed duplicate Insert(orgA): got role=%q version=%d, want role=%q version=%d",
			afterB.Role, afterB.RoleVersion, baselineB.Role, baselineB.RoleVersion)
	}
	if !afterB.CreatedAt.Equal(baselineB.CreatedAt) {
		t.Errorf("orgB.created_at = %v, want %v — failed Insert(orgA) reset orgB.created_at", afterB.CreatedAt, baselineB.CreatedAt)
	}
	if !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) {
		t.Errorf("orgB.updated_at = %v, want %v — failed Insert(orgA) refreshed orgB.updated_at via the trigger", afterB.UpdatedAt, baselineB.UpdatedAt)
	}
}

// TestMembershipRepositoryListByOrganizationCountsAreIsolated proves the
// rendered length of ListByOrganization is local to the queried tenant
// — never the global count, never a sum across tenants. orgA has one
// member; orgB has three. List(orgA) must return exactly 1 row;
// List(orgB) must return exactly 3. A SELECT without the WHERE
// organization_id filter would have returned 4 for both calls.
func TestMembershipRepositoryListByOrganizationCountsAreIsolated(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	adaID := seedUser(t, db, f, orgA, "ada")
	beaID := seedUser(t, db, f, orgB, "bea")
	caraID := seedUser(t, db, f, orgB, "cara")
	deeID := seedUser(t, db, f, orgB, "dee")
	seedMembership(t, db, orgA.ID, adaID, "owner", 1)
	seedMembership(t, db, orgB.ID, beaID, "owner", 1)
	seedMembership(t, db, orgB.ID, caraID, "admin", 1)
	seedMembership(t, db, orgB.ID, deeID, "member", 1)

	var gotA []store.OrganizationMember
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.ListByOrganization(ctx, q, orgA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(gotA) != 1 {
		t.Errorf("ListByOrganization(orgA) returned %d rows, want 1 — orgB membership rows leaked", len(gotA))
	}
	for _, m := range gotA {
		if m.OrganizationID != orgA.ID {
			t.Errorf("ListByOrganization(orgA) returned a foreign row: %+v", m)
		}
	}

	var gotB []store.OrganizationMember
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.ListByOrganization(ctx, q, orgB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB): %v", err)
	}
	if len(gotB) != 3 {
		t.Errorf("ListByOrganization(orgB) returned %d rows, want 3", len(gotB))
	}
	for _, m := range gotB {
		if m.OrganizationID != orgB.ID {
			t.Errorf("ListByOrganization(orgB) returned a foreign row: %+v", m)
		}
	}

	// The two responses must not overlap — if they did, the WHERE
	// filter is the only thing keeping them apart, and the only way
	// for both calls to share a row is a WHERE-less SELECT.
	seenInB := make(map[string]struct{}, len(gotB))
	for _, m := range gotB {
		seenInB[m.UserID] = struct{}{}
	}
	for _, m := range gotA {
		if _, overlap := seenInB[m.UserID]; overlap {
			t.Errorf("user %q appears in both List(orgA) and List(orgB) responses", m.UserID)
		}
	}
}

// TestMembershipRepositoryListByOrganizationIsolatesSharedUser proves
// that when the SAME user is a member of BOTH tenants, ListByOrganization
// renders only THIS tenant's row for that user — not both rows joined,
// not the other tenant's row, not a duplicate. This is the
// shared-user-row safety net that complements the disjoint-user-base
// count test above: a join that accidentally produced a row per
// (membership × every memberships row for the same user_id) would
// double-count Ada in one or both lists.
func TestMembershipRepositoryListByOrganizationIsolatesSharedUser(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	adaID := seedUser(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, adaID, "owner", 1)
	seedMembership(t, db, orgB.ID, adaID, "member", 9)

	var gotA []store.OrganizationMember
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.ListByOrganization(ctx, q, orgA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(gotA) != 1 {
		t.Fatalf("ListByOrganization(orgA) returned %d rows, want exactly 1 — orgB's membership for the same user leaked or duplicated", len(gotA))
	}
	if gotA[0].OrganizationID != orgA.ID || gotA[0].UserID != adaID || gotA[0].Role != "owner" || gotA[0].RoleVersion != 1 {
		t.Errorf("ListByOrganization(orgA)[0] = %+v, want orgA/ada/owner/1", gotA[0])
	}

	var gotB []store.OrganizationMember
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.ListByOrganization(ctx, q, orgB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB): %v", err)
	}
	if len(gotB) != 1 {
		t.Fatalf("ListByOrganization(orgB) returned %d rows, want exactly 1 — orgA's membership for the same user leaked or duplicated", len(gotB))
	}
	if gotB[0].OrganizationID != orgB.ID || gotB[0].UserID != adaID || gotB[0].Role != "member" || gotB[0].RoleVersion != 9 {
		t.Errorf("ListByOrganization(orgB)[0] = %+v, want orgB/ada/member/9", gotB[0])
	}
}

// TestMembershipRepositoryCrossTenantErrorIsIndistinguishableFromUnknownPair
// proves the cross-tenant NotFound shape — Code AND Hint — is the SAME
// shape an unknown (organization_id, user_id) pair produces. A probing
// caller who guesses a peer tenant's user_id cannot infer that the user
// IS a member of another tenant from the response: both surfaces emit
// yerr.CodeNotFound with matching Hint values. This is the analogue of
// BE-0428's "real-but-non-member id and unknown id are indistinguishable"
// proof, adapted for the composite-key link table.
func TestMembershipRepositoryCrossTenantErrorIsIndistinguishableFromUnknownPair(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewMembershipRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	adaID := seedUser(t, db, f, orgB, "ada") // member of orgB ONLY
	seedMembership(t, db, orgB.ID, adaID, "owner", 1)

	// Cross-tenant probe: (orgA, ada). Ada is a real user and IS a
	// member of a different tenant, but not of orgA.
	crossTenantErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, adaID)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Get error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	// Wholly unknown pair: (orgA, never-seeded-user-id).
	unknownErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, "usr_no_such_user_ever")
		return err
	})
	var yeUnknown *yerr.Error
	if !stderrors.As(unknownErr, &yeUnknown) || yeUnknown.Code != yerr.CodeNotFound {
		t.Fatalf("unknown-pair Get error = %v, want a typed E_NOT_FOUND", unknownErr)
	}

	// The two shapes must be indistinguishable on Code AND Hint — a
	// caller who diffed the response surfaces could otherwise enumerate
	// peers by probing user ids.
	if yeCross.Code != yeUnknown.Code {
		t.Errorf("cross-tenant Code = %s, unknown-pair Code = %s — existence leaks via Code", yeCross.Code, yeUnknown.Code)
	}
	if yeCross.Hint != yeUnknown.Hint {
		t.Errorf("cross-tenant Hint = %q, unknown-pair Hint = %q — existence leaks via Hint", yeCross.Hint, yeUnknown.Hint)
	}

	// The same indistinguishability check must hold for the JOIN-bearing
	// GetMember read — a divergence in the JOIN'd version of NotFound
	// would be a separate leak surface.
	crossTenantMemberErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.GetMember(ctx, q, orgA.ID, adaID)
		return err
	})
	var yeCrossMember *yerr.Error
	if !stderrors.As(crossTenantMemberErr, &yeCrossMember) || yeCrossMember.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant GetMember error = %v, want a typed E_NOT_FOUND", crossTenantMemberErr)
	}
	unknownMemberErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.GetMember(ctx, q, orgA.ID, "usr_no_such_user_ever")
		return err
	})
	var yeUnknownMember *yerr.Error
	if !stderrors.As(unknownMemberErr, &yeUnknownMember) || yeUnknownMember.Code != yerr.CodeNotFound {
		t.Fatalf("unknown-pair GetMember error = %v, want a typed E_NOT_FOUND", unknownMemberErr)
	}
	if yeCrossMember.Code != yeUnknownMember.Code || yeCrossMember.Hint != yeUnknownMember.Hint {
		t.Errorf("GetMember cross-tenant vs unknown-pair diverge: cross={Code=%s,Hint=%q} unknown={Code=%s,Hint=%q}",
			yeCrossMember.Code, yeCrossMember.Hint, yeUnknownMember.Code, yeUnknownMember.Hint)
	}
}
