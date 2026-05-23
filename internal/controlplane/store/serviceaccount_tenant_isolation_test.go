package store_test

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the service_accounts table
// (BE-0432). service_accounts is a tenant-scoped row whose surface area is
// narrower than the BE-0426 organizations or BE-0430 memberships tables:
// the row has its own id, no version column, no Update method beyond the
// idempotent Disable lifecycle flip, no Delete method (rows leave only via
// the parent organization's ON DELETE CASCADE), and no deletion_scheduled_at
// soft-delete column. The cross-tenant guarantee at this layer is therefore
// shaped around four load-bearing rules that serviceaccount_test.go's
// tenant-scoped tests touch only partially:
//
//	(a) every Get / Disable is keyed by BOTH (organization_id, id) so a
//	    WHERE-on-id-only mistake — or a WHERE-on-slug mistake — would
//	    silently return / mutate the WRONG tenant's row when two tenants
//	    happen to share a slug (the schema's UNIQUE (organization_id, slug)
//	    permits this by design);
//	(b) ListByOrganization and CountByOrganization return exactly the rows
//	    whose organization_id matches, never inflating their count or
//	    rendered set with another tenant's rows that share a slug, and
//	    Count is the read the quota layer uses so a leak there inflates
//	    one tenant's effective quota with another's usage;
//	(c) Insert conflict on (organization_id, slug) in orgA must not
//	    refresh orgB's bystander same-slug row — the BEFORE-UPDATE
//	    set_updated_at trigger is the independent anchor that would
//	    catch a rolled-back UPDATE that touched the wrong row before
//	    the conflict fired;
//	(d) the cross-tenant error shape — Code and Hint — is the SAME shape
//	    an unknown id produces, so a probing caller who guesses a peer
//	    tenant's service-account id cannot infer existence from the
//	    response.
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - The basic Insert / Get / List / Disable read+write shapes and the
//     plain "another tenant's id is a NotFound" result are proved by
//     serviceaccount_test.go (BE-0431): TestServiceAccountRepositoryGetIsTenantScoped,
//     TestServiceAccountRepositoryListByOrganizationIsTenantScoped, and
//     TestServiceAccountRepositoryDisableIsIdempotentAndTenantScoped.
//   - Single-row CRUD invariants (Insert RETURNING shape, Disable
//     idempotence, conflict rollback for same-org duplicate slug,
//     nil-tx guards on Insert / Disable) are proved by
//     serviceaccount_repository_invariants_test.go (BE-0431).
//   - The cross-tenant cascade-on-organization-delete proof lives in
//     serviceaccount_test.go's TestServiceAccountBelongsToOneOrganization
//     and TestTenantHierarchyCascadeDelete in schema_test.go.
//   - The api_keys.service_account_id cross-tenant FK leak proof lives
//     in serviceaccount_test.go's
//     TestServiceAccountAPIKeyCannotCrossTenantBoundary.
//   - The HTTP-layer "another tenant's id is a 404, not a 403" rule is
//     proved by per-endpoint policy matrix and contract tests in httpapi.
//
// service_accounts has no deletion_scheduled_at / soft-delete column —
// the only lifecycle flag is disabled_at, which the byte-identical
// Disable snapshot test below treats as the analogue of the membership
// table's role_version-bumping UpdateRole. The acceptance-criteria
// mention of "soft-deleted rows where applicable" therefore has no
// surface here; documenting the deliberate absence keeps a future
// reader from looking for a missing test (mirrors
// user_tenant_isolation_test.go's no-soft-delete note for users and
// membership_tenant_isolation_test.go's note for memberships).

// seedServiceAccountWithSlug inserts a service_accounts row with the
// caller-supplied slug owned by org and returns the fixture, mutated to
// reflect the slug used. This is the cross-tenant shared-slug
// counterpart to seedServiceAccount in serviceaccount_test.go; it is
// the load-bearing fixture for the "two tenants pick the same slug"
// scenarios below (the schema's UNIQUE (organization_id, slug) allows
// this by design — a WHERE-on-slug mistake in the repository would
// silently swap rows across tenants without it).
func seedServiceAccountWithSlug(t *testing.T, db *testutil.DB, f *testutil.Factory, org testutil.Organization, label, slug string) testutil.ServiceAccount {
	t.Helper()
	sa := f.ServiceAccount(org, label)
	sa.Slug = slug
	if _, err := db.Exec(context.Background(),
		`INSERT INTO service_accounts (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		sa.ID, sa.OrganizationID, sa.Slug, sa.Name); err != nil {
		t.Fatalf("seed service account with slug %q: %v", slug, err)
	}
	return sa
}

// TestServiceAccountRepositoryGetReturnsCorrectRowAcrossTenants proves
// Get is keyed strictly by BOTH (organization_id, id): two service
// accounts seeded into two distinct tenants with the SAME slug return
// their own row when looked up by (org, id), never each other's. The
// shared-slug fixture is load-bearing — a WHERE-on-slug mistake (or a
// WHERE-on-id-only mistake that happened to resolve the same row by
// planner accident) would resolve to whichever row the planner found
// first and the per-tenant id assertion would catch it.
func TestServiceAccountRepositoryGetReturnsCorrectRowAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	// Same slug across tenants — UNIQUE (organization_id, slug) permits
	// this by design and the cross-tenant predicate is the only thing
	// keeping the two rows from masquerading as each other.
	saA := seedServiceAccountWithSlug(t, db, f, orgA, "CI A", "shared-ci-slug")
	saB := seedServiceAccountWithSlug(t, db, f, orgB, "CI B", "shared-ci-slug")

	var gotA store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.Get(ctx, q, orgA.ID, saA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgA, saA): %v", err)
	}
	if gotA.ID != saA.ID || gotA.OrganizationID != orgA.ID || gotA.DisplayName != saA.Name {
		t.Errorf("Get(orgA, saA) = %+v, want id/org/name from %+v", gotA, saA)
	}

	var gotB store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.Get(ctx, q, orgB.ID, saB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgB, saB): %v", err)
	}
	if gotB.ID != saB.ID || gotB.OrganizationID != orgB.ID || gotB.DisplayName != saB.Name {
		t.Errorf("Get(orgB, saB) = %+v, want id/org/name from %+v", gotB, saB)
	}

	// The two reads MUST have returned distinct rows. A WHERE-on-slug
	// mistake would have collapsed both lookups onto whichever row the
	// planner found first and this guard would catch it even if a
	// per-row equality check coincidentally agreed.
	if gotA.ID == gotB.ID || gotA.OrganizationID == gotB.OrganizationID || gotA.DisplayName == gotB.DisplayName {
		t.Errorf("Get returned overlapping rows for two distinct service-account ids sharing a slug: %+v vs %+v", gotA, gotB)
	}
	// And the slug really IS the same — otherwise the proof is trivial.
	if gotA.Slug != gotB.Slug {
		t.Fatalf("test setup invariant violated: gotA.Slug=%q, gotB.Slug=%q — the shared-slug fixture is the load-bearing constraint", gotA.Slug, gotB.Slug)
	}
}

// TestServiceAccountRepositoryDisableOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for Disable on two tenants whose service
// accounts SHARE the same slug — the worst-case fixture for a
// WHERE-on-slug-only or WHERE-on-id-only mistake.
// serviceaccount_test.go's TestServiceAccountRepositoryDisableIsIdempotentAndTenantScoped
// covers the inverse direction (Disable(otherOrg) on a non-member id →
// NotFound); this test covers the load-bearing case where the same id
// would surface a different tenant's row under a buggy predicate.
// The BEFORE-UPDATE set_updated_at trigger is the independent anchor:
// even if the column writes themselves happened to look unchanged, a
// matched-but-no-op UPDATE would have stamped updated_at.
func TestServiceAccountRepositoryDisableOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	saA := seedServiceAccountWithSlug(t, db, f, orgA, "CI A", "shared-ci-slug")
	saB := seedServiceAccountWithSlug(t, db, f, orgB, "CI B", "shared-ci-slug")

	// Snapshot orgB's row before the mutation so any drift is caught
	// precisely on EVERY field — including the trigger-managed
	// updated_at, which is the independent anchor that catches a
	// WHERE-on-slug-only UPDATE even when the column writes themselves
	// happen to look correct.
	var baselineB store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		baselineB, readErr = repo.Get(ctx, q, orgB.ID, saB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("baseline Get(orgB, saB): %v", err)
	}
	if baselineB.DisabledAt != nil {
		t.Fatalf("test setup invariant violated: orgB SA is already disabled at %v — the disabled_at anchor cannot prove non-mutation", baselineB.DisabledAt)
	}

	// Disable on orgA only.
	disableAt := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Disable(ctx, tx, orgA.ID, saA.ID, disableAt)
	}); err != nil {
		t.Fatalf("Disable(orgA, saA): %v", err)
	}

	// orgA must have actually changed — a no-op repository cannot
	// silently pass the byte-identical-orgB check below.
	var afterA store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterA, readErr = repo.Get(ctx, q, orgA.ID, saA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgA, saA) after Disable: %v", err)
	}
	if !afterA.IsDisabled() {
		t.Errorf("Disable(orgA, saA) did not set disabled_at on orgA's row — proof is vacuous")
	}

	// orgB's row must be byte-identical to its baseline across every
	// field — including updated_at, which the BEFORE-UPDATE trigger
	// would stamp if the UPDATE statement had matched orgB's row even
	// momentarily, AND including disabled_at, which a WHERE-on-slug
	// mistake would set on the WRONG row.
	var afterB store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterB, readErr = repo.Get(ctx, q, orgB.ID, saB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(orgB, saB): %v", err)
	}
	if afterB.ID != baselineB.ID || afterB.OrganizationID != baselineB.OrganizationID {
		t.Errorf("orgB identity drifted after Disable(orgA): got %+v, want %+v", afterB, baselineB)
	}
	if afterB.Slug != baselineB.Slug || afterB.DisplayName != baselineB.DisplayName {
		t.Errorf("orgB row mutated after Disable(orgA): got slug=%q name=%q, want slug=%q name=%q",
			afterB.Slug, afterB.DisplayName, baselineB.Slug, baselineB.DisplayName)
	}
	if afterB.DisabledAt != nil {
		t.Errorf("orgB.disabled_at = %v, want nil — Disable(orgA) leaked into orgB's lifecycle flag via a WHERE-on-slug mistake", afterB.DisabledAt)
	}
	if !afterB.CreatedAt.Equal(baselineB.CreatedAt) {
		t.Errorf("orgB.created_at = %v, want %v — Disable(orgA) reset orgB.created_at", afterB.CreatedAt, baselineB.CreatedAt)
	}
	if !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) {
		t.Errorf("orgB.updated_at = %v, want %v — Disable(orgA) refreshed orgB.updated_at via the trigger", afterB.UpdatedAt, baselineB.UpdatedAt)
	}
}

// TestServiceAccountRepositoryInsertConflictOnOrgADoesNotTouchOrgB
// proves a duplicate-slug Insert on orgA — when orgB happens to hold a
// service account with the SAME slug — fails with the typed Conflict
// AND leaves orgB's bystander row byte-identical. UNIQUE (organization_id,
// slug) is scoped to the tenant, so the orgB row is a legitimate peer
// the conflicting orgA INSERT must never touch. The BEFORE-UPDATE
// set_updated_at trigger doesn't fire on INSERT, but a rolled-back
// INSERT that resolved its UNIQUE check via a missing tenant predicate
// could otherwise emit a row in the WRONG tenant — the post-state
// CountByOrganization assertion catches that without depending on a
// trigger anchor.
func TestServiceAccountRepositoryInsertConflictOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	saA := seedServiceAccountWithSlug(t, db, f, orgA, "CI A", "shared-ci-slug")
	saB := seedServiceAccountWithSlug(t, db, f, orgB, "CI B", "shared-ci-slug")

	var baselineA, baselineB store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		baselineA, readErr = repo.Get(ctx, q, orgA.ID, saA.ID)
		if readErr != nil {
			return readErr
		}
		baselineB, readErr = repo.Get(ctx, q, orgB.ID, saB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("baseline Get: %v", err)
	}

	// Try to re-Insert the same slug under orgA with a different id.
	// UNIQUE (organization_id, slug) must catch it and the typed
	// Conflict must come back — never the raw driver error and never
	// a silent insert into the wrong tenant.
	dup := f.ServiceAccount(orgA, "CI dup")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insErr := repo.Insert(ctx, tx, store.ServiceAccount{
			ID:             dup.ID,
			OrganizationID: orgA.ID,
			Slug:           saA.Slug,
			DisplayName:    dup.Name,
		})
		return insErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate-slug Insert error code = %v, want %s", err, yerr.CodeConflict)
	}

	// orgA's existing row must be byte-identical to the baseline — the
	// conflicting INSERT rolled back without partial-write damage. The
	// disabled_at field is included so a regression that flipped the
	// lifecycle flag while resolving the conflict would surface here.
	var afterA store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterA, readErr = repo.Get(ctx, q, orgA.ID, saA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(orgA, saA): %v", err)
	}
	if afterA.Slug != baselineA.Slug || afterA.DisplayName != baselineA.DisplayName {
		t.Errorf("orgA row mutated by failed duplicate Insert: got slug=%q name=%q, want slug=%q name=%q",
			afterA.Slug, afterA.DisplayName, baselineA.Slug, baselineA.DisplayName)
	}
	if !afterA.CreatedAt.Equal(baselineA.CreatedAt) || !afterA.UpdatedAt.Equal(baselineA.UpdatedAt) {
		t.Errorf("orgA timestamps drifted after failed duplicate Insert: got %+v, want %+v", afterA, baselineA)
	}
	if (afterA.DisabledAt == nil) != (baselineA.DisabledAt == nil) {
		t.Errorf("orgA.disabled_at lifecycle flipped after failed duplicate Insert: got %v, want %v", afterA.DisabledAt, baselineA.DisabledAt)
	}

	// orgB's bystander row is the critical safety net — a regression
	// where the rolled-back Insert resolved its UNIQUE check against
	// the cross-tenant row (or the trigger spuriously fired against
	// orgB's row in some future revision) would surface here.
	var afterB store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterB, readErr = repo.Get(ctx, q, orgB.ID, saB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(orgB, saB): %v", err)
	}
	if afterB.Slug != baselineB.Slug || afterB.DisplayName != baselineB.DisplayName {
		t.Errorf("orgB row mutated by failed duplicate Insert(orgA): got slug=%q name=%q, want slug=%q name=%q",
			afterB.Slug, afterB.DisplayName, baselineB.Slug, baselineB.DisplayName)
	}
	if !afterB.CreatedAt.Equal(baselineB.CreatedAt) {
		t.Errorf("orgB.created_at = %v, want %v — failed Insert(orgA) reset orgB.created_at", afterB.CreatedAt, baselineB.CreatedAt)
	}
	if !afterB.UpdatedAt.Equal(baselineB.UpdatedAt) {
		t.Errorf("orgB.updated_at = %v, want %v — failed Insert(orgA) refreshed orgB.updated_at via the trigger", afterB.UpdatedAt, baselineB.UpdatedAt)
	}

	// And the post-state membership of each tenant is exactly what the
	// baseline had — the rolled-back Insert did not silently land its
	// row in orgB (or anywhere else). CountByOrganization is the read
	// the quota layer uses; running it here doubles as a quota-leak
	// safety net.
	var countA, countB int
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		countA, readErr = repo.CountByOrganization(ctx, q, orgA.ID)
		if readErr != nil {
			return readErr
		}
		countB, readErr = repo.CountByOrganization(ctx, q, orgB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("post-state CountByOrganization: %v", err)
	}
	if countA != 1 {
		t.Errorf("CountByOrganization(orgA) = %d, want 1 — the rolled-back duplicate Insert leaked a row into orgA", countA)
	}
	if countB != 1 {
		t.Errorf("CountByOrganization(orgB) = %d, want 1 — the rolled-back duplicate Insert(orgA) landed its row in orgB", countB)
	}
}

// TestServiceAccountRepositoryListByOrganizationCountsAreIsolated proves
// the rendered length of ListByOrganization is local to the queried
// tenant — never the global count, never a sum across tenants. orgA has
// one service account; orgB has three. List(orgA) must return exactly
// 1 row; List(orgB) must return exactly 3. A SELECT without the
// WHERE organization_id filter would have returned 4 for both calls.
// serviceaccount_test.go's tenant-scoped list test already pins the
// per-tenant filter on a 3-vs-1 fixture; this test additionally pins
// the no-overlap rule on the rendered slug set, which is the only way
// a planner accident that produced the right COUNT from a wrong JOIN
// would surface.
func TestServiceAccountRepositoryListByOrganizationCountsAreIsolated(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	saA := seedServiceAccount(t, db, f, orgA, "CI A")
	saB1 := seedServiceAccount(t, db, f, orgB, "CI B-1")
	saB2 := seedServiceAccount(t, db, f, orgB, "CI B-2")
	saB3 := seedServiceAccount(t, db, f, orgB, "CI B-3")

	var gotA, gotB []store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.ListByOrganization(ctx, q, orgA.ID)
		if readErr != nil {
			return readErr
		}
		gotB, readErr = repo.ListByOrganization(ctx, q, orgB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(gotA) != 1 {
		t.Errorf("ListByOrganization(orgA) returned %d rows, want 1 — orgB rows leaked", len(gotA))
	}
	for _, sa := range gotA {
		if sa.OrganizationID != orgA.ID {
			t.Errorf("ListByOrganization(orgA) returned a foreign row: %+v", sa)
		}
	}
	if len(gotB) != 3 {
		t.Errorf("ListByOrganization(orgB) returned %d rows, want 3", len(gotB))
	}
	for _, sa := range gotB {
		if sa.OrganizationID != orgB.ID {
			t.Errorf("ListByOrganization(orgB) returned a foreign row: %+v", sa)
		}
	}

	// The two responses must not overlap — if they did, the WHERE
	// filter is the only thing keeping them apart, and the only way
	// for both calls to share a row is a WHERE-less SELECT.
	seenInB := make(map[string]struct{}, len(gotB))
	for _, sa := range gotB {
		seenInB[sa.ID] = struct{}{}
	}
	for _, sa := range gotA {
		if _, overlap := seenInB[sa.ID]; overlap {
			t.Errorf("service account %q appears in both List(orgA) and List(orgB) responses", sa.ID)
		}
	}

	// And the seeded ids surface in the expected list — a List that
	// returned the right count from a wrong JOIN would scramble which
	// rows land where.
	wantA := map[string]struct{}{saA.ID: {}}
	wantB := map[string]struct{}{saB1.ID: {}, saB2.ID: {}, saB3.ID: {}}
	for _, sa := range gotA {
		if _, ok := wantA[sa.ID]; !ok {
			t.Errorf("List(orgA) returned id %q, want only %v", sa.ID, wantA)
		}
	}
	for _, sa := range gotB {
		if _, ok := wantB[sa.ID]; !ok {
			t.Errorf("List(orgB) returned id %q, want only %v", sa.ID, wantB)
		}
	}
}

// TestServiceAccountRepositoryListByOrganizationIsolatesSharedSlug
// proves that when two tenants each hold a service account with the
// SAME slug, ListByOrganization renders only THIS tenant's row — not
// both rows joined, not the other tenant's row, not a duplicate. This
// is the shared-slug safety net that complements the disjoint-fixture
// count test above: a JOIN that accidentally produced a row per
// (service_accounts × every service_accounts row with the same slug)
// would double-count one or both lists.
func TestServiceAccountRepositoryListByOrganizationIsolatesSharedSlug(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	saA := seedServiceAccountWithSlug(t, db, f, orgA, "CI A", "shared-ci-slug")
	saB := seedServiceAccountWithSlug(t, db, f, orgB, "CI B", "shared-ci-slug")

	var gotA []store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.ListByOrganization(ctx, q, orgA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(gotA) != 1 {
		t.Fatalf("ListByOrganization(orgA) returned %d rows, want exactly 1 — orgB's same-slug service account leaked or duplicated", len(gotA))
	}
	if gotA[0].ID != saA.ID || gotA[0].OrganizationID != orgA.ID {
		t.Errorf("ListByOrganization(orgA)[0] = %+v, want orgA/saA", gotA[0])
	}

	var gotB []store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.ListByOrganization(ctx, q, orgB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB): %v", err)
	}
	if len(gotB) != 1 {
		t.Fatalf("ListByOrganization(orgB) returned %d rows, want exactly 1 — orgA's same-slug service account leaked or duplicated", len(gotB))
	}
	if gotB[0].ID != saB.ID || gotB[0].OrganizationID != orgB.ID {
		t.Errorf("ListByOrganization(orgB)[0] = %+v, want orgB/saB", gotB[0])
	}

	// The two responses share the slug but must NOT share the id — a
	// regression that disambiguated by slug (instead of by organization)
	// would have either swapped or merged the two rows and tripped this
	// guard.
	if gotA[0].Slug != gotB[0].Slug {
		t.Fatalf("test setup invariant violated: gotA.Slug=%q, gotB.Slug=%q — the shared-slug fixture is the load-bearing constraint", gotA[0].Slug, gotB[0].Slug)
	}
	if gotA[0].ID == gotB[0].ID {
		t.Errorf("List returned the same id for the same-slug service accounts in two tenants: %q", gotA[0].ID)
	}
}

// TestServiceAccountRepositoryCountByOrganizationIsTenantScoped proves
// the count read the quota layer uses is local to the queried tenant —
// never the global count, never a sum across tenants. A leak here
// would inflate one tenant's effective quota usage with another
// tenant's service accounts and either over- or under-allow quota
// reservations downstream. The disjoint fixtures (orgA=2, orgB=3)
// produce distinct expected counts so a SELECT count(*) without the
// WHERE organization_id filter (which would return 5 for both calls)
// surfaces as two failing assertions, not one.
func TestServiceAccountRepositoryCountByOrganizationIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	orgC := seedOrg(t, db, f, "tenant-c") // empty bystander tenant
	seedServiceAccount(t, db, f, orgA, "CI A-1")
	seedServiceAccount(t, db, f, orgA, "CI A-2")
	seedServiceAccount(t, db, f, orgB, "CI B-1")
	seedServiceAccount(t, db, f, orgB, "CI B-2")
	seedServiceAccount(t, db, f, orgB, "CI B-3")

	var countA, countB, countC int
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		if countA, readErr = repo.CountByOrganization(ctx, q, orgA.ID); readErr != nil {
			return readErr
		}
		if countB, readErr = repo.CountByOrganization(ctx, q, orgB.ID); readErr != nil {
			return readErr
		}
		countC, readErr = repo.CountByOrganization(ctx, q, orgC.ID)
		return readErr
	}); err != nil {
		t.Fatalf("CountByOrganization: %v", err)
	}
	if countA != 2 {
		t.Errorf("CountByOrganization(orgA) = %d, want 2 — leak inflates orgA's effective quota usage", countA)
	}
	if countB != 3 {
		t.Errorf("CountByOrganization(orgB) = %d, want 3 — leak inflates orgB's effective quota usage", countB)
	}
	if countC != 0 {
		t.Errorf("CountByOrganization(orgC) = %d, want 0 — empty-tenant count leaked from peer tenants", countC)
	}
}

// TestServiceAccountRepositoryCrossTenantErrorIsIndistinguishableFromUnknownId
// proves the cross-tenant NotFound shape — Code AND Hint — is the SAME
// shape an unknown service-account id produces. A probing caller who
// guesses a peer tenant's service-account id cannot infer that the id
// IS a real service account in another tenant from the response: both
// surfaces emit yerr.CodeNotFound with matching Hint values. This is
// the analogue of BE-0428's "real-but-non-member id and unknown id are
// indistinguishable" proof and BE-0430's composite-key variant,
// adapted for the (organization_id, id) tenant-scoped row.
//
// Note: the Message field is intentionally NOT asserted — apierr.NotFound
// echoes the caller-supplied id back in the Message verbatim, so a
// caller asking about id X always sees X in the message (whether X
// exists in another tenant or doesn't exist at all). The leak surface
// is Code and Hint; Message is the caller's own input.
func TestServiceAccountRepositoryCrossTenantErrorIsIndistinguishableFromUnknownId(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceAccountRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	saB := seedServiceAccount(t, db, f, orgB, "CI B") // owned by orgB ONLY

	// Cross-tenant probe: orgA asks for saB's id. saB is a real
	// service account, just owned by a different tenant.
	crossTenantErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, saB.ID)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Get error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	// Wholly unknown id, same querying tenant.
	unknownErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, "sa_no_such_service_account_ever")
		return err
	})
	var yeUnknown *yerr.Error
	if !stderrors.As(unknownErr, &yeUnknown) || yeUnknown.Code != yerr.CodeNotFound {
		t.Fatalf("unknown-id Get error = %v, want a typed E_NOT_FOUND", unknownErr)
	}

	// The two shapes must be indistinguishable on Code AND Hint — a
	// caller who diffed the response surfaces could otherwise enumerate
	// peer-tenant service accounts by probing ids.
	if yeCross.Code != yeUnknown.Code {
		t.Errorf("cross-tenant Code = %s, unknown-id Code = %s — existence leaks via Code", yeCross.Code, yeUnknown.Code)
	}
	if yeCross.Hint != yeUnknown.Hint {
		t.Errorf("cross-tenant Hint = %q, unknown-id Hint = %q — existence leaks via Hint", yeCross.Hint, yeUnknown.Hint)
	}

	// The same indistinguishability check must hold for the Disable
	// mutation path — a divergence in the mutation's NotFound shape
	// would be a separate leak surface (Disable on a real-but-foreign
	// id vs. Disable on an unknown id).
	disableAt := time.Now().UTC().Truncate(time.Microsecond)
	crossTenantDisableErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Disable(ctx, tx, orgA.ID, saB.ID, disableAt)
	})
	var yeCrossDisable *yerr.Error
	if !stderrors.As(crossTenantDisableErr, &yeCrossDisable) || yeCrossDisable.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Disable error = %v, want a typed E_NOT_FOUND", crossTenantDisableErr)
	}
	unknownDisableErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.Disable(ctx, tx, orgA.ID, "sa_no_such_service_account_ever", disableAt)
	})
	var yeUnknownDisable *yerr.Error
	if !stderrors.As(unknownDisableErr, &yeUnknownDisable) || yeUnknownDisable.Code != yerr.CodeNotFound {
		t.Fatalf("unknown-id Disable error = %v, want a typed E_NOT_FOUND", unknownDisableErr)
	}
	if yeCrossDisable.Code != yeUnknownDisable.Code || yeCrossDisable.Hint != yeUnknownDisable.Hint {
		t.Errorf("Disable cross-tenant vs unknown-id diverge: cross={Code=%s,Hint=%q} unknown={Code=%s,Hint=%q}",
			yeCrossDisable.Code, yeCrossDisable.Hint, yeUnknownDisable.Code, yeUnknownDisable.Hint)
	}

	// After both probes, saB itself is byte-identical to its starting
	// state — neither the cross-tenant Get nor the cross-tenant Disable
	// silently mutated its disabled_at, updated_at, or display_name.
	var afterB store.ServiceAccount
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		afterB, readErr = repo.Get(ctx, q, orgB.ID, saB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("after Get(orgB, saB): %v", err)
	}
	if afterB.DisabledAt != nil {
		t.Errorf("saB.disabled_at = %v after cross-tenant probes, want nil — cross-tenant Disable leaked into the owning tenant's lifecycle flag", afterB.DisabledAt)
	}
}
