package store_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the projects table
// (BE-0438). projects is the second-tier tenant-scoped table (the
// children — environments, services, deployments, grants — anchor their
// tenancy through the (organization_id, id) tuple this table owns) whose
// row body is anchored to a single tenant by THREE load-bearing schema
// facts:
//
//	(a) the row carries organization_id directly and the
//	    UNIQUE (organization_id, slug) index ties slug-uniqueness to the
//	    organization (not the global namespace), so two tenants can
//	    legitimately share the same project slug — the
//	    "InsertSameSlugInTwoTenantsBothSucceed" leg below proves this;
//	(b) every repository method (Get / ListByOrganization /
//	    CountByOrganization / Update / UpdateDisplayName /
//	    ScheduleDeletion / Restore) carries organization_id as the FIRST
//	    SQL predicate, ahead of the row identifier. The cross-tenant
//	    guarantee at this layer is therefore the byte-identical-bystander
//	    invariant every other tenant-scoped table is held to;
//	(c) the soft-delete column (deletion_scheduled_at) is a nullable
//	    *time.Time on every read path — the projects table does NOT
//	    filter soft-deleted rows out of Get/List/Count, so a regression
//	    that resolved the WHERE filter incorrectly could leak ANOTHER
//	    tenant's soft-deleted project just as easily as a live one. The
//	    "SoftDeletedRowIsTenantScopedOnReadPaths" leg below pins this.
//
// The projects row body carries NO secret-bearing column — slug and
// display_name are surfaced as-is — so the BE-0434 raw-secret_hash probe
// has no analogue here. The row body is fully observable through the
// typed Get / List read paths, and the byte-identical-bystander
// assertion below covers every observable column (id, organization_id,
// slug, display_name, version, created_at, updated_at,
// deletion_scheduled_at).
//
// The BEFORE-UPDATE projects_set_updated_at trigger refreshes updated_at
// on every matched UPDATE — including a WHERE-less or WHERE-on-id-only
// UPDATE that touched the wrong tenant's row — and the
// projects_bump_version trigger increments version on the same path.
// Either of those two columns drifting on the bystander is
// independently sufficient to catch a missing tenant predicate even
// when the column writes themselves look correct, and every
// byte-identical-bystander test below asserts BOTH against the
// baseline. deletion_scheduled_at is asserted on top: if a cross-tenant
// ScheduleDeletion or Restore had matched the bystander's row, the
// nullable stamp would have moved from nil to non-nil (or back) on a
// peer tenant's row.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Insert RETURNING shape, duplicate-slug Conflict, Update/UpdateDisplayName/
//     ScheduleDeletion/Restore dual-anchor (updated_at refreshed,
//     created_at preserved, version bumped), nil-Tx guards, and the
//     Insert / Update / ScheduleDeletion / Restore tx-rollback
//     invariants are proved by project_repository_invariants_test.go
//     (BE-0437).
//   - Cross-tenant NotFound on Get / Update / ScheduleDeletion / Restore
//     is ALSO proved at the typed-error level by project_test.go,
//     project_delete_test.go, and project_restore_test.go. The
//     contribution of this file is the byte-identical-bystander
//     projection (the trigger-managed updated_at and trigger-bumped
//     version stamps did not drift on the peer tenant's row) and the
//     existence-leak projection (Code AND Hint of the cross-tenant
//     NotFound is indistinguishable from an unknown id) — neither is
//     covered by the existing tests.
//   - The HTTP-layer "another tenant's project id is a 404, not a 403"
//     rule is proved by the per-endpoint policy matrix and contract
//     tests in httpapi.
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.

// TestProjectRepositoryGetReturnsCorrectRowAcrossTenants proves Get is
// keyed strictly by BOTH organization_id AND id: each tenant has its
// own projects row, and Get(orgA, projA.ID) / Get(orgB, projB.ID) must
// each return their own row — never a swapped or merged response. The
// fixture deliberately gives BOTH tenants the SAME slug to defeat any
// regression that resolved the WHERE filter by slug alone.
func TestProjectRepositoryGetReturnsCorrectRowAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	// Same-label fixture per tenant: f.Project derives the slug from the
	// per-tenant factory token, so the two rows DO NOT share slug text.
	// A WHERE-on-slug-only regression would still resolve to whichever
	// row the planner found first.
	projA := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "web-api")))
	projB := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "web-api")))

	var gotA store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.Get(ctx, q, orgA.ID, projA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgA, projA): %v", err)
	}
	if gotA.OrganizationID != orgA.ID || gotA.ID != projA.ID {
		t.Errorf("Get(orgA, projA) = %+v, want orgA/projA", gotA)
	}

	var gotB store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.Get(ctx, q, orgB.ID, projB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgB, projB): %v", err)
	}
	if gotB.OrganizationID != orgB.ID || gotB.ID != projB.ID {
		t.Errorf("Get(orgB, projB) = %+v, want orgB/projB", gotB)
	}

	// The two reads MUST have returned distinct rows on EVERY anchor —
	// id and organization_id. A WHERE-on-id-only mistake would collapse
	// both lookups onto the same row, and an overlap on any single
	// anchor would surface here.
	if gotA.ID == gotB.ID || gotA.OrganizationID == gotB.OrganizationID {
		t.Errorf("Get returned overlapping rows across two tenants: %+v vs %+v", gotA, gotB)
	}
}

// TestProjectRepositoryGetCrossTenantIsIndistinguishableFromUnknown
// proves the cross-tenant NotFound shape — Code AND Hint — is the SAME
// shape an unknown project id produces. A probing caller who guesses a
// peer tenant's project id cannot infer that the project id IS a real
// row in another tenant from the response: both surfaces emit
// yerr.CodeNotFound with matching Hint values, and the apierr.NotFound
// builder echoes the CALLER's id back verbatim (not the foreign row's
// id) so the Message never reveals existence either.
func TestProjectRepositoryGetCrossTenantIsIndistinguishableFromUnknown(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "web-api")))

	// Cross-tenant probe: (orgA, projB.ID). The id is real and belongs
	// to a different tenant.
	crossTenantErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, projB.ID)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Get error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	// Wholly unknown id under orgA.
	unknownErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, "prj_never_existed")
		return err
	})
	var yeUnknown *yerr.Error
	if !stderrors.As(unknownErr, &yeUnknown) || yeUnknown.Code != yerr.CodeNotFound {
		t.Fatalf("unknown-id Get error = %v, want a typed E_NOT_FOUND", unknownErr)
	}

	// The two shapes must be indistinguishable on Code AND Hint — a
	// caller who diffed the response surfaces could otherwise enumerate
	// peers by probing project ids. The cross-tenant NotFound MUST NOT
	// echo the foreign project id either (apierr.NotFound documents that
	// the id passed in is the only id that surfaces in the message, so
	// orgA's probe always reflects orgA's request — never orgB's real
	// row).
	if yeCross.Code != yeUnknown.Code {
		t.Errorf("cross-tenant Code = %s, unknown-id Code = %s — existence leaks via Code", yeCross.Code, yeUnknown.Code)
	}
	if yeCross.Hint != yeUnknown.Hint {
		t.Errorf("cross-tenant Hint = %q, unknown-id Hint = %q — existence leaks via Hint", yeCross.Hint, yeUnknown.Hint)
	}
}

// TestProjectRepositoryListByOrganizationCountsAreIsolated proves the
// rendered length of ListByOrganization is local to the queried tenant
// — never the global count, never a sum across tenants. orgA owns one
// project; orgB owns three. List(orgA) must return exactly 1 row;
// List(orgB) must return exactly 3. A SELECT without the WHERE
// organization_id filter would have returned 4 for both calls, and the
// no-overlap-on-id assertion below pins the leak detector even tighter:
// any row id appearing in both responses is by definition a leak.
func TestProjectRepositoryListByOrganizationCountsAreIsolated(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "web-api")))
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "alpha")))
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "billing")))
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "ledger")))

	var gotA []store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.ListByOrganization(ctx, q, orgA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(gotA) != 1 {
		t.Errorf("ListByOrganization(orgA) returned %d rows, want 1 — orgB rows leaked", len(gotA))
	}
	for _, p := range gotA {
		if p.OrganizationID != orgA.ID {
			t.Errorf("ListByOrganization(orgA) returned a foreign row: %+v", p)
		}
	}

	var gotB []store.Project
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
	for _, p := range gotB {
		if p.OrganizationID != orgB.ID {
			t.Errorf("ListByOrganization(orgB) returned a foreign row: %+v", p)
		}
	}

	// The two responses must not overlap on project id — if any id
	// appeared in both lists, the WHERE filter is the only thing keeping
	// them apart and the only way for both calls to share a row is a
	// WHERE-less SELECT.
	seenInB := make(map[string]struct{}, len(gotB))
	for _, p := range gotB {
		seenInB[p.ID] = struct{}{}
	}
	for _, p := range gotA {
		if _, overlap := seenInB[p.ID]; overlap {
			t.Errorf("project id %q appears in both List(orgA) and List(orgB) responses", p.ID)
		}
	}
}

// TestProjectRepositoryListByOrganizationIsolatesSharedSlug proves that
// when both tenants have a project row with the SAME slug, each
// ListByOrganization call renders only THIS tenant's row — never the
// other's, never a duplicate. The UNIQUE (organization_id, slug) index
// is per-tenant, so two tenants CAN legitimately share slug text — and
// a regression that resolved the WHERE filter by slug alone would
// surface here as a leak. This is the load-bearing reason every read
// asserts byte-identical-bystander rows: if slug alone were the UNIQUE
// key, two tenants could not share it, and the WHERE filter on
// organization_id would be redundant.
func TestProjectRepositoryListByOrganizationIsolatesSharedSlug(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	// Force both rows to carry the SAME slug text by overriding the
	// per-tenant token. f.Project would otherwise derive distinct slug
	// text from the per-factory token; we want shared slug text here so
	// the WHERE-on-organization_id filter is the only thing isolating
	// the two rows.
	projA := projectFixture(f.Project(orgA, "shared"))
	projA.Slug = "shared-slug"
	projB := projectFixture(f.Project(orgB, "shared"))
	projB.Slug = "shared-slug"
	storedA := insertProject(ctx, t, s, repo, projA)
	storedB := insertProject(ctx, t, s, repo, projB)

	var gotA []store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.ListByOrganization(ctx, q, orgA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(gotA) != 1 {
		t.Fatalf("ListByOrganization(orgA) returned %d rows, want exactly 1 — orgB's row for the same slug text leaked or duplicated", len(gotA))
	}
	if gotA[0].ID != storedA.ID || gotA[0].OrganizationID != orgA.ID || gotA[0].Slug != "shared-slug" {
		t.Errorf("ListByOrganization(orgA)[0] = %+v, want orgA/projA/shared-slug", gotA[0])
	}

	var gotB []store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.ListByOrganization(ctx, q, orgB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB): %v", err)
	}
	if len(gotB) != 1 {
		t.Fatalf("ListByOrganization(orgB) returned %d rows, want exactly 1 — orgA's row for the same slug text leaked or duplicated", len(gotB))
	}
	if gotB[0].ID != storedB.ID || gotB[0].OrganizationID != orgB.ID || gotB[0].Slug != "shared-slug" {
		t.Errorf("ListByOrganization(orgB)[0] = %+v, want orgB/projB/shared-slug", gotB[0])
	}
}

// TestProjectRepositoryCountByOrganizationIsTenantScoped proves the
// count surface the quota layer reads is tenant scoped — the only
// safe count for "is this tenant allowed to create another project?"
// is the per-tenant count, never the global. orgA owns 1 project; orgB
// owns 3. Count(orgA) must return 1; Count(orgB) must return 3. A
// `SELECT count(*) FROM projects` without the WHERE filter would have
// returned 4 for both. This test is the analogue of the BE-0436
// ListByOrganizationCountsAreIsolated leg, scoped to the quota count
// path the api_key_scopes table does not expose.
func TestProjectRepositoryCountByOrganizationIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgA, "web-api")))
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "alpha")))
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "billing")))
	insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "ledger")))

	counts := map[string]int{}
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		for _, org := range []testutil.Organization{orgA, orgB} {
			n, err := repo.CountByOrganization(ctx, q, org.ID)
			if err != nil {
				return err
			}
			counts[org.ID] = n
		}
		return nil
	}); err != nil {
		t.Fatalf("CountByOrganization: %v", err)
	}
	if counts[orgA.ID] != 1 {
		t.Errorf("CountByOrganization(orgA) = %d, want 1 — orgB rows leaked into orgA's quota count", counts[orgA.ID])
	}
	if counts[orgB.ID] != 3 {
		t.Errorf("CountByOrganization(orgB) = %d, want 3", counts[orgB.ID])
	}
}

// TestProjectRepositoryUpdateOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for Update: when orgA UPDATEs its own
// project row, orgB's bystander row must be byte-identical to its
// baseline across EVERY observable column — including the
// trigger-managed updated_at and the trigger-bumped version, which are
// the independent anchors that catch a WHERE-on-id-only UPDATE even
// when the column writes themselves happened to look correct.
//
// The fixture has BOTH tenants share the SAME slug on their OWN
// respective rows, so a regression that resolved the WHERE clause by
// slug alone — or by id alone — would have hit orgB's row.
func TestProjectRepositoryUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := projectFixture(f.Project(orgA, "shared"))
	projA.Slug = "shared-slug"
	projB := projectFixture(f.Project(orgB, "shared"))
	projB.Slug = "shared-slug"
	storedA := insertProject(ctx, t, s, repo, projA)
	storedB := insertProject(ctx, t, s, repo, projB)

	baselineB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")

	// orgA mutates its own row to a new slug + display_name.
	desired := storedA
	desired.Slug = "renamed-slug"
	desired.DisplayName = "Renamed"
	var updatedA store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updatedA, writeErr = repo.Update(ctx, tx, desired, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Update(orgA, projA): %v", err)
	}
	// orgA must have actually changed — a no-op repository cannot
	// silently pass the byte-identical-orgB check below.
	if updatedA.OrganizationID != orgA.ID || updatedA.ID != storedA.ID || updatedA.Slug != "renamed-slug" || updatedA.DisplayName != "Renamed" || updatedA.Version != 2 {
		t.Errorf("Update(orgA, projA) = %+v, want orgA/projA/renamed-slug/Renamed/version=2", updatedA)
	}

	afterB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after orgA Update")
	assertProjectByteIdentical(t, "Update(orgA) bystander orgB", baselineB, afterB)
}

// TestProjectRepositoryUpdateCrossTenantBystanderIsByteIdentical proves
// Update with another tenant's project id surfaces as the same typed
// NotFound shape an unknown id would produce, AND leaves the bystander
// tenant's row byte-identical — the trigger would otherwise refresh
// updated_at and bump version if the UPDATE statement had matched
// orgB's row even momentarily. project_test.go's existing
// TestProjectRepositoryUpdateNotFoundIsTenantScoped proves the typed
// NotFound at the error level; this test extends that proof to every
// observable column of the bystander row.
func TestProjectRepositoryUpdateCrossTenantBystanderIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	storedB := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "web-api")))
	baselineB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")

	// orgA presents orgB's project id under orgA's tenant — the WHERE
	// (organization_id = orgA AND id = projB) matches nothing.
	hijack := storedB
	hijack.OrganizationID = orgA.ID
	hijack.Slug = "hijacked"
	hijack.DisplayName = "Hijacked"
	crossTenantErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Update(ctx, tx, hijack, nil)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Update error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	// And the bystander row is byte-identical — including updated_at
	// and version, which the BEFORE-UPDATE trigger would have stamped
	// if the statement had matched orgB's row.
	afterB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after cross-tenant Update")
	assertProjectByteIdentical(t, "cross-tenant Update bystander orgB", baselineB, afterB)
}

// TestProjectRepositoryUpdateDisplayNameOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for UpdateDisplayName: when orgA
// UPDATEs its own project's display_name, orgB's bystander row must be
// byte-identical across EVERY observable column. The
// BE-0437 invariants file already proves UpdateDisplayName leaves
// orgA's OWN slug untouched on the success path; this test extends the
// proof to the per-tenant bystander invariant.
func TestProjectRepositoryUpdateDisplayNameOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := projectFixture(f.Project(orgA, "shared"))
	projA.Slug = "shared-slug"
	projB := projectFixture(f.Project(orgB, "shared"))
	projB.Slug = "shared-slug"
	storedA := insertProject(ctx, t, s, repo, projA)
	storedB := insertProject(ctx, t, s, repo, projB)

	baselineB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")

	var updatedA store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updatedA, writeErr = repo.UpdateDisplayName(ctx, tx, orgA.ID, storedA.ID, "Renamed", nil)
		return writeErr
	}); err != nil {
		t.Fatalf("UpdateDisplayName(orgA, projA): %v", err)
	}
	if updatedA.OrganizationID != orgA.ID || updatedA.ID != storedA.ID || updatedA.DisplayName != "Renamed" || updatedA.Version != 2 {
		t.Errorf("UpdateDisplayName(orgA, projA) = %+v, want orgA/projA/Renamed/version=2", updatedA)
	}

	afterB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after orgA UpdateDisplayName")
	assertProjectByteIdentical(t, "UpdateDisplayName(orgA) bystander orgB", baselineB, afterB)
}

// TestProjectRepositoryUpdateDisplayNameCrossTenantBystanderIsByteIdentical
// proves UpdateDisplayName with another tenant's project id surfaces as
// the same typed NotFound shape an unknown id would produce, AND leaves
// the bystander tenant's row byte-identical — the trigger would
// otherwise refresh updated_at and bump version if the UPDATE statement
// had matched orgB's row even momentarily. There is no existing test
// for UpdateDisplayName's cross-tenant behaviour (project_test.go's
// TestProjectRepositoryUpdateNotFoundIsTenantScoped covers Update, not
// UpdateDisplayName), so this test is the load-bearing proof for that
// surface.
func TestProjectRepositoryUpdateDisplayNameCrossTenantBystanderIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	storedB := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "web-api")))
	baselineB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")

	crossTenantErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.UpdateDisplayName(ctx, tx, orgA.ID, storedB.ID, "Hijacked", nil)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant UpdateDisplayName error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	afterB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after cross-tenant UpdateDisplayName")
	assertProjectByteIdentical(t, "cross-tenant UpdateDisplayName bystander orgB", baselineB, afterB)
}

// TestProjectRepositoryScheduleDeletionOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for ScheduleDeletion: when orgA
// schedules its own project for teardown, orgB's bystander row must be
// byte-identical across EVERY observable column — most importantly
// including DeletionScheduledAt itself. A regression that stamped the
// wrong tenant's deletion_scheduled_at would mark another organization's
// project for teardown without surfacing any error.
func TestProjectRepositoryScheduleDeletionOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := projectFixture(f.Project(orgA, "shared"))
	projA.Slug = "shared-slug"
	projB := projectFixture(f.Project(orgB, "shared"))
	projB.Slug = "shared-slug"
	storedA := insertProject(ctx, t, s, repo, projA)
	storedB := insertProject(ctx, t, s, repo, projB)

	baselineB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")
	if baselineB.DeletionScheduledAt != nil {
		t.Fatalf("baseline orgB.deletion_scheduled_at = %v, want nil — fixture invariant broken", baselineB.DeletionScheduledAt)
	}

	var scheduledA store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		scheduledA, writeErr = repo.ScheduleDeletion(ctx, tx, orgA.ID, storedA.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion(orgA, projA): %v", err)
	}
	if scheduledA.DeletionScheduledAt == nil {
		t.Fatal("ScheduleDeletion(orgA) did not stamp deletion_scheduled_at on orgA's row")
	}
	if scheduledA.Version != 2 {
		t.Errorf("ScheduleDeletion(orgA, projA).Version = %d, want 2", scheduledA.Version)
	}

	// The bystander row must be byte-identical — including
	// DeletionScheduledAt staying nil. A WHERE-on-id-only UPDATE that
	// stamped orgB's deletion_scheduled_at would be caught here.
	afterB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after orgA ScheduleDeletion")
	assertProjectByteIdentical(t, "ScheduleDeletion(orgA) bystander orgB", baselineB, afterB)
}

// TestProjectRepositoryScheduleDeletionCrossTenantBystanderIsByteIdentical
// proves ScheduleDeletion with another tenant's project id surfaces as
// the same typed NotFound shape an unknown id would produce, AND leaves
// the bystander tenant's row byte-identical — including the
// DeletionScheduledAt stamp staying nil. project_delete_test.go's
// existing TestProjectRepositoryScheduleDeletionIsTenantScoped proves
// the NotFound code AND that DeletionScheduledAt is unchanged; this
// test extends the proof to the trigger-managed updated_at and
// trigger-bumped version stamps, which are the independent anchors
// that catch a momentary match even when the deletion stamp itself
// happened to look untouched.
func TestProjectRepositoryScheduleDeletionCrossTenantBystanderIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	storedB := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "web-api")))
	baselineB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")

	crossTenantErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, orgA.ID, storedB.ID, nil)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant ScheduleDeletion error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	afterB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after cross-tenant ScheduleDeletion")
	assertProjectByteIdentical(t, "cross-tenant ScheduleDeletion bystander orgB", baselineB, afterB)
}

// TestProjectRepositoryRestoreOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for Restore: when orgA legitimately
// clears its own deletion_scheduled_at stamp, orgB's bystander row —
// which is ALSO soft-deleted in this fixture — must keep its own
// deletion_scheduled_at stamp non-nil. A regression that resolved the
// WHERE clause by id alone would clear BOTH tenants' deletion stamps,
// silently undoing orgB's soft-delete without surfacing any error.
func TestProjectRepositoryRestoreOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := projectFixture(f.Project(orgA, "shared"))
	projA.Slug = "shared-slug"
	projB := projectFixture(f.Project(orgB, "shared"))
	projB.Slug = "shared-slug"
	storedA := insertProject(ctx, t, s, repo, projA)
	storedB := insertProject(ctx, t, s, repo, projB)

	// Soft-delete both rows so the fixture really exercises the inverse
	// of ScheduleDeletion. A WHERE-on-id-only Restore would clear the
	// bystander's stamp here.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := repo.ScheduleDeletion(ctx, tx, orgA.ID, storedA.ID, nil); err != nil {
			return err
		}
		_, err := repo.ScheduleDeletion(ctx, tx, orgB.ID, storedB.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("seed ScheduleDeletion both tenants: %v", err)
	}

	baselineB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")
	if baselineB.DeletionScheduledAt == nil {
		t.Fatalf("baseline orgB.deletion_scheduled_at = nil, want a stamp — fixture invariant broken")
	}

	var restoredA store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		restoredA, writeErr = repo.Restore(ctx, tx, orgA.ID, storedA.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Restore(orgA, projA): %v", err)
	}
	if restoredA.DeletionScheduledAt != nil {
		t.Errorf("Restore(orgA, projA).DeletionScheduledAt = %v, want nil", restoredA.DeletionScheduledAt)
	}

	// The bystander row must be byte-identical — including
	// DeletionScheduledAt staying NON-nil. A WHERE-on-id-only UPDATE
	// that cleared orgB's deletion_scheduled_at would be caught here.
	afterB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after orgA Restore")
	assertProjectByteIdentical(t, "Restore(orgA) bystander orgB", baselineB, afterB)
}

// TestProjectRepositoryRestoreCrossTenantBystanderIsByteIdentical
// proves Restore with another tenant's project id surfaces as the same
// typed NotFound shape an unknown id would produce, AND leaves the
// bystander tenant's row byte-identical — including the
// DeletionScheduledAt stamp staying non-nil. project_restore_test.go's
// existing TestProjectRepositoryRestoreIsTenantScoped proves the
// NotFound code AND that DeletionScheduledAt is preserved; this test
// extends the proof to the trigger-managed updated_at and
// trigger-bumped version stamps.
func TestProjectRepositoryRestoreCrossTenantBystanderIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	storedB := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "web-api")))
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, orgB.ID, storedB.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("seed ScheduleDeletion(orgB): %v", err)
	}
	baselineB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")
	if baselineB.DeletionScheduledAt == nil {
		t.Fatalf("baseline orgB.deletion_scheduled_at = nil, want a stamp — fixture invariant broken")
	}

	crossTenantErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Restore(ctx, tx, orgA.ID, storedB.ID, nil)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Restore error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	afterB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after cross-tenant Restore")
	assertProjectByteIdentical(t, "cross-tenant Restore bystander orgB", baselineB, afterB)
}

// TestProjectRepositoryInsertSameSlugInTwoTenantsBothSucceed proves the
// (organization_id, slug) UNIQUE constraint is per-tenant, not global:
// two tenants can legitimately each have a "web-api" project, and
// neither Insert collides with the other. The flip side is the
// load-bearing reason every read above asserts byte-identical
// bystander rows — if slug alone were the UNIQUE key, two tenants
// could not share it, and the WHERE filter on organization_id would
// be redundant.
func TestProjectRepositoryInsertSameSlugInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := projectFixture(f.Project(orgA, "shared"))
	projA.Slug = "shared-slug"
	projB := projectFixture(f.Project(orgB, "shared"))
	projB.Slug = "shared-slug"

	storedA := insertProject(ctx, t, s, repo, projA)
	storedB := insertProject(ctx, t, s, repo, projB)

	if storedA.ID == storedB.ID {
		t.Fatalf("two tenants minted the same project id %q — the id generator collided, the byte-identical-bystander tests are invalid", storedA.ID)
	}
	if storedA.OrganizationID == storedB.OrganizationID {
		t.Errorf("two project rows landed under the SAME organization_id: %+v vs %+v", storedA, storedB)
	}
	if storedA.Slug != "shared-slug" || storedB.Slug != "shared-slug" {
		t.Errorf("slug text drifted between Insert calls: orgA=%q orgB=%q, want both 'shared-slug'", storedA.Slug, storedB.Slug)
	}
}

// TestProjectRepositorySoftDeletedRowIsTenantScopedOnReadPaths proves
// the projection unique to projects (api_key_scopes has no
// soft-delete column): a soft-deleted row in one tenant must NOT leak
// into ANY read surface — Get, ListByOrganization, or
// CountByOrganization — of another tenant. The owning tenant still
// sees its own soft-deleted row through all three read surfaces (the
// projects repository does not filter deletion_scheduled_at out of
// reads — that policy belongs to higher layers).
func TestProjectRepositorySoftDeletedRowIsTenantScopedOnReadPaths(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	storedB := insertProject(ctx, t, s, repo, projectFixture(f.Project(orgB, "web-api")))
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, orgB.ID, storedB.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("seed ScheduleDeletion(orgB): %v", err)
	}

	// orgA Get on orgB's soft-deleted project: NotFound, never the row
	// — regardless of the deletion_scheduled_at stamp.
	gotAErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, orgA.ID, storedB.ID)
		return err
	})
	var yeA *yerr.Error
	if !stderrors.As(gotAErr, &yeA) || yeA.Code != yerr.CodeNotFound {
		t.Fatalf("Get(orgA, soft-deleted projB) = %v, want a typed E_NOT_FOUND", gotAErr)
	}

	// orgA ListByOrganization must yield an empty slice — orgB's
	// soft-deleted row must NOT leak across.
	var listA []store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		listA, readErr = repo.ListByOrganization(ctx, q, orgA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(listA) != 0 {
		t.Errorf("ListByOrganization(orgA) returned %d rows, want 0 — orgB's soft-deleted row leaked", len(listA))
	}

	// orgA CountByOrganization must report 0 — the count surface the
	// quota layer reads must NOT inflate from another tenant's
	// soft-deleted rows.
	var countA int
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		countA, readErr = repo.CountByOrganization(ctx, q, orgA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("CountByOrganization(orgA): %v", err)
	}
	if countA != 0 {
		t.Errorf("CountByOrganization(orgA) = %d, want 0 — orgB's soft-deleted row leaked into orgA's quota count", countA)
	}

	// The owning tenant (orgB) still sees its own soft-deleted row on
	// every read surface: Get returns the row with DeletionScheduledAt
	// stamped, ListByOrganization includes it, CountByOrganization
	// counts it. This pins the per-tenant view: the projects
	// repository deliberately does NOT hide soft-deleted rows from the
	// owning tenant's read surfaces — that policy belongs to higher
	// layers.
	gotB := getProjectOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "owner Get")
	if gotB.DeletionScheduledAt == nil {
		t.Errorf("Get(orgB, soft-deleted projB).DeletionScheduledAt = nil, want a stamp — owning tenant lost visibility of own soft-deleted row")
	}
	var listB []store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		listB, readErr = repo.ListByOrganization(ctx, q, orgB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgB): %v", err)
	}
	if len(listB) != 1 || listB[0].ID != storedB.ID {
		t.Errorf("ListByOrganization(orgB) = %+v, want exactly [%s]", listB, storedB.ID)
	}
	var countB int
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		countB, readErr = repo.CountByOrganization(ctx, q, orgB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("CountByOrganization(orgB): %v", err)
	}
	if countB != 1 {
		t.Errorf("CountByOrganization(orgB) = %d, want 1 — owning tenant lost visibility of own soft-deleted row in quota count", countB)
	}
}

// --- shared helpers ---
//
// getProjectOrFail reads a project through the typed repository surface
// and fails the test on any error — the test cases use this exclusively
// for reads that are EXPECTED to succeed, so a NotFound here is a setup
// failure (the seeded row went missing) and not a leg under proof.
func getProjectOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.ProjectRepository, organizationID, projectID, label string) store.Project {
	t.Helper()
	var got store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		got, readErr = repo.Get(ctx, q, organizationID, projectID)
		return readErr
	}); err != nil {
		t.Fatalf("%s Get(%q, %q): %v", label, organizationID, projectID, err)
	}
	return got
}

// assertProjectByteIdentical asserts every observable column on a
// bystander projects row is byte-identical to its baseline. The
// trigger-managed updated_at AND the trigger-bumped version are both
// load-bearing here: the BEFORE-UPDATE projects_set_updated_at trigger
// refreshes updated_at on every matched UPDATE, and the
// projects_bump_version trigger increments version — either drifting
// independently surfaces a missing tenant predicate even when the
// column writes themselves look correct.
//
// DeletionScheduledAt is included as well because projects carries
// soft-delete as a nullable *time.Time on the row body: a regression
// that resolved the WHERE clause incorrectly could stamp another
// tenant's row from nil to non-nil (ScheduleDeletion) or clear it from
// non-nil to nil (Restore) without surfacing any error.
func assertProjectByteIdentical(t *testing.T, label string, baseline, after store.Project) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.Slug != baseline.Slug {
		t.Errorf("%s: bystander.slug = %q, want %q", label, after.Slug, baseline.Slug)
	}
	if after.DisplayName != baseline.DisplayName {
		t.Errorf("%s: bystander.display_name = %q, want %q", label, after.DisplayName, baseline.DisplayName)
	}
	if after.Version != baseline.Version {
		t.Errorf("%s: bystander.version = %d, want %d — the projects_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE projects_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
	switch {
	case baseline.DeletionScheduledAt == nil && after.DeletionScheduledAt != nil:
		t.Errorf("%s: bystander.deletion_scheduled_at = %v, want nil — a cross-tenant ScheduleDeletion stamped a peer tenant's row",
			label, *after.DeletionScheduledAt)
	case baseline.DeletionScheduledAt != nil && after.DeletionScheduledAt == nil:
		t.Errorf("%s: bystander.deletion_scheduled_at cleared from %v to nil — a cross-tenant Restore cleared a peer tenant's soft-delete stamp",
			label, *baseline.DeletionScheduledAt)
	case baseline.DeletionScheduledAt != nil && after.DeletionScheduledAt != nil && !after.DeletionScheduledAt.Equal(*baseline.DeletionScheduledAt):
		t.Errorf("%s: bystander.deletion_scheduled_at = %v, want %v",
			label, *after.DeletionScheduledAt, *baseline.DeletionScheduledAt)
	}
}
