package store_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the environments table
// (BE-0442). environments is a tenant-scoped grandchild table whose row
// body is anchored to a single tenant by THREE load-bearing schema
// facts:
//
//	(a) every column carries organization_id directly, and the
//	    composite FK (organization_id, project_id) -> projects
//	    (organization_id, id) is MATCH SIMPLE — so an environment whose
//	    parent project belongs to one tenant is structurally
//	    unrepresentable under another tenant's organization_id at the
//	    database layer. The BE-0441 invariants file already proves the
//	    Insert path returns the row in the expected shape, so this file
//	    does not re-prove the FK rejection.
//	(b) every repository method (Insert / GetByID / ListByProject /
//	    Update / ScheduleDeletion) carries organization_id as the FIRST
//	    SQL predicate, ahead of the row identifier (and ahead of
//	    project_id on the ListByProject leg). The cross-tenant guarantee
//	    at this layer is therefore the byte-identical-bystander invariant
//	    every other tenant-scoped table is held to;
//	(c) the soft-delete column (deletion_scheduled_at) is a nullable
//	    *time.Time on every read path — the environments repository does
//	    NOT filter soft-deleted rows out of GetByID or ListByProject, so
//	    a regression that resolved the WHERE filter incorrectly could
//	    leak ANOTHER tenant's soft-deleted environment just as easily as
//	    a live one. The "SoftDeletedRowIsTenantScopedOnReadPaths" leg
//	    below pins this.
//
// The environments row body carries NO secret-bearing column — slug,
// display_name, and kind are surfaced as-is, and environment-scoped
// secrets live in a separate environment_variables table — so the
// BE-0434 raw-secret_hash probe has no analogue here. The row body is
// fully observable through the typed GetByID / ListByProject read paths,
// and the byte-identical-bystander assertion below covers every
// observable column (id, organization_id, project_id, slug,
// display_name, kind, version, created_at, updated_at,
// deletion_scheduled_at).
//
// The BEFORE-UPDATE environments_set_updated_at trigger refreshes
// updated_at on every matched UPDATE — including a WHERE-less or
// WHERE-on-id-only UPDATE that touched the wrong tenant's row — and the
// environments_bump_version trigger increments version on the same
// path. Either of those two columns drifting on the bystander is
// independently sufficient to catch a missing tenant predicate even
// when the column writes themselves look correct, and every
// byte-identical-bystander test below asserts BOTH against the
// baseline. deletion_scheduled_at is asserted on top: if a cross-tenant
// ScheduleDeletion had matched the bystander's row, the nullable stamp
// would have moved from nil to non-nil on a peer tenant's row.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Insert RETURNING shape, duplicate-slug Conflict, Update /
//     ScheduleDeletion dual-anchor (updated_at refreshed, created_at
//     preserved, version bumped), nil-Tx guards, and the Insert
//     tx-rollback invariant are proved by
//     environment_repository_invariants_test.go (BE-0441).
//   - Cross-tenant NotFound on GetByID / Update / ScheduleDeletion is
//     ALSO proved at the typed-error level by
//     TestEnvironmentRepoGetByIDIsTenantScoped (environment_test.go),
//     TestEnvironmentRepoUpdateCrossTenantIsNotFound
//     (environment_update_test.go), and
//     TestEnvironmentRepositoryScheduleDeletionIsTenantScoped
//     (environment_delete_test.go). The contribution of this file is
//     the byte-identical-bystander projection (the trigger-managed
//     updated_at and trigger-bumped version stamps did not drift on the
//     peer tenant's row) and the existence-leak projection (Code AND
//     Hint of the cross-tenant NotFound is indistinguishable from an
//     unknown id) — neither is covered by the existing tests.
//   - The Restore / UpdateDisplayName flips proved in the projects
//     tenant-isolation file have no analogue here: the
//     EnvironmentRepository exposes neither method, so the BE-0441
//     invariants matrix already documents their absence as a deliberate
//     surface boundary.
//   - The HTTP-layer "another tenant's environment id is a 404, not a
//     403" rule is proved by the per-endpoint policy matrix and contract
//     tests in httpapi.
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.

// TestEnvironmentRepositoryGetByIDReturnsCorrectRowAcrossTenants proves
// GetByID is keyed strictly by BOTH organization_id AND id: each tenant
// has its own environments row, and GetByID(orgA, envA) /
// GetByID(orgB, envB) must each return their own row — never a swapped
// or merged response. The fixture deliberately gives BOTH tenants the
// SAME slug on their respective projects to defeat any regression that
// resolved the WHERE filter by slug alone.
func TestEnvironmentRepositoryGetByIDReturnsCorrectRowAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgA, "web")))
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	// Override the per-tenant slug derived by the factory so both rows
	// carry the SAME slug text on their OWN projects. A WHERE-on-slug-only
	// regression would still resolve to whichever row the planner found
	// first.
	envFixA := environmentFixture(f.Environment(projATuple(projA), "production"))
	envFixA.Slug = "production"
	envFixB := environmentFixture(f.Environment(projATuple(projB), "production"))
	envFixB.Slug = "production"
	envA := insertEnvironment(ctx, t, s, envRepo, envFixA)
	envB := insertEnvironment(ctx, t, s, envRepo, envFixB)

	var gotA store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = envRepo.GetByID(ctx, q, orgA.ID, envA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("GetByID(orgA, envA): %v", err)
	}
	if gotA.OrganizationID != orgA.ID || gotA.ID != envA.ID || gotA.ProjectID != projA.ID {
		t.Errorf("GetByID(orgA, envA) = %+v, want orgA/envA/projA", gotA)
	}

	var gotB store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = envRepo.GetByID(ctx, q, orgB.ID, envB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("GetByID(orgB, envB): %v", err)
	}
	if gotB.OrganizationID != orgB.ID || gotB.ID != envB.ID || gotB.ProjectID != projB.ID {
		t.Errorf("GetByID(orgB, envB) = %+v, want orgB/envB/projB", gotB)
	}

	// The two reads MUST have returned distinct rows on EVERY anchor —
	// id, organization_id, and project_id. A WHERE-on-id-only mistake
	// would collapse both lookups onto the same row, and an overlap on
	// any single anchor would surface here.
	if gotA.ID == gotB.ID || gotA.OrganizationID == gotB.OrganizationID || gotA.ProjectID == gotB.ProjectID {
		t.Errorf("GetByID returned overlapping rows across two tenants: %+v vs %+v", gotA, gotB)
	}
}

// TestEnvironmentRepositoryGetByIDCrossTenantIsIndistinguishableFromUnknown
// proves the cross-tenant NotFound shape — Code AND Hint — is the SAME
// shape an unknown environment id produces. A probing caller who guesses
// a peer tenant's environment id cannot infer that the environment id IS
// a real row in another tenant from the response: both surfaces emit
// yerr.CodeNotFound with matching Hint values, and the apierr.NotFound
// builder echoes the CALLER's id back verbatim (not the foreign row's
// id) so the Message never reveals existence either.
func TestEnvironmentRepositoryGetByIDCrossTenantIsIndistinguishableFromUnknown(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	envB := insertEnvironment(ctx, t, s, envRepo, environmentFixture(f.Environment(projATuple(projB), "production")))

	// Cross-tenant probe: (orgA, envB.ID). The id is real and belongs to
	// a different tenant.
	crossTenantErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := envRepo.GetByID(ctx, q, orgA.ID, envB.ID)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant GetByID error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	// Wholly unknown id under orgA.
	unknownErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := envRepo.GetByID(ctx, q, orgA.ID, "env_never_existed")
		return err
	})
	var yeUnknown *yerr.Error
	if !stderrors.As(unknownErr, &yeUnknown) || yeUnknown.Code != yerr.CodeNotFound {
		t.Fatalf("unknown-id GetByID error = %v, want a typed E_NOT_FOUND", unknownErr)
	}

	// The two shapes must be indistinguishable on Code AND Hint — a
	// caller who diffed the response surfaces could otherwise enumerate
	// peers by probing environment ids. The cross-tenant NotFound MUST
	// NOT echo the foreign environment id either (apierr.NotFound
	// documents that the id passed in is the only id that surfaces in
	// the message, so orgA's probe always reflects orgA's request —
	// never orgB's real row).
	if yeCross.Code != yeUnknown.Code {
		t.Errorf("cross-tenant Code = %s, unknown-id Code = %s — existence leaks via Code", yeCross.Code, yeUnknown.Code)
	}
	if yeCross.Hint != yeUnknown.Hint {
		t.Errorf("cross-tenant Hint = %q, unknown-id Hint = %q — existence leaks via Hint", yeCross.Hint, yeUnknown.Hint)
	}
}

// TestEnvironmentRepositoryListByProjectCountsAreIsolated proves the
// rendered length of ListByProject is local to the queried (org,
// project) tuple — never the global count, never a sum across tenants.
// orgA's project owns one environment; orgB's project owns three.
// ListByProject(orgA, projA) must return exactly 1 row;
// ListByProject(orgB, projB) must return exactly 3. A SELECT without
// the WHERE organization_id (or project_id) filter would have returned
// 4 for both calls, and the no-overlap-on-id assertion below pins the
// leak detector even tighter: any row id appearing in both responses
// is by definition a leak.
func TestEnvironmentRepositoryListByProjectCountsAreIsolated(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgA, "web")))
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	insertEnvironment(ctx, t, s, envRepo, environmentFixture(f.Environment(projATuple(projA), "production")))
	insertEnvironment(ctx, t, s, envRepo, environmentFixture(f.Environment(projATuple(projB), "alpha")))
	insertEnvironment(ctx, t, s, envRepo, environmentFixture(f.Environment(projATuple(projB), "beta")))
	insertEnvironment(ctx, t, s, envRepo, environmentFixture(f.Environment(projATuple(projB), "gamma")))

	var gotA []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = envRepo.ListByProject(ctx, q, orgA.ID, projA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByProject(orgA, projA): %v", err)
	}
	if len(gotA) != 1 {
		t.Errorf("ListByProject(orgA, projA) returned %d rows, want 1 — orgB rows leaked", len(gotA))
	}
	for _, e := range gotA {
		if e.OrganizationID != orgA.ID || e.ProjectID != projA.ID {
			t.Errorf("ListByProject(orgA, projA) returned a foreign row: %+v", e)
		}
	}

	var gotB []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = envRepo.ListByProject(ctx, q, orgB.ID, projB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByProject(orgB, projB): %v", err)
	}
	if len(gotB) != 3 {
		t.Errorf("ListByProject(orgB, projB) returned %d rows, want 3", len(gotB))
	}
	for _, e := range gotB {
		if e.OrganizationID != orgB.ID || e.ProjectID != projB.ID {
			t.Errorf("ListByProject(orgB, projB) returned a foreign row: %+v", e)
		}
	}

	// The two responses must not overlap on environment id — if any id
	// appeared in both lists, the WHERE filter is the only thing keeping
	// them apart and the only way for both calls to share a row is a
	// WHERE-less SELECT.
	seenInB := make(map[string]struct{}, len(gotB))
	for _, e := range gotB {
		seenInB[e.ID] = struct{}{}
	}
	for _, e := range gotA {
		if _, overlap := seenInB[e.ID]; overlap {
			t.Errorf("environment id %q appears in both ListByProject(orgA, projA) and ListByProject(orgB, projB) responses", e.ID)
		}
	}
}

// TestEnvironmentRepositoryListByProjectIsolatesSharedSlug proves that
// when each tenant has an environment with the SAME slug under its OWN
// project, each ListByProject call renders only THIS (org, project)'s
// row — never the other's, never a duplicate. The UNIQUE (project_id,
// slug) index is per-project, so two tenants CAN legitimately share
// slug text on their separate projects — and a regression that
// resolved the WHERE filter by slug alone would surface here as a
// leak. This is the load-bearing reason every read asserts
// byte-identical-bystander rows: if slug alone were the UNIQUE key,
// two tenants could not share it, and the WHERE filter on
// organization_id (and project_id) would be redundant.
func TestEnvironmentRepositoryListByProjectIsolatesSharedSlug(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgA, "web")))
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	// Force both rows to carry the SAME slug text by overriding the
	// per-tenant token. f.Environment would otherwise derive distinct
	// slug text from the per-factory token; we want shared slug text
	// here so the WHERE-on-(organization_id, project_id) filter is the
	// only thing isolating the two rows.
	envFixA := environmentFixture(f.Environment(projATuple(projA), "shared"))
	envFixA.Slug = "production"
	envFixB := environmentFixture(f.Environment(projATuple(projB), "shared"))
	envFixB.Slug = "production"
	storedA := insertEnvironment(ctx, t, s, envRepo, envFixA)
	storedB := insertEnvironment(ctx, t, s, envRepo, envFixB)

	var gotA []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = envRepo.ListByProject(ctx, q, orgA.ID, projA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByProject(orgA, projA): %v", err)
	}
	if len(gotA) != 1 {
		t.Fatalf("ListByProject(orgA, projA) returned %d rows, want exactly 1 — orgB's row for the same slug text leaked or duplicated", len(gotA))
	}
	if gotA[0].ID != storedA.ID || gotA[0].OrganizationID != orgA.ID || gotA[0].ProjectID != projA.ID || gotA[0].Slug != "production" {
		t.Errorf("ListByProject(orgA, projA)[0] = %+v, want orgA/projA/envA/production", gotA[0])
	}

	var gotB []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = envRepo.ListByProject(ctx, q, orgB.ID, projB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByProject(orgB, projB): %v", err)
	}
	if len(gotB) != 1 {
		t.Fatalf("ListByProject(orgB, projB) returned %d rows, want exactly 1 — orgA's row for the same slug text leaked or duplicated", len(gotB))
	}
	if gotB[0].ID != storedB.ID || gotB[0].OrganizationID != orgB.ID || gotB[0].ProjectID != projB.ID || gotB[0].Slug != "production" {
		t.Errorf("ListByProject(orgB, projB)[0] = %+v, want orgB/projB/envB/production", gotB[0])
	}
}

// TestEnvironmentRepositoryListByProjectIgnoresCrossTenantOrgIDOnOwnedProject
// proves that a list scoped to orgA but pointed at orgB's project_id
// returns zero rows — never orgB's environments — and that orgA's own
// (empty) project, queried through the same call, also returns zero.
// The cross-tenant call is indistinguishable from a wholly unknown
// (org, project) tuple on the wire: an empty slice in both cases. The
// existing TestEnvironmentRepoListByProjectIsTenantScoped proves the
// cross-tenant projB.ID under orgA returns empty; this test pins the
// "indistinguishable from unknown" projection by also exercising the
// empty-but-owned and entirely-unknown legs.
func TestEnvironmentRepositoryListByProjectIgnoresCrossTenantOrgIDOnOwnedProject(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgA, "empty-a")))
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	// Seed orgB's project so the cross-tenant probe has something to
	// leak if the WHERE filter is broken.
	insertEnvironment(ctx, t, s, envRepo, environmentFixture(f.Environment(projATuple(projB), "production")))

	cases := []struct {
		label     string
		orgID     string
		projectID string
	}{
		{"orgA owned empty project", orgA.ID, projA.ID},
		{"orgA probing orgB project", orgA.ID, projB.ID},
		{"orgA probing unknown project", orgA.ID, "prj_never_existed"},
	}
	for _, c := range cases {
		var got []store.Environment
		if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
			var readErr error
			got, readErr = envRepo.ListByProject(ctx, q, c.orgID, c.projectID)
			return readErr
		}); err != nil {
			t.Fatalf("ListByProject(%s): %v", c.label, err)
		}
		if got == nil {
			t.Errorf("ListByProject(%s) = nil, want non-nil empty slice — the wire shape must be a deterministic empty list", c.label)
		}
		if len(got) != 0 {
			t.Errorf("ListByProject(%s) returned %d rows, want 0 — orgB's environment leaked", c.label, len(got))
		}
	}
}

// TestEnvironmentRepositoryUpdateOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for Update: when orgA UPDATEs its own
// environment row, orgB's bystander row must be byte-identical to its
// baseline across EVERY observable column — including the
// trigger-managed updated_at and the trigger-bumped version, which are
// the independent anchors that catch a WHERE-on-id-only UPDATE even
// when the column writes themselves happened to look correct.
//
// The fixture has BOTH tenants share the SAME slug on their OWN
// respective projects, so a regression that resolved the WHERE clause
// by slug alone — or by id alone — would have hit orgB's row.
func TestEnvironmentRepositoryUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgA, "web")))
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	envFixA := environmentFixture(f.Environment(projATuple(projA), "shared"))
	envFixA.Slug = "production"
	envFixB := environmentFixture(f.Environment(projATuple(projB), "shared"))
	envFixB.Slug = "production"
	storedA := insertEnvironment(ctx, t, s, envRepo, envFixA)
	storedB := insertEnvironment(ctx, t, s, envRepo, envFixB)

	baselineB := getEnvironmentOrFail(ctx, t, s, envRepo, orgB.ID, storedB.ID, "baseline")

	// orgA mutates its own row to a new slug + display_name.
	desired := storedA
	desired.Slug = "production-v2"
	desired.DisplayName = "Production v2"
	var updatedA store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updatedA, writeErr = envRepo.Update(ctx, tx, desired, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Update(orgA, envA): %v", err)
	}
	// orgA must have actually changed — a no-op repository cannot
	// silently pass the byte-identical-orgB check below.
	if updatedA.OrganizationID != orgA.ID || updatedA.ID != storedA.ID || updatedA.Slug != "production-v2" || updatedA.DisplayName != "Production v2" || updatedA.Version != 2 {
		t.Errorf("Update(orgA, envA) = %+v, want orgA/envA/production-v2/Production v2/version=2", updatedA)
	}

	afterB := getEnvironmentOrFail(ctx, t, s, envRepo, orgB.ID, storedB.ID, "after orgA Update")
	assertEnvironmentByteIdentical(t, "Update(orgA) bystander orgB", baselineB, afterB)
}

// TestEnvironmentRepositoryUpdateCrossTenantBystanderIsByteIdentical
// proves Update with another tenant's environment id surfaces as the
// same typed NotFound shape an unknown id would produce, AND leaves
// the bystander tenant's row byte-identical — the trigger would
// otherwise refresh updated_at and bump version if the UPDATE
// statement had matched orgB's row even momentarily.
// environment_update_test.go's existing
// TestEnvironmentRepoUpdateCrossTenantIsNotFound proves the typed
// NotFound at the error level; this test extends that proof to every
// observable column of the bystander row.
func TestEnvironmentRepositoryUpdateCrossTenantBystanderIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	storedB := insertEnvironment(ctx, t, s, envRepo, environmentFixture(f.Environment(projATuple(projB), "production")))
	baselineB := getEnvironmentOrFail(ctx, t, s, envRepo, orgB.ID, storedB.ID, "baseline")

	// orgA presents orgB's environment id under orgA's tenant — the
	// WHERE (organization_id = orgA AND id = envB) matches nothing.
	hijack := storedB
	hijack.OrganizationID = orgA.ID
	hijack.Slug = "hijacked"
	hijack.DisplayName = "Hijacked"
	crossTenantErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := envRepo.Update(ctx, tx, hijack, nil)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Update error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	// And the bystander row is byte-identical — including updated_at
	// and version, which the BEFORE-UPDATE trigger would have stamped
	// if the statement had matched orgB's row.
	afterB := getEnvironmentOrFail(ctx, t, s, envRepo, orgB.ID, storedB.ID, "after cross-tenant Update")
	assertEnvironmentByteIdentical(t, "cross-tenant Update bystander orgB", baselineB, afterB)
}

// TestEnvironmentRepositoryScheduleDeletionOnOrgADoesNotTouchOrgB is
// the byte-identical snapshot proof for ScheduleDeletion: when orgA
// schedules its own environment for teardown, orgB's bystander row
// must be byte-identical across EVERY observable column — most
// importantly including DeletionScheduledAt itself. A regression that
// stamped the wrong tenant's deletion_scheduled_at would mark another
// organization's environment for teardown without surfacing any error.
func TestEnvironmentRepositoryScheduleDeletionOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgA, "web")))
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	envFixA := environmentFixture(f.Environment(projATuple(projA), "shared"))
	envFixA.Slug = "production"
	envFixB := environmentFixture(f.Environment(projATuple(projB), "shared"))
	envFixB.Slug = "production"
	storedA := insertEnvironment(ctx, t, s, envRepo, envFixA)
	storedB := insertEnvironment(ctx, t, s, envRepo, envFixB)

	baselineB := getEnvironmentOrFail(ctx, t, s, envRepo, orgB.ID, storedB.ID, "baseline")
	if baselineB.DeletionScheduledAt != nil {
		t.Fatalf("baseline orgB.deletion_scheduled_at = %v, want nil — fixture invariant broken", baselineB.DeletionScheduledAt)
	}

	var scheduledA store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		scheduledA, writeErr = envRepo.ScheduleDeletion(ctx, tx, orgA.ID, storedA.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion(orgA, envA): %v", err)
	}
	if scheduledA.DeletionScheduledAt == nil {
		t.Fatal("ScheduleDeletion(orgA) did not stamp deletion_scheduled_at on orgA's row")
	}
	if scheduledA.Version != 2 {
		t.Errorf("ScheduleDeletion(orgA, envA).Version = %d, want 2", scheduledA.Version)
	}

	// The bystander row must be byte-identical — including
	// DeletionScheduledAt staying nil. A WHERE-on-id-only UPDATE that
	// stamped orgB's deletion_scheduled_at would be caught here.
	afterB := getEnvironmentOrFail(ctx, t, s, envRepo, orgB.ID, storedB.ID, "after orgA ScheduleDeletion")
	assertEnvironmentByteIdentical(t, "ScheduleDeletion(orgA) bystander orgB", baselineB, afterB)
}

// TestEnvironmentRepositoryScheduleDeletionCrossTenantBystanderIsByteIdentical
// proves ScheduleDeletion with another tenant's environment id
// surfaces as the same typed NotFound shape an unknown id would
// produce, AND leaves the bystander tenant's row byte-identical —
// including the DeletionScheduledAt stamp staying nil.
// environment_delete_test.go's existing
// TestEnvironmentRepositoryScheduleDeletionIsTenantScoped proves the
// NotFound code; this test extends the proof to every observable
// column of the bystander row, with the trigger-managed updated_at and
// trigger-bumped version stamps as the independent anchors that catch
// a momentary match even when the deletion stamp itself happened to
// look untouched.
func TestEnvironmentRepositoryScheduleDeletionCrossTenantBystanderIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	storedB := insertEnvironment(ctx, t, s, envRepo, environmentFixture(f.Environment(projATuple(projB), "production")))
	baselineB := getEnvironmentOrFail(ctx, t, s, envRepo, orgB.ID, storedB.ID, "baseline")

	crossTenantErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := envRepo.ScheduleDeletion(ctx, tx, orgA.ID, storedB.ID, nil)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant ScheduleDeletion error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	afterB := getEnvironmentOrFail(ctx, t, s, envRepo, orgB.ID, storedB.ID, "after cross-tenant ScheduleDeletion")
	assertEnvironmentByteIdentical(t, "cross-tenant ScheduleDeletion bystander orgB", baselineB, afterB)
}

// TestEnvironmentRepositoryInsertSameSlugInTwoTenantsBothSucceed proves
// the UNIQUE (project_id, slug) constraint is per-project, not global:
// two tenants can legitimately each have a "production" environment on
// their OWN projects, and neither Insert collides with the other. The
// flip side is the load-bearing reason every read above asserts
// byte-identical bystander rows — if slug alone were the UNIQUE key,
// two tenants could not share it, and the WHERE filter on
// organization_id (and project_id) would be redundant. The
// same-project / same-slug Conflict case lives in
// environment_repository_invariants_test.go.
func TestEnvironmentRepositoryInsertSameSlugInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgA, "web")))
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	envFixA := environmentFixture(f.Environment(projATuple(projA), "shared"))
	envFixA.Slug = "production"
	envFixB := environmentFixture(f.Environment(projATuple(projB), "shared"))
	envFixB.Slug = "production"

	storedA := insertEnvironment(ctx, t, s, envRepo, envFixA)
	storedB := insertEnvironment(ctx, t, s, envRepo, envFixB)

	if storedA.ID == storedB.ID {
		t.Fatalf("two tenants minted the same environment id %q — the id generator collided, the byte-identical-bystander tests are invalid", storedA.ID)
	}
	if storedA.OrganizationID == storedB.OrganizationID {
		t.Errorf("two environment rows landed under the SAME organization_id: %+v vs %+v", storedA, storedB)
	}
	if storedA.ProjectID == storedB.ProjectID {
		t.Errorf("two environment rows landed under the SAME project_id: %+v vs %+v", storedA, storedB)
	}
	if storedA.Slug != "production" || storedB.Slug != "production" {
		t.Errorf("slug text drifted between Insert calls: orgA=%q orgB=%q, want both 'production'", storedA.Slug, storedB.Slug)
	}
}

// TestEnvironmentRepositorySoftDeletedRowIsTenantScopedOnReadPaths
// proves the projection unique to environments (mirroring projects but
// scoped to a per-project read surface): a soft-deleted row in one
// tenant must NOT leak into ANY read surface — GetByID or
// ListByProject — of another tenant. The owning tenant still sees its
// own soft-deleted row through both read surfaces (the environments
// repository does not filter deletion_scheduled_at out of reads — that
// policy belongs to higher layers).
func TestEnvironmentRepositorySoftDeletedRowIsTenantScopedOnReadPaths(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	projRepo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgA, "empty-a")))
	projB := insertProject(ctx, t, s, projRepo, projectFixture(f.Project(orgB, "web")))
	storedB := insertEnvironment(ctx, t, s, envRepo, environmentFixture(f.Environment(projATuple(projB), "production")))
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := envRepo.ScheduleDeletion(ctx, tx, orgB.ID, storedB.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("seed ScheduleDeletion(orgB): %v", err)
	}

	// orgA GetByID on orgB's soft-deleted environment: NotFound, never
	// the row — regardless of the deletion_scheduled_at stamp.
	gotAErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := envRepo.GetByID(ctx, q, orgA.ID, storedB.ID)
		return err
	})
	var yeA *yerr.Error
	if !stderrors.As(gotAErr, &yeA) || yeA.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(orgA, soft-deleted envB) = %v, want a typed E_NOT_FOUND", gotAErr)
	}

	// orgA ListByProject on its own (empty) project must yield an empty
	// slice — orgB's soft-deleted row must NOT leak across.
	var listA []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		listA, readErr = envRepo.ListByProject(ctx, q, orgA.ID, projA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByProject(orgA, projA): %v", err)
	}
	if len(listA) != 0 {
		t.Errorf("ListByProject(orgA, projA) returned %d rows, want 0 — orgB's soft-deleted row leaked", len(listA))
	}

	// Also: orgA presenting orgB's project_id under orgA's org-id must
	// yield empty — a regression that resolved the WHERE clause by
	// project_id alone would have returned orgB's soft-deleted row here.
	var listACross []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		listACross, readErr = envRepo.ListByProject(ctx, q, orgA.ID, projB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByProject(orgA, projB): %v", err)
	}
	if len(listACross) != 0 {
		t.Errorf("ListByProject(orgA, projB) returned %d rows, want 0 — orgB's soft-deleted row leaked via cross-tenant project_id", len(listACross))
	}

	// The owning tenant (orgB) still sees its own soft-deleted row on
	// both read surfaces: GetByID returns the row with
	// DeletionScheduledAt stamped, ListByProject includes it. This pins
	// the per-tenant view: the environments repository deliberately
	// does NOT hide soft-deleted rows from the owning tenant's read
	// surfaces — that policy belongs to higher layers.
	gotB := getEnvironmentOrFail(ctx, t, s, envRepo, orgB.ID, storedB.ID, "owner GetByID")
	if gotB.DeletionScheduledAt == nil {
		t.Errorf("GetByID(orgB, soft-deleted envB).DeletionScheduledAt = nil, want a stamp — owning tenant lost visibility of own soft-deleted row")
	}
	var listB []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		listB, readErr = envRepo.ListByProject(ctx, q, orgB.ID, projB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByProject(orgB, projB): %v", err)
	}
	if len(listB) != 1 || listB[0].ID != storedB.ID {
		t.Errorf("ListByProject(orgB, projB) = %+v, want exactly [%s]", listB, storedB.ID)
	}
}

// --- shared helpers ---
//
// projATuple lifts a store.Project into the testutil.Project shape the
// factory's Environment / Service builders accept. The store.Project
// row carries the (id, organization_id) tuple the factory needs to
// derive a child environment's parent identifiers; the factory does
// not depend on the row's lifecycle columns. A local helper avoids a
// dependency on testutil internals from this test file and keeps the
// per-test seeding readable.
func projATuple(p store.Project) testutil.Project {
	return testutil.Project{ID: p.ID, OrganizationID: p.OrganizationID, Slug: p.Slug, Name: p.DisplayName}
}

// getEnvironmentOrFail reads an environment through the typed
// repository surface and fails the test on any error — the test cases
// use this exclusively for reads that are EXPECTED to succeed, so a
// NotFound here is a setup failure (the seeded row went missing) and
// not a leg under proof.
func getEnvironmentOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.EnvironmentRepository, organizationID, environmentID, label string) store.Environment {
	t.Helper()
	var got store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		got, readErr = repo.GetByID(ctx, q, organizationID, environmentID)
		return readErr
	}); err != nil {
		t.Fatalf("%s GetByID(%q, %q): %v", label, organizationID, environmentID, err)
	}
	return got
}

// assertEnvironmentByteIdentical asserts every observable column on a
// bystander environments row is byte-identical to its baseline. The
// trigger-managed updated_at AND the trigger-bumped version are both
// load-bearing here: the BEFORE-UPDATE environments_set_updated_at
// trigger refreshes updated_at on every matched UPDATE, and the
// environments_bump_version trigger increments version — either
// drifting independently surfaces a missing tenant predicate even when
// the column writes themselves look correct.
//
// DeletionScheduledAt is included as well because environments carries
// soft-delete as a nullable *time.Time on the row body: a regression
// that resolved the WHERE clause incorrectly could stamp another
// tenant's row from nil to non-nil (ScheduleDeletion) without
// surfacing any error.
func assertEnvironmentByteIdentical(t *testing.T, label string, baseline, after store.Environment) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.ProjectID != baseline.ProjectID {
		t.Errorf("%s: bystander.project_id = %q, want %q", label, after.ProjectID, baseline.ProjectID)
	}
	if after.Slug != baseline.Slug {
		t.Errorf("%s: bystander.slug = %q, want %q", label, after.Slug, baseline.Slug)
	}
	if after.DisplayName != baseline.DisplayName {
		t.Errorf("%s: bystander.display_name = %q, want %q", label, after.DisplayName, baseline.DisplayName)
	}
	if after.Kind != baseline.Kind {
		t.Errorf("%s: bystander.kind = %q, want %q", label, after.Kind, baseline.Kind)
	}
	if after.Version != baseline.Version {
		t.Errorf("%s: bystander.version = %d, want %d — the environments_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE environments_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
	switch {
	case baseline.DeletionScheduledAt == nil && after.DeletionScheduledAt != nil:
		t.Errorf("%s: bystander.deletion_scheduled_at = %v, want nil — a cross-tenant ScheduleDeletion stamped a peer tenant's row",
			label, *after.DeletionScheduledAt)
	case baseline.DeletionScheduledAt != nil && after.DeletionScheduledAt == nil:
		t.Errorf("%s: bystander.deletion_scheduled_at cleared from %v to nil — a cross-tenant operation cleared a peer tenant's soft-delete stamp",
			label, *baseline.DeletionScheduledAt)
	case baseline.DeletionScheduledAt != nil && after.DeletionScheduledAt != nil && !after.DeletionScheduledAt.Equal(*baseline.DeletionScheduledAt):
		t.Errorf("%s: bystander.deletion_scheduled_at = %v, want %v",
			label, *after.DeletionScheduledAt, *baseline.DeletionScheduledAt)
	}
}
