package store_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for the services table
// (BE-0446). services is a tenant-scoped great-grandchild table whose
// row body is anchored to a single tenant by THREE load-bearing schema
// facts:
//
//	(a) every column carries organization_id directly, and the
//	    composite FK (organization_id, project_id, environment_id) ->
//	    environments (organization_id, project_id, id) declared in
//	    migration 0002 is MATCH SIMPLE — so a service whose parent
//	    environment belongs to one tenant is structurally unrepresentable
//	    under another tenant's organization_id at the database layer.
//	    The BE-0445 invariants file already proves the Insert path
//	    returns the row in the expected shape, so this file does not
//	    re-prove the FK rejection;
//	(b) every repository method (Insert / GetByID / ListByEnvironment /
//	    Update / ScheduleDeletion / Restore) carries organization_id as
//	    the FIRST SQL predicate, ahead of the row identifier (and ahead
//	    of environment_id on the ListByEnvironment leg). The
//	    cross-tenant guarantee at this layer is therefore the
//	    byte-identical-bystander invariant every other tenant-scoped
//	    table is held to;
//	(c) the soft-delete column (deletion_scheduled_at, migration 0020)
//	    is a nullable *time.Time on every read path — the services
//	    repository does NOT filter soft-deleted rows out of GetByID or
//	    ListByEnvironment, so a regression that resolved the WHERE
//	    filter incorrectly could leak ANOTHER tenant's soft-deleted
//	    service just as easily as a live one. The
//	    "SoftDeletedRowIsTenantScopedOnReadPaths" leg below pins this.
//
// The services row body carries NO secret-bearing column — slug,
// display_name, and kind are surfaced as-is, and service-scoped
// secrets live in a separate service_variables table — so a raw
// secret-projection probe has no analogue here. The row body is fully
// observable through the typed GetByID / ListByEnvironment read paths,
// and the byte-identical-bystander assertion below covers every
// observable column (id, organization_id, project_id, environment_id,
// slug, display_name, kind, version, created_at, updated_at,
// deletion_scheduled_at).
//
// The BEFORE-UPDATE services_set_updated_at trigger (migration 0002)
// refreshes updated_at on every matched UPDATE — including a
// WHERE-less or WHERE-on-id-only UPDATE that touched the wrong
// tenant's row — and the services_bump_version trigger (migration
// 0011) increments version on the same path. Either of those two
// columns drifting on the bystander is independently sufficient to
// catch a missing tenant predicate even when the column writes
// themselves look correct, and every byte-identical-bystander test
// below asserts BOTH against the baseline. deletion_scheduled_at is
// asserted on top: if a cross-tenant ScheduleDeletion (or Restore)
// had matched the bystander's row, the nullable stamp would have
// moved from nil to non-nil (or back) on a peer tenant's row.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Insert RETURNING shape, duplicate-slug Conflict (UNIQUE
//     (environment_id, slug)), Update / ScheduleDeletion / Restore
//     dual-anchor (updated_at refreshed, created_at preserved, version
//     bumped), nil-Tx guards, and the Insert tx-rollback invariant are
//     proved by service_repository_invariants_test.go (BE-0445).
//   - Cross-tenant NotFound on GetByID / ListByEnvironment is ALSO
//     proved at the typed-error level by
//     TestServiceRepoGetByIDIsTenantScoped /
//     TestServiceRepoListByEnvironmentIsTenantScoped (service_test.go),
//     and TestServiceServiceUpdateCrossTenantIsNotFound /
//     TestServiceRepositoryRestoreIsTenantScoped at the service-layer
//     and restore-path level. The contribution of this file is the
//     byte-identical-bystander projection (the trigger-managed
//     updated_at and trigger-bumped version stamps did not drift on
//     the peer tenant's row) and the existence-leak projection (Code
//     AND Hint of the cross-tenant NotFound is indistinguishable from
//     an unknown id) — neither is covered by the existing tests.
//   - The HTTP-layer "another tenant's service id is a 404, not a
//     403" rule is proved by the per-endpoint policy matrix and
//     contract tests in httpapi.
//
// The tests run against an isolated, freshly migrated Postgres
// database and skip when YALLA_TEST_DATABASE_URL is unset.

// TestServiceRepositoryGetByIDReturnsCorrectRowAcrossTenants proves
// GetByID is keyed strictly by BOTH organization_id AND id: each
// tenant has its own services row, and GetByID(orgA, svcA) /
// GetByID(orgB, svcB) must each return their own row — never a
// swapped or merged response. The fixture deliberately gives BOTH
// tenants the SAME slug on their respective environments to defeat
// any regression that resolved the WHERE filter by slug alone.
func TestServiceRepositoryGetByIDReturnsCorrectRowAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web")
	projB := seedProject(t, db, f, orgB, "web")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	// Override the per-tenant slug derived by the factory so both rows
	// carry the SAME slug text on their OWN environments. A
	// WHERE-on-slug-only regression would still resolve to whichever
	// row the planner found first.
	svcFixA := serviceFixture(f.Service(envA, "api"))
	svcFixA.Slug = "api"
	svcFixB := serviceFixture(f.Service(envB, "api"))
	svcFixB.Slug = "api"
	svcA := insertService(ctx, t, s, repo, svcFixA)
	svcB := insertService(ctx, t, s, repo, svcFixB)

	var gotA store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.GetByID(ctx, q, orgA.ID, svcA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("GetByID(orgA, svcA): %v", err)
	}
	if gotA.OrganizationID != orgA.ID || gotA.ID != svcA.ID || gotA.ProjectID != projA.ID || gotA.EnvironmentID != envA.ID {
		t.Errorf("GetByID(orgA, svcA) = %+v, want orgA/svcA/projA/envA", gotA)
	}

	var gotB store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.GetByID(ctx, q, orgB.ID, svcB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("GetByID(orgB, svcB): %v", err)
	}
	if gotB.OrganizationID != orgB.ID || gotB.ID != svcB.ID || gotB.ProjectID != projB.ID || gotB.EnvironmentID != envB.ID {
		t.Errorf("GetByID(orgB, svcB) = %+v, want orgB/svcB/projB/envB", gotB)
	}

	// The two reads MUST have returned distinct rows on EVERY anchor —
	// id, organization_id, project_id, environment_id. A WHERE-on-id-only
	// mistake would collapse both lookups onto the same row, and an
	// overlap on any single anchor would surface here.
	if gotA.ID == gotB.ID || gotA.OrganizationID == gotB.OrganizationID || gotA.ProjectID == gotB.ProjectID || gotA.EnvironmentID == gotB.EnvironmentID {
		t.Errorf("GetByID returned overlapping rows across two tenants: %+v vs %+v", gotA, gotB)
	}
}

// TestServiceRepositoryGetByIDCrossTenantIsIndistinguishableFromUnknown
// proves the cross-tenant NotFound shape — Code AND Hint — is the SAME
// shape an unknown service id produces. A probing caller who guesses
// a peer tenant's service id cannot infer that the service id IS a
// real row in another tenant from the response: both surfaces emit
// yerr.CodeNotFound with matching Hint values, and the apierr.NotFound
// builder echoes the CALLER's id back verbatim (not the foreign row's
// id) so the Message never reveals existence either.
func TestServiceRepositoryGetByIDCrossTenantIsIndistinguishableFromUnknown(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcB := insertService(ctx, t, s, repo, serviceFixture(f.Service(envB, "api")))

	// Cross-tenant probe: (orgA, svcB.ID). The id is real and belongs
	// to a different tenant.
	crossTenantErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.GetByID(ctx, q, orgA.ID, svcB.ID)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant GetByID error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	// Wholly unknown id under orgA.
	unknownErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.GetByID(ctx, q, orgA.ID, "svc_never_existed")
		return err
	})
	var yeUnknown *yerr.Error
	if !stderrors.As(unknownErr, &yeUnknown) || yeUnknown.Code != yerr.CodeNotFound {
		t.Fatalf("unknown-id GetByID error = %v, want a typed E_NOT_FOUND", unknownErr)
	}

	// The two shapes must be indistinguishable on Code AND Hint — a
	// caller who diffed the response surfaces could otherwise enumerate
	// peers by probing service ids. The cross-tenant NotFound MUST NOT
	// echo the foreign service id either (apierr.NotFound documents
	// that the id passed in is the only id that surfaces in the
	// message, so orgA's probe always reflects orgA's request — never
	// orgB's real row).
	if yeCross.Code != yeUnknown.Code {
		t.Errorf("cross-tenant Code = %s, unknown-id Code = %s — existence leaks via Code", yeCross.Code, yeUnknown.Code)
	}
	if yeCross.Hint != yeUnknown.Hint {
		t.Errorf("cross-tenant Hint = %q, unknown-id Hint = %q — existence leaks via Hint", yeCross.Hint, yeUnknown.Hint)
	}
}

// TestServiceRepositoryListByEnvironmentCountsAreIsolated proves the
// rendered length of ListByEnvironment is local to the queried (org,
// environment) tuple — never the global count, never a sum across
// tenants. orgA's environment owns one service; orgB's environment
// owns three. ListByEnvironment(orgA, envA) must return exactly 1
// row; ListByEnvironment(orgB, envB) must return exactly 3. A SELECT
// without the WHERE organization_id (or environment_id) filter would
// have returned 4 for both calls, and the no-overlap-on-id assertion
// below pins the leak detector even tighter: any row id appearing in
// both responses is by definition a leak.
func TestServiceRepositoryListByEnvironmentCountsAreIsolated(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web")
	projB := seedProject(t, db, f, orgB, "web")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	insertService(ctx, t, s, repo, serviceFixture(f.Service(envA, "api")))
	insertService(ctx, t, s, repo, serviceFixture(f.Service(envB, "alpha")))
	insertService(ctx, t, s, repo, serviceFixture(f.Service(envB, "beta")))
	insertService(ctx, t, s, repo, serviceFixture(f.Service(envB, "gamma")))

	var gotA []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.ListByEnvironment(ctx, q, orgA.ID, envA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(orgA, envA): %v", err)
	}
	if len(gotA) != 1 {
		t.Errorf("ListByEnvironment(orgA, envA) returned %d rows, want 1 — orgB rows leaked", len(gotA))
	}
	for _, svc := range gotA {
		if svc.OrganizationID != orgA.ID || svc.EnvironmentID != envA.ID {
			t.Errorf("ListByEnvironment(orgA, envA) returned a foreign row: %+v", svc)
		}
	}

	var gotB []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.ListByEnvironment(ctx, q, orgB.ID, envB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(orgB, envB): %v", err)
	}
	if len(gotB) != 3 {
		t.Errorf("ListByEnvironment(orgB, envB) returned %d rows, want 3", len(gotB))
	}
	for _, svc := range gotB {
		if svc.OrganizationID != orgB.ID || svc.EnvironmentID != envB.ID {
			t.Errorf("ListByEnvironment(orgB, envB) returned a foreign row: %+v", svc)
		}
	}

	// The two responses must not overlap on service id — if any id
	// appeared in both lists, the WHERE filter is the only thing
	// keeping them apart and the only way for both calls to share a
	// row is a WHERE-less SELECT.
	seenInB := make(map[string]struct{}, len(gotB))
	for _, svc := range gotB {
		seenInB[svc.ID] = struct{}{}
	}
	for _, svc := range gotA {
		if _, overlap := seenInB[svc.ID]; overlap {
			t.Errorf("service id %q appears in both ListByEnvironment(orgA, envA) and ListByEnvironment(orgB, envB) responses", svc.ID)
		}
	}
}

// TestServiceRepositoryListByEnvironmentIsolatesSharedSlug proves that
// when each tenant has a service with the SAME slug under its OWN
// environment, each ListByEnvironment call renders only THIS (org,
// environment)'s row — never the other's, never a duplicate. The
// UNIQUE (environment_id, slug) index is per-environment, so two
// tenants CAN legitimately share slug text on their separate
// environments — and a regression that resolved the WHERE filter by
// slug alone would surface here as a leak. This is the load-bearing
// reason every read asserts byte-identical-bystander rows: if slug
// alone were the UNIQUE key, two tenants could not share it, and the
// WHERE filter on organization_id (and environment_id) would be
// redundant.
func TestServiceRepositoryListByEnvironmentIsolatesSharedSlug(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web")
	projB := seedProject(t, db, f, orgB, "web")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	// Force both rows to carry the SAME slug text by overriding the
	// per-tenant token. f.Service would otherwise derive distinct slug
	// text from the per-factory token; we want shared slug text here
	// so the WHERE-on-(organization_id, environment_id) filter is the
	// only thing isolating the two rows.
	svcFixA := serviceFixture(f.Service(envA, "shared"))
	svcFixA.Slug = "api"
	svcFixB := serviceFixture(f.Service(envB, "shared"))
	svcFixB.Slug = "api"
	storedA := insertService(ctx, t, s, repo, svcFixA)
	storedB := insertService(ctx, t, s, repo, svcFixB)

	var gotA []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotA, readErr = repo.ListByEnvironment(ctx, q, orgA.ID, envA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(orgA, envA): %v", err)
	}
	if len(gotA) != 1 {
		t.Fatalf("ListByEnvironment(orgA, envA) returned %d rows, want exactly 1 — orgB's row for the same slug text leaked or duplicated", len(gotA))
	}
	if gotA[0].ID != storedA.ID || gotA[0].OrganizationID != orgA.ID || gotA[0].EnvironmentID != envA.ID || gotA[0].Slug != "api" {
		t.Errorf("ListByEnvironment(orgA, envA)[0] = %+v, want orgA/envA/svcA/api", gotA[0])
	}

	var gotB []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		gotB, readErr = repo.ListByEnvironment(ctx, q, orgB.ID, envB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(orgB, envB): %v", err)
	}
	if len(gotB) != 1 {
		t.Fatalf("ListByEnvironment(orgB, envB) returned %d rows, want exactly 1 — orgA's row for the same slug text leaked or duplicated", len(gotB))
	}
	if gotB[0].ID != storedB.ID || gotB[0].OrganizationID != orgB.ID || gotB[0].EnvironmentID != envB.ID || gotB[0].Slug != "api" {
		t.Errorf("ListByEnvironment(orgB, envB)[0] = %+v, want orgB/envB/svcB/api", gotB[0])
	}
}

// TestServiceRepositoryListByEnvironmentIgnoresCrossTenantOrgIDOnOwnedEnvironment
// proves that a list scoped to orgA but pointed at orgB's
// environment_id returns zero rows — never orgB's services — and that
// orgA's own (empty) environment, queried through the same call, also
// returns zero. The cross-tenant call is indistinguishable from a
// wholly unknown (org, env) tuple on the wire: an empty slice in both
// cases. The existing TestServiceRepoListByEnvironmentIsTenantScoped
// proves the cross-tenant envB.ID under orgA returns empty; this test
// pins the "indistinguishable from unknown" projection by also
// exercising the empty-but-owned and entirely-unknown legs.
func TestServiceRepositoryListByEnvironmentIgnoresCrossTenantOrgIDOnOwnedEnvironment(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "empty-a")
	projB := seedProject(t, db, f, orgB, "web")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	// Seed orgB's environment so the cross-tenant probe has something
	// to leak if the WHERE filter is broken.
	insertService(ctx, t, s, repo, serviceFixture(f.Service(envB, "api")))

	cases := []struct {
		label         string
		orgID         string
		environmentID string
	}{
		{"orgA owned empty env", orgA.ID, envA.ID},
		{"orgA probing orgB env", orgA.ID, envB.ID},
		{"orgA probing unknown env", orgA.ID, "env_never_existed"},
	}
	for _, c := range cases {
		var got []store.Service
		if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
			var readErr error
			got, readErr = repo.ListByEnvironment(ctx, q, c.orgID, c.environmentID)
			return readErr
		}); err != nil {
			t.Fatalf("ListByEnvironment(%s): %v", c.label, err)
		}
		if got == nil {
			t.Errorf("ListByEnvironment(%s) = nil, want non-nil empty slice — the wire shape must be a deterministic empty list", c.label)
		}
		if len(got) != 0 {
			t.Errorf("ListByEnvironment(%s) returned %d rows, want 0 — orgB's service leaked", c.label, len(got))
		}
	}
}

// TestServiceRepositoryUpdateOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for Update: when orgA UPDATEs its own
// service row, orgB's bystander row must be byte-identical to its
// baseline across EVERY observable column — including the
// trigger-managed updated_at and the trigger-bumped version, which
// are the independent anchors that catch a WHERE-on-id-only UPDATE
// even when the column writes themselves happened to look correct.
//
// The fixture has BOTH tenants share the SAME slug on their OWN
// respective environments, so a regression that resolved the WHERE
// clause by slug alone — or by id alone — would have hit orgB's row.
func TestServiceRepositoryUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web")
	projB := seedProject(t, db, f, orgB, "web")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcFixA := serviceFixture(f.Service(envA, "shared"))
	svcFixA.Slug = "api"
	svcFixB := serviceFixture(f.Service(envB, "shared"))
	svcFixB.Slug = "api"
	storedA := insertService(ctx, t, s, repo, svcFixA)
	storedB := insertService(ctx, t, s, repo, svcFixB)

	baselineB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")

	// orgA mutates its own row to a new slug + display_name.
	desired := storedA
	desired.Slug = "api-v2"
	desired.DisplayName = "API v2"
	var updatedA store.Service
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		updatedA, writeErr = repo.Update(ctx, tx, desired, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Update(orgA, svcA): %v", err)
	}
	// orgA must have actually changed — a no-op repository cannot
	// silently pass the byte-identical-orgB check below.
	if updatedA.OrganizationID != orgA.ID || updatedA.ID != storedA.ID || updatedA.Slug != "api-v2" || updatedA.DisplayName != "API v2" || updatedA.Version != 2 {
		t.Errorf("Update(orgA, svcA) = %+v, want orgA/svcA/api-v2/API v2/version=2", updatedA)
	}

	afterB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after orgA Update")
	assertServiceByteIdentical(t, "Update(orgA) bystander orgB", baselineB, afterB)
}

// TestServiceRepositoryUpdateCrossTenantBystanderIsByteIdentical
// proves Update with another tenant's service id surfaces as the
// same typed NotFound shape an unknown id would produce, AND leaves
// the bystander tenant's row byte-identical — the trigger would
// otherwise refresh updated_at and bump version if the UPDATE
// statement had matched orgB's row even momentarily.
// serviceservice_update_test.go's existing
// TestServiceServiceUpdateCrossTenantIsNotFound proves the typed
// NotFound at the service layer; this test extends the proof to
// every observable column of the bystander row through the
// repository's own surface.
func TestServiceRepositoryUpdateCrossTenantBystanderIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web")
	envB := seedEnvironment(t, db, f, projB, "production")
	storedB := insertService(ctx, t, s, repo, serviceFixture(f.Service(envB, "api")))
	baselineB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")

	// orgA presents orgB's service id under orgA's tenant — the WHERE
	// (organization_id = orgA AND id = svcB) matches nothing.
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
	afterB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after cross-tenant Update")
	assertServiceByteIdentical(t, "cross-tenant Update bystander orgB", baselineB, afterB)
}

// TestServiceRepositoryScheduleDeletionOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for ScheduleDeletion: when orgA
// schedules its own service for teardown, orgB's bystander row must
// be byte-identical across EVERY observable column — most importantly
// including DeletionScheduledAt itself. A regression that stamped the
// wrong tenant's deletion_scheduled_at would mark another
// organization's service for teardown without surfacing any error.
func TestServiceRepositoryScheduleDeletionOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web")
	projB := seedProject(t, db, f, orgB, "web")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcFixA := serviceFixture(f.Service(envA, "shared"))
	svcFixA.Slug = "api"
	svcFixB := serviceFixture(f.Service(envB, "shared"))
	svcFixB.Slug = "api"
	storedA := insertService(ctx, t, s, repo, svcFixA)
	storedB := insertService(ctx, t, s, repo, svcFixB)

	baselineB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")
	if baselineB.DeletionScheduledAt != nil {
		t.Fatalf("baseline orgB.deletion_scheduled_at = %v, want nil — fixture invariant broken", baselineB.DeletionScheduledAt)
	}

	var scheduledA store.Service
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		scheduledA, writeErr = repo.ScheduleDeletion(ctx, tx, orgA.ID, storedA.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion(orgA, svcA): %v", err)
	}
	if scheduledA.DeletionScheduledAt == nil {
		t.Fatal("ScheduleDeletion(orgA) did not stamp deletion_scheduled_at on orgA's row")
	}
	if scheduledA.Version != 2 {
		t.Errorf("ScheduleDeletion(orgA, svcA).Version = %d, want 2", scheduledA.Version)
	}

	// The bystander row must be byte-identical — including
	// DeletionScheduledAt staying nil. A WHERE-on-id-only UPDATE that
	// stamped orgB's deletion_scheduled_at would be caught here.
	afterB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after orgA ScheduleDeletion")
	assertServiceByteIdentical(t, "ScheduleDeletion(orgA) bystander orgB", baselineB, afterB)
}

// TestServiceRepositoryScheduleDeletionCrossTenantBystanderIsByteIdentical
// proves ScheduleDeletion with another tenant's service id surfaces
// as the same typed NotFound shape an unknown id would produce, AND
// leaves the bystander tenant's row byte-identical — including the
// DeletionScheduledAt stamp staying nil. The trigger-managed
// updated_at and trigger-bumped version stamps are the independent
// anchors that catch a momentary match even when the deletion stamp
// itself happened to look untouched.
func TestServiceRepositoryScheduleDeletionCrossTenantBystanderIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web")
	envB := seedEnvironment(t, db, f, projB, "production")
	storedB := insertService(ctx, t, s, repo, serviceFixture(f.Service(envB, "api")))
	baselineB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")

	crossTenantErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, orgA.ID, storedB.ID, nil)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant ScheduleDeletion error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	afterB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after cross-tenant ScheduleDeletion")
	assertServiceByteIdentical(t, "cross-tenant ScheduleDeletion bystander orgB", baselineB, afterB)
}

// TestServiceRepositoryRestoreOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for Restore: when orgA restores its
// own soft-deleted service, orgB's bystander row must be
// byte-identical across EVERY observable column — including
// DeletionScheduledAt staying at its prior value. The services
// repository's Restore method is the inverse of ScheduleDeletion (it
// clears deletion_scheduled_at back to NULL); the bystander
// projection here pins the WHERE clause on (organization_id, id)
// against the same hostile-fixture seeding the other Update / delete
// surfaces use. Two distinct soft-delete states are exercised on the
// peer tenant: nil (orgB live) and non-nil (orgB also soft-deleted),
// so a regression that incorrectly cleared the wrong tenant's stamp
// surfaces on BOTH the live-peer and the soft-deleted-peer paths.
func TestServiceRepositoryRestoreOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web")
	projB := seedProject(t, db, f, orgB, "web")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcFixA := serviceFixture(f.Service(envA, "shared"))
	svcFixA.Slug = "api"
	svcFixB := serviceFixture(f.Service(envB, "shared"))
	svcFixB.Slug = "api"
	storedA := insertService(ctx, t, s, repo, svcFixA)
	storedB := insertService(ctx, t, s, repo, svcFixB)

	// Seed the precondition for Restore: orgA's row is scheduled for
	// deletion so Restore has something to undo.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, orgA.ID, storedA.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("seed ScheduleDeletion(orgA): %v", err)
	}

	baselineB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline live peer")

	// Restore orgA. orgB is live (DeletionScheduledAt nil) and must
	// stay byte-identical on every column — most importantly the
	// nullable soft-delete stamp staying nil.
	var restoredA store.Service
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		restoredA, writeErr = repo.Restore(ctx, tx, orgA.ID, storedA.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Restore(orgA, svcA): %v", err)
	}
	if restoredA.DeletionScheduledAt != nil {
		t.Errorf("Restore(orgA) did not clear deletion_scheduled_at on orgA's row: %v", restoredA.DeletionScheduledAt)
	}
	if restoredA.Version != 3 {
		t.Errorf("Restore(orgA, svcA).Version = %d, want 3 (Insert=1, ScheduleDeletion=2, Restore=3)", restoredA.Version)
	}

	afterBLive := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after orgA Restore against live peer")
	assertServiceByteIdentical(t, "Restore(orgA) bystander orgB live", baselineB, afterBLive)

	// Now exercise the OTHER soft-delete state on the peer: orgB also
	// soft-deleted. A regression that cleared the wrong tenant's stamp
	// from non-nil to nil would surface here even though the
	// live-peer case above did not exercise that flip direction.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, orgB.ID, storedB.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("seed ScheduleDeletion(orgB): %v", err)
	}
	// Re-schedule orgA so a fresh Restore has something to undo.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, orgA.ID, storedA.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("re-schedule orgA: %v", err)
	}

	baselineBDeleted := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline soft-deleted peer")
	if baselineBDeleted.DeletionScheduledAt == nil {
		t.Fatal("baseline orgB.deletion_scheduled_at = nil after seed ScheduleDeletion — fixture invariant broken")
	}

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Restore(ctx, tx, orgA.ID, storedA.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("Restore(orgA) over soft-deleted peer: %v", err)
	}

	afterBDeleted := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after orgA Restore against soft-deleted peer")
	assertServiceByteIdentical(t, "Restore(orgA) bystander orgB soft-deleted", baselineBDeleted, afterBDeleted)
}

// TestServiceRepositoryRestoreCrossTenantBystanderIsByteIdentical
// proves Restore with another tenant's service id surfaces as the
// same typed NotFound shape an unknown id would produce, AND leaves
// the bystander tenant's row byte-identical. The peer row is
// soft-deleted in this fixture (DeletionScheduledAt non-nil) so a
// regression that incorrectly cleared the peer's stamp would be
// caught by the DeletionScheduledAt projection of the byte-identical
// helper. service_restore_test.go's existing
// TestServiceRepositoryRestoreIsTenantScoped proves the typed
// NotFound; this test extends the proof to every observable column.
func TestServiceRepositoryRestoreCrossTenantBystanderIsByteIdentical(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web")
	envB := seedEnvironment(t, db, f, projB, "production")
	storedB := insertService(ctx, t, s, repo, serviceFixture(f.Service(envB, "api")))

	// orgB's row is soft-deleted: a cross-tenant Restore from orgA
	// must NOT clear it.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, orgB.ID, storedB.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("seed ScheduleDeletion(orgB): %v", err)
	}
	baselineB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "baseline")
	if baselineB.DeletionScheduledAt == nil {
		t.Fatal("baseline orgB.deletion_scheduled_at = nil after seed ScheduleDeletion — fixture invariant broken")
	}

	crossTenantErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Restore(ctx, tx, orgA.ID, storedB.ID, nil)
		return err
	})
	var yeCross *yerr.Error
	if !stderrors.As(crossTenantErr, &yeCross) || yeCross.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Restore error = %v, want a typed E_NOT_FOUND", crossTenantErr)
	}

	afterB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "after cross-tenant Restore")
	assertServiceByteIdentical(t, "cross-tenant Restore bystander orgB", baselineB, afterB)
}

// TestServiceRepositoryInsertSameSlugInTwoTenantsBothSucceed proves
// the UNIQUE (environment_id, slug) constraint is per-environment,
// not global: two tenants can legitimately each have an "api" service
// on their OWN environments, and neither Insert collides with the
// other. The flip side is the load-bearing reason every read above
// asserts byte-identical bystander rows — if slug alone were the
// UNIQUE key, two tenants could not share it, and the WHERE filter
// on organization_id (and environment_id) would be redundant. The
// same-environment / same-slug Conflict case lives in
// service_repository_invariants_test.go.
func TestServiceRepositoryInsertSameSlugInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web")
	projB := seedProject(t, db, f, orgB, "web")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcFixA := serviceFixture(f.Service(envA, "shared"))
	svcFixA.Slug = "api"
	svcFixB := serviceFixture(f.Service(envB, "shared"))
	svcFixB.Slug = "api"

	storedA := insertService(ctx, t, s, repo, svcFixA)
	storedB := insertService(ctx, t, s, repo, svcFixB)

	if storedA.ID == storedB.ID {
		t.Fatalf("two tenants minted the same service id %q — the id generator collided, the byte-identical-bystander tests are invalid", storedA.ID)
	}
	if storedA.OrganizationID == storedB.OrganizationID {
		t.Errorf("two service rows landed under the SAME organization_id: %+v vs %+v", storedA, storedB)
	}
	if storedA.EnvironmentID == storedB.EnvironmentID {
		t.Errorf("two service rows landed under the SAME environment_id: %+v vs %+v", storedA, storedB)
	}
	if storedA.Slug != "api" || storedB.Slug != "api" {
		t.Errorf("slug text drifted between Insert calls: orgA=%q orgB=%q, want both 'api'", storedA.Slug, storedB.Slug)
	}
}

// TestServiceRepositorySoftDeletedRowIsTenantScopedOnReadPaths proves
// the projection unique to services (mirroring environments but
// scoped to a per-environment read surface): a soft-deleted row in
// one tenant must NOT leak into ANY read surface — GetByID or
// ListByEnvironment — of another tenant. The owning tenant still
// sees its own soft-deleted row through both read surfaces (the
// services repository does not filter deletion_scheduled_at out of
// reads — that policy belongs to higher layers).
func TestServiceRepositorySoftDeletedRowIsTenantScopedOnReadPaths(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "empty-a")
	projB := seedProject(t, db, f, orgB, "web")
	envA := seedEnvironment(t, db, f, projA, "production")
	envB := seedEnvironment(t, db, f, projB, "production")
	storedB := insertService(ctx, t, s, repo, serviceFixture(f.Service(envB, "api")))
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, orgB.ID, storedB.ID, nil)
		return err
	}); err != nil {
		t.Fatalf("seed ScheduleDeletion(orgB): %v", err)
	}

	// orgA GetByID on orgB's soft-deleted service: NotFound, never
	// the row — regardless of the deletion_scheduled_at stamp.
	gotAErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.GetByID(ctx, q, orgA.ID, storedB.ID)
		return err
	})
	var yeA *yerr.Error
	if !stderrors.As(gotAErr, &yeA) || yeA.Code != yerr.CodeNotFound {
		t.Fatalf("GetByID(orgA, soft-deleted svcB) = %v, want a typed E_NOT_FOUND", gotAErr)
	}

	// orgA ListByEnvironment on its own (empty) environment must yield
	// an empty slice — orgB's soft-deleted row must NOT leak across.
	var listA []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		listA, readErr = repo.ListByEnvironment(ctx, q, orgA.ID, envA.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(orgA, envA): %v", err)
	}
	if len(listA) != 0 {
		t.Errorf("ListByEnvironment(orgA, envA) returned %d rows, want 0 — orgB's soft-deleted row leaked", len(listA))
	}

	// Also: orgA presenting orgB's environment_id under orgA's org-id
	// must yield empty — a regression that resolved the WHERE clause
	// by environment_id alone would have returned orgB's soft-deleted
	// row here.
	var listACross []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		listACross, readErr = repo.ListByEnvironment(ctx, q, orgA.ID, envB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(orgA, envB): %v", err)
	}
	if len(listACross) != 0 {
		t.Errorf("ListByEnvironment(orgA, envB) returned %d rows, want 0 — orgB's soft-deleted row leaked via cross-tenant environment_id", len(listACross))
	}

	// The owning tenant (orgB) still sees its own soft-deleted row on
	// both read surfaces: GetByID returns the row with
	// DeletionScheduledAt stamped, ListByEnvironment includes it. This
	// pins the per-tenant view: the services repository deliberately
	// does NOT hide soft-deleted rows from the owning tenant's read
	// surfaces — that policy belongs to higher layers.
	gotB := getServiceOrFail(ctx, t, s, repo, orgB.ID, storedB.ID, "owner GetByID")
	if gotB.DeletionScheduledAt == nil {
		t.Errorf("GetByID(orgB, soft-deleted svcB).DeletionScheduledAt = nil, want a stamp — owning tenant lost visibility of own soft-deleted row")
	}
	var listB []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		listB, readErr = repo.ListByEnvironment(ctx, q, orgB.ID, envB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(orgB, envB): %v", err)
	}
	if len(listB) != 1 || listB[0].ID != storedB.ID {
		t.Errorf("ListByEnvironment(orgB, envB) = %+v, want exactly [%s]", listB, storedB.ID)
	}
}

// --- shared helpers ---

// getServiceOrFail reads a service through the typed repository
// surface and fails the test on any error — the test cases use this
// exclusively for reads that are EXPECTED to succeed, so a NotFound
// here is a setup failure (the seeded row went missing) and not a
// leg under proof.
func getServiceOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceRepository, organizationID, serviceID, label string) store.Service {
	t.Helper()
	var got store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		got, readErr = repo.GetByID(ctx, q, organizationID, serviceID)
		return readErr
	}); err != nil {
		t.Fatalf("%s GetByID(%q, %q): %v", label, organizationID, serviceID, err)
	}
	return got
}

// assertServiceByteIdentical asserts every observable column on a
// bystander services row is byte-identical to its baseline. The
// trigger-managed updated_at AND the trigger-bumped version are both
// load-bearing here: the BEFORE-UPDATE services_set_updated_at
// trigger (migration 0002) refreshes updated_at on every matched
// UPDATE, and the services_bump_version trigger (migration 0011)
// increments version — either drifting independently surfaces a
// missing tenant predicate even when the column writes themselves
// look correct.
//
// DeletionScheduledAt is included as well because services carries
// soft-delete as a nullable *time.Time on the row body: a regression
// that resolved the WHERE clause incorrectly could stamp another
// tenant's row from nil to non-nil (ScheduleDeletion) or clear a
// peer's stamp from non-nil to nil (Restore) without surfacing any
// error.
func assertServiceByteIdentical(t *testing.T, label string, baseline, after store.Service) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.ProjectID != baseline.ProjectID {
		t.Errorf("%s: bystander.project_id = %q, want %q", label, after.ProjectID, baseline.ProjectID)
	}
	if after.EnvironmentID != baseline.EnvironmentID {
		t.Errorf("%s: bystander.environment_id = %q, want %q", label, after.EnvironmentID, baseline.EnvironmentID)
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
		t.Errorf("%s: bystander.version = %d, want %d — the services_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE services_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
	switch {
	case baseline.DeletionScheduledAt == nil && after.DeletionScheduledAt != nil:
		t.Errorf("%s: bystander.deletion_scheduled_at = %v, want nil — a cross-tenant ScheduleDeletion stamped a peer tenant's row",
			label, *after.DeletionScheduledAt)
	case baseline.DeletionScheduledAt != nil && after.DeletionScheduledAt == nil:
		t.Errorf("%s: bystander.deletion_scheduled_at cleared from %v to nil — a cross-tenant Restore (or ScheduleDeletion-clear) cleared a peer tenant's soft-delete stamp",
			label, *baseline.DeletionScheduledAt)
	case baseline.DeletionScheduledAt != nil && after.DeletionScheduledAt != nil && !after.DeletionScheduledAt.Equal(*baseline.DeletionScheduledAt):
		t.Errorf("%s: bystander.deletion_scheduled_at = %v, want %v",
			label, *after.DeletionScheduledAt, *baseline.DeletionScheduledAt)
	}
}
