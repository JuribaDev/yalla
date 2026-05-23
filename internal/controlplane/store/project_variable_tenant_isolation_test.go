package store_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Repository-layer tenant-isolation tests for the project_variables
// table (BE-0450). project_variables is a tenant-scoped child table
// (project variables are parented to projects, which are parented to
// organizations) whose row body is anchored to a single tenant by FOUR
// load-bearing schema facts:
//
//	(a) every column carries organization_id explicitly, and the
//	    composite FK (organization_id, project_id) -> projects
//	    (organization_id, id) is MATCH SIMPLE — so a row whose project
//	    belongs to one tenant is structurally unrepresentable as another
//	    tenant's variable at the database layer. The BE-0449 invariants
//	    file (project_variable_repository_invariants_test.go) already
//	    proves the per-row Upsert and CHECK paths; this file targets the
//	    bystander-on-peer-mutation surface.
//	(b) every repository method (ListByProject / Upsert /
//	    DeleteByProjectExceptKeys) carries organization_id as the first
//	    SQL predicate, ahead of the project identifier. The cross-tenant
//	    guarantee at this layer is therefore the byte-identical-bystander
//	    invariant every other tenant-scoped table is held to.
//	(c) the UNIQUE constraint project_variables_organization_id_project_id_key_key
//	    targets the COMPOSITE tuple (organization_id, project_id, key) —
//	    organization_id is in the conflict target itself, so two tenants
//	    can legitimately each own a row with the SAME key on their OWN
//	    projects. The shared-scope-tuple safety net below pins this and
//	    makes the byte-identical-bystander projection on Upsert load-
//	    bearing (a regression that resolved the conflict by the
//	    (project_id, key) pair alone would have hit the peer tenant's
//	    row).
//	(d) project_variables carries SECRET-BEARING columns — value (for
//	    non-secret variables) and the (secret_provider, secret_key_id,
//	    secret_ciphertext) tuple (for is_secret rows). Cross-tenant
//	    ERROR shapes must never echo another tenant's value or
//	    ciphertext; a cross-tenant MUTATION must leave the bystander
//	    tenant's value AND ciphertext byte-identical. The
//	    byte-identical-bystander projection below covers BOTH surfaces
//	    so a regression that re-sealed orgB's row with orgA's secret
//	    bytes — or stamped orgA's plaintext into orgB's value column —
//	    surfaces here.
//
// project_variables is a STRUCTURAL VARIANT of organization_variables:
// it adds the per-project scope leg the org-level table does not have,
// and its UNIQUE conflict target tuples (organization_id, project_id,
// key) instead of (organization_id, key). Every leg of the
// org-variable template that exercised a key-collision across two
// tenants resolves here on the SAME key against the per-project
// composite, exercising the project_id leg of the conflict target as
// the per-tenant boundary the previous file did not have.
//
// The BEFORE-UPDATE project_variables_set_updated_at trigger refreshes
// updated_at on every matched UPDATE — including a WHERE-less or
// WHERE-on-scope-tuple-only UPDATE that touched the wrong tenant's row —
// and the project_variables_bump_version trigger increments version on
// the same path. Either of those two columns drifting on the bystander
// is independently sufficient to catch a missing tenant predicate even
// when the column writes themselves look correct, and every byte-
// identical-bystander test below asserts BOTH against the baseline.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Upsert INSERT RETURNING shape, Upsert UPDATE-branch dual-anchor
//     (updated_at refreshed, created_at preserved, version bumped,
//     caller-id ignored), cross-tenant project_id FK Conflict,
//     duplicate-PK Conflict, secret-columns CHECK violations, ON DELETE
//     CASCADE from projects, Upsert tx-rollback, and nil-Tx guards are
//     proved by project_variable_repository_invariants_test.go
//     (BE-0449).
//   - ListByProject deterministic ordering, non-nil empty slice, and
//     the basic ListByProject tenant-scoping property (cross-tenant
//     projectID returns an empty slice) are proved by
//     project_variable_test.go.
//   - The HTTP-layer "another tenant's project id is a 404, not a 403"
//     rule is proved by the per-endpoint policy matrix and contract
//     tests in httpapi.
//   - project_variables exposes NO per-id Get, NO per-key Get, and NO
//     per-key Delete on the repository surface — the only mutation
//     paths are Upsert (which either INSERTs or fires the ON CONFLICT
//     DO UPDATE branch) and DeleteByProjectExceptKeys (bulk delete by
//     exclusion). The byte-identical-bystander projection is therefore
//     observed through ListByProject (the only read surface for a
//     project-variable row from the repository).
//   - project_variables has no deletion_scheduled_at / soft-delete
//     column — rows are hard-deleted in a single statement, and the
//     cross-tenant cascade behaviour (projects deletion removing child
//     variable rows) belongs to the parent table. The acceptance-
//     criteria mention of "soft-deleted rows where applicable"
//     therefore has no surface here; documenting the deliberate absence
//     keeps a future reader from looking for a missing test (mirrors
//     service_grant_tenant_isolation_test.go's note).
//
// The tests run against an isolated, freshly migrated Postgres database
// and skip when YALLA_TEST_DATABASE_URL is unset.

// newProjectVariableID mints a fresh `pvar_<token_n>` id from the
// factory's per-test counter. The factory's id generator only stamps
// known domain prefixes; the project_variable invariants test inlines
// its own variant, so this file defines its own helper with a name
// distinct from every other *_test.go file under store/.
func newProjectVariableID(f *testutil.Factory, org testutil.Organization, label string) string {
	return "pvar_" + f.Project(org, label).ID[len("prj_"):]
}

// upsertProjectVariable runs the repository Upsert inside Store.Write
// and returns the persisted row. The helper name is distinct from the
// (non-existent) helper in project_variable_repository_invariants_test.go
// and from every other *_test.go file in the package.
func upsertProjectVariable(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.ProjectVariableRepository,
	id, organizationID, projectID, key string,
	in store.ProjectVariableUpsert,
) store.ProjectVariable {
	t.Helper()
	var stored store.ProjectVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Upsert(ctx, tx, id, organizationID, projectID, key, in)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("upsert project variable: %v", err)
	}
	return stored
}

// listProjectVariablesOrFail runs ListByProject inside Store.Read and
// fatals on error. The helper name is distinct from every other
// *_test.go file in the package.
func listProjectVariablesOrFail(
	ctx context.Context,
	t *testing.T,
	s *store.Store,
	repo *store.ProjectVariableRepository,
	organizationID, projectID string,
) []store.ProjectVariable {
	t.Helper()
	var out []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, lerr := repo.ListByProject(ctx, q, organizationID, projectID)
		if lerr != nil {
			return lerr
		}
		out = rows
		return nil
	}); err != nil {
		t.Fatalf("ListByProject(%q, %q): %v", organizationID, projectID, err)
	}
	return out
}

// TestProjectVariableRepositoryListByProjectReturnsCorrectRowsAcrossTenants
// proves ListByProject is keyed strictly by BOTH organization_id AND
// project_id: each tenant has its own project and its own variable row,
// and ListByProject(orgA, projA) / ListByProject(orgB, projB) must each
// return their own row — never a swapped or merged response.
func TestProjectVariableRepositoryListByProjectReturnsCorrectRowsAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	rowA := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgA, "alpha"), orgA.ID, projA.ID, "REGION_A",
		store.ProjectVariableUpsert{Value: "us-east-1", IsSecret: false})
	rowB := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgB, "beta"), orgB.ID, projB.ID, "REGION_B",
		store.ProjectVariableUpsert{Value: "eu-west-1", IsSecret: false})

	listA := listProjectVariablesOrFail(ctx, t, s, repo, orgA.ID, projA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByProject(orgA, projA) returned %d rows, want exactly 1 — orgB rows leaked", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != orgA.ID || listA[0].ProjectID != projA.ID || listA[0].Key != "REGION_A" || listA[0].Value != "us-east-1" {
		t.Errorf("ListByProject(orgA, projA)[0] = %+v, want orgA/projA/REGION_A/us-east-1", listA[0])
	}

	listB := listProjectVariablesOrFail(ctx, t, s, repo, orgB.ID, projB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByProject(orgB, projB) returned %d rows, want exactly 1 — orgA rows leaked", len(listB))
	}
	if listB[0].ID != rowB.ID || listB[0].OrganizationID != orgB.ID || listB[0].ProjectID != projB.ID || listB[0].Key != "REGION_B" || listB[0].Value != "eu-west-1" {
		t.Errorf("ListByProject(orgB, projB)[0] = %+v, want orgB/projB/REGION_B/eu-west-1", listB[0])
	}

	if listA[0].ID == listB[0].ID || listA[0].OrganizationID == listB[0].OrganizationID ||
		listA[0].ProjectID == listB[0].ProjectID || listA[0].Key == listB[0].Key ||
		listA[0].Value == listB[0].Value {
		t.Errorf("ListByProject returned overlapping rows across two tenants: %+v vs %+v", listA[0], listB[0])
	}
}

// TestProjectVariableRepositoryListByProjectCrossTenantProjectIDReturnsEmpty
// proves ListByProject is tenant scoped at the SQL predicate: a
// cross-tenant project_id (a real project in another organization)
// matches no rows and yields a non-nil empty slice, and an unknown
// project_id under the same organization lands on the same empty-slice
// shape. A probing caller cannot infer the existence of a peer tenant's
// project from the response either.
func TestProjectVariableRepositoryListByProjectCrossTenantProjectIDReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web-b")

	upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgB, "leak1"), orgB.ID, projB.ID, "SECRET_VALUE_ONE",
		store.ProjectVariableUpsert{Value: "tenant-b-only-1", IsSecret: false})
	upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgB, "leak2"), orgB.ID, projB.ID, "SECRET_VALUE_TWO",
		store.ProjectVariableUpsert{Value: "tenant-b-only-2", IsSecret: false})

	crossTenant := listProjectVariablesOrFail(ctx, t, s, repo, orgA.ID, projB.ID)
	if len(crossTenant) != 0 {
		t.Errorf("ListByProject(orgA, projB) returned %d rows, want 0 — orgB variables leaked through a cross-tenant project_id", len(crossTenant))
	}
	if crossTenant == nil {
		t.Error("ListByProject(orgA, projB) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice so callers can iterate without a nil check")
	}

	unknown := listProjectVariablesOrFail(ctx, t, s, repo, orgA.ID, "prj_never_existed")
	if len(unknown) != 0 {
		t.Errorf("ListByProject(orgA, unknown) returned %d rows, want 0", len(unknown))
	}
	if unknown == nil {
		t.Error("ListByProject(orgA, unknown) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice")
	}
}

// TestProjectVariableRepositoryListByProjectIsolatesSharedKey proves
// that when both tenants have a variable row whose key is IDENTICAL —
// but on their OWN respective projects — each ListByProject call
// renders only THIS tenant's row, never the other's, never a duplicate.
// The (organization_id, project_id, key) UNIQUE conflict target is per-
// tenant, so both rows coexist; a regression that resolved the WHERE
// filter by (project_id, key) or by key alone — without
// organization_id — would surface here as a leak.
func TestProjectVariableRepositoryListByProjectIsolatesSharedKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	rowA := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgA, "shared-a"), orgA.ID, projA.ID, "DB_URL",
		store.ProjectVariableUpsert{Value: "postgres://orgA-only", IsSecret: false})
	rowB := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgB, "shared-b"), orgB.ID, projB.ID, "DB_URL",
		store.ProjectVariableUpsert{Value: "postgres://orgB-only", IsSecret: false})

	listA := listProjectVariablesOrFail(ctx, t, s, repo, orgA.ID, projA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByProject(orgA, projA) returned %d rows, want exactly 1 — orgB row for the same key leaked or duplicated", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != orgA.ID || listA[0].Value != "postgres://orgA-only" {
		t.Errorf("ListByProject(orgA, projA)[0] = %+v, want id=%q org=%q value='postgres://orgA-only'", listA[0], rowA.ID, orgA.ID)
	}

	listB := listProjectVariablesOrFail(ctx, t, s, repo, orgB.ID, projB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByProject(orgB, projB) returned %d rows, want exactly 1 — orgA row for the same key leaked or duplicated", len(listB))
	}
	if listB[0].ID != rowB.ID || listB[0].OrganizationID != orgB.ID || listB[0].Value != "postgres://orgB-only" {
		t.Errorf("ListByProject(orgB, projB)[0] = %+v, want id=%q org=%q value='postgres://orgB-only'", listB[0], rowB.ID, orgB.ID)
	}

	// The two responses must not overlap on id — if any id appeared in
	// both lists, the WHERE filter is the only thing keeping them apart
	// and the only way for both calls to share a row is a WHERE-less
	// SELECT.
	if listA[0].ID == listB[0].ID {
		t.Errorf("variable id %q appears in both List(orgA, projA) and List(orgB, projB) responses", listA[0].ID)
	}
	// And neither side's value column may carry the OTHER tenant's
	// value — the most direct check that a value-leak regression has
	// not happened.
	if listA[0].Value == "postgres://orgB-only" || listB[0].Value == "postgres://orgA-only" {
		t.Errorf("variable value crossed tenant boundary: orgA.value=%q orgB.value=%q", listA[0].Value, listB[0].Value)
	}
}

// TestProjectVariableRepositoryUpsertInsertOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for the Upsert INSERT branch: when orgA
// inserts a fresh variable on its own project, orgB's bystander
// variable row — which legitimately shares the SAME key on its own
// project — must be byte-identical to its baseline across EVERY
// observable column, including value, the trigger-managed updated_at,
// and the trigger-bumped version.
func TestProjectVariableRepositoryUpsertInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	// orgB's bystander row lands FIRST so the baseline timestamps and
	// version are stable before orgA mutates.
	rowB := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgB, "bystander"), orgB.ID, projB.ID, "API_KEY",
		store.ProjectVariableUpsert{Value: "orgB-secret-fixture-zzy", IsSecret: false})
	baselineB := getProjectVariableFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, rowB.ID, "baseline")

	// orgA INSERTs a row with the IDENTICAL key on its own project. If
	// the conflict target leaked across tenants this would fire the
	// UPDATE branch on orgB's row and refresh both updated_at and
	// version on the peer.
	insertedA := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgA, "alpha"), orgA.ID, projA.ID, "API_KEY",
		store.ProjectVariableUpsert{Value: "orgA-only-fixture", IsSecret: false})
	if insertedA.OrganizationID != orgA.ID || insertedA.ProjectID != projA.ID || insertedA.Version != 1 {
		t.Errorf("Upsert(orgA, projA) inserted row = %+v, want orgA/projA/version=1", insertedA)
	}
	if insertedA.ID == rowB.ID {
		t.Fatalf("orgA's freshly inserted variable id %q collides with orgB's bystander id — the id mint is unsound and the bystander test below is invalid", insertedA.ID)
	}

	afterB := getProjectVariableFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, rowB.ID, "after orgA Upsert INSERT")
	assertProjectVariableByteIdentical(t, "Upsert INSERT(orgA) bystander orgB", baselineB, afterB)
}

// TestProjectVariableRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB is the
// byte-identical snapshot proof for the Upsert UPDATE branch: when orgA
// re-upserts its own variable (firing the ON CONFLICT DO UPDATE branch
// on its own row), orgB's bystander variable row — which legitimately
// shares the SAME key on its own project — must be byte-identical to
// its baseline across EVERY observable column.
func TestProjectVariableRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	// Both tenants seed an identical-key variable first so the
	// re-upsert below fires the ON CONFLICT DO UPDATE branch on orgA's
	// row.
	rowA := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgA, "alpha"), orgA.ID, projA.ID, "DB_URL",
		store.ProjectVariableUpsert{Value: "postgres://orgA-old", IsSecret: false})
	rowB := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgB, "bystander"), orgB.ID, projB.ID, "DB_URL",
		store.ProjectVariableUpsert{Value: "postgres://orgB-baseline-zzy", IsSecret: false})

	baselineB := getProjectVariableFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, rowB.ID, "baseline")

	// orgA re-upserts the SAME key with a different value. The ON
	// CONFLICT DO UPDATE branch fires on orgA's row only — the per-
	// tenant conflict target rules out orgB.
	updatedA := upsertProjectVariable(ctx, t, s, repo,
		// Caller-supplied id is IGNORED on the conflict branch — pass a
		// fresh one to prove that.
		newProjectVariableID(f, orgA, "alpha-rebump"), orgA.ID, projA.ID, "DB_URL",
		store.ProjectVariableUpsert{Value: "postgres://orgA-new", IsSecret: false})
	// orgA's row must have actually changed — a no-op repository cannot
	// silently pass the byte-identical-orgB check below.
	if updatedA.ID != rowA.ID {
		t.Errorf("UpdatedA.ID = %q, want %q (caller-id should be ignored on the conflict branch)", updatedA.ID, rowA.ID)
	}
	if updatedA.Value != "postgres://orgA-new" || updatedA.Version != rowA.Version+1 {
		t.Errorf("UpdatedA = %+v, want value=postgres://orgA-new version=%d", updatedA, rowA.Version+1)
	}

	afterB := getProjectVariableFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, rowB.ID, "after orgA Upsert UPDATE")
	assertProjectVariableByteIdentical(t, "Upsert UPDATE(orgA) bystander orgB", baselineB, afterB)
}

// TestProjectVariableRepositoryDeleteByProjectExceptKeysClearAllOnOrgADoesNotTouchOrgB
// is the byte-identical snapshot proof for the unconditional-DELETE
// codepath of DeleteByProjectExceptKeys: when orgA clears every
// variable on its own project (nil keepKeys), orgB's bystander
// variable row on its own project must be byte-identical to its
// baseline. The trigger would refresh updated_at if the DELETE
// statement had matched orgB's row even momentarily.
func TestProjectVariableRepositoryDeleteByProjectExceptKeysClearAllOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgA, "a1"), orgA.ID, projA.ID, "REGION",
		store.ProjectVariableUpsert{Value: "us-east-1", IsSecret: false})
	upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgA, "a2"), orgA.ID, projA.ID, "TIER",
		store.ProjectVariableUpsert{Value: "premium", IsSecret: false})
	rowB := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgB, "bystander"), orgB.ID, projB.ID, "REGION",
		store.ProjectVariableUpsert{Value: "eu-west-1-zzy", IsSecret: false})
	baselineB := getProjectVariableFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, rowB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptKeys(ctx, tx, orgA.ID, projA.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptKeys(orgA, projA, nil): %v", err)
	}

	if remaining := listProjectVariablesOrFail(ctx, t, s, repo, orgA.ID, projA.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByProjectExceptKeys(orgA, projA, nil) %d rows remain on orgA, want 0", len(remaining))
	}

	afterB := getProjectVariableFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, rowB.ID, "after orgA DeleteByProjectExceptKeys(nil)")
	assertProjectVariableByteIdentical(t, "DeleteByProjectExceptKeys(orgA, nil) bystander orgB", baselineB, afterB)
}

// TestProjectVariableRepositoryDeleteByProjectExceptKeysKeepSubsetOnOrgADoesNotTouchOrgB
// is the byte-identical snapshot proof for the conditional-DELETE
// codepath of DeleteByProjectExceptKeys (len(keepKeys)>0 -> DELETE
// WHERE key NOT IN ANY): when orgA keeps a subset of its own
// variables and deletes the rest, orgB's bystander variable row on its
// own project must be byte-identical to its baseline. The key NOT IN
// ANY filter is the only thing that selects WHICH of orgA's rows
// survive, and a regression that dropped the tenant predicate would
// let the DELETE reach into orgB's variables (whose keys are NOT in
// keepKeys and would therefore become eligible for deletion).
func TestProjectVariableRepositoryDeleteByProjectExceptKeysKeepSubsetOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	keepA := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgA, "keep"), orgA.ID, projA.ID, "KEEP_ME",
		store.ProjectVariableUpsert{Value: "keeper-value", IsSecret: false})
	dropA := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgA, "drop"), orgA.ID, projA.ID, "DROP_ME",
		store.ProjectVariableUpsert{Value: "dropper-value", IsSecret: false})
	// orgB owns one variable whose key is deliberately NOT in keepKeys
	// (so a regression that lost the tenant predicate would delete it
	// through the "NOT IN ANY" branch).
	rowB := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgB, "bystander"), orgB.ID, projB.ID, "BYSTANDER_KEY",
		store.ProjectVariableUpsert{Value: "orgB-survives-zzy", IsSecret: false})
	baselineB := getProjectVariableFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, rowB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptKeys(ctx, tx, orgA.ID, projA.ID, []string{"KEEP_ME"})
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptKeys(orgA, projA, [KEEP_ME]): %v", err)
	}

	remaining := listProjectVariablesOrFail(ctx, t, s, repo, orgA.ID, projA.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByProjectExceptKeys(orgA, projA, [KEEP_ME]) %d rows remain on orgA, want 1", len(remaining))
	}
	if remaining[0].ID != keepA.ID || remaining[0].Key != "KEEP_ME" {
		t.Errorf("survivor on orgA = %+v, want keepA id=%q key=KEEP_ME", remaining[0], keepA.ID)
	}
	if remaining[0].ID == dropA.ID {
		t.Errorf("dropA (%q) was retained; expected deletion", dropA.ID)
	}

	afterB := getProjectVariableFromListOrFail(ctx, t, s, repo, orgB.ID, projB.ID, rowB.ID, "after orgA DeleteByProjectExceptKeys([KEEP_ME])")
	assertProjectVariableByteIdentical(t, "DeleteByProjectExceptKeys(orgA, [KEEP_ME]) bystander orgB", baselineB, afterB)
}

// TestProjectVariableRepositoryUpsertSameKeyInTwoTenantsBothSucceed
// proves the (organization_id, project_id, key) UNIQUE constraint is
// per-tenant, not global: two tenants can legitimately each have a row
// with the SAME key on their own respective projects, and neither
// Upsert collides with the other. The flip side is the load-bearing
// reason every byte-identical-bystander test above asserts BOTH
// version and updated_at — if the (project_id, key) pair alone were
// the UNIQUE key, two tenants could not share it, and the WHERE filter
// would be redundant.
func TestProjectVariableRepositoryUpsertSameKeyInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")

	rowA := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgA, "alpha"), orgA.ID, projA.ID, "DATABASE_URL",
		store.ProjectVariableUpsert{Value: "postgres://orgA-fixture-one-zzy", IsSecret: false})
	rowB := upsertProjectVariable(ctx, t, s, repo,
		newProjectVariableID(f, orgB, "beta"), orgB.ID, projB.ID, "DATABASE_URL",
		store.ProjectVariableUpsert{Value: "postgres://orgB-fixture-two-zzy", IsSecret: false})

	if rowA.ID == rowB.ID {
		t.Fatalf("two tenants minted the same variable id %q — the id generator collided, the byte-identical-bystander tests in this file are invalid", rowA.ID)
	}
	if rowA.OrganizationID == rowB.OrganizationID {
		t.Errorf("two variable rows landed under the SAME organization_id: %+v vs %+v", rowA, rowB)
	}
	if rowA.ProjectID == rowB.ProjectID {
		t.Errorf("two variable rows landed under the SAME project_id: %+v vs %+v", rowA, rowB)
	}
	if rowA.Key != "DATABASE_URL" || rowB.Key != "DATABASE_URL" {
		t.Errorf("key drifted between Upsert calls: orgA=%q orgB=%q, want both 'DATABASE_URL'", rowA.Key, rowB.Key)
	}
	if rowA.Value == rowB.Value {
		t.Errorf("two variable rows somehow share an identical value: orgA=%q orgB=%q", rowA.Value, rowB.Value)
	}
}

// --- shared helpers ---

// getProjectVariableFromListOrFail observes a single project_variables
// row through the repository's ListByProject surface — the ONLY read
// path the repository exposes for project variables — and returns the
// entry whose id matches the caller's. It fails the test on any error
// AND on the row's absence from the list.
//
// The name is intentionally distinct from
// service_grant_tenant_isolation_test.go's
// getServiceGrantFromListOrFail and from any sibling variable file's
// helpers to avoid a same-package collision — every *_test.go file
// under internal/controlplane/store/ shares the same store_test
// package.
func getProjectVariableFromListOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.ProjectVariableRepository, organizationID, projectID, variableID, label string) store.ProjectVariable {
	t.Helper()
	rows := listProjectVariablesOrFail(ctx, t, s, repo, organizationID, projectID)
	for _, row := range rows {
		if row.ID == variableID {
			return row
		}
	}
	t.Fatalf("%s: variable %q missing from ListByProject(%q, %q): got %d rows", label, variableID, organizationID, projectID, len(rows))
	return store.ProjectVariable{}
}

// assertProjectVariableByteIdentical asserts every observable column on
// a bystander project_variables row is byte-identical to its baseline.
// The trigger-managed updated_at AND the trigger-bumped version are
// both load-bearing here: the BEFORE-UPDATE
// project_variables_set_updated_at trigger refreshes updated_at on
// every matched UPDATE, and the project_variables_bump_version trigger
// increments version — either drifting independently surfaces a
// missing tenant predicate even when the column writes themselves look
// correct.
//
// Value and the secret tuple (IsSecret, SecretProvider, SecretKeyID,
// SecretCiphertext) are anchored explicitly: a regression that swapped
// orgA's payload onto orgB's row — or that stamped orgA's secret
// ciphertext onto orgB's IsSecret=false row — surfaces here even if
// every identity column happened to look correct.
func assertProjectVariableByteIdentical(t *testing.T, label string, baseline, after store.ProjectVariable) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.ProjectID != baseline.ProjectID {
		t.Errorf("%s: bystander.project_id = %q, want %q", label, after.ProjectID, baseline.ProjectID)
	}
	if after.Key != baseline.Key {
		t.Errorf("%s: bystander.key = %q, want %q", label, after.Key, baseline.Key)
	}
	if after.Value != baseline.Value {
		t.Errorf("%s: bystander.value drifted across tenants — a peer-tenant mutation reached the value column", label)
	}
	if after.IsSecret != baseline.IsSecret {
		t.Errorf("%s: bystander.is_secret = %v, want %v", label, after.IsSecret, baseline.IsSecret)
	}
	if after.SecretProvider != baseline.SecretProvider {
		t.Errorf("%s: bystander.secret_provider = %q, want %q", label, after.SecretProvider, baseline.SecretProvider)
	}
	if after.SecretKeyID != baseline.SecretKeyID {
		t.Errorf("%s: bystander.secret_key_id = %q, want %q", label, after.SecretKeyID, baseline.SecretKeyID)
	}
	if !bytes.Equal(after.SecretCiphertext, baseline.SecretCiphertext) {
		t.Errorf("%s: bystander.secret_ciphertext drifted across tenants — a peer-tenant mutation reached the sealed bytes", label)
	}
	if after.Version != baseline.Version {
		t.Errorf("%s: bystander.version = %d, want %d — the project_variables_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE project_variables_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}
