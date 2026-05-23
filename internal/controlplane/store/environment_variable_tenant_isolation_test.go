package store_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Repository-layer tenant-isolation tests for the environment_variables
// table (BE-0450). environment_variables is a tenant-scoped grandchild
// table (environment variables are parented to environments, which are
// parented to projects, which are parented to organizations) whose row
// body is anchored to a single tenant by the same FOUR load-bearing
// schema facts as project_variables (see
// project_variable_tenant_isolation_test.go for the full breakdown):
// every column carries organization_id, every repository method
// predicates on organization_id ahead of environment_id, the UNIQUE
// (organization_id, environment_id, key) conflict target is per-tenant,
// and the secret-bearing columns (value + secret_provider/key_id/
// ciphertext) are anchored explicitly in the byte-identical-bystander
// projection.
//
// environment_variables is a STRUCTURAL VARIANT of project_variables:
// the scope leg moves from project_id to environment_id; the
// repository surface is otherwise identical (ListByEnvironment / Upsert
// / DeleteByEnvironmentExceptKeys). Every test in this file mirrors
// project_variable_tenant_isolation_test.go's per-scope shape, with
// the per-tenant fixture extended one level (each tenant owns its own
// project and its own environment).
//
// The BEFORE-UPDATE environment_variables_set_updated_at and
// environment_variables_bump_version triggers fire on every matched
// UPDATE, so updated_at and version on the bystander row are
// independently sufficient anchors to catch a missing tenant
// predicate even when the column writes themselves look correct.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Upsert INSERT RETURNING shape, Upsert UPDATE-branch dual-anchor,
//     cross-tenant environment_id FK Conflict, duplicate-PK Conflict,
//     secret-columns CHECK violations, ON DELETE CASCADE from
//     environments, Upsert tx-rollback, and nil-Tx guards are proved
//     by environment_variable_repository_invariants_test.go (BE-0449).
//   - ListByEnvironment deterministic ordering, non-nil empty slice,
//     and the basic ListByEnvironment tenant-scoping property are
//     proved by environment_variable_test.go.
//   - The HTTP-layer "another tenant's environment id is a 404, not a
//     403" rule is proved by the per-endpoint policy matrix and
//     contract tests in httpapi.
//   - environment_variables exposes NO per-id or per-key Get/Delete on
//     the repository surface — the only mutation paths are Upsert and
//     DeleteByEnvironmentExceptKeys. The byte-identical-bystander
//     projection is observed through ListByEnvironment.
//   - environment_variables has no soft-delete column; the
//     acceptance-criteria mention of "soft-deleted rows where
//     applicable" has no surface here.
//
// Helpers newEnvironmentVariableID / upsertEnvironmentVariable /
// listEnvironmentVariablesOrFail are defined in
// environment_variable_repository_invariants_test.go (same package,
// store_test) and reused here. This file adds
// getEnvironmentVariableFromListOrFail and
// assertEnvironmentVariableByteIdentical — both named to avoid
// same-package collisions with project_variable_tenant_isolation_test.go's
// getProjectVariableFromListOrFail and the sibling service/org files.

// TestEnvironmentVariableRepositoryListByEnvironmentReturnsCorrectRowsAcrossTenants
// proves ListByEnvironment is keyed strictly by BOTH organization_id
// AND environment_id.
func TestEnvironmentVariableRepositoryListByEnvironmentReturnsCorrectRowsAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	rowA := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "alpha"), orgA.ID, envA.ID, "REGION_A",
		store.EnvironmentVariableUpsert{Value: "us-east-1", IsSecret: false})
	rowB := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "beta"), orgB.ID, envB.ID, "REGION_B",
		store.EnvironmentVariableUpsert{Value: "eu-west-1", IsSecret: false})

	listA := listEnvironmentVariablesOrFail(ctx, t, s, repo, orgA.ID, envA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByEnvironment(orgA, envA) returned %d rows, want exactly 1 — orgB rows leaked", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != orgA.ID || listA[0].EnvironmentID != envA.ID || listA[0].Key != "REGION_A" || listA[0].Value != "us-east-1" {
		t.Errorf("ListByEnvironment(orgA, envA)[0] = %+v, want orgA/envA/REGION_A/us-east-1", listA[0])
	}

	listB := listEnvironmentVariablesOrFail(ctx, t, s, repo, orgB.ID, envB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByEnvironment(orgB, envB) returned %d rows, want exactly 1 — orgA rows leaked", len(listB))
	}
	if listB[0].ID != rowB.ID || listB[0].OrganizationID != orgB.ID || listB[0].EnvironmentID != envB.ID || listB[0].Key != "REGION_B" || listB[0].Value != "eu-west-1" {
		t.Errorf("ListByEnvironment(orgB, envB)[0] = %+v, want orgB/envB/REGION_B/eu-west-1", listB[0])
	}

	if listA[0].ID == listB[0].ID || listA[0].OrganizationID == listB[0].OrganizationID ||
		listA[0].EnvironmentID == listB[0].EnvironmentID || listA[0].Key == listB[0].Key ||
		listA[0].Value == listB[0].Value {
		t.Errorf("ListByEnvironment returned overlapping rows across two tenants: %+v vs %+v", listA[0], listB[0])
	}
}

// TestEnvironmentVariableRepositoryListByEnvironmentCrossTenantEnvironmentIDReturnsEmpty
// proves ListByEnvironment is tenant scoped at the SQL predicate.
func TestEnvironmentVariableRepositoryListByEnvironmentCrossTenantEnvironmentIDReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web-b")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "leak1"), orgB.ID, envB.ID, "SECRET_VALUE_ONE",
		store.EnvironmentVariableUpsert{Value: "tenant-b-only-1", IsSecret: false})
	upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "leak2"), orgB.ID, envB.ID, "SECRET_VALUE_TWO",
		store.EnvironmentVariableUpsert{Value: "tenant-b-only-2", IsSecret: false})

	crossTenant := listEnvironmentVariablesOrFail(ctx, t, s, repo, orgA.ID, envB.ID)
	if len(crossTenant) != 0 {
		t.Errorf("ListByEnvironment(orgA, envB) returned %d rows, want 0 — orgB variables leaked through a cross-tenant environment_id", len(crossTenant))
	}
	if crossTenant == nil {
		t.Error("ListByEnvironment(orgA, envB) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice so callers can iterate without a nil check")
	}

	unknown := listEnvironmentVariablesOrFail(ctx, t, s, repo, orgA.ID, "env_never_existed")
	if len(unknown) != 0 {
		t.Errorf("ListByEnvironment(orgA, unknown) returned %d rows, want 0", len(unknown))
	}
	if unknown == nil {
		t.Error("ListByEnvironment(orgA, unknown) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice")
	}
}

// TestEnvironmentVariableRepositoryListByEnvironmentIsolatesSharedKey
// proves that two tenants can legitimately each own a row with the
// same key on their own environments without leaking across the WHERE
// filter.
func TestEnvironmentVariableRepositoryListByEnvironmentIsolatesSharedKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	rowA := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "shared-a"), orgA.ID, envA.ID, "DB_URL",
		store.EnvironmentVariableUpsert{Value: "postgres://orgA-only", IsSecret: false})
	rowB := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "shared-b"), orgB.ID, envB.ID, "DB_URL",
		store.EnvironmentVariableUpsert{Value: "postgres://orgB-only", IsSecret: false})

	listA := listEnvironmentVariablesOrFail(ctx, t, s, repo, orgA.ID, envA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByEnvironment(orgA, envA) returned %d rows, want exactly 1 — orgB row for the same key leaked or duplicated", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != orgA.ID || listA[0].Value != "postgres://orgA-only" {
		t.Errorf("ListByEnvironment(orgA, envA)[0] = %+v, want id=%q org=%q value='postgres://orgA-only'", listA[0], rowA.ID, orgA.ID)
	}

	listB := listEnvironmentVariablesOrFail(ctx, t, s, repo, orgB.ID, envB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByEnvironment(orgB, envB) returned %d rows, want exactly 1 — orgA row for the same key leaked or duplicated", len(listB))
	}
	if listB[0].ID != rowB.ID || listB[0].OrganizationID != orgB.ID || listB[0].Value != "postgres://orgB-only" {
		t.Errorf("ListByEnvironment(orgB, envB)[0] = %+v, want id=%q org=%q value='postgres://orgB-only'", listB[0], rowB.ID, orgB.ID)
	}

	if listA[0].ID == listB[0].ID {
		t.Errorf("variable id %q appears in both List(orgA, envA) and List(orgB, envB) responses", listA[0].ID)
	}
	if listA[0].Value == "postgres://orgB-only" || listB[0].Value == "postgres://orgA-only" {
		t.Errorf("variable value crossed tenant boundary: orgA.value=%q orgB.value=%q", listA[0].Value, listB[0].Value)
	}
}

// TestEnvironmentVariableRepositoryUpsertInsertOnOrgADoesNotTouchOrgB
// proves the Upsert INSERT branch does not stamp a peer tenant's row
// when the same key is in use on the peer's environment.
func TestEnvironmentVariableRepositoryUpsertInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	rowB := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "bystander"), orgB.ID, envB.ID, "API_KEY",
		store.EnvironmentVariableUpsert{Value: "orgB-secret-fixture-zzy", IsSecret: false})
	baselineB := getEnvironmentVariableFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, rowB.ID, "baseline")

	insertedA := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "alpha"), orgA.ID, envA.ID, "API_KEY",
		store.EnvironmentVariableUpsert{Value: "orgA-only-fixture", IsSecret: false})
	if insertedA.OrganizationID != orgA.ID || insertedA.EnvironmentID != envA.ID || insertedA.Version != 1 {
		t.Errorf("Upsert(orgA, envA) inserted row = %+v, want orgA/envA/version=1", insertedA)
	}
	if insertedA.ID == rowB.ID {
		t.Fatalf("orgA's freshly inserted variable id %q collides with orgB's bystander id — the id mint is unsound and the bystander test below is invalid", insertedA.ID)
	}

	afterB := getEnvironmentVariableFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, rowB.ID, "after orgA Upsert INSERT")
	assertEnvironmentVariableByteIdentical(t, "Upsert INSERT(orgA) bystander orgB", baselineB, afterB)
}

// TestEnvironmentVariableRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB
// proves the Upsert ON CONFLICT DO UPDATE branch fires only on orgA's
// own (organization_id, environment_id, key) tuple.
func TestEnvironmentVariableRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	rowA := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "alpha"), orgA.ID, envA.ID, "DB_URL",
		store.EnvironmentVariableUpsert{Value: "postgres://orgA-old", IsSecret: false})
	rowB := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "bystander"), orgB.ID, envB.ID, "DB_URL",
		store.EnvironmentVariableUpsert{Value: "postgres://orgB-baseline-zzy", IsSecret: false})

	baselineB := getEnvironmentVariableFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, rowB.ID, "baseline")

	updatedA := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "alpha-rebump"), orgA.ID, envA.ID, "DB_URL",
		store.EnvironmentVariableUpsert{Value: "postgres://orgA-new", IsSecret: false})
	if updatedA.ID != rowA.ID {
		t.Errorf("UpdatedA.ID = %q, want %q (caller-id should be ignored on the conflict branch)", updatedA.ID, rowA.ID)
	}
	if updatedA.Value != "postgres://orgA-new" || updatedA.Version != rowA.Version+1 {
		t.Errorf("UpdatedA = %+v, want value=postgres://orgA-new version=%d", updatedA, rowA.Version+1)
	}

	afterB := getEnvironmentVariableFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, rowB.ID, "after orgA Upsert UPDATE")
	assertEnvironmentVariableByteIdentical(t, "Upsert UPDATE(orgA) bystander orgB", baselineB, afterB)
}

// TestEnvironmentVariableRepositoryDeleteByEnvironmentExceptKeysClearAllOnOrgADoesNotTouchOrgB
// proves the unconditional-DELETE codepath (nil keepKeys) is tenant
// scoped.
func TestEnvironmentVariableRepositoryDeleteByEnvironmentExceptKeysClearAllOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "a1"), orgA.ID, envA.ID, "REGION",
		store.EnvironmentVariableUpsert{Value: "us-east-1", IsSecret: false})
	upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "a2"), orgA.ID, envA.ID, "TIER",
		store.EnvironmentVariableUpsert{Value: "premium", IsSecret: false})
	rowB := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "bystander"), orgB.ID, envB.ID, "REGION",
		store.EnvironmentVariableUpsert{Value: "eu-west-1-zzy", IsSecret: false})
	baselineB := getEnvironmentVariableFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, rowB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptKeys(ctx, tx, orgA.ID, envA.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptKeys(orgA, envA, nil): %v", err)
	}

	if remaining := listEnvironmentVariablesOrFail(ctx, t, s, repo, orgA.ID, envA.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByEnvironmentExceptKeys(orgA, envA, nil) %d rows remain on orgA, want 0", len(remaining))
	}

	afterB := getEnvironmentVariableFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, rowB.ID, "after orgA DeleteByEnvironmentExceptKeys(nil)")
	assertEnvironmentVariableByteIdentical(t, "DeleteByEnvironmentExceptKeys(orgA, nil) bystander orgB", baselineB, afterB)
}

// TestEnvironmentVariableRepositoryDeleteByEnvironmentExceptKeysKeepSubsetOnOrgADoesNotTouchOrgB
// proves the conditional-DELETE codepath (len(keepKeys)>0 -> DELETE
// WHERE key NOT IN ANY) is tenant scoped: a regression that dropped
// the tenant predicate would let the DELETE reach into orgB's
// variables (whose keys are NOT in keepKeys and would therefore become
// eligible for deletion).
func TestEnvironmentVariableRepositoryDeleteByEnvironmentExceptKeysKeepSubsetOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	keepA := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "keep"), orgA.ID, envA.ID, "KEEP_ME",
		store.EnvironmentVariableUpsert{Value: "keeper-value", IsSecret: false})
	dropA := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "drop"), orgA.ID, envA.ID, "DROP_ME",
		store.EnvironmentVariableUpsert{Value: "dropper-value", IsSecret: false})
	rowB := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "bystander"), orgB.ID, envB.ID, "BYSTANDER_KEY",
		store.EnvironmentVariableUpsert{Value: "orgB-survives-zzy", IsSecret: false})
	baselineB := getEnvironmentVariableFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, rowB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByEnvironmentExceptKeys(ctx, tx, orgA.ID, envA.ID, []string{"KEEP_ME"})
	}); err != nil {
		t.Fatalf("DeleteByEnvironmentExceptKeys(orgA, envA, [KEEP_ME]): %v", err)
	}

	remaining := listEnvironmentVariablesOrFail(ctx, t, s, repo, orgA.ID, envA.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByEnvironmentExceptKeys(orgA, envA, [KEEP_ME]) %d rows remain on orgA, want 1", len(remaining))
	}
	if remaining[0].ID != keepA.ID || remaining[0].Key != "KEEP_ME" {
		t.Errorf("survivor on orgA = %+v, want keepA id=%q key=KEEP_ME", remaining[0], keepA.ID)
	}
	if remaining[0].ID == dropA.ID {
		t.Errorf("dropA (%q) was retained; expected deletion", dropA.ID)
	}

	afterB := getEnvironmentVariableFromListOrFail(ctx, t, s, repo, orgB.ID, envB.ID, rowB.ID, "after orgA DeleteByEnvironmentExceptKeys([KEEP_ME])")
	assertEnvironmentVariableByteIdentical(t, "DeleteByEnvironmentExceptKeys(orgA, [KEEP_ME]) bystander orgB", baselineB, afterB)
}

// TestEnvironmentVariableRepositoryUpsertSameKeyInTwoTenantsBothSucceed
// proves the (organization_id, environment_id, key) UNIQUE constraint
// is per-tenant, not global.
func TestEnvironmentVariableRepositoryUpsertSameKeyInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")

	rowA := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "alpha"), orgA.ID, envA.ID, "DATABASE_URL",
		store.EnvironmentVariableUpsert{Value: "postgres://orgA-fixture-one-zzy", IsSecret: false})
	rowB := upsertEnvironmentVariable(ctx, t, s, repo,
		newEnvironmentVariableID(f, "beta"), orgB.ID, envB.ID, "DATABASE_URL",
		store.EnvironmentVariableUpsert{Value: "postgres://orgB-fixture-two-zzy", IsSecret: false})

	if rowA.ID == rowB.ID {
		t.Fatalf("two tenants minted the same variable id %q — the id generator collided, the byte-identical-bystander tests in this file are invalid", rowA.ID)
	}
	if rowA.OrganizationID == rowB.OrganizationID {
		t.Errorf("two variable rows landed under the SAME organization_id: %+v vs %+v", rowA, rowB)
	}
	if rowA.EnvironmentID == rowB.EnvironmentID {
		t.Errorf("two variable rows landed under the SAME environment_id: %+v vs %+v", rowA, rowB)
	}
	if rowA.Key != "DATABASE_URL" || rowB.Key != "DATABASE_URL" {
		t.Errorf("key drifted between Upsert calls: orgA=%q orgB=%q, want both 'DATABASE_URL'", rowA.Key, rowB.Key)
	}
	if rowA.Value == rowB.Value {
		t.Errorf("two variable rows somehow share an identical value: orgA=%q orgB=%q", rowA.Value, rowB.Value)
	}
}

// --- shared helpers ---

// getEnvironmentVariableFromListOrFail observes a single
// environment_variables row through ListByEnvironment — the ONLY read
// path the repository exposes for environment variables — and returns
// the entry whose id matches the caller's. The name is distinct from
// project_variable_tenant_isolation_test.go's
// getProjectVariableFromListOrFail (same package, store_test).
func getEnvironmentVariableFromListOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.EnvironmentVariableRepository, organizationID, environmentID, variableID, label string) store.EnvironmentVariable {
	t.Helper()
	rows := listEnvironmentVariablesOrFail(ctx, t, s, repo, organizationID, environmentID)
	for _, row := range rows {
		if row.ID == variableID {
			return row
		}
	}
	t.Fatalf("%s: variable %q missing from ListByEnvironment(%q, %q): got %d rows", label, variableID, organizationID, environmentID, len(rows))
	return store.EnvironmentVariable{}
}

// assertEnvironmentVariableByteIdentical asserts every observable
// column on a bystander environment_variables row is byte-identical
// to its baseline. Value and the secret tuple (IsSecret,
// SecretProvider, SecretKeyID, SecretCiphertext) are anchored
// explicitly: a regression that swapped orgA's payload onto orgB's
// row — or that stamped orgA's secret ciphertext onto orgB's
// IsSecret=false row — surfaces here.
func assertEnvironmentVariableByteIdentical(t *testing.T, label string, baseline, after store.EnvironmentVariable) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.EnvironmentID != baseline.EnvironmentID {
		t.Errorf("%s: bystander.environment_id = %q, want %q", label, after.EnvironmentID, baseline.EnvironmentID)
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
		t.Errorf("%s: bystander.version = %d, want %d — the environment_variables_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE environment_variables_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}
