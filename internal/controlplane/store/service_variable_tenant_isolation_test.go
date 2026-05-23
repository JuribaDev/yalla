package store_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Repository-layer tenant-isolation tests for the service_variables
// table (BE-0450). service_variables is the highest-precedence /
// narrowest-scope layer of the Organization -> Project -> Environment
// -> Service variable hierarchy: each row is parented to a service,
// which is parented to an environment, which is parented to a project,
// which is parented to an organization. The row body is anchored to a
// single tenant by the same FOUR load-bearing schema facts as
// project_variables and environment_variables (see
// project_variable_tenant_isolation_test.go for the full breakdown):
// every column carries organization_id, every repository method
// predicates on organization_id ahead of service_id, the UNIQUE
// (organization_id, service_id, key) conflict target is per-tenant,
// and the secret-bearing columns (value + secret_provider/key_id/
// ciphertext) are anchored explicitly in the byte-identical-bystander
// projection.
//
// service_variables is a STRUCTURAL VARIANT of environment_variables:
// the scope leg moves from environment_id to service_id; the
// repository surface is otherwise identical (ListByService / Upsert /
// DeleteByServiceExceptKeys). Every test in this file mirrors
// environment_variable_tenant_isolation_test.go's per-scope shape,
// with the per-tenant fixture extended one level (each tenant owns its
// own project, environment, AND service).
//
// The BEFORE-UPDATE service_variables_set_updated_at and
// service_variables_bump_version triggers fire on every matched
// UPDATE, so updated_at and version on the bystander row are
// independently sufficient anchors to catch a missing tenant
// predicate.
//
// What is intentionally NOT exercised here, and where the proof lives
// instead:
//   - Upsert INSERT RETURNING shape, Upsert UPDATE-branch dual-anchor,
//     cross-tenant service_id FK Conflict, duplicate-PK Conflict,
//     secret-columns CHECK violations, ON DELETE CASCADE from
//     services, Upsert tx-rollback, and nil-Tx guards are proved by
//     service_variable_repository_invariants_test.go (BE-0449).
//   - ListByService deterministic ordering, non-nil empty slice, and
//     the basic ListByService tenant-scoping property are proved by
//     service_variable_test.go.
//   - The HTTP-layer "another tenant's service id is a 404, not a
//     403" rule is proved by the per-endpoint policy matrix and
//     contract tests in httpapi.
//   - service_variables exposes NO per-id or per-key Get/Delete on the
//     repository surface — the only mutation paths are Upsert and
//     DeleteByServiceExceptKeys. The byte-identical-bystander
//     projection is observed through ListByService.
//   - service_variables has no soft-delete column; the
//     acceptance-criteria mention of "soft-deleted rows where
//     applicable" has no surface here.
//
// Helpers newServiceVariableID / upsertServiceVariable /
// listServiceVariablesOrFail are defined in
// service_variable_repository_invariants_test.go (same package,
// store_test) and reused here. This file adds
// getServiceVariableFromListOrFail and
// assertServiceVariableByteIdentical — both named to avoid
// same-package collisions with the project / environment / organization
// sibling files.

// TestServiceVariableRepositoryListByServiceReturnsCorrectRowsAcrossTenants
// proves ListByService is keyed strictly by BOTH organization_id AND
// service_id.
func TestServiceVariableRepositoryListByServiceReturnsCorrectRowsAcrossTenants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	rowA := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "alpha"), orgA.ID, svcA.ID, "REGION_A",
		store.ServiceVariableUpsert{Value: "us-east-1", IsSecret: false})
	rowB := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "beta"), orgB.ID, svcB.ID, "REGION_B",
		store.ServiceVariableUpsert{Value: "eu-west-1", IsSecret: false})

	listA := listServiceVariablesOrFail(ctx, t, s, repo, orgA.ID, svcA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByService(orgA, svcA) returned %d rows, want exactly 1 — orgB rows leaked", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != orgA.ID || listA[0].ServiceID != svcA.ID || listA[0].Key != "REGION_A" || listA[0].Value != "us-east-1" {
		t.Errorf("ListByService(orgA, svcA)[0] = %+v, want orgA/svcA/REGION_A/us-east-1", listA[0])
	}

	listB := listServiceVariablesOrFail(ctx, t, s, repo, orgB.ID, svcB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByService(orgB, svcB) returned %d rows, want exactly 1 — orgA rows leaked", len(listB))
	}
	if listB[0].ID != rowB.ID || listB[0].OrganizationID != orgB.ID || listB[0].ServiceID != svcB.ID || listB[0].Key != "REGION_B" || listB[0].Value != "eu-west-1" {
		t.Errorf("ListByService(orgB, svcB)[0] = %+v, want orgB/svcB/REGION_B/eu-west-1", listB[0])
	}

	if listA[0].ID == listB[0].ID || listA[0].OrganizationID == listB[0].OrganizationID ||
		listA[0].ServiceID == listB[0].ServiceID || listA[0].Key == listB[0].Key ||
		listA[0].Value == listB[0].Value {
		t.Errorf("ListByService returned overlapping rows across two tenants: %+v vs %+v", listA[0], listB[0])
	}
}

// TestServiceVariableRepositoryListByServiceCrossTenantServiceIDReturnsEmpty
// proves ListByService is tenant scoped at the SQL predicate.
func TestServiceVariableRepositoryListByServiceCrossTenantServiceIDReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projB := seedProject(t, db, f, orgB, "web-b")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcB := seedService(t, db, f, envB, "api-b")

	upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "leak1"), orgB.ID, svcB.ID, "SECRET_VALUE_ONE",
		store.ServiceVariableUpsert{Value: "tenant-b-only-1", IsSecret: false})
	upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "leak2"), orgB.ID, svcB.ID, "SECRET_VALUE_TWO",
		store.ServiceVariableUpsert{Value: "tenant-b-only-2", IsSecret: false})

	crossTenant := listServiceVariablesOrFail(ctx, t, s, repo, orgA.ID, svcB.ID)
	if len(crossTenant) != 0 {
		t.Errorf("ListByService(orgA, svcB) returned %d rows, want 0 — orgB variables leaked through a cross-tenant service_id", len(crossTenant))
	}
	if crossTenant == nil {
		t.Error("ListByService(orgA, svcB) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice so callers can iterate without a nil check")
	}

	unknown := listServiceVariablesOrFail(ctx, t, s, repo, orgA.ID, "svc_never_existed")
	if len(unknown) != 0 {
		t.Errorf("ListByService(orgA, unknown) returned %d rows, want 0", len(unknown))
	}
	if unknown == nil {
		t.Error("ListByService(orgA, unknown) returned a nil slice; the contract guarantees a non-nil (possibly empty) slice")
	}
}

// TestServiceVariableRepositoryListByServiceIsolatesSharedKey proves
// that two tenants can legitimately each own a row with the same key
// on their own services without leaking across the WHERE filter.
func TestServiceVariableRepositoryListByServiceIsolatesSharedKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")
	rowA := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "shared-a"), orgA.ID, svcA.ID, "DB_URL",
		store.ServiceVariableUpsert{Value: "postgres://orgA-only", IsSecret: false})
	rowB := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "shared-b"), orgB.ID, svcB.ID, "DB_URL",
		store.ServiceVariableUpsert{Value: "postgres://orgB-only", IsSecret: false})

	listA := listServiceVariablesOrFail(ctx, t, s, repo, orgA.ID, svcA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByService(orgA, svcA) returned %d rows, want exactly 1 — orgB row for the same key leaked or duplicated", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != orgA.ID || listA[0].Value != "postgres://orgA-only" {
		t.Errorf("ListByService(orgA, svcA)[0] = %+v, want id=%q org=%q value='postgres://orgA-only'", listA[0], rowA.ID, orgA.ID)
	}

	listB := listServiceVariablesOrFail(ctx, t, s, repo, orgB.ID, svcB.ID)
	if len(listB) != 1 {
		t.Fatalf("ListByService(orgB, svcB) returned %d rows, want exactly 1 — orgA row for the same key leaked or duplicated", len(listB))
	}
	if listB[0].ID != rowB.ID || listB[0].OrganizationID != orgB.ID || listB[0].Value != "postgres://orgB-only" {
		t.Errorf("ListByService(orgB, svcB)[0] = %+v, want id=%q org=%q value='postgres://orgB-only'", listB[0], rowB.ID, orgB.ID)
	}

	if listA[0].ID == listB[0].ID {
		t.Errorf("variable id %q appears in both List(orgA, svcA) and List(orgB, svcB) responses", listA[0].ID)
	}
	if listA[0].Value == "postgres://orgB-only" || listB[0].Value == "postgres://orgA-only" {
		t.Errorf("variable value crossed tenant boundary: orgA.value=%q orgB.value=%q", listA[0].Value, listB[0].Value)
	}
}

// TestServiceVariableRepositoryUpsertInsertOnOrgADoesNotTouchOrgB
// proves the Upsert INSERT branch does not stamp a peer tenant's row
// when the same key is in use on the peer's service.
func TestServiceVariableRepositoryUpsertInsertOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	rowB := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "bystander"), orgB.ID, svcB.ID, "API_KEY",
		store.ServiceVariableUpsert{Value: "orgB-secret-fixture-zzy", IsSecret: false})
	baselineB := getServiceVariableFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, rowB.ID, "baseline")

	insertedA := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "alpha"), orgA.ID, svcA.ID, "API_KEY",
		store.ServiceVariableUpsert{Value: "orgA-only-fixture", IsSecret: false})
	if insertedA.OrganizationID != orgA.ID || insertedA.ServiceID != svcA.ID || insertedA.Version != 1 {
		t.Errorf("Upsert(orgA, svcA) inserted row = %+v, want orgA/svcA/version=1", insertedA)
	}
	if insertedA.ID == rowB.ID {
		t.Fatalf("orgA's freshly inserted variable id %q collides with orgB's bystander id — the id mint is unsound and the bystander test below is invalid", insertedA.ID)
	}

	afterB := getServiceVariableFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, rowB.ID, "after orgA Upsert INSERT")
	assertServiceVariableByteIdentical(t, "Upsert INSERT(orgA) bystander orgB", baselineB, afterB)
}

// TestServiceVariableRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB
// proves the Upsert ON CONFLICT DO UPDATE branch fires only on orgA's
// own (organization_id, service_id, key) tuple.
func TestServiceVariableRepositoryUpsertUpdateOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	rowA := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "alpha"), orgA.ID, svcA.ID, "DB_URL",
		store.ServiceVariableUpsert{Value: "postgres://orgA-old", IsSecret: false})
	rowB := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "bystander"), orgB.ID, svcB.ID, "DB_URL",
		store.ServiceVariableUpsert{Value: "postgres://orgB-baseline-zzy", IsSecret: false})

	baselineB := getServiceVariableFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, rowB.ID, "baseline")

	updatedA := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "alpha-rebump"), orgA.ID, svcA.ID, "DB_URL",
		store.ServiceVariableUpsert{Value: "postgres://orgA-new", IsSecret: false})
	if updatedA.ID != rowA.ID {
		t.Errorf("UpdatedA.ID = %q, want %q (caller-id should be ignored on the conflict branch)", updatedA.ID, rowA.ID)
	}
	if updatedA.Value != "postgres://orgA-new" || updatedA.Version != rowA.Version+1 {
		t.Errorf("UpdatedA = %+v, want value=postgres://orgA-new version=%d", updatedA, rowA.Version+1)
	}

	afterB := getServiceVariableFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, rowB.ID, "after orgA Upsert UPDATE")
	assertServiceVariableByteIdentical(t, "Upsert UPDATE(orgA) bystander orgB", baselineB, afterB)
}

// TestServiceVariableRepositoryDeleteByServiceExceptKeysClearAllOnOrgADoesNotTouchOrgB
// proves the unconditional-DELETE codepath (nil keepKeys) is tenant
// scoped.
func TestServiceVariableRepositoryDeleteByServiceExceptKeysClearAllOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "a1"), orgA.ID, svcA.ID, "REGION",
		store.ServiceVariableUpsert{Value: "us-east-1", IsSecret: false})
	upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "a2"), orgA.ID, svcA.ID, "TIER",
		store.ServiceVariableUpsert{Value: "premium", IsSecret: false})
	rowB := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "bystander"), orgB.ID, svcB.ID, "REGION",
		store.ServiceVariableUpsert{Value: "eu-west-1-zzy", IsSecret: false})
	baselineB := getServiceVariableFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, rowB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptKeys(ctx, tx, orgA.ID, svcA.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptKeys(orgA, svcA, nil): %v", err)
	}

	if remaining := listServiceVariablesOrFail(ctx, t, s, repo, orgA.ID, svcA.ID); len(remaining) != 0 {
		t.Errorf("after DeleteByServiceExceptKeys(orgA, svcA, nil) %d rows remain on orgA, want 0", len(remaining))
	}

	afterB := getServiceVariableFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, rowB.ID, "after orgA DeleteByServiceExceptKeys(nil)")
	assertServiceVariableByteIdentical(t, "DeleteByServiceExceptKeys(orgA, nil) bystander orgB", baselineB, afterB)
}

// TestServiceVariableRepositoryDeleteByServiceExceptKeysKeepSubsetOnOrgADoesNotTouchOrgB
// proves the conditional-DELETE codepath (len(keepKeys)>0 -> DELETE
// WHERE key NOT IN ANY) is tenant scoped.
func TestServiceVariableRepositoryDeleteByServiceExceptKeysKeepSubsetOnOrgADoesNotTouchOrgB(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	keepA := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "keep"), orgA.ID, svcA.ID, "KEEP_ME",
		store.ServiceVariableUpsert{Value: "keeper-value", IsSecret: false})
	dropA := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "drop"), orgA.ID, svcA.ID, "DROP_ME",
		store.ServiceVariableUpsert{Value: "dropper-value", IsSecret: false})
	rowB := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "bystander"), orgB.ID, svcB.ID, "BYSTANDER_KEY",
		store.ServiceVariableUpsert{Value: "orgB-survives-zzy", IsSecret: false})
	baselineB := getServiceVariableFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, rowB.ID, "baseline")

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByServiceExceptKeys(ctx, tx, orgA.ID, svcA.ID, []string{"KEEP_ME"})
	}); err != nil {
		t.Fatalf("DeleteByServiceExceptKeys(orgA, svcA, [KEEP_ME]): %v", err)
	}

	remaining := listServiceVariablesOrFail(ctx, t, s, repo, orgA.ID, svcA.ID)
	if len(remaining) != 1 {
		t.Fatalf("after DeleteByServiceExceptKeys(orgA, svcA, [KEEP_ME]) %d rows remain on orgA, want 1", len(remaining))
	}
	if remaining[0].ID != keepA.ID || remaining[0].Key != "KEEP_ME" {
		t.Errorf("survivor on orgA = %+v, want keepA id=%q key=KEEP_ME", remaining[0], keepA.ID)
	}
	if remaining[0].ID == dropA.ID {
		t.Errorf("dropA (%q) was retained; expected deletion", dropA.ID)
	}

	afterB := getServiceVariableFromListOrFail(ctx, t, s, repo, orgB.ID, svcB.ID, rowB.ID, "after orgA DeleteByServiceExceptKeys([KEEP_ME])")
	assertServiceVariableByteIdentical(t, "DeleteByServiceExceptKeys(orgA, [KEEP_ME]) bystander orgB", baselineB, afterB)
}

// TestServiceVariableRepositoryUpsertSameKeyInTwoTenantsBothSucceed
// proves the (organization_id, service_id, key) UNIQUE constraint is
// per-tenant, not global.
func TestServiceVariableRepositoryUpsertSameKeyInTwoTenantsBothSucceed(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceVariableRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")

	rowA := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "alpha"), orgA.ID, svcA.ID, "DATABASE_URL",
		store.ServiceVariableUpsert{Value: "postgres://orgA-fixture-one-zzy", IsSecret: false})
	rowB := upsertServiceVariable(ctx, t, s, repo,
		newServiceVariableID(f, "beta"), orgB.ID, svcB.ID, "DATABASE_URL",
		store.ServiceVariableUpsert{Value: "postgres://orgB-fixture-two-zzy", IsSecret: false})

	if rowA.ID == rowB.ID {
		t.Fatalf("two tenants minted the same variable id %q — the id generator collided, the byte-identical-bystander tests in this file are invalid", rowA.ID)
	}
	if rowA.OrganizationID == rowB.OrganizationID {
		t.Errorf("two variable rows landed under the SAME organization_id: %+v vs %+v", rowA, rowB)
	}
	if rowA.ServiceID == rowB.ServiceID {
		t.Errorf("two variable rows landed under the SAME service_id: %+v vs %+v", rowA, rowB)
	}
	if rowA.Key != "DATABASE_URL" || rowB.Key != "DATABASE_URL" {
		t.Errorf("key drifted between Upsert calls: orgA=%q orgB=%q, want both 'DATABASE_URL'", rowA.Key, rowB.Key)
	}
	if rowA.Value == rowB.Value {
		t.Errorf("two variable rows somehow share an identical value: orgA=%q orgB=%q", rowA.Value, rowB.Value)
	}
}

// --- shared helpers ---

// getServiceVariableFromListOrFail observes a single
// service_variables row through ListByService — the ONLY read path the
// repository exposes for service variables.
func getServiceVariableFromListOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceVariableRepository, organizationID, serviceID, variableID, label string) store.ServiceVariable {
	t.Helper()
	rows := listServiceVariablesOrFail(ctx, t, s, repo, organizationID, serviceID)
	for _, row := range rows {
		if row.ID == variableID {
			return row
		}
	}
	t.Fatalf("%s: variable %q missing from ListByService(%q, %q): got %d rows", label, variableID, organizationID, serviceID, len(rows))
	return store.ServiceVariable{}
}

// assertServiceVariableByteIdentical asserts every observable column
// on a bystander service_variables row is byte-identical to its
// baseline. Value and the secret tuple are anchored explicitly.
func assertServiceVariableByteIdentical(t *testing.T, label string, baseline, after store.ServiceVariable) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID {
		t.Errorf("%s: bystander identity drifted: got id=%q org=%q, want id=%q org=%q",
			label, after.ID, after.OrganizationID, baseline.ID, baseline.OrganizationID)
	}
	if after.ServiceID != baseline.ServiceID {
		t.Errorf("%s: bystander.service_id = %q, want %q", label, after.ServiceID, baseline.ServiceID)
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
		t.Errorf("%s: bystander.version = %d, want %d — the service_variables_bump_version trigger bumped version on a peer tenant's row, which means an UPDATE matched it",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: bystander.created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: bystander.updated_at = %v, want %v — the BEFORE-UPDATE service_variables_set_updated_at trigger refreshed updated_at on a peer tenant's row, which means an UPDATE matched it",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}
