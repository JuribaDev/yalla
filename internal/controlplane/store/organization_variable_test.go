package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Integration tests for the OrganizationVariableRepository — the
// persistence half of the organization-variables surface. They run
// against an isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset. The tests prove tenant scoping,
// deterministic ordering, and that the repository never crosses a tenant
// boundary.

// seedOrganizationVariable inserts an organization_variables row with the
// supplied (id, organizationID, key, value, isSecret) and returns it.
// Uniqueness, key validation, and update flow are exercised by future
// PUT/PATCH stories — this fixture only seeds rows for the read path.
func seedOrganizationVariable(t *testing.T, db *testutil.DB, id, organizationID, key, value string, isSecret bool) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO organization_variables (id, organization_id, key, value, is_secret)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, organizationID, key, value, isSecret); err != nil {
		t.Fatalf("seed organization_variables: %v", err)
	}
}

// TestOrganizationVariableRepoListByOrganizationReturnsRowsInDeterministicOrder
// proves the SQL ORDER BY contract — (key ASC, id ASC) — so an HTTP
// agent observing the response sees the same ordering on every call.
func TestOrganizationVariableRepoListByOrganizationReturnsRowsInDeterministicOrder(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "VarsAcme")
	seedOrganizationVariable(t, db, "ovar_z", org.ID, "ZETA", "z-value", false)
	seedOrganizationVariable(t, db, "ovar_a", org.ID, "ALPHA", "a-value", false)
	seedOrganizationVariable(t, db, "ovar_m", org.ID, "MIDDLE", "m-value", true)

	repo := store.NewOrganizationVariableRepository()
	var got []store.OrganizationVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByOrganization(ctx, q, org.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (got %+v)", len(got), got)
	}
	wantKeys := []string{"ALPHA", "MIDDLE", "ZETA"}
	for i, want := range wantKeys {
		if got[i].Key != want {
			t.Errorf("got[%d].Key = %q, want %q", i, got[i].Key, want)
		}
	}
	// Spot-check value + is_secret round-trip.
	if got[1].Value != "m-value" || !got[1].IsSecret {
		t.Errorf("got[1] = %+v; want (m-value, is_secret=true)", got[1])
	}
}

// TestOrganizationVariableRepoListByOrganizationIsTenantScoped proves the
// SQL predicate is the tenant boundary: a cross-tenant id matches no
// rows, never another organization's variables.
func TestOrganizationVariableRepoListByOrganizationIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "VarsA")
	orgB := seedOrg(t, db, f, "VarsB")
	seedOrganizationVariable(t, db, "ovar_a1", orgA.ID, "ALPHA", "a", false)
	seedOrganizationVariable(t, db, "ovar_b1", orgB.ID, "BETA", "b", false)

	repo := store.NewOrganizationVariableRepository()
	var gotA []store.OrganizationVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		gotA, listErr = repo.ListByOrganization(ctx, q, orgA.ID)
		return listErr
	}); err != nil {
		t.Fatalf("orgA: %v", err)
	}
	if len(gotA) != 1 || gotA[0].OrganizationID != orgA.ID {
		t.Fatalf("orgA listing = %+v, want a single row scoped to orgA", gotA)
	}

	var gotB []store.OrganizationVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		gotB, listErr = repo.ListByOrganization(ctx, q, orgB.ID)
		return listErr
	}); err != nil {
		t.Fatalf("orgB: %v", err)
	}
	if len(gotB) != 1 || gotB[0].OrganizationID != orgB.ID {
		t.Fatalf("orgB listing = %+v, want a single row scoped to orgB", gotB)
	}
}

// TestOrganizationVariableReaderListByOrganizationWiresThroughStore proves
// the reader adapter composes the repository through Store.Read, so the
// tenant scoping the repository proves is inherited at the HTTP boundary.
func TestOrganizationVariableReaderListByOrganizationWiresThroughStore(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderVarsAcme")
	seedOrganizationVariable(t, db, "ovar_only", org.ID, "ONLY", "value", false)

	reader, err := store.NewOrganizationVariableReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationVariableReader: %v", err)
	}
	got, err := reader.ListByOrganization(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(got) != 1 || got[0].Key != "ONLY" {
		t.Fatalf("got %+v, want a single row keyed ONLY", got)
	}
}

// TestOrganizationVariableReaderReturnsEmptyForUnknownOrg proves a tenant
// with no configured variables (or a cross-tenant id that does not match
// any row) surfaces as a deterministic empty list, mirroring every list
// endpoint the HTTP layer serves.
func TestOrganizationVariableReaderReturnsEmptyForUnknownOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	reader, err := store.NewOrganizationVariableReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationVariableReader: %v", err)
	}
	got, err := reader.ListByOrganization(ctx, "org_no_such_tenant")
	if err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d rows for an unknown org, want 0", len(got))
	}
}

// TestNewOrganizationVariableReaderRejectsNilStore proves a misconfigured
// adapter fails at construction rather than on its first request.
func TestNewOrganizationVariableReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewOrganizationVariableReader(nil); err == nil {
		t.Error("NewOrganizationVariableReader(nil) returned no error; want a nil-store error")
	}
}

// TestOrganizationVariableSchemaEnforcesUniqueKeyPerOrganization proves
// the (organization_id, key) uniqueness constraint at the DB layer: two
// rows with the same key in the same tenant is a constraint violation,
// while the same key in two different tenants is allowed.
func TestOrganizationVariableSchemaEnforcesUniqueKeyPerOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "UniqVarsA")
	orgB := seedOrg(t, db, f, "UniqVarsB")
	// Same key in two different tenants — allowed.
	seedOrganizationVariable(t, db, "ovar_a", orgA.ID, "SHARED", "a", false)
	seedOrganizationVariable(t, db, "ovar_b", orgB.ID, "SHARED", "b", false)

	// Duplicate key in the same tenant — must violate the unique constraint.
	if _, err := db.Exec(ctx,
		`INSERT INTO organization_variables (id, organization_id, key, value, is_secret)
		 VALUES ($1, $2, $3, $4, $5)`,
		"ovar_dup", orgA.ID, "SHARED", "c", false); err == nil {
		t.Errorf("duplicate (org_id, key) insert succeeded; want a unique-constraint violation")
	}
}

// TestOrganizationVariableSchemaCascadesOnOrganizationDelete proves the
// FK ON DELETE CASCADE: tearing down the parent organization removes
// the child rows.
func TestOrganizationVariableSchemaCascadesOnOrganizationDelete(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "CascadeVars")
	seedOrganizationVariable(t, db, "ovar_x", org.ID, "X", "v", false)
	if _, err := db.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, org.ID); err != nil {
		t.Fatalf("delete organization: %v", err)
	}

	var n int
	row := db.QueryRow(ctx,
		`SELECT COUNT(*) FROM organization_variables WHERE organization_id = $1`, org.ID)
	if err := row.Scan(&n); err != nil {
		t.Fatalf("count after cascade: %v", err)
	}
	if n != 0 {
		t.Errorf("rows remaining = %d, want 0 (cascade should have removed them)", n)
	}
}

// TestOrganizationVariableSchemaBumpsVersionOnUpdate proves the
// bump_version trigger maintains the optimistic-concurrency counter on
// every UPDATE, so a later PATCH/DELETE story can rely on If-Match
// preconditions matching this column.
func TestOrganizationVariableSchemaBumpsVersionOnUpdate(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "VersionVars")
	seedOrganizationVariable(t, db, "ovar_v", org.ID, "K", "v1", false)

	if _, err := db.Exec(ctx,
		`UPDATE organization_variables SET value = $1 WHERE id = $2`, "v2", "ovar_v"); err != nil {
		t.Fatalf("update: %v", err)
	}

	var version int64
	row := db.QueryRow(ctx, `SELECT version FROM organization_variables WHERE id = $1`, "ovar_v")
	if err := row.Scan(&version); err != nil {
		t.Fatalf("scan version: %v", err)
	}
	if version != 2 {
		t.Errorf("version after one update = %d, want 2", version)
	}
}
