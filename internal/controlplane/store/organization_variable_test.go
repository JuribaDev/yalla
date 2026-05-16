package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// revealVariableValue returns the literal plaintext value of v. For
// non-secret rows it is just v.Value. For is_secret rows the literal
// value lives in v.SecretCiphertext (the schema CHECK forces Value=”
// for secret rows after BE-0339), so we return the ciphertext bytes
// verbatim — every test in this package wires the Plaintext provider,
// for which Seal(plaintext) is plaintext, so the equivalence holds
// without dragging a live provider through every assertion.
func revealVariableValue(v store.OrganizationVariable) string {
	if v.IsSecret {
		return string(v.SecretCiphertext)
	}
	return v.Value
}

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
	// Migration 0029 added a CHECK constraint requiring that secret rows
	// carry a populated (secret_provider, secret_key_id, secret_ciphertext)
	// tuple AND that the plain `value` column is ''. For test fixtures
	// we stand in the secrets.Plaintext provider's wire identifiers so
	// rows stay self-contained (no live provider dependency) and the
	// HTTP/audit redaction contract still holds — the wire layer never
	// projects the on-disk bytes for secret rows.
	plainValue := value
	var (
		provider   any
		keyID      any
		ciphertext any
	)
	if isSecret {
		plainValue = ""
		provider = "plaintext-v1"
		keyID = "plaintext"
		ciphertext = []byte(value)
	}
	if _, err := db.Exec(context.Background(),
		`INSERT INTO organization_variables (id, organization_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, organizationID, key, plainValue, isSecret, provider, keyID, ciphertext); err != nil {
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
	// Spot-check value + is_secret round-trip. For is_secret=true rows the
	// literal value lives in secret_ciphertext after BE-0339; revealVariableValue
	// projects the on-disk shape back to the plaintext for the assertion.
	if revealVariableValue(got[1]) != "m-value" || !got[1].IsSecret {
		t.Errorf("got[1] = %+v; want (m-value, is_secret=true)", got[1])
	}
}

// TestOrganizationVariableRepoDeleteByKeyReturnsRemovedSnapshot proves
// the persistence half of DELETE /v1/organizations/{org_id}/variables/
// {key}: a DELETE inside Store.Write returns the row exactly as it
// stood at the moment of removal — including id, value, is_secret,
// version — and the row is physically gone afterwards (a subsequent
// ListByOrganization no longer observes it).
func TestOrganizationVariableRepoDeleteByKeyReturnsRemovedSnapshot(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "DelAcme")
	seedOrganizationVariable(t, db, "ovar_alpha", org.ID, "ALPHA", "a-value", false)
	seedOrganizationVariable(t, db, "ovar_beta", org.ID, "BETA", "secret-b", true)

	repo := store.NewOrganizationVariableRepository()
	var removed store.OrganizationVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		v, delErr := repo.DeleteByKey(ctx, tx, org.ID, "BETA")
		removed = v
		return delErr
	}); err != nil {
		t.Fatalf("DeleteByKey: %v", err)
	}
	if removed.ID != "ovar_beta" {
		t.Errorf("removed.id = %q, want ovar_beta", removed.ID)
	}
	if removed.Key != "BETA" || revealVariableValue(removed) != "secret-b" || !removed.IsSecret {
		t.Errorf("removed = %+v, want BETA/secret-b/is_secret=true", removed)
	}

	// After the delete, only ALPHA remains.
	var remaining []store.OrganizationVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var lerr error
		remaining, lerr = repo.ListByOrganization(ctx, q, org.ID)
		return lerr
	}); err != nil {
		t.Fatalf("post-delete ListByOrganization: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Key != "ALPHA" {
		t.Errorf("remaining = %+v, want only ALPHA", remaining)
	}
}

// TestOrganizationVariableRepoDeleteByKeyNotFoundForMissingRow proves
// a DELETE against a key that does not exist in this tenant surfaces
// as the typed NotFound the GET endpoint uses — never a 5xx, never a
// "deleted nothing silently".
func TestOrganizationVariableRepoDeleteByKeyNotFoundForMissingRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "DelAcme")
	repo := store.NewOrganizationVariableRepository()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, delErr := repo.DeleteByKey(ctx, tx, org.ID, "NEVER_SET")
		return delErr
	})
	if err == nil {
		t.Fatalf("DeleteByKey returned no error for a missing row, want NotFound")
	}
}

// TestOrganizationVariableRepoDeleteByKeyIsTenantScoped proves the SQL
// predicate is the tenant boundary: a DELETE against (organization,
// key) never reaches another tenant's row — the foreign tenant's row
// is left intact and the cross-tenant call reports NotFound.
func TestOrganizationVariableRepoDeleteByKeyIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	acme := seedOrg(t, db, f, "Acme")
	rival := seedOrg(t, db, f, "Rival")
	seedOrganizationVariable(t, db, "ovar_acme_region", acme.ID, "REGION", "us-east-1", false)
	seedOrganizationVariable(t, db, "ovar_rival_region", rival.ID, "REGION", "rival-eu-west-1", false)

	repo := store.NewOrganizationVariableRepository()
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, delErr := repo.DeleteByKey(ctx, tx, acme.ID, "REGION")
		return delErr
	}); err != nil {
		t.Fatalf("DeleteByKey on acme: %v", err)
	}

	// Verify rival's row is still present.
	var rivalRows []store.OrganizationVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var lerr error
		rivalRows, lerr = repo.ListByOrganization(ctx, q, rival.ID)
		return lerr
	}); err != nil {
		t.Fatalf("rival ListByOrganization: %v", err)
	}
	if len(rivalRows) != 1 || rivalRows[0].Key != "REGION" || rivalRows[0].Value != "rival-eu-west-1" {
		t.Errorf("rival rows = %+v, want REGION intact after acme-side DELETE", rivalRows)
	}

	// A second acme-side delete of the same key now reports NotFound
	// (the previous delete removed it). A cross-tenant attempt where
	// acme tries to delete the rival's RIVAL_ONLY key would similarly
	// report NotFound — the predicate uses both org and key.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, delErr := repo.DeleteByKey(ctx, tx, acme.ID, "REGION")
		return delErr
	}); err == nil {
		t.Errorf("second acme-side DeleteByKey returned no error; want NotFound after the row was removed")
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
