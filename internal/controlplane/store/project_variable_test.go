package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Integration tests for the ProjectVariableRepository and
// ProjectVariableReader — the persistence half of the project-scoped
// variables surface. They run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// tests prove tenant scoping, deterministic ordering, project-existence
// checks at the reader, and that a cross-tenant project_id never reveals
// another tenant's variables.

// seedProjectVariable inserts one project_variables row through the test
// pool. It builds the smallest column set the schema requires (id,
// organization_id, project_id, key, value, is_secret); the bump_version
// and set_updated_at triggers from migrations 0011 / 0015 populate the
// rest.
func seedProjectVariable(t *testing.T, db *testutil.DB, id, organizationID, projectID, key, value string, isSecret bool) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO project_variables (id, organization_id, project_id, key, value, is_secret)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, organizationID, projectID, key, value, isSecret); err != nil {
		t.Fatalf("seed project_variables: %v", err)
	}
}

// TestProjectVariableRepoListByProjectReturnsDeterministicOrdering proves
// ListByProject yields rows in the documented (key ASC, id ASC) order.
// The ordering is part of the public contract: a given set of rows must
// render the same wire payload across calls so agents can checksum the
// response.
func TestProjectVariableRepoListByProjectReturnsDeterministicOrdering(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "VarsAcme")
	proj := seedProject(t, db, f, org, "Backend")

	// Seed in deliberately unsorted insertion order. The expected final
	// order is: DATABASE_URL first, REGION second (key ASC).
	seedProjectVariable(t, db, "pvar_region", org.ID, proj.ID, "REGION", "us-east-1", false)
	seedProjectVariable(t, db, "pvar_db", org.ID, proj.ID, "DATABASE_URL", "postgres://user:hunter2@db.internal/yalla", true)

	repo := store.NewProjectVariableRepository()
	var got []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByProject(ctx, q, org.ID, proj.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByProject: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (got %+v)", len(got), got)
	}
	if got[0].ID != "pvar_db" || got[0].Key != "DATABASE_URL" || !got[0].IsSecret {
		t.Errorf("got[0] = %+v; want (pvar_db, DATABASE_URL, is_secret=true)", got[0])
	}
	if got[1].ID != "pvar_region" || got[1].Key != "REGION" || got[1].IsSecret {
		t.Errorf("got[1] = %+v; want (pvar_region, REGION, is_secret=false)", got[1])
	}
	// Optimistic concurrency starts at 1.
	for i, v := range got {
		if v.Version != 1 {
			t.Errorf("got[%d].Version = %d, want 1", i, v.Version)
		}
	}
	// Value reaches the repository verbatim; redaction is the HTTP layer's
	// job. Pin that contract here so a future regression that pre-redacts
	// at persistence (which would break a round-trip write path) fails.
	if got[0].Value != "postgres://user:hunter2@db.internal/yalla" {
		t.Errorf("got[0].Value should round-trip the literal; got %q", got[0].Value)
	}
}

// TestProjectVariableRepoListByProjectIsTenantScoped seeds two
// organizations with overlapping-looking variable rows on each tenant's
// project. A read for org A's project must never observe a variable filed
// under org B's project. This is the load-bearing tenant-isolation
// property of the repository.
func TestProjectVariableRepoListByProjectIsTenantScoped(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "VarTenantA")
	orgB := seedOrg(t, db, f, "VarTenantB")
	projA := seedProject(t, db, f, orgA, "Service")
	projB := seedProject(t, db, f, orgB, "Service")

	seedProjectVariable(t, db, "pvar_a", orgA.ID, projA.ID, "DATABASE_URL", "tenantA", true)
	seedProjectVariable(t, db, "pvar_b", orgB.ID, projB.ID, "DATABASE_URL", "tenantB", true)

	repo := store.NewProjectVariableRepository()
	var listA []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listA, listErr = repo.ListByProject(ctx, q, orgA.ID, projA.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByProject(A): %v", err)
	}
	if len(listA) != 1 || listA[0].ID != "pvar_a" {
		t.Fatalf("listA = %+v; want exactly pvar_a", listA)
	}

	// A cross-tenant attempt — org A asking for org B's projectID — must
	// return zero rows. Same the other way around.
	var listCross []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listCross, listErr = repo.ListByProject(ctx, q, orgA.ID, projB.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByProject(cross): %v", err)
	}
	if len(listCross) != 0 {
		t.Fatalf("cross-tenant list = %+v; want empty", listCross)
	}
}

// TestProjectVariableRepoListByProjectEmptyProject proves a real project
// without variables returns the deterministic empty slice — not nil — so
// HTTP projections can iterate without a nil check.
func TestProjectVariableRepoListByProjectEmptyProject(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EmptyVarsAcme")
	proj := seedProject(t, db, f, org, "Empty")

	repo := store.NewProjectVariableRepository()
	var got []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByProject(ctx, q, org.ID, proj.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if got == nil {
		t.Errorf("got = nil; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

// TestProjectVariableReaderListProjectVariablesHappyPath proves the
// store-backed adapter composes the project existence check + variable
// list inside one short-lived read transaction and projects the rows
// verbatim to the caller.
func TestProjectVariableReaderListProjectVariablesHappyPath(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderVarsAcme")
	proj := seedProject(t, db, f, org, "Web")
	seedProjectVariable(t, db, "pvar_one", org.ID, proj.ID, "REGION", "us-east-1", false)
	seedProjectVariable(t, db, "pvar_two", org.ID, proj.ID, "DATABASE_URL", "secret", true)

	reader, err := store.NewProjectVariableReader(s)
	if err != nil {
		t.Fatalf("NewProjectVariableReader: %v", err)
	}

	got, err := reader.ListProjectVariables(ctx, org.ID, proj.ID)
	if err != nil {
		t.Fatalf("ListProjectVariables: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Key != "DATABASE_URL" || got[1].Key != "REGION" {
		t.Errorf("ordering = (%q, %q); want (DATABASE_URL, REGION)", got[0].Key, got[1].Key)
	}
}

// TestProjectVariableReaderRejectsCrossTenantProjectID proves a
// cross-tenant project_id reaches the projects.Get check inside the
// reader's transaction and surfaces as a typed apierr.NotFound — never as
// an empty list, which would invite an agent to believe the project
// exists with no variables.
func TestProjectVariableReaderRejectsCrossTenantProjectID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "VarCrossA")
	orgB := seedOrg(t, db, f, "VarCrossB")
	projB := seedProject(t, db, f, orgB, "B")
	seedProjectVariable(t, db, "pvar_leak", orgB.ID, projB.ID, "API_TOKEN", "hunter2", true)

	reader, err := store.NewProjectVariableReader(s)
	if err != nil {
		t.Fatalf("NewProjectVariableReader: %v", err)
	}

	got, err := reader.ListProjectVariables(ctx, orgA.ID, projB.ID)
	if err == nil {
		t.Fatalf("ListProjectVariables(crossTenant) = %+v, nil; want apierr.NotFound", got)
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
	// The pvar_leak row from org B must not appear in the error string —
	// neither the row id, the key, nor any fragment of the secret value.
	leaks := []string{"pvar_leak", "API_TOKEN", "hunter2"}
	msg := err.Error()
	for _, n := range leaks {
		if strings.Contains(msg, n) {
			t.Errorf("error leaks cross-tenant identifier %q: %v", n, err)
		}
	}
}

// TestProjectVariableReaderUnknownProjectID proves an unknown project_id
// (in the principal's own tenant) surfaces as the same deterministic
// apierr.NotFound — same shape as a cross-tenant id, so the response is
// not a "does this project_id exist?" oracle.
func TestProjectVariableReaderUnknownProjectID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UnknownVarsAcme")

	reader, err := store.NewProjectVariableReader(s)
	if err != nil {
		t.Fatalf("NewProjectVariableReader: %v", err)
	}

	_, err = reader.ListProjectVariables(ctx, org.ID, "proj_unknown")
	if err == nil {
		t.Fatalf("ListProjectVariables(unknown) returned no error; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestNewProjectVariableReaderRejectsNilStore proves the constructor
// refuses a nil *Store so a misconfigured adapter cannot reach a request —
// it fails at construction, not at first use.
func TestNewProjectVariableReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewProjectVariableReader(nil); err == nil {
		t.Error("NewProjectVariableReader(nil) returned no error; want a nil-store error")
	}
}

// TestProjectVariableRepoUpsertInsertsNewRow proves Upsert inserts a fresh
// row at the (organization_id, project_id, key) tuple, returns the persisted
// columns verbatim, and stamps the database-owned version + timestamp
// fields. The caller-supplied id survives because no conflict exists.
func TestProjectVariableRepoUpsertInsertsNewRow(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UpsertVarAcme")
	proj := seedProject(t, db, f, org, "Backend")

	repo := store.NewProjectVariableRepository()
	var got store.ProjectVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		v, upErr := repo.Upsert(ctx, tx, "pvar_new", org.ID, proj.ID, "REGION", "us-east-1", false)
		if upErr != nil {
			return upErr
		}
		got = v
		return nil
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if got.ID != "pvar_new" || got.OrganizationID != org.ID || got.ProjectID != proj.ID {
		t.Errorf("got identity = (%q, %q, %q); want (pvar_new, %q, %q)", got.ID, got.OrganizationID, got.ProjectID, org.ID, proj.ID)
	}
	if got.Key != "REGION" || got.Value != "us-east-1" || got.IsSecret {
		t.Errorf("got fields = (%q, %q, %t); want (REGION, us-east-1, false)", got.Key, got.Value, got.IsSecret)
	}
	if got.Version != 1 {
		t.Errorf("got.Version = %d; want 1 (initial insert)", got.Version)
	}
}

// TestProjectVariableRepoUpsertUpdatesExistingRow proves a second Upsert at
// the same (organization_id, project_id, key) preserves the original row id
// (the existing row's id, NOT the caller-supplied one), and bumps version
// through the bump_version trigger. Value and is_secret reach the new
// values. This is the load-bearing idempotence property of the bulk-replace
// unit of work.
func TestProjectVariableRepoUpsertUpdatesExistingRow(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UpsertVarUpdAcme")
	proj := seedProject(t, db, f, org, "Web")
	seedProjectVariable(t, db, "pvar_existing", org.ID, proj.ID, "DATABASE_URL", "v1", false)

	repo := store.NewProjectVariableRepository()
	var got store.ProjectVariable
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		v, upErr := repo.Upsert(ctx, tx, "pvar_caller", org.ID, proj.ID, "DATABASE_URL", "v2-secret", true)
		if upErr != nil {
			return upErr
		}
		got = v
		return nil
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if got.ID != "pvar_existing" {
		t.Errorf("got.ID = %q; want pvar_existing (existing row id preserved on conflict)", got.ID)
	}
	if got.Value != "v2-secret" || !got.IsSecret {
		t.Errorf("got fields = (%q, %t); want (v2-secret, true)", got.Value, got.IsSecret)
	}
	if got.Version != 2 {
		t.Errorf("got.Version = %d; want 2 (bump_version trigger on UPDATE)", got.Version)
	}
}

// TestProjectVariableRepoUpsertRejectsCrossTenant proves a (organization_id,
// project_id) tuple whose project belongs to another tenant fails through
// the composite FK on projects, surfacing as apierr.Conflict — not a silent
// insert that smuggles a row under a foreign tenant.
func TestProjectVariableRepoUpsertRejectsCrossTenant(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "UpsertCrossA")
	orgB := seedOrg(t, db, f, "UpsertCrossB")
	projB := seedProject(t, db, f, orgB, "Web")

	repo := store.NewProjectVariableRepository()
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, upErr := repo.Upsert(ctx, tx, "pvar_attempt", orgA.ID, projB.ID, "REGION", "leak", false)
		return upErr
	})
	if err == nil {
		t.Fatal("Upsert(crossTenant) succeeded; want apierr.Conflict from composite FK")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) {
		t.Fatalf("err = %v (%T); want a typed yerr.Error", err, err)
	}
	if ye.Code != yerr.CodeConflict {
		t.Errorf("err.Code = %q; want %q (FK violation)", ye.Code, yerr.CodeConflict)
	}
}

// TestProjectVariableRepoUpsertRejectsNilTx proves the mutation guards
// against a nil transaction at the boundary — a programming error must
// surface as apierr.Internal, not a nil-pointer panic.
func TestProjectVariableRepoUpsertRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewProjectVariableRepository()
	_, err := repo.Upsert(context.Background(), nil, "id", "org", "proj", "K", "v", false)
	if err == nil {
		t.Fatal("Upsert(nilTx) returned no error; want apierr.Internal")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Fatalf("err = %v (%T); want yerr CodeInternal", err, err)
	}
}

// TestProjectVariableRepoDeleteByProjectExceptKeysDropsTheRest proves the
// counterpart of the bulk replace: every row in (org, project) whose key is
// not in the keep set is removed, the rest is preserved verbatim.
func TestProjectVariableRepoDeleteByProjectExceptKeysDropsTheRest(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "DelExceptAcme")
	proj := seedProject(t, db, f, org, "Web")
	seedProjectVariable(t, db, "pvar_keep_a", org.ID, proj.ID, "KEEP_A", "a", false)
	seedProjectVariable(t, db, "pvar_keep_b", org.ID, proj.ID, "KEEP_B", "b", false)
	seedProjectVariable(t, db, "pvar_drop", org.ID, proj.ID, "DROP", "d", false)

	repo := store.NewProjectVariableRepository()
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptKeys(ctx, tx, org.ID, proj.ID, []string{"KEEP_A", "KEEP_B"})
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptKeys: %v", err)
	}

	var after []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		after, listErr = repo.ListByProject(ctx, q, org.ID, proj.ID)
		return listErr
	}); err != nil {
		t.Fatalf("post-list: %v", err)
	}
	if len(after) != 2 {
		t.Fatalf("len = %d; want 2 (KEEP_A, KEEP_B)", len(after))
	}
	if after[0].Key != "KEEP_A" || after[1].Key != "KEEP_B" {
		t.Errorf("after = (%q, %q); want (KEEP_A, KEEP_B)", after[0].Key, after[1].Key)
	}
}

// TestProjectVariableRepoDeleteByProjectExceptKeysEmptyKeepClears proves an
// empty / nil keep set clears every row in (org, project) — the deliberate
// full-clear path the bulk-replace unit of work uses when the caller
// submits an empty Variables list.
func TestProjectVariableRepoDeleteByProjectExceptKeysEmptyKeepClears(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "DelClearAcme")
	proj := seedProject(t, db, f, org, "Web")
	seedProjectVariable(t, db, "pvar_x", org.ID, proj.ID, "X", "x", false)
	seedProjectVariable(t, db, "pvar_y", org.ID, proj.ID, "Y", "y", false)

	repo := store.NewProjectVariableRepository()
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptKeys(ctx, tx, org.ID, proj.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptKeys(nil): %v", err)
	}

	var after []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		after, listErr = repo.ListByProject(ctx, q, org.ID, proj.ID)
		return listErr
	}); err != nil {
		t.Fatalf("post-list: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("len = %d; want 0 (full clear)", len(after))
	}
}

// TestProjectVariableRepoDeleteByProjectExceptKeysIsTenantScoped proves a
// cross-tenant (organization_id, project_id) tuple deletes nothing — never
// another tenant's data, even if the keep set is empty.
func TestProjectVariableRepoDeleteByProjectExceptKeysIsTenantScoped(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "DelTenantA")
	orgB := seedOrg(t, db, f, "DelTenantB")
	projB := seedProject(t, db, f, orgB, "Web")
	seedProjectVariable(t, db, "pvar_keep", orgB.ID, projB.ID, "KEEP", "v", true)

	repo := store.NewProjectVariableRepository()
	// Org A asks to clear org B's project. Tenant-scoping must protect the
	// row.
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		return repo.DeleteByProjectExceptKeys(ctx, tx, orgA.ID, projB.ID, nil)
	}); err != nil {
		t.Fatalf("DeleteByProjectExceptKeys(crossTenant): %v", err)
	}

	var after []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		after, listErr = repo.ListByProject(ctx, q, orgB.ID, projB.ID)
		return listErr
	}); err != nil {
		t.Fatalf("post-list: %v", err)
	}
	if len(after) != 1 || after[0].ID != "pvar_keep" {
		t.Errorf("after = %+v; want untouched pvar_keep row", after)
	}
}

// TestProjectVariableRepoDeleteByProjectExceptKeysRejectsNilTx proves the
// mutation guards against a nil transaction at the boundary.
func TestProjectVariableRepoDeleteByProjectExceptKeysRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewProjectVariableRepository()
	err := repo.DeleteByProjectExceptKeys(context.Background(), nil, "org", "proj", nil)
	if err == nil {
		t.Fatal("DeleteByProjectExceptKeys(nilTx) returned no error; want apierr.Internal")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Fatalf("err = %v (%T); want yerr CodeInternal", err, err)
	}
}
