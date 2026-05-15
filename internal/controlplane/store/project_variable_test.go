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
