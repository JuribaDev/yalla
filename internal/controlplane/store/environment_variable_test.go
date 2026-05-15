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

// Integration tests for the EnvironmentVariableRepository and
// EnvironmentVariableReader — the persistence half of the
// environment-scoped variables surface. They run against an isolated,
// freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset. The tests prove tenant scoping,
// deterministic ordering, environment-existence checks at the reader,
// and that a cross-tenant environment_id never reveals another
// tenant's variables.

// seedEnvironmentVariable inserts one environment_variables row through
// the test pool. It builds the smallest column set the schema requires
// (id, organization_id, environment_id, key, value, is_secret); the
// bump_version and set_updated_at triggers from migrations 0011 / 0018
// populate the rest.
func seedEnvironmentVariable(t *testing.T, db *testutil.DB, id, organizationID, environmentID, key, value string, isSecret bool) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO environment_variables (id, organization_id, environment_id, key, value, is_secret)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, organizationID, environmentID, key, value, isSecret); err != nil {
		t.Fatalf("seed environment_variables: %v", err)
	}
}

// TestEnvironmentVariableRepoListByEnvironmentReturnsDeterministicOrdering
// proves ListByEnvironment yields rows in the documented (key ASC, id
// ASC) order. The ordering is part of the public contract: a given set
// of rows must render the same wire payload across calls so agents can
// checksum the response.
func TestEnvironmentVariableRepoListByEnvironmentReturnsDeterministicOrdering(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvVarsAcme")
	proj := seedProject(t, db, f, org, "Backend")
	env := seedEnvironment(t, db, f, proj, "Prod")

	// Seed in deliberately unsorted insertion order. The expected final
	// order is: DATABASE_URL first, REGION second (key ASC).
	seedEnvironmentVariable(t, db, "evar_region", org.ID, env.ID, "REGION", "us-east-1", false)
	seedEnvironmentVariable(t, db, "evar_db", org.ID, env.ID, "DATABASE_URL", "postgres://user:hunter2@db.internal/yalla", true)

	repo := store.NewEnvironmentVariableRepository()
	var got []store.EnvironmentVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByEnvironment(ctx, q, org.ID, env.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByEnvironment: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (got %+v)", len(got), got)
	}
	if got[0].ID != "evar_db" || got[0].Key != "DATABASE_URL" || !got[0].IsSecret {
		t.Errorf("got[0] = %+v; want (evar_db, DATABASE_URL, is_secret=true)", got[0])
	}
	if got[1].ID != "evar_region" || got[1].Key != "REGION" || got[1].IsSecret {
		t.Errorf("got[1] = %+v; want (evar_region, REGION, is_secret=false)", got[1])
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

// TestEnvironmentVariableRepoListByEnvironmentIsTenantScoped seeds two
// organizations with overlapping-looking variable rows on each tenant's
// environment. A read for org A's environment must never observe a
// variable filed under org B's environment. This is the load-bearing
// tenant-isolation property of the repository.
func TestEnvironmentVariableRepoListByEnvironmentIsTenantScoped(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "EnvVarTenantA")
	orgB := seedOrg(t, db, f, "EnvVarTenantB")
	projA := seedProject(t, db, f, orgA, "Service")
	projB := seedProject(t, db, f, orgB, "Service")
	envA := seedEnvironment(t, db, f, projA, "Prod")
	envB := seedEnvironment(t, db, f, projB, "Prod")

	seedEnvironmentVariable(t, db, "evar_a", orgA.ID, envA.ID, "DATABASE_URL", "tenantA", true)
	seedEnvironmentVariable(t, db, "evar_b", orgB.ID, envB.ID, "DATABASE_URL", "tenantB", true)

	repo := store.NewEnvironmentVariableRepository()
	var listA []store.EnvironmentVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listA, listErr = repo.ListByEnvironment(ctx, q, orgA.ID, envA.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(A): %v", err)
	}
	if len(listA) != 1 || listA[0].ID != "evar_a" {
		t.Fatalf("listA = %+v; want exactly evar_a", listA)
	}

	// A cross-tenant attempt — org A asking for org B's environmentID — must
	// return zero rows. Same the other way around.
	var listCross []store.EnvironmentVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listCross, listErr = repo.ListByEnvironment(ctx, q, orgA.ID, envB.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(cross): %v", err)
	}
	if len(listCross) != 0 {
		t.Fatalf("cross-tenant list = %+v; want empty", listCross)
	}
}

// TestEnvironmentVariableRepoListByEnvironmentEmptyEnvironment proves a
// real environment without variables returns the deterministic empty
// slice — not nil — so HTTP projections can iterate without a nil
// check.
func TestEnvironmentVariableRepoListByEnvironmentEmptyEnvironment(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EmptyEnvVarsAcme")
	proj := seedProject(t, db, f, org, "Empty")
	env := seedEnvironment(t, db, f, proj, "Empty")

	repo := store.NewEnvironmentVariableRepository()
	var got []store.EnvironmentVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByEnvironment(ctx, q, org.ID, env.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByEnvironment: %v", err)
	}
	if got == nil {
		t.Errorf("got = nil; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

// TestEnvironmentVariableReaderListEnvironmentVariablesHappyPath proves
// the store-backed adapter composes the environment existence check +
// variable list inside one short-lived read transaction and projects
// the rows verbatim to the caller.
func TestEnvironmentVariableReaderListEnvironmentVariablesHappyPath(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderEnvVarsAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	seedEnvironmentVariable(t, db, "evar_one", org.ID, env.ID, "REGION", "us-east-1", false)
	seedEnvironmentVariable(t, db, "evar_two", org.ID, env.ID, "DATABASE_URL", "secret", true)

	reader, err := store.NewEnvironmentVariableReader(s)
	if err != nil {
		t.Fatalf("NewEnvironmentVariableReader: %v", err)
	}

	got, err := reader.ListEnvironmentVariables(ctx, org.ID, env.ID)
	if err != nil {
		t.Fatalf("ListEnvironmentVariables: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Key != "DATABASE_URL" || got[1].Key != "REGION" {
		t.Errorf("ordering = (%q, %q); want (DATABASE_URL, REGION)", got[0].Key, got[1].Key)
	}
}

// TestEnvironmentVariableReaderRejectsCrossTenantEnvironmentID proves a
// cross-tenant environment_id reaches the environments.GetByID check
// inside the reader's transaction and surfaces as a typed
// apierr.NotFound — never as an empty list, which would invite an
// agent to believe the environment exists with no variables.
func TestEnvironmentVariableReaderRejectsCrossTenantEnvironmentID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "EnvVarCrossA")
	orgB := seedOrg(t, db, f, "EnvVarCrossB")
	projB := seedProject(t, db, f, orgB, "B")
	envB := seedEnvironment(t, db, f, projB, "Prod")
	seedEnvironmentVariable(t, db, "evar_leak", orgB.ID, envB.ID, "API_TOKEN", "hunter2", true)

	reader, err := store.NewEnvironmentVariableReader(s)
	if err != nil {
		t.Fatalf("NewEnvironmentVariableReader: %v", err)
	}

	got, err := reader.ListEnvironmentVariables(ctx, orgA.ID, envB.ID)
	if err == nil {
		t.Fatalf("ListEnvironmentVariables(crossTenant) = %+v, nil; want apierr.NotFound", got)
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
	// The evar_leak row from org B must not appear in the error string —
	// neither the row id, the key, nor any fragment of the secret value.
	leaks := []string{"evar_leak", "API_TOKEN", "hunter2"}
	msg := err.Error()
	for _, n := range leaks {
		if strings.Contains(msg, n) {
			t.Errorf("error leaks cross-tenant identifier %q: %v", n, err)
		}
	}
}

// TestEnvironmentVariableReaderUnknownEnvironmentID proves an unknown
// environment_id (in the principal's own tenant) surfaces as the same
// deterministic apierr.NotFound — same shape as a cross-tenant id, so
// the response is not a "does this environment_id exist?" oracle.
func TestEnvironmentVariableReaderUnknownEnvironmentID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UnknownEnvVarsAcme")

	reader, err := store.NewEnvironmentVariableReader(s)
	if err != nil {
		t.Fatalf("NewEnvironmentVariableReader: %v", err)
	}

	_, err = reader.ListEnvironmentVariables(ctx, org.ID, "env_unknown")
	if err == nil {
		t.Fatalf("ListEnvironmentVariables(unknown) returned no error; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestNewEnvironmentVariableReaderRejectsNilStore proves the
// constructor refuses a nil *Store so a misconfigured adapter cannot
// reach a request — it fails at construction, not at first use.
func TestNewEnvironmentVariableReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewEnvironmentVariableReader(nil); err == nil {
		t.Error("NewEnvironmentVariableReader(nil) returned no error; want a nil-store error")
	}
}
