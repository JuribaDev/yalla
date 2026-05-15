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

// Integration tests for the EnvironmentRepository and EnvironmentReader —
// the persistence half of the environments surface. They run against an
// isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset. The tests prove tenant scoping,
// deterministic ordering, project-existence checks at the reader, and
// that a cross-tenant project_id never reveals another tenant's
// environments.

// TestEnvironmentRepoListByProjectReturnsDeterministicOrdering proves
// ListByProject yields rows in the documented (slug ASC, id ASC) order.
// The ordering is part of the public contract: a given set of rows must
// render the same wire payload across calls so agents can checksum the
// response.
func TestEnvironmentRepoListByProjectReturnsDeterministicOrdering(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvOrderAcme")
	proj := seedProject(t, db, f, org, "Backend")

	// Seed in deliberately unsorted insertion order. Expected final order
	// is: production first, staging second (slug ASC).
	envStaging := seedEnvironment(t, db, f, proj, "staging")
	envProd := seedEnvironment(t, db, f, proj, "production")

	repo := store.NewEnvironmentRepository()
	var got []store.Environment
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
	if got[0].ID != envProd.ID || got[0].Slug != "production" {
		t.Errorf("got[0] = %+v; want (id=%q, slug=production)", got[0], envProd.ID)
	}
	if got[1].ID != envStaging.ID || got[1].Slug != "staging" {
		t.Errorf("got[1] = %+v; want (id=%q, slug=staging)", got[1], envStaging.ID)
	}
	// Optimistic concurrency starts at 1.
	for i, e := range got {
		if e.Version != 1 {
			t.Errorf("got[%d].Version = %d; want 1 (a fresh INSERT)", i, e.Version)
		}
	}
}

// TestEnvironmentRepoListByProjectIsTenantScoped proves a cross-tenant
// (organization_id, project_id) tuple yields no rows even when an
// environment of the same project_id exists in another organization.
// Note: because project_id is globally unique in the projects table,
// this exercises the organization_id leg of the WHERE clause; a
// cross-tenant id behaves as "no such (org, project) pair", which is
// exactly the empty-slice contract.
func TestEnvironmentRepoListByProjectIsTenantScoped(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "EnvTenantA")
	orgB := seedOrg(t, db, f, "EnvTenantB")
	projB := seedProject(t, db, f, orgB, "B")
	_ = seedEnvironment(t, db, f, projB, "production")

	repo := store.NewEnvironmentRepository()
	var got []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByProject(ctx, q, orgA.ID, projB.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByProject: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("ListByProject(cross-tenant) returned %d rows; want 0", len(got))
	}
}

// TestEnvironmentRepoListByProjectEmptyProject proves a live project with
// no environments yields a deterministic empty slice (not nil), so
// callers can iterate without a nil check.
func TestEnvironmentRepoListByProjectEmptyProject(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvEmptyAcme")
	proj := seedProject(t, db, f, org, "Lonely")

	repo := store.NewEnvironmentRepository()
	var got []store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByProject(ctx, q, org.ID, proj.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByProject: %v", err)
	}
	if got == nil {
		t.Fatalf("ListByProject(emptyProject) = nil; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d; want 0", len(got))
	}
}

// TestEnvironmentReaderListProjectEnvironmentsHappyPath proves the
// store-backed adapter composes the project existence check + environment
// list inside one short-lived read transaction and projects the rows
// verbatim to the caller.
func TestEnvironmentReaderListProjectEnvironmentsHappyPath(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderEnvAcme")
	proj := seedProject(t, db, f, org, "Web")
	envProd := seedEnvironment(t, db, f, proj, "production")
	envStaging := seedEnvironment(t, db, f, proj, "staging")

	reader, err := store.NewEnvironmentReader(s)
	if err != nil {
		t.Fatalf("NewEnvironmentReader: %v", err)
	}

	got, err := reader.ListProjectEnvironments(ctx, org.ID, proj.ID)
	if err != nil {
		t.Fatalf("ListProjectEnvironments: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].ID != envProd.ID || got[1].ID != envStaging.ID {
		t.Errorf("ordering = (%q, %q); want (%q, %q)", got[0].ID, got[1].ID, envProd.ID, envStaging.ID)
	}
}

// TestEnvironmentReaderRejectsCrossTenantProjectID proves a cross-tenant
// project_id reaches the projects.Get check inside the reader's
// transaction and surfaces as a typed apierr.NotFound — never as an
// empty list, which would invite an agent to believe the project exists
// with no environments. The error must not echo any cross-tenant
// identifier (project id, environment id, slug, or display name).
func TestEnvironmentReaderRejectsCrossTenantProjectID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "EnvCrossA")
	orgB := seedOrg(t, db, f, "EnvCrossB")
	projB := seedProject(t, db, f, orgB, "B")
	envB := seedEnvironment(t, db, f, projB, "production")

	reader, err := store.NewEnvironmentReader(s)
	if err != nil {
		t.Fatalf("NewEnvironmentReader: %v", err)
	}

	got, err := reader.ListProjectEnvironments(ctx, orgA.ID, projB.ID)
	if err == nil {
		t.Fatalf("ListProjectEnvironments(crossTenant) = %+v, nil; want apierr.NotFound", got)
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
	// The envB row from org B must not appear in the error string —
	// neither the row id, the project id, nor the slug.
	leaks := []string{envB.ID, projB.ID, envB.Slug}
	msg := err.Error()
	for _, n := range leaks {
		if n != "" && strings.Contains(msg, n) {
			t.Errorf("error leaks cross-tenant identifier %q: %v", n, err)
		}
	}
}

// TestEnvironmentReaderUnknownProjectID proves an unknown project_id
// (in the principal's own tenant) surfaces as the same deterministic
// apierr.NotFound — same shape as a cross-tenant id, so the response is
// not a "does this project_id exist?" oracle.
func TestEnvironmentReaderUnknownProjectID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UnknownEnvAcme")

	reader, err := store.NewEnvironmentReader(s)
	if err != nil {
		t.Fatalf("NewEnvironmentReader: %v", err)
	}

	_, err = reader.ListProjectEnvironments(ctx, org.ID, "proj_unknown")
	if err == nil {
		t.Fatalf("ListProjectEnvironments(unknown) returned no error; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestNewEnvironmentReaderRejectsNilStore proves the constructor fails
// fast — a misconfigured adapter fails at construction rather than on
// its first request.
func TestNewEnvironmentReaderRejectsNilStore(t *testing.T) {
	t.Parallel()

	_, err := store.NewEnvironmentReader(nil)
	if err == nil {
		t.Fatalf("NewEnvironmentReader(nil) returned no error")
	}
}
