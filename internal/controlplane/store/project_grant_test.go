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

// Integration tests for the ProjectGrantRepository and ProjectGrantReader —
// the persistence half of the project-scoped grants surface. They run
// against an isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset. The tests prove tenant scoping,
// deterministic ordering, project-existence checks at the reader, and that
// a cross-tenant project_id never reveals another tenant's grants.

// seedProjectGrant inserts one project_grants row through the test pool. It
// builds the smallest column set the schema requires (id, organization_id,
// project_id, principal_id, principal_kind, role) and leaves environment_id
// / service_id NULL unless the caller explicitly opts in through the
// envID / svcID arguments (empty string = NULL). The bump_version and
// set_updated_at triggers from migrations 0011 / 0014 populate the rest.
func seedProjectGrant(t *testing.T, db *testutil.DB, id, organizationID, projectID, principalID, principalKind, role, envID, svcID string) {
	t.Helper()
	var envIDArg, svcIDArg any
	if envID != "" {
		envIDArg = envID
	}
	if svcID != "" {
		svcIDArg = svcID
	}
	if _, err := db.Exec(context.Background(),
		`INSERT INTO project_grants (id, organization_id, project_id, principal_id, principal_kind, role, environment_id, service_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, organizationID, projectID, principalID, principalKind, role, envIDArg, svcIDArg); err != nil {
		t.Fatalf("seed project_grants: %v", err)
	}
}

// TestProjectGrantRepoListByProjectReturnsDeterministicOrdering proves
// ListByProject yields rows in the documented (principal_id ASC,
// environment_id ASC NULLS FIRST, service_id ASC NULLS FIRST, id ASC)
// order. The ordering is part of the public contract: a given set of rows
// must render the same wire payload across calls so agents can checksum
// the response.
func TestProjectGrantRepoListByProjectReturnsDeterministicOrdering(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "GrantsAcme")
	proj := seedProject(t, db, f, org, "Backend")

	// Seed grants in a deliberately unsorted insertion order. The expected
	// final order is: principal alpha (no env, no svc), principal alpha
	// (env e1, no svc), principal beta (no env, no svc).
	seedProjectGrant(t, db, "pgrnt_beta_root", org.ID, proj.ID, "usr_beta", "usr", "developer", "", "")
	seedProjectGrant(t, db, "pgrnt_alpha_env", org.ID, proj.ID, "usr_alpha", "usr", "viewer", "env_e1", "")
	seedProjectGrant(t, db, "pgrnt_alpha_root", org.ID, proj.ID, "usr_alpha", "usr", "admin", "", "")

	repo := store.NewProjectGrantRepository()
	var got []store.ProjectGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByProject(ctx, q, org.ID, proj.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByProject: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (got %+v)", len(got), got)
	}
	wantIDs := []string{"pgrnt_alpha_root", "pgrnt_alpha_env", "pgrnt_beta_root"}
	for i, want := range wantIDs {
		if got[i].ID != want {
			t.Errorf("got[%d].ID = %q, want %q", i, got[i].ID, want)
		}
	}
	// Spot-check that all the structural fields round-trip.
	if got[0].Role != "admin" || got[0].PrincipalID != "usr_alpha" || got[0].PrincipalKind != "usr" {
		t.Errorf("got[0] = %+v; want (admin, usr_alpha, usr)", got[0])
	}
	if got[1].EnvironmentID == nil || *got[1].EnvironmentID != "env_e1" {
		t.Errorf("got[1].EnvironmentID = %v; want env_e1", got[1].EnvironmentID)
	}
	if got[2].EnvironmentID != nil || got[2].ServiceID != nil {
		t.Errorf("got[2] should have nil env/svc, got %+v", got[2])
	}
	// Optimistic concurrency starts at 1.
	for i, g := range got {
		if g.Version != 1 {
			t.Errorf("got[%d].Version = %d, want 1", i, g.Version)
		}
	}
}

// TestProjectGrantRepoListByProjectIsTenantScoped seeds two organizations
// with overlapping-looking grant rows on each tenant's project. A read for
// org A's project must never observe a grant filed under org B's project.
// This is the load-bearing tenant-isolation property of the repository.
func TestProjectGrantRepoListByProjectIsTenantScoped(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "TenantA")
	orgB := seedOrg(t, db, f, "TenantB")
	projA := seedProject(t, db, f, orgA, "Service")
	projB := seedProject(t, db, f, orgB, "Service")

	seedProjectGrant(t, db, "pgrnt_a", orgA.ID, projA.ID, "usr_a", "usr", "developer", "", "")
	seedProjectGrant(t, db, "pgrnt_b", orgB.ID, projB.ID, "usr_b", "usr", "developer", "", "")

	repo := store.NewProjectGrantRepository()
	var listA []store.ProjectGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listA, listErr = repo.ListByProject(ctx, q, orgA.ID, projA.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByProject(A): %v", err)
	}
	if len(listA) != 1 || listA[0].ID != "pgrnt_a" {
		t.Fatalf("listA = %+v; want exactly pgrnt_a", listA)
	}

	// A cross-tenant attempt — org A asking for org B's projectID — must
	// return zero rows. Same the other way around.
	var listCross []store.ProjectGrant
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

// TestProjectGrantRepoListByProjectEmptyProject proves a real project
// without grants returns the deterministic empty slice — not nil — so HTTP
// projections can iterate without a nil check.
func TestProjectGrantRepoListByProjectEmptyProject(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EmptyAcme")
	proj := seedProject(t, db, f, org, "Empty")

	repo := store.NewProjectGrantRepository()
	var got []store.ProjectGrant
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

// TestProjectGrantReaderListProjectGrantsHappyPath proves the
// store-backed adapter composes the project existence check + grant list
// inside one short-lived read transaction and projects the rows verbatim
// to the caller.
func TestProjectGrantReaderListProjectGrantsHappyPath(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderAcme")
	proj := seedProject(t, db, f, org, "Web")
	seedProjectGrant(t, db, "pgrnt_one", org.ID, proj.ID, "usr_one", "usr", "developer", "", "")
	seedProjectGrant(t, db, "pgrnt_two", org.ID, proj.ID, "sa_one", "sa", "ci", "env_prod", "svc_web")

	reader, err := store.NewProjectGrantReader(s)
	if err != nil {
		t.Fatalf("NewProjectGrantReader: %v", err)
	}

	got, err := reader.ListProjectGrants(ctx, org.ID, proj.ID)
	if err != nil {
		t.Fatalf("ListProjectGrants: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
}

// TestProjectGrantReaderRejectsCrossTenantProjectID proves a cross-tenant
// project_id reaches the projects.Get check inside the reader's
// transaction and surfaces as a typed apierr.NotFound — never as an empty
// list, which would invite an agent to believe the project exists with no
// grants.
func TestProjectGrantReaderRejectsCrossTenantProjectID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "CrossA")
	orgB := seedOrg(t, db, f, "CrossB")
	projB := seedProject(t, db, f, orgB, "B")
	seedProjectGrant(t, db, "pgrnt_leak", orgB.ID, projB.ID, "usr_x", "usr", "developer", "", "")

	reader, err := store.NewProjectGrantReader(s)
	if err != nil {
		t.Fatalf("NewProjectGrantReader: %v", err)
	}

	got, err := reader.ListProjectGrants(ctx, orgA.ID, projB.ID)
	if err == nil {
		t.Fatalf("ListProjectGrants(crossTenant) = %+v, nil; want apierr.NotFound", got)
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
	// The pgrnt_leak row from org B must not appear in the error string,
	// so the response cannot be a leak oracle.
	if strings.Contains(err.Error(), "pgrnt_leak") || strings.Contains(err.Error(), "usr_x") {
		t.Errorf("error leaks cross-tenant identifiers: %v", err)
	}
}

// TestProjectGrantReaderUnknownProjectID proves an unknown project_id (in
// the principal's own tenant) surfaces as the same deterministic
// apierr.NotFound — same shape as a cross-tenant id, so the response is
// not a "does this project_id exist?" oracle.
func TestProjectGrantReaderUnknownProjectID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UnknownAcme")

	reader, err := store.NewProjectGrantReader(s)
	if err != nil {
		t.Fatalf("NewProjectGrantReader: %v", err)
	}

	_, err = reader.ListProjectGrants(ctx, org.ID, "prj_unknown")
	if err == nil {
		t.Fatalf("ListProjectGrants(unknown) returned no error; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestNewProjectGrantReaderRejectsNilStore proves the constructor refuses a
// nil *Store so a misconfigured adapter cannot reach a request — it fails
// at construction, not at first use.
func TestNewProjectGrantReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewProjectGrantReader(nil); err == nil {
		t.Error("NewProjectGrantReader(nil) returned no error; want a nil-store error")
	}
}
