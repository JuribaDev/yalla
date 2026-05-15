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

// Integration tests for the EnvironmentGrantRepository and
// EnvironmentGrantReader — the persistence half of the environment-scoped
// grants surface. They run against an isolated, freshly migrated Postgres
// database and skip when YALLA_TEST_DATABASE_URL is unset. The tests prove
// tenant scoping, deterministic ordering, environment-existence checks at
// the reader, and that a cross-tenant environment_id never reveals another
// tenant's grants.

// seedEnvironmentGrant inserts one environment_grants row through the test
// pool. It builds the smallest column set the schema requires (id,
// organization_id, environment_id, principal_id, principal_kind, role) and
// leaves service_id NULL unless the caller explicitly opts in through the
// svcID argument (empty string = NULL). The bump_version and
// set_updated_at triggers from migrations 0011 / 0017 populate the rest.
func seedEnvironmentGrant(t *testing.T, db *testutil.DB, id, organizationID, environmentID, principalID, principalKind, role, svcID string) {
	t.Helper()
	var svcIDArg any
	if svcID != "" {
		svcIDArg = svcID
	}
	if _, err := db.Exec(context.Background(),
		`INSERT INTO environment_grants (id, organization_id, environment_id, principal_id, principal_kind, role, service_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, organizationID, environmentID, principalID, principalKind, role, svcIDArg); err != nil {
		t.Fatalf("seed environment_grants: %v", err)
	}
}

// TestEnvironmentGrantRepoListByEnvironmentReturnsDeterministicOrdering
// proves ListByEnvironment yields rows in the documented (principal_id
// ASC, service_id ASC NULLS FIRST, id ASC) order. The ordering is part of
// the public contract: a given set of rows must render the same wire
// payload across calls so agents can checksum the response.
func TestEnvironmentGrantRepoListByEnvironmentReturnsDeterministicOrdering(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EGrantsAcme")
	proj := seedProject(t, db, f, org, "Backend")
	env := seedEnvironment(t, db, f, proj, "Prod")

	// Seed grants in a deliberately unsorted insertion order. The expected
	// final order is: principal alpha (no svc), principal alpha (svc s1),
	// principal beta (no svc).
	seedEnvironmentGrant(t, db, "egrnt_beta_root", org.ID, env.ID, "usr_beta", "usr", "developer", "")
	seedEnvironmentGrant(t, db, "egrnt_alpha_svc", org.ID, env.ID, "usr_alpha", "usr", "viewer", "svc_s1")
	seedEnvironmentGrant(t, db, "egrnt_alpha_root", org.ID, env.ID, "usr_alpha", "usr", "admin", "")

	repo := store.NewEnvironmentGrantRepository()
	var got []store.EnvironmentGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByEnvironment(ctx, q, org.ID, env.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByEnvironment: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (got %+v)", len(got), got)
	}
	wantIDs := []string{"egrnt_alpha_root", "egrnt_alpha_svc", "egrnt_beta_root"}
	for i, want := range wantIDs {
		if got[i].ID != want {
			t.Errorf("got[%d].ID = %q, want %q", i, got[i].ID, want)
		}
	}
	// Spot-check that all the structural fields round-trip.
	if got[0].Role != "admin" || got[0].PrincipalID != "usr_alpha" || got[0].PrincipalKind != "usr" {
		t.Errorf("got[0] = %+v; want (admin, usr_alpha, usr)", got[0])
	}
	if got[1].ServiceID == nil || *got[1].ServiceID != "svc_s1" {
		t.Errorf("got[1].ServiceID = %v; want svc_s1", got[1].ServiceID)
	}
	if got[2].ServiceID != nil {
		t.Errorf("got[2] should have nil svc, got %+v", got[2])
	}
	// Optimistic concurrency starts at 1.
	for i, g := range got {
		if g.Version != 1 {
			t.Errorf("got[%d].Version = %d, want 1", i, g.Version)
		}
	}
}

// TestEnvironmentGrantRepoListByEnvironmentIsTenantScoped seeds two
// organizations with overlapping-looking grant rows on each tenant's
// environment. A read for org A's environment must never observe a grant
// filed under org B's environment. This is the load-bearing
// tenant-isolation property of the repository.
func TestEnvironmentGrantRepoListByEnvironmentIsTenantScoped(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "TenantEgA")
	orgB := seedOrg(t, db, f, "TenantEgB")
	projA := seedProject(t, db, f, orgA, "Service")
	projB := seedProject(t, db, f, orgB, "Service")
	envA := seedEnvironment(t, db, f, projA, "Prod")
	envB := seedEnvironment(t, db, f, projB, "Prod")

	seedEnvironmentGrant(t, db, "egrnt_a", orgA.ID, envA.ID, "usr_a", "usr", "developer", "")
	seedEnvironmentGrant(t, db, "egrnt_b", orgB.ID, envB.ID, "usr_b", "usr", "developer", "")

	repo := store.NewEnvironmentGrantRepository()
	var listA []store.EnvironmentGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listA, listErr = repo.ListByEnvironment(ctx, q, orgA.ID, envA.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByEnvironment(A): %v", err)
	}
	if len(listA) != 1 || listA[0].ID != "egrnt_a" {
		t.Fatalf("listA = %+v; want exactly egrnt_a", listA)
	}

	// A cross-tenant attempt — org A asking for org B's environmentID — must
	// return zero rows. The tenant-scoped query filters by organization_id
	// so a foreign environment id matches no rows.
	var listCross []store.EnvironmentGrant
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

// TestEnvironmentGrantRepoListByEnvironmentEmptyEnvironment proves a real
// environment without grants returns the deterministic empty slice — not
// nil — so HTTP projections can iterate without a nil check.
func TestEnvironmentGrantRepoListByEnvironmentEmptyEnvironment(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EmptyEgAcme")
	proj := seedProject(t, db, f, org, "Empty")
	env := seedEnvironment(t, db, f, proj, "Empty")

	repo := store.NewEnvironmentGrantRepository()
	var got []store.EnvironmentGrant
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

// TestEnvironmentGrantReaderListEnvironmentGrantsHappyPath proves the
// store-backed adapter composes the environment existence check + grant
// list inside one short-lived read transaction and projects the rows
// verbatim to the caller.
func TestEnvironmentGrantReaderListEnvironmentGrantsHappyPath(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderEgAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	seedEnvironmentGrant(t, db, "egrnt_one", org.ID, env.ID, "usr_one", "usr", "developer", "")
	seedEnvironmentGrant(t, db, "egrnt_two", org.ID, env.ID, "sa_one", "sa", "ci", "svc_web")

	reader, err := store.NewEnvironmentGrantReader(s)
	if err != nil {
		t.Fatalf("NewEnvironmentGrantReader: %v", err)
	}

	got, err := reader.ListEnvironmentGrants(ctx, org.ID, env.ID)
	if err != nil {
		t.Fatalf("ListEnvironmentGrants: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
}

// TestEnvironmentGrantReaderRejectsCrossTenantEnvironmentID proves a
// cross-tenant environment_id reaches the environments.GetByID check
// inside the reader's transaction and surfaces as a typed apierr.NotFound
// — never as an empty list, which would invite an agent to believe the
// environment exists with no grants.
func TestEnvironmentGrantReaderRejectsCrossTenantEnvironmentID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "CrossEgA")
	orgB := seedOrg(t, db, f, "CrossEgB")
	projB := seedProject(t, db, f, orgB, "B")
	envB := seedEnvironment(t, db, f, projB, "B")
	seedEnvironmentGrant(t, db, "egrnt_leak", orgB.ID, envB.ID, "usr_x", "usr", "developer", "")

	reader, err := store.NewEnvironmentGrantReader(s)
	if err != nil {
		t.Fatalf("NewEnvironmentGrantReader: %v", err)
	}

	got, err := reader.ListEnvironmentGrants(ctx, orgA.ID, envB.ID)
	if err == nil {
		t.Fatalf("ListEnvironmentGrants(crossTenant) = %+v, nil; want apierr.NotFound", got)
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
	// The egrnt_leak row from org B must not appear in the error string,
	// so the response cannot be a leak oracle.
	if strings.Contains(err.Error(), "egrnt_leak") || strings.Contains(err.Error(), "usr_x") {
		t.Errorf("error leaks cross-tenant identifiers: %v", err)
	}
}

// TestEnvironmentGrantReaderUnknownEnvironmentID proves an unknown
// environment_id (in the principal's own tenant) surfaces as the same
// deterministic apierr.NotFound — same shape as a cross-tenant id, so the
// response is not a "does this environment_id exist?" oracle.
func TestEnvironmentGrantReaderUnknownEnvironmentID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UnknownEgAcme")

	reader, err := store.NewEnvironmentGrantReader(s)
	if err != nil {
		t.Fatalf("NewEnvironmentGrantReader: %v", err)
	}

	_, err = reader.ListEnvironmentGrants(ctx, org.ID, "env_unknown")
	if err == nil {
		t.Fatalf("ListEnvironmentGrants(unknown) returned no error; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestNewEnvironmentGrantReaderRejectsNilStore proves the constructor
// refuses a nil *Store so a misconfigured adapter cannot reach a request
// — it fails at construction, not at first use.
func TestNewEnvironmentGrantReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewEnvironmentGrantReader(nil); err == nil {
		t.Error("NewEnvironmentGrantReader(nil) returned no error; want a nil-store error")
	}
}
