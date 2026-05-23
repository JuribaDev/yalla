package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Integration tests for the ServiceGrantRepository — the persistence half
// of the service-scoped grants surface. They run against an isolated,
// freshly migrated Postgres database and skip when YALLA_TEST_DATABASE_URL
// is unset. The tests prove tenant scoping, deterministic ordering, and
// that a cross-tenant service_id never reveals another tenant's grants.

// seedServiceGrant inserts one service_grants row through the test pool.
// It builds the smallest column set the schema requires (id,
// organization_id, service_id, principal_id, principal_kind, role); the
// service_grants_bump_version and service_grants_set_updated_at triggers
// from migrations 0034 / 0011 populate the rest.
func seedServiceGrant(t *testing.T, db *testutil.DB, id, organizationID, serviceID, principalID, principalKind, role string) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO service_grants (id, organization_id, service_id, principal_id, principal_kind, role)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, organizationID, serviceID, principalID, principalKind, role); err != nil {
		t.Fatalf("seed service_grants: %v", err)
	}
}

// TestServiceGrantRepoListByServiceReturnsDeterministicOrdering proves
// ListByService yields rows in the documented (principal_id ASC, id ASC)
// order. The ordering is part of the public contract: a given set of rows
// must render the same wire payload across calls so agents can checksum
// the response.
func TestServiceGrantRepoListByServiceReturnsDeterministicOrdering(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SGrantsAcme")
	proj := seedProject(t, db, f, org, "Backend")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	// Seed grants in a deliberately unsorted insertion order. The expected
	// final order is: principal alpha (id alpha-a), principal alpha (id
	// alpha-b), principal beta. Ordering by (principal_id, id) keeps the
	// per-principal rows together and breaks any cross-principal tie by id.
	seedServiceGrant(t, db, "sgrnt_beta", org.ID, svc.ID, "usr_beta", "usr", "developer")
	seedServiceGrant(t, db, "sgrnt_alpha_b", org.ID, svc.ID, "usr_alpha_b", "usr", "viewer")
	seedServiceGrant(t, db, "sgrnt_alpha_a", org.ID, svc.ID, "usr_alpha_a", "usr", "admin")

	repo := store.NewServiceGrantRepository()
	var got []store.ServiceGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByService(ctx, q, org.ID, svc.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByService: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (got %+v)", len(got), got)
	}
	wantIDs := []string{"sgrnt_alpha_a", "sgrnt_alpha_b", "sgrnt_beta"}
	for i, want := range wantIDs {
		if got[i].ID != want {
			t.Errorf("got[%d].ID = %q, want %q", i, got[i].ID, want)
		}
	}
	// Spot-check that all the structural fields round-trip.
	if got[0].Role != "admin" || got[0].PrincipalID != "usr_alpha_a" || got[0].PrincipalKind != "usr" {
		t.Errorf("got[0] = %+v; want (admin, usr_alpha_a, usr)", got[0])
	}
	// Optimistic concurrency starts at 1.
	for i, g := range got {
		if g.Version != 1 {
			t.Errorf("got[%d].Version = %d, want 1", i, g.Version)
		}
	}
}

// TestServiceGrantRepoListByServiceIsTenantScoped seeds two organizations
// with overlapping-looking grant rows on each tenant's service. A read for
// org A's service must never observe a grant filed under org B's service.
// This is the load-bearing tenant-isolation property of the repository.
func TestServiceGrantRepoListByServiceIsTenantScoped(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "TenantSgA")
	orgB := seedOrg(t, db, f, "TenantSgB")
	projA := seedProject(t, db, f, orgA, "Service")
	projB := seedProject(t, db, f, orgB, "Service")
	envA := seedEnvironment(t, db, f, projA, "Prod")
	envB := seedEnvironment(t, db, f, projB, "Prod")
	svcA := seedService(t, db, f, envA, "API")
	svcB := seedService(t, db, f, envB, "API")

	seedServiceGrant(t, db, "sgrnt_a", orgA.ID, svcA.ID, "usr_a", "usr", "developer")
	seedServiceGrant(t, db, "sgrnt_b", orgB.ID, svcB.ID, "usr_b", "usr", "developer")

	repo := store.NewServiceGrantRepository()
	var listA []store.ServiceGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listA, listErr = repo.ListByService(ctx, q, orgA.ID, svcA.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByService(A): %v", err)
	}
	if len(listA) != 1 || listA[0].ID != "sgrnt_a" {
		t.Fatalf("listA = %+v; want exactly sgrnt_a", listA)
	}

	// A cross-tenant attempt — org A asking for org B's serviceID — must
	// return zero rows. The tenant-scoped query filters by organization_id
	// so a foreign service id matches no rows.
	var listCross []store.ServiceGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listCross, listErr = repo.ListByService(ctx, q, orgA.ID, svcB.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByService(cross): %v", err)
	}
	if len(listCross) != 0 {
		t.Fatalf("cross-tenant list = %+v; want empty", listCross)
	}
}

// TestServiceGrantRepoListByServiceEmptyService proves a real service
// without grants returns the deterministic empty slice — not nil — so
// HTTP projections can iterate without a nil check.
func TestServiceGrantRepoListByServiceEmptyService(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EmptySgAcme")
	proj := seedProject(t, db, f, org, "Empty")
	env := seedEnvironment(t, db, f, proj, "Empty")
	svc := seedService(t, db, f, env, "Empty")

	repo := store.NewServiceGrantRepository()
	var got []store.ServiceGrant
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByService(ctx, q, org.ID, svc.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByService: %v", err)
	}
	if got == nil {
		t.Errorf("got = nil; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}
