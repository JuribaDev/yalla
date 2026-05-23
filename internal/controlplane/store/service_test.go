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

// Integration tests for the ServiceRepository and ServiceReader — the
// persistence half of the services surface. They run against an
// isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset. The tests prove tenant scoping,
// deterministic ordering, environment-existence checks at the reader,
// and that a cross-tenant environment_id never reveals another
// tenant's services.

// TestServiceRepoListByEnvironmentReturnsDeterministicOrdering proves
// ListByEnvironment yields rows in the documented (slug ASC, id ASC)
// order. The ordering is part of the public contract: a given set of
// rows must render the same wire payload across calls so agents can
// checksum the response.
func TestServiceRepoListByEnvironmentReturnsDeterministicOrdering(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcOrderAcme")
	proj := seedProject(t, db, f, org, "Backend")
	env := seedEnvironment(t, db, f, proj, "production")

	// Seed in deliberately unsorted insertion order. Expected final
	// order is: api first, web second (slug ASC).
	svcWeb := seedService(t, db, f, env, "web")
	svcAPI := seedService(t, db, f, env, "api")

	repo := store.NewServiceRepository()
	var got []store.Service
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
	if got[0].ID != svcAPI.ID || !strings.HasPrefix(got[0].Slug, "api-") {
		t.Errorf("got[0] = %+v; want (id=%q, slug~api-*)", got[0], svcAPI.ID)
	}
	if got[1].ID != svcWeb.ID || !strings.HasPrefix(got[1].Slug, "web-") {
		t.Errorf("got[1] = %+v; want (id=%q, slug~web-*)", got[1], svcWeb.ID)
	}
	for i, sv := range got {
		if sv.Version != 1 {
			t.Errorf("got[%d].Version = %d; want 1 (a fresh INSERT)", i, sv.Version)
		}
		if sv.Kind == "" {
			t.Errorf("got[%d].Kind is empty; want non-empty", i)
		}
		if sv.OrganizationID != org.ID || sv.ProjectID != proj.ID || sv.EnvironmentID != env.ID {
			t.Errorf("got[%d] tenancy = (org=%q, proj=%q, env=%q); want (%q, %q, %q)",
				i, sv.OrganizationID, sv.ProjectID, sv.EnvironmentID, org.ID, proj.ID, env.ID)
		}
	}
}

// TestServiceRepoListByEnvironmentIsTenantScoped proves a cross-tenant
// (organization_id, environment_id) tuple yields no rows even when an
// environment of the same id exists in another organization. The
// repository never re-reads the parent existence check; tenant scoping
// is purely structural at the SQL predicate.
func TestServiceRepoListByEnvironmentIsTenantScoped(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "SvcTenantA")
	orgB := seedOrg(t, db, f, "SvcTenantB")
	projB := seedProject(t, db, f, orgB, "B")
	envB := seedEnvironment(t, db, f, projB, "production")
	_ = seedService(t, db, f, envB, "api")

	repo := store.NewServiceRepository()
	var got []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByEnvironment(ctx, q, orgA.ID, envB.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByEnvironment: %v", err)
	}
	if got == nil {
		t.Fatalf("ListByEnvironment(crossTenant) = nil; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d; want 0 (cross-tenant must not leak)", len(got))
	}
}

// TestServiceRepoListByEnvironmentEmptyEnvironment proves an
// environment with no services yields a non-nil empty slice and no
// error — agents iterate the response without a nil check.
func TestServiceRepoListByEnvironmentEmptyEnvironment(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcEmptyAcme")
	proj := seedProject(t, db, f, org, "P")
	env := seedEnvironment(t, db, f, proj, "production")

	repo := store.NewServiceRepository()
	var got []store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByEnvironment(ctx, q, org.ID, env.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByEnvironment: %v", err)
	}
	if got == nil {
		t.Fatalf("ListByEnvironment(emptyEnv) = nil; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d; want 0", len(got))
	}
}

// TestServiceReaderListEnvironmentServicesHappyPath proves the
// store-backed adapter composes the environment existence check + the
// service list inside one short-lived read transaction and projects
// the rows verbatim to the caller.
func TestServiceReaderListEnvironmentServicesHappyPath(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderSvcAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcAPI := seedService(t, db, f, env, "api")
	svcWeb := seedService(t, db, f, env, "web")

	reader, err := store.NewServiceReader(s)
	if err != nil {
		t.Fatalf("NewServiceReader: %v", err)
	}

	got, err := reader.ListEnvironmentServices(ctx, org.ID, env.ID)
	if err != nil {
		t.Fatalf("ListEnvironmentServices: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].ID != svcAPI.ID || got[1].ID != svcWeb.ID {
		t.Errorf("ordering = (%q, %q); want (%q, %q)", got[0].ID, got[1].ID, svcAPI.ID, svcWeb.ID)
	}
}

// TestServiceReaderRejectsCrossTenantEnvironmentID proves a
// cross-tenant environment_id reaches the environments.GetByID check
// inside the reader's transaction and surfaces as a typed
// apierr.NotFound — never as an empty list, which would invite an
// agent to believe the environment exists with no services. The error
// must not echo any cross-tenant identifier (env id, project id,
// service id, or slug).
func TestServiceReaderRejectsCrossTenantEnvironmentID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "SvcCrossA")
	orgB := seedOrg(t, db, f, "SvcCrossB")
	projB := seedProject(t, db, f, orgB, "B")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcB := seedService(t, db, f, envB, "api")

	reader, err := store.NewServiceReader(s)
	if err != nil {
		t.Fatalf("NewServiceReader: %v", err)
	}

	got, err := reader.ListEnvironmentServices(ctx, orgA.ID, envB.ID)
	if err == nil {
		t.Fatalf("ListEnvironmentServices(crossTenant) = %+v, nil; want apierr.NotFound", got)
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
	// envB.ID is the caller-supplied path parameter — it is allowed
	// to appear in the not-found message because the caller already
	// knew it. The leakable identifiers are the ones the caller did
	// NOT supply: the parent project id, the environment's slug, and
	// any sibling service id or slug.
	leaks := []string{projB.ID, envB.Slug, svcB.ID, svcB.Slug}
	msg := err.Error()
	for _, n := range leaks {
		if n != "" && strings.Contains(msg, n) {
			t.Errorf("error leaks cross-tenant identifier %q: %v", n, err)
		}
	}
}

// TestServiceReaderUnknownEnvironmentID proves an unknown
// environment_id (in the principal's own tenant) surfaces as the same
// deterministic apierr.NotFound — same shape as a cross-tenant id, so
// the response is not a "does this environment_id exist?" oracle.
func TestServiceReaderUnknownEnvironmentID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UnknownSvcAcme")

	reader, err := store.NewServiceReader(s)
	if err != nil {
		t.Fatalf("NewServiceReader: %v", err)
	}

	_, err = reader.ListEnvironmentServices(ctx, org.ID, "env_unknown")
	if err == nil {
		t.Fatalf("ListEnvironmentServices(unknown) returned no error; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestServiceReaderEmptyEnvironmentReturnsEmptyList proves an
// environment with no services yields a non-nil empty slice and a nil
// error — it must not be confused with the apierr.NotFound the
// existence check produces for a missing environment.
func TestServiceReaderEmptyEnvironmentReturnsEmptyList(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderEmptySvcAcme")
	proj := seedProject(t, db, f, org, "P")
	env := seedEnvironment(t, db, f, proj, "production")

	reader, err := store.NewServiceReader(s)
	if err != nil {
		t.Fatalf("NewServiceReader: %v", err)
	}

	got, err := reader.ListEnvironmentServices(ctx, org.ID, env.ID)
	if err != nil {
		t.Fatalf("ListEnvironmentServices: %v", err)
	}
	if got == nil {
		t.Fatalf("ListEnvironmentServices(emptyEnv) = nil; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d; want 0", len(got))
	}
}

// TestNewServiceReaderRejectsNilStore proves the constructor refuses a
// nil store rather than panicking on the first read — the API boot
// path can surface the wiring mistake as a typed startup failure.
func TestNewServiceReaderRejectsNilStore(t *testing.T) {
	t.Parallel()

	if _, err := store.NewServiceReader(nil); err == nil {
		t.Fatalf("NewServiceReader(nil) = nil; want non-nil error")
	}
}

// TestServiceRepoGetByIDHappyPath proves GetByID returns the persisted
// row verbatim under its own tenancy. Version starts at 1 on the fresh
// INSERT and the tenancy legs (organization_id, project_id,
// environment_id) match the seeded parents — the predicate is
// non-optional, so a missing or wrong organization_id would not match
// the row.
func TestServiceRepoGetByIDHappyPath(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcGetAcme")
	proj := seedProject(t, db, f, org, "Backend")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")

	repo := store.NewServiceRepository()
	var got store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		got, getErr = repo.GetByID(ctx, q, org.ID, svc.ID)
		return getErr
	}); err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != svc.ID {
		t.Errorf("ID = %q; want %q", got.ID, svc.ID)
	}
	if got.OrganizationID != org.ID || got.ProjectID != proj.ID || got.EnvironmentID != env.ID {
		t.Errorf("tenancy = (org=%q, proj=%q, env=%q); want (%q, %q, %q)",
			got.OrganizationID, got.ProjectID, got.EnvironmentID, org.ID, proj.ID, env.ID)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d; want 1 (a fresh INSERT)", got.Version)
	}
	if got.Kind == "" {
		t.Errorf("Kind is empty; want non-empty")
	}
}

// TestServiceRepoGetByIDIsTenantScoped proves a service id that belongs
// to another organization is reported as the same apierr.NotFound as a
// truly missing id, so the predicate is never an oracle revealing
// another tenant's service ids. The not-found payload must NOT echo any
// cross-tenant identifier (project id, environment id, environment
// slug, service slug).
func TestServiceRepoGetByIDIsTenantScoped(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "SvcGetTenantA")
	orgB := seedOrg(t, db, f, "SvcGetTenantB")
	projB := seedProject(t, db, f, orgB, "B")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcB := seedService(t, db, f, envB, "api")

	repo := store.NewServiceRepository()
	var err error
	if readErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err = repo.GetByID(ctx, q, orgA.ID, svcB.ID)
		return nil
	}); readErr != nil {
		t.Fatalf("Read: %v", readErr)
	}
	if err == nil {
		t.Fatalf("GetByID(crossTenant) returned no error; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
	leaks := []string{projB.ID, envB.ID, envB.Slug, svcB.Slug}
	msg := err.Error()
	for _, n := range leaks {
		if n != "" && strings.Contains(msg, n) {
			t.Errorf("error leaks cross-tenant identifier %q: %v", n, err)
		}
	}
}

// TestServiceReaderGetServiceHappyPath proves the store-backed adapter
// resolves an in-tenant service_id inside a short-lived read-only
// transaction and projects the row verbatim to the caller.
func TestServiceReaderGetServiceHappyPath(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderGetSvcAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")

	reader, err := store.NewServiceReader(s)
	if err != nil {
		t.Fatalf("NewServiceReader: %v", err)
	}

	got, err := reader.GetService(ctx, org.ID, svc.ID)
	if err != nil {
		t.Fatalf("GetService: %v", err)
	}
	if got.ID != svc.ID {
		t.Errorf("ID = %q; want %q", got.ID, svc.ID)
	}
	if got.OrganizationID != org.ID || got.ProjectID != proj.ID || got.EnvironmentID != env.ID {
		t.Errorf("tenancy = (org=%q, proj=%q, env=%q); want (%q, %q, %q)",
			got.OrganizationID, got.ProjectID, got.EnvironmentID, org.ID, proj.ID, env.ID)
	}
}

// TestServiceReaderGetServiceCrossTenantNotFound proves a service id
// that belongs to another organization surfaces as a typed
// apierr.NotFound through the reader's short-lived read-only
// transaction, never as another tenant's row. The error must not echo
// cross-tenant identifiers other than the caller-supplied id.
func TestServiceReaderGetServiceCrossTenantNotFound(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "ReaderGetSvcCrossA")
	orgB := seedOrg(t, db, f, "ReaderGetSvcCrossB")
	projB := seedProject(t, db, f, orgB, "B")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcB := seedService(t, db, f, envB, "api")

	reader, err := store.NewServiceReader(s)
	if err != nil {
		t.Fatalf("NewServiceReader: %v", err)
	}

	_, err = reader.GetService(ctx, orgA.ID, svcB.ID)
	if err == nil {
		t.Fatalf("GetService(crossTenant) = nil; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
	leaks := []string{projB.ID, envB.ID, envB.Slug, svcB.Slug}
	msg := err.Error()
	for _, n := range leaks {
		if n != "" && strings.Contains(msg, n) {
			t.Errorf("error leaks cross-tenant identifier %q: %v", n, err)
		}
	}
}

// TestServiceReaderGetServiceUnknownIDNotFound proves an unknown
// service id (in the principal's own tenant) surfaces as the same
// deterministic apierr.NotFound as a cross-tenant id — the response is
// not a "does this service_id exist?" oracle.
func TestServiceReaderGetServiceUnknownIDNotFound(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderGetSvcUnknownAcme")

	reader, err := store.NewServiceReader(s)
	if err != nil {
		t.Fatalf("NewServiceReader: %v", err)
	}

	_, err = reader.GetService(ctx, org.ID, "svc_unknown")
	if err == nil {
		t.Fatalf("GetService(unknown) = nil; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}
