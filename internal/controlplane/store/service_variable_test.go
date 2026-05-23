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

// Integration tests for the ServiceVariableRepository and
// ServiceVariableReader — the persistence half of the service-scoped
// variables surface. They run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset. The
// tests prove tenant scoping, deterministic ordering, service-existence
// checks at the reader, and that a cross-tenant service_id never
// reveals another tenant's variables.

// revealServiceVariableValue returns the literal plaintext value of v.
// For non-secret rows it is just v.Value. For is_secret rows the literal
// value lives in v.SecretCiphertext (the schema CHECK forces Value=""
// for secret rows after BE-0342), so we return the ciphertext bytes
// verbatim — every test in this package wires the Plaintext provider,
// for which Seal(plaintext) is plaintext, so the equivalence holds
// without dragging a live provider through every assertion.
func revealServiceVariableValue(v store.ServiceVariable) string {
	if v.IsSecret {
		return string(v.SecretCiphertext)
	}
	return v.Value
}

// seedServiceVariable inserts one service_variables row through the
// test pool. It builds the schema-required column set (id,
// organization_id, service_id, key, value, is_secret) plus — for
// is_secret = true rows — the encryption-at-rest tuple migration
// 0032's CHECK constraint requires. The bump_version and
// set_updated_at triggers from migrations 0011 / 0021 populate the
// rest.
//
// For is_secret = true rows the helper stands in the secrets.Plaintext
// provider's wire identifiers (plaintext-v1 / plaintext) so test
// fixtures stay self-contained (no live provider dependency) and the
// HTTP / audit redaction contract still holds — the wire layer never
// projects the on-disk bytes for secret rows, so revealing the literal
// here is only visible to test assertions.
func seedServiceVariable(t *testing.T, db *testutil.DB, id, organizationID, serviceID, key, value string, isSecret bool) {
	t.Helper()
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
		`INSERT INTO service_variables (id, organization_id, service_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, organizationID, serviceID, key, plainValue, isSecret, provider, keyID, ciphertext); err != nil {
		t.Fatalf("seed service_variables: %v", err)
	}
}

// TestServiceVariableRepoListByServiceReturnsDeterministicOrdering
// proves ListByService yields rows in the documented (key ASC, id ASC)
// order. The ordering is part of the public contract: a given set of
// rows must render the same wire payload across calls so agents can
// checksum the response.
func TestServiceVariableRepoListByServiceReturnsDeterministicOrdering(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcVarsAcme")
	proj := seedProject(t, db, f, org, "Backend")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")

	// Seed in deliberately unsorted insertion order. The expected final
	// order is: DATABASE_URL first, REGION second (key ASC).
	seedServiceVariable(t, db, "svar_region", org.ID, svc.ID, "REGION", "us-east-1", false)
	seedServiceVariable(t, db, "svar_db", org.ID, svc.ID, "DATABASE_URL", "postgres://user:hunter2@db.internal/yalla", true)

	repo := store.NewServiceVariableRepository()
	var got []store.ServiceVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByService(ctx, q, org.ID, svc.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByService: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (got %+v)", len(got), got)
	}
	if got[0].ID != "svar_db" || got[0].Key != "DATABASE_URL" || !got[0].IsSecret {
		t.Errorf("got[0] = %+v; want (svar_db, DATABASE_URL, is_secret=true)", got[0])
	}
	if got[1].ID != "svar_region" || got[1].Key != "REGION" || got[1].IsSecret {
		t.Errorf("got[1] = %+v; want (svar_region, REGION, is_secret=false)", got[1])
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
	// For is_secret = true rows the on-disk shape after BE-0342 forces
	// Value="" and stores the literal in SecretCiphertext (the
	// seedServiceVariable helper stands in the plaintext provider's wire
	// identifiers), so the assertion goes through revealServiceVariableValue.
	if revealServiceVariableValue(got[0]) != "postgres://user:hunter2@db.internal/yalla" {
		t.Errorf("got[0] value should round-trip the literal; got %q", revealServiceVariableValue(got[0]))
	}
}

// TestServiceVariableRepoListByServiceIsTenantScoped seeds two
// organizations with overlapping-looking variable rows on each
// tenant's service. A read for org A's service must never observe a
// variable filed under org B's service. This is the load-bearing
// tenant-isolation property of the repository.
func TestServiceVariableRepoListByServiceIsTenantScoped(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "SvcVarTenantA")
	orgB := seedOrg(t, db, f, "SvcVarTenantB")
	projA := seedProject(t, db, f, orgA, "Backend")
	projB := seedProject(t, db, f, orgB, "Backend")
	envA := seedEnvironment(t, db, f, projA, "Prod")
	envB := seedEnvironment(t, db, f, projB, "Prod")
	svcA := seedService(t, db, f, envA, "API")
	svcB := seedService(t, db, f, envB, "API")

	seedServiceVariable(t, db, "svar_a", orgA.ID, svcA.ID, "DATABASE_URL", "tenantA", true)
	seedServiceVariable(t, db, "svar_b", orgB.ID, svcB.ID, "DATABASE_URL", "tenantB", true)

	repo := store.NewServiceVariableRepository()
	var listA []store.ServiceVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		listA, listErr = repo.ListByService(ctx, q, orgA.ID, svcA.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByService(A): %v", err)
	}
	if len(listA) != 1 || listA[0].ID != "svar_a" {
		t.Fatalf("listA = %+v; want exactly svar_a", listA)
	}

	// A cross-tenant attempt — org A asking for org B's serviceID — must
	// return zero rows. Same the other way around.
	var listCross []store.ServiceVariable
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

// TestServiceVariableRepoListByServiceEmptyService proves a real
// service without variables returns the deterministic empty slice —
// not nil — so HTTP projections can iterate without a nil check.
func TestServiceVariableRepoListByServiceEmptyService(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EmptySvcVarsAcme")
	proj := seedProject(t, db, f, org, "Empty")
	env := seedEnvironment(t, db, f, proj, "Empty")
	svc := seedService(t, db, f, env, "Empty")

	repo := store.NewServiceVariableRepository()
	var got []store.ServiceVariable
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

// TestServiceVariableRepoListByServiceSiblingServiceIsolation proves
// two services in the SAME environment under the SAME tenant do not
// see each other's variables. Same key on each service is two
// independent rows by design.
func TestServiceVariableRepoListByServiceSiblingServiceIsolation(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SiblingSvcVarsAcme")
	proj := seedProject(t, db, f, org, "Backend")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svcA := seedService(t, db, f, env, "ServiceA")
	svcB := seedService(t, db, f, env, "ServiceB")

	seedServiceVariable(t, db, "svar_alpha", org.ID, svcA.ID, "DATABASE_URL", "alpha-secret", true)
	seedServiceVariable(t, db, "svar_beta", org.ID, svcB.ID, "DATABASE_URL", "beta-secret", true)

	repo := store.NewServiceVariableRepository()
	var got []store.ServiceVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		got, listErr = repo.ListByService(ctx, q, org.ID, svcA.ID)
		return listErr
	}); err != nil {
		t.Fatalf("ListByService(svcA): %v", err)
	}
	if len(got) != 1 || got[0].ID != "svar_alpha" {
		t.Fatalf("svcA listing = %+v; want exactly svar_alpha", got)
	}
}

// TestServiceVariableReaderListServiceVariablesHappyPath proves the
// store-backed adapter composes the service existence check + variable
// list inside one short-lived read transaction and projects the rows
// verbatim to the caller.
func TestServiceVariableReaderListServiceVariablesHappyPath(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderSvcVarsAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "API")
	seedServiceVariable(t, db, "svar_one", org.ID, svc.ID, "REGION", "us-east-1", false)
	seedServiceVariable(t, db, "svar_two", org.ID, svc.ID, "DATABASE_URL", "secret", true)

	reader, err := store.NewServiceVariableReader(s)
	if err != nil {
		t.Fatalf("NewServiceVariableReader: %v", err)
	}

	got, err := reader.ListServiceVariables(ctx, org.ID, svc.ID)
	if err != nil {
		t.Fatalf("ListServiceVariables: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Key != "DATABASE_URL" || got[1].Key != "REGION" {
		t.Errorf("ordering = (%q, %q); want (DATABASE_URL, REGION)", got[0].Key, got[1].Key)
	}
}

// TestServiceVariableReaderRejectsCrossTenantServiceID proves a
// cross-tenant service_id reaches the services.GetByID check inside
// the reader's transaction and surfaces as a typed apierr.NotFound —
// never as an empty list, which would invite an agent to believe the
// service exists with no variables.
func TestServiceVariableReaderRejectsCrossTenantServiceID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "SvcVarCrossA")
	orgB := seedOrg(t, db, f, "SvcVarCrossB")
	projB := seedProject(t, db, f, orgB, "B")
	envB := seedEnvironment(t, db, f, projB, "Prod")
	svcB := seedService(t, db, f, envB, "API")
	seedServiceVariable(t, db, "svar_leak", orgB.ID, svcB.ID, "API_TOKEN", "hunter2", true)

	reader, err := store.NewServiceVariableReader(s)
	if err != nil {
		t.Fatalf("NewServiceVariableReader: %v", err)
	}

	got, err := reader.ListServiceVariables(ctx, orgA.ID, svcB.ID)
	if err == nil {
		t.Fatalf("ListServiceVariables(crossTenant) = %+v, nil; want apierr.NotFound", got)
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
	// The svar_leak row from org B must not appear in the error string —
	// neither the row id, the key, nor any fragment of the secret value.
	leaks := []string{"svar_leak", "API_TOKEN", "hunter2"}
	msg := err.Error()
	for _, n := range leaks {
		if strings.Contains(msg, n) {
			t.Errorf("error leaks cross-tenant identifier %q: %v", n, err)
		}
	}
}

// TestServiceVariableReaderUnknownServiceID proves an unknown
// service_id (in the principal's own tenant) surfaces as the same
// deterministic apierr.NotFound — same shape as a cross-tenant id, so
// the response is not a "does this service_id exist?" oracle.
func TestServiceVariableReaderUnknownServiceID(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UnknownSvcVarsAcme")

	reader, err := store.NewServiceVariableReader(s)
	if err != nil {
		t.Fatalf("NewServiceVariableReader: %v", err)
	}

	_, err = reader.ListServiceVariables(ctx, org.ID, "svc_unknown")
	if err == nil {
		t.Fatalf("ListServiceVariables(unknown) returned no error; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestNewServiceVariableReaderRejectsNilStore proves the constructor
// refuses a nil *Store so a misconfigured adapter cannot reach a
// request — it fails at construction, not at first use.
func TestNewServiceVariableReaderRejectsNilStore(t *testing.T) {
	t.Parallel()
	if _, err := store.NewServiceVariableReader(nil); err == nil {
		t.Error("NewServiceVariableReader(nil) returned no error; want a nil-store error")
	}
}
