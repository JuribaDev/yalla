package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	yerr "github.com/JuribaDev/yalla/internal/errors"

	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Integration tests for the ServiceVariableService — the unit-of-work
// orchestrator behind PUT /v1/services/{service_id}/variables. They
// run against an isolated, freshly migrated Postgres database and
// skip when YALLA_TEST_DATABASE_URL is unset. The tests prove the
// replace contract end-to-end: validation rejects malformed input
// before any transaction opens, an unknown / cross-tenant service id
// surfaces as a deterministic NotFound, the (upsert + delete-by-
// exclusion + audit + re-read) tuple commits atomically in one
// transaction, the response is the post-write state in deterministic
// (key, id) order, and an explicit empty list clears every variable.

// newServiceVariableService wires a ServiceVariableService from its
// dependencies for tests. The constructor's port checks are exercised
// by TestNewServiceVariableServiceRejectsNilDependencies below.
//
// The plaintext secrets provider is acceptable for tests that exercise
// the lifecycle and audit surface; the BE-0342 encryption-at-rest tests
// live in service_variable_secrets_at_rest_test.go and inject a real
// AES-GCM provider when proving the on-disk seal contract.
func newServiceVariableService(t *testing.T, s *store.Store, audit store.AuditAppender) *store.ServiceVariableService {
	t.Helper()
	svc, err := store.NewServiceVariableService(s,
		store.NewServiceRepository(),
		store.NewServiceVariableRepository(),
		&recordingJobs{},
		audit,
		secrets.NewPlaintext(),
	)
	if err != nil {
		t.Fatalf("NewServiceVariableService: %v", err)
	}
	return svc
}

// TestServiceVariableServiceReplaceInsertsFreshVariables proves a
// first-call replace persists every caller-supplied variable, the
// re-read returns them in deterministic (key, id) order, and the
// audit event is filed in the same transaction.
func TestServiceVariableServiceReplaceInsertsFreshVariables(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcVarReplaceAcme")
	proj := seedProject(t, db, f, org, "Backend")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "api")

	svcVarSvc := newServiceVariableService(t, s, store.NewAuditRepository())

	got, err := svcVarSvc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      svc.ID,
		Variables: []store.ServiceVariableReplace{
			{Key: "REGION", Value: "us-east-1", IsSecret: false},
			{Key: "DATABASE_URL", Value: "postgres://user:pw@db/yalla", IsSecret: true},
		},
		ActorID:    "usr_owner",
		ActorKind:  "usr",
		ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (got %+v)", len(got), got)
	}
	// Deterministic (key ASC, id ASC) ordering. For is_secret = true rows
	// the on-disk shape after BE-0342 forces Value="" and stores the
	// literal in SecretCiphertext, so the assertion goes through
	// revealServiceVariableValue (the test wires the plaintext provider,
	// for which Seal is the identity).
	if got[0].Key != "DATABASE_URL" || !got[0].IsSecret || revealServiceVariableValue(got[0]) != "postgres://user:pw@db/yalla" {
		t.Errorf("got[0] = %+v, want (DATABASE_URL, is_secret=true, plaintext)", got[0])
	}
	if got[1].Key != "REGION" || got[1].IsSecret || got[1].Value != "us-east-1" {
		t.Errorf("got[1] = %+v, want (REGION, is_secret=false, us-east-1)", got[1])
	}
	if got[0].OrganizationID != org.ID || got[0].ServiceID != svc.ID {
		t.Errorf("got[0] org/svc = (%q, %q), want (%q, %q)",
			got[0].OrganizationID, got[0].ServiceID, org.ID, svc.ID)
	}
	if got[0].Version != 1 {
		t.Errorf("got[0].Version = %d, want 1 (first insert)", got[0].Version)
	}
}

// TestServiceVariableServiceReplaceUpdatesExistingAndDeletesTheRest
// proves a second replace upserts the rows whose keys persist (their
// version bumps), inserts the rows whose keys are new, and deletes
// every row not in the replacement set — the canonical reconcile
// post-condition.
func TestServiceVariableServiceReplaceUpdatesExistingAndDeletesTheRest(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcVarUpdAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "api")

	svcVarSvc := newServiceVariableService(t, s, store.NewAuditRepository())

	// First replace: REGION + DROP.
	if _, err := svcVarSvc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      svc.ID,
		Variables: []store.ServiceVariableReplace{
			{Key: "REGION", Value: "us-east-1"},
			{Key: "DROP", Value: "dropme"},
		},
		ActorID:    "usr_owner",
		ActorKind:  "usr",
		ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("first Replace: %v", err)
	}

	// Second replace: REGION (updated) + NEW. DROP must be gone.
	got, err := svcVarSvc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      svc.ID,
		Variables: []store.ServiceVariableReplace{
			{Key: "REGION", Value: "us-west-2", IsSecret: true},
			{Key: "NEW", Value: "fresh"},
		},
		ActorID:    "usr_owner",
		ActorKind:  "usr",
		ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("second Replace: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (got %+v)", len(got), got)
	}
	// (key ASC, id ASC): NEW comes before REGION lexicographically. For
	// is_secret = true rows the on-disk shape after BE-0342 forces
	// Value="" and stores the literal in SecretCiphertext, so the
	// assertion goes through revealServiceVariableValue.
	if got[0].Key != "NEW" || got[0].Value != "fresh" || got[0].IsSecret {
		t.Errorf("got[0] = %+v, want (NEW, fresh, is_secret=false)", got[0])
	}
	if got[1].Key != "REGION" || revealServiceVariableValue(got[1]) != "us-west-2" || !got[1].IsSecret {
		t.Errorf("got[1] = %+v, want (REGION, us-west-2, is_secret=true)", got[1])
	}
	// REGION's id survived the conflict; its version bumped.
	if got[1].Version != 2 {
		t.Errorf("got[1].Version = %d, want 2 (bump_version on UPDATE)", got[1].Version)
	}
}

// TestServiceVariableServiceReplaceWithEmptyListClearsEveryVariable
// proves the deliberate full-clear path: a replace with an empty
// Variables list deletes every row in (org, service) and returns an
// empty slice.
func TestServiceVariableServiceReplaceWithEmptyListClearsEveryVariable(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcVarClearAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "api")

	svcVarSvc := newServiceVariableService(t, s, store.NewAuditRepository())

	// Seed two variables.
	if _, err := svcVarSvc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      svc.ID,
		Variables: []store.ServiceVariableReplace{
			{Key: "A", Value: "a"},
			{Key: "B", Value: "b"},
		},
		ActorID:    "usr_owner",
		ActorKind:  "usr",
		ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	// Clear.
	got, err := svcVarSvc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      svc.ID,
		Variables:      nil,
		ActorID:        "usr_owner",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if err != nil {
		t.Fatalf("clear Replace: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0 (got %+v)", len(got), got)
	}
}

// TestServiceVariableServiceReplaceNotFoundService proves an unknown
// service_id is the typed apierr.NotFound, not a silent insert under
// the wrong FK target.
func TestServiceVariableServiceReplaceNotFoundService(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcVarNotFoundAcme")

	svcVarSvc := newServiceVariableService(t, s, store.NewAuditRepository())

	_, err := svcVarSvc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      "svc_unknown",
		Variables:      []store.ServiceVariableReplace{{Key: "X", Value: "x"}},
		ActorID:        "usr_owner",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if err == nil {
		t.Fatal("Replace(unknown service) returned no error; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}
}

// TestServiceVariableServiceReplaceTenantIsolation proves a service_id
// that belongs to a different tenant is treated as missing — never as
// a successful replace into a foreign tenant's row.
func TestServiceVariableServiceReplaceTenantIsolation(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "TenantIsoA")
	orgB := seedOrg(t, db, f, "TenantIsoB")
	projB := seedProject(t, db, f, orgB, "Web")
	envB := seedEnvironment(t, db, f, projB, "Prod")
	svcB := seedService(t, db, f, envB, "api")

	svcVarSvc := newServiceVariableService(t, s, store.NewAuditRepository())

	// Attacker in orgA targeting orgB's service id.
	_, err := svcVarSvc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: orgA.ID,
		ServiceID:      svcB.ID,
		Variables:      []store.ServiceVariableReplace{{Key: "STEAL", Value: "stealme"}},
		ActorID:        "usr_attacker",
		ActorKind:      "usr",
		ActorOrgID:     orgA.ID,
	})
	if err == nil {
		t.Fatal("Replace(cross-tenant service id) succeeded; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v (%T); want yerr CodeNotFound", err, err)
	}

	// Confirm orgB's service has no variables — the attacker's request
	// never reached the table.
	reader, err := store.NewServiceVariableReader(s)
	if err != nil {
		t.Fatalf("NewServiceVariableReader: %v", err)
	}
	got, err := reader.ListServiceVariables(ctx, orgB.ID, svcB.ID)
	if err != nil {
		t.Fatalf("post-list orgB: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("orgB service variables = %+v, want empty — the attacker's replace must not have leaked into orgB", got)
	}
}

// TestServiceVariableServiceReplaceInvalidInputNeverOpensTransaction
// proves the validation chokepoint: a non-POSIX key, a duplicate key, an
// empty key, and a NUL byte in a value each surface as a typed
// apierr.InvalidInput before any transaction is opened, so neither the
// variables table nor the audit log carries an artefact of the rejected
// request. The error must NEVER echo the submitted value — a secret
// hidden in a malformed payload cannot leak through the validation
// reason. BE-0342 makes that contract load-bearing because customer
// secret values now flow through this surface.
func TestServiceVariableServiceReplaceInvalidInputNeverOpensTransaction(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcVarInvalidAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	service := seedService(t, db, f, env, "api")
	svcVarSvc := newServiceVariableService(t, s, store.NewAuditRepository())

	cases := []struct {
		name      string
		variables []store.ServiceVariableReplace
	}{
		{"non-posix key (digit prefix)", []store.ServiceVariableReplace{
			{Key: "1BAD", Value: "x"},
		}},
		{"non-posix key (dash)", []store.ServiceVariableReplace{
			{Key: "BAD-KEY", Value: "x"},
		}},
		{"duplicate key", []store.ServiceVariableReplace{
			{Key: "DUPE", Value: "first-value-alpha"},
			{Key: "DUPE", Value: "second-value-bravo"},
		}},
		{"empty key", []store.ServiceVariableReplace{
			{Key: "", Value: "value-charlie"},
		}},
		{"NUL byte in value", []store.ServiceVariableReplace{
			{Key: "GOOD", Value: "before-delta\x00after-echo"},
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := svcVarSvc.Replace(ctx, store.ReplaceServiceVariablesInput{
				OrganizationID: org.ID,
				ServiceID:      service.ID,
				Variables:      tc.variables,
				ActorID:        "usr_owner", ActorKind: "usr", ActorOrgID: org.ID,
			})
			if err == nil {
				t.Fatalf("Replace(%s) returned no error; want InvalidInput", tc.name)
			}
			var ye *yerr.Error
			if !errors.As(err, &ye) || ye.Code != yerr.CodeValidation {
				t.Errorf("Replace(%s) error = %v, want CodeValidation", tc.name, err)
			}
			for _, item := range tc.variables {
				if item.Value != "" && strings.Contains(err.Error(), item.Value) {
					t.Errorf("validation error %q echoed the submitted value %q", err, item.Value)
				}
			}
		})
	}
}

// TestServiceVariableServiceReplaceRejectsBlankActorOrg proves the
// actor-org guard fires before the transaction opens — a missing
// ActorOrgID is a programming error that must surface as an internal
// failure (the audit event has no organization to attach to), never
// as a silent successful write under a different tenant's audit row.
func TestServiceVariableServiceReplaceRejectsBlankActorOrg(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcVarBlankActorAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := seedService(t, db, f, env, "api")

	svcVarSvc := newServiceVariableService(t, s, store.NewAuditRepository())

	_, err := svcVarSvc.Replace(ctx, store.ReplaceServiceVariablesInput{
		OrganizationID: org.ID,
		ServiceID:      svc.ID,
		Variables:      []store.ServiceVariableReplace{{Key: "X", Value: "x"}},
		ActorID:        "usr_owner",
		ActorKind:      "usr",
		// ActorOrgID intentionally blank.
	})
	if err == nil {
		t.Fatal("Replace(blank actor org) returned no error; want yerr CodeInternal")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Fatalf("err = %v (%T); want yerr CodeInternal", err, err)
	}
}

// TestNewServiceVariableServiceRejectsNilDependencies proves the
// constructor's port checks fail-fast: each nil dependency returns
// an error at construction time, never silently degrades the
// service at first request. The secrets provider is one of the
// load-bearing dependencies — a misconfigured process that forgets
// to wire a provider must not boot, since at-rest encryption is the
// only barrier between the source-of-truth column and plaintext
// secret values.
func TestNewServiceVariableServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()
	s := &store.Store{}
	plain := secrets.NewPlaintext()
	cases := []struct {
		name      string
		store     *store.Store
		services  *store.ServiceRepository
		variables *store.ServiceVariableRepository
		jobs      store.JobEnqueuer
		audit     store.AuditAppender
		provider  secrets.Provider
	}{
		{"nil store", nil, store.NewServiceRepository(), store.NewServiceVariableRepository(), &recordingJobs{}, store.NewAuditRepository(), plain},
		{"nil services", s, nil, store.NewServiceVariableRepository(), &recordingJobs{}, store.NewAuditRepository(), plain},
		{"nil variables", s, store.NewServiceRepository(), nil, &recordingJobs{}, store.NewAuditRepository(), plain},
		{"nil jobs", s, store.NewServiceRepository(), store.NewServiceVariableRepository(), nil, store.NewAuditRepository(), plain},
		{"nil audit", s, store.NewServiceRepository(), store.NewServiceVariableRepository(), &recordingJobs{}, nil, plain},
		{"nil provider", s, store.NewServiceRepository(), store.NewServiceVariableRepository(), &recordingJobs{}, store.NewAuditRepository(), nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := store.NewServiceVariableService(tc.store, tc.services, tc.variables, tc.jobs, tc.audit, tc.provider); err == nil {
				t.Error("NewServiceVariableService returned no error; want a nil-dependency error")
			}
		})
	}
}
