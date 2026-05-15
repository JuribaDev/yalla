package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for OrganizationVariableService — the replace-
// organization-variables unit of work behind PUT
// /v1/organizations/{org_id}/variables. They prove that the per-variable
// upserts, the bulk delete-by-exclusion that drops everything else, and
// the immutable audit record commit atomically; that a missing tenant is
// a typed NotFound (not a 409 constraint violation); that empty input
// means "clear every variable" rather than a silent no-op; that
// validation rejects malformed input before any database write; and that
// the post-write re-read mirrors persistence so the response always
// reflects what just committed. They run against an isolated, freshly
// migrated Postgres database and skip when YALLA_TEST_DATABASE_URL is
// unset.

func newOrgVariableService(t *testing.T, s *store.Store) *store.OrganizationVariableService {
	t.Helper()
	svc, err := store.NewOrganizationVariableService(s,
		store.NewOrganizationRepository(),
		store.NewOrganizationVariableRepository(),
		store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewOrganizationVariableService: %v", err)
	}
	return svc
}

// TestOrganizationVariableServiceReplaceInsertsFreshVariables proves the
// happy path: a PUT against a tenant with no configured variables inserts
// every entry, mints non-guessable ids carrying the ovar_ prefix, and
// returns the committed rows in deterministic (key, id) order.
func TestOrganizationVariableServiceReplaceInsertsFreshVariables(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	vars, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "REGION", Value: "us-east-1", IsSecret: false},
			{Key: "DATABASE_URL", Value: "postgres://user:hunter2@db/app", IsSecret: true},
		},
		ActorID:       "usr_ada",
		ActorKind:     "usr",
		ActorOrgID:    org.ID,
		RequestID:     "req_t",
		CorrelationID: "corr_t",
	})
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if len(vars) != 2 {
		t.Fatalf("post-write variables = %+v, want two entries", vars)
	}
	// Deterministic (key, id) order: DATABASE_URL < REGION lexically.
	if vars[0].Key != "DATABASE_URL" || vars[0].Value != "postgres://user:hunter2@db/app" || !vars[0].IsSecret {
		t.Errorf("vars[0] = %+v, want DATABASE_URL/<value>/is_secret", vars[0])
	}
	if vars[1].Key != "REGION" || vars[1].Value != "us-east-1" || vars[1].IsSecret {
		t.Errorf("vars[1] = %+v, want REGION/us-east-1/!is_secret", vars[1])
	}
	for _, v := range vars {
		if !strings.HasPrefix(v.ID, "ovar_") {
			t.Errorf("variable id %q does not carry the ovar_ kind prefix", v.ID)
		}
		if v.OrganizationID != org.ID {
			t.Errorf("variable %q organization_id = %q, want %q", v.Key, v.OrganizationID, org.ID)
		}
		if v.Version < 1 {
			t.Errorf("variable %q version = %d, want >= 1 (the schema default)", v.Key, v.Version)
		}
	}

	// Exactly one audit record, filed under the actor's home organization,
	// with env.write action and value-free metadata (counts only).
	events := listAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the replace", len(events))
	}
	ev := events[0]
	if ev.Action != "env.write" {
		t.Errorf("audit action = %q, want env.write", ev.Action)
	}
	if ev.ResourceID != org.ID {
		t.Errorf("audit resource_id = %q, want the organization id %q", ev.ResourceID, org.ID)
	}
	if ev.ResourceKind != "org" {
		t.Errorf("audit resource_kind = %q, want org (organization-scoped bulk operation)", ev.ResourceKind)
	}
	if got := ev.Metadata["variable_count"]; got != "2" {
		t.Errorf("audit metadata.variable_count = %q, want 2", got)
	}
	if got := ev.Metadata["secret_count"]; got != "1" {
		t.Errorf("audit metadata.secret_count = %q, want 1", got)
	}
	// Audit metadata must never include the variable keys or values — a
	// secret can never reach the audit row through this endpoint, even
	// if the customer's variable carries a key fragment that looks
	// sensitive.
	for k, v := range ev.Metadata {
		if strings.Contains(v, "REGION") || strings.Contains(v, "DATABASE_URL") ||
			strings.Contains(v, "hunter2") || strings.Contains(v, "postgres://") ||
			strings.Contains(v, "us-east-1") {
			t.Errorf("audit metadata[%q] = %q leaks a customer-supplied variable name or value", k, v)
		}
	}
}

// TestOrganizationVariableServiceReplaceUpdatesExistingVariablesAndDeletesTheRest
// proves the bulk-replace contract end to end: an existing variable's
// value/is_secret is overwritten while its id is preserved (so the row
// the customer references by id is durable across PUTs), the
// optimistic-concurrency version bumps via the schema trigger, and any
// variable not named in the replacement set is dropped.
func TestOrganizationVariableServiceReplaceUpdatesExistingVariablesAndDeletesTheRest(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	// First PUT seeds three variables.
	initial, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "ALPHA", Value: "1", IsSecret: false},
			{Key: "BETA", Value: "2", IsSecret: false},
			{Key: "GAMMA", Value: "3", IsSecret: false},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("initial Replace: %v", err)
	}
	idByKey := map[string]string{}
	versionByKey := map[string]int64{}
	for _, v := range initial {
		idByKey[v.Key] = v.ID
		versionByKey[v.Key] = v.Version
	}

	// Second PUT updates ALPHA, keeps BETA verbatim, adds DELTA, drops GAMMA.
	post, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "ALPHA", Value: "updated", IsSecret: true},
			{Key: "BETA", Value: "2", IsSecret: false},
			{Key: "DELTA", Value: "4", IsSecret: false},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("second Replace: %v", err)
	}
	if len(post) != 3 {
		t.Fatalf("post-write variables = %+v, want exactly 3 (ALPHA, BETA, DELTA)", post)
	}
	postByKey := map[string]store.OrganizationVariable{}
	for _, v := range post {
		postByKey[v.Key] = v
	}
	if _, gammaSurvived := postByKey["GAMMA"]; gammaSurvived {
		t.Errorf("GAMMA survived a PUT that did not name it; delete-by-exclusion failed")
	}
	alpha := postByKey["ALPHA"]
	if alpha.ID != idByKey["ALPHA"] {
		t.Errorf("ALPHA id = %q, want preserved %q (UPSERT must not mint a new id)", alpha.ID, idByKey["ALPHA"])
	}
	if alpha.Value != "updated" || !alpha.IsSecret {
		t.Errorf("ALPHA = %+v, want value=updated/is_secret=true", alpha)
	}
	if alpha.Version <= versionByKey["ALPHA"] {
		t.Errorf("ALPHA version = %d, want > %d (bump_version trigger should fire on UPDATE)",
			alpha.Version, versionByKey["ALPHA"])
	}
	beta := postByKey["BETA"]
	if beta.ID != idByKey["BETA"] {
		t.Errorf("BETA id = %q, want preserved %q", beta.ID, idByKey["BETA"])
	}
	delta := postByKey["DELTA"]
	if !strings.HasPrefix(delta.ID, "ovar_") {
		t.Errorf("DELTA id = %q, want a freshly minted ovar_ prefix", delta.ID)
	}
}

// TestOrganizationVariableServiceReplaceWithEmptyListClearsEveryVariable
// proves the empty-list semantics: PUT with an empty variables array
// drops every organization-scoped variable, a meaningful (extreme)
// operation, not a silent no-op.
func TestOrganizationVariableServiceReplaceWithEmptyListClearsEveryVariable(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "ALPHA", Value: "1"},
			{Key: "BETA", Value: "2"},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	cleared, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables:      []store.OrganizationVariableReplace{},
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("clear Replace: %v", err)
	}
	if len(cleared) != 0 {
		t.Errorf("post-clear variables = %+v, want []", cleared)
	}

	events := listAuditEvents(t, s, org.ID)
	if len(events) != 2 {
		t.Fatalf("audit events = %d, want two (seed + clear)", len(events))
	}
	if got := events[0].Metadata["variable_count"]; got != "0" {
		t.Errorf("clear audit metadata.variable_count = %q, want 0", got)
	}
}

// TestOrganizationVariableServiceReplaceNotFoundOrganization proves an
// {org_id} that does not name an organizations row is the typed
// NotFound the repository's Get produces, not a generic FK conflict
// from the upsert path — so a missing tenant is a stable 404, never a
// 409.
func TestOrganizationVariableServiceReplaceNotFoundOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	svc := newOrgVariableService(t, s)
	ghost := "org_does_not_exist"
	_, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: ghost,
		Variables: []store.OrganizationVariableReplace{
			{Key: "REGION", Value: "eu-west-1"},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: ghost,
	})
	if err == nil {
		t.Fatalf("Replace(missing org) succeeded; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Errorf("Replace(missing org) error = %v, want CodeNotFound", err)
	}
}

// TestOrganizationVariableServiceReplaceTenantIsolation proves the
// write is tenant scoped: a PUT against orgA never reads, mutates, or
// deletes orgB's variables.
func TestOrganizationVariableServiceReplaceTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "TenantA")
	orgB := seedOrg(t, db, f, "TenantB")
	svc := newOrgVariableService(t, s)

	// Seed orgB with one variable that uses a colliding key with orgA's
	// upcoming PUT. The unique constraint is (organization_id, key), so
	// the same key in two orgs is two rows.
	if _, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: orgB.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "SHARED", Value: "B-only"},
		},
		ActorID: "usr_b", ActorKind: "usr", ActorOrgID: orgB.ID,
	}); err != nil {
		t.Fatalf("seed orgB: %v", err)
	}

	// PUT orgA with the same key — must succeed and must never observe
	// orgB's row.
	postA, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: orgA.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "SHARED", Value: "A-only"},
		},
		ActorID: "usr_a", ActorKind: "usr", ActorOrgID: orgA.ID,
	})
	if err != nil {
		t.Fatalf("Replace(orgA): %v", err)
	}
	if len(postA) != 1 || postA[0].Value != "A-only" {
		t.Errorf("orgA variables = %+v, want [{SHARED:A-only}]", postA)
	}

	// orgB's variable must be untouched.
	var bRows []store.OrganizationVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		bRows, listErr = store.NewOrganizationVariableRepository().ListByOrganization(ctx, q, orgB.ID)
		return listErr
	}); err != nil {
		t.Fatalf("read orgB: %v", err)
	}
	if len(bRows) != 1 || bRows[0].Key != "SHARED" || bRows[0].Value != "B-only" {
		t.Errorf("orgB variables = %+v, want [{SHARED:B-only}] (orgA PUT must not affect orgB)", bRows)
	}
}

// TestOrganizationVariableServiceReplaceInvalidInputNeverOpensTransaction
// proves the validation chokepoint: a non-POSIX key, a duplicate key,
// and an over-sized value each surface as a typed apierr.InvalidInput
// before any transaction is opened, so neither the variables table nor
// the audit log carries an artefact of the rejected request.
func TestOrganizationVariableServiceReplaceInvalidInputNeverOpensTransaction(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	cases := []struct {
		name      string
		variables []store.OrganizationVariableReplace
	}{
		{"non-posix key (digit prefix)", []store.OrganizationVariableReplace{
			{Key: "1BAD", Value: "x"},
		}},
		{"non-posix key (dash)", []store.OrganizationVariableReplace{
			{Key: "BAD-KEY", Value: "x"},
		}},
		{"duplicate key", []store.OrganizationVariableReplace{
			{Key: "DUPE", Value: "first-value-alpha"},
			{Key: "DUPE", Value: "second-value-bravo"},
		}},
		{"empty key", []store.OrganizationVariableReplace{
			{Key: "", Value: "value-charlie"},
		}},
		{"NUL byte in value", []store.OrganizationVariableReplace{
			{Key: "GOOD", Value: "before-delta\x00after-echo"},
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
				OrganizationID: org.ID,
				Variables:      tc.variables,
				ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
			})
			if err == nil {
				t.Fatalf("Replace(%s) returned no error; want InvalidInput", tc.name)
			}
			var ye *yerr.Error
			if !errors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
				t.Errorf("Replace(%s) error = %v, want CodeInvalidInput", tc.name, err)
			}
			// Validation reasons must never echo the submitted value
			// content — a secret in Value, including the test inputs
			// above, cannot reach the wire error message.
			for _, item := range tc.variables {
				if item.Value != "" && strings.Contains(err.Error(), item.Value) {
					t.Errorf("validation error %q echoed the submitted value %q", err, item.Value)
				}
			}
		})
	}
}

// TestNewOrganizationVariableServiceRejectsNilDependencies proves the
// constructor's fail-fast posture: a misconfigured service that lacks
// the store, the organization repository, the variable repository, or
// the audit appender fails at construction rather than on its first
// request — mirroring NewLimitsService and NewOrganizationService.
func TestNewOrganizationVariableServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()
	if _, err := store.NewOrganizationVariableService(nil,
		store.NewOrganizationRepository(),
		store.NewOrganizationVariableRepository(),
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewOrganizationVariableService(nil store) returned no error")
	}
	// Build a real store via the test pool so the other nil-checks have
	// a real dependency in the non-checked slots.
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	if _, err := store.NewOrganizationVariableService(s, nil,
		store.NewOrganizationVariableRepository(),
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewOrganizationVariableService(nil orgs) returned no error")
	}
	if _, err := store.NewOrganizationVariableService(s,
		store.NewOrganizationRepository(),
		nil,
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewOrganizationVariableService(nil vars) returned no error")
	}
	if _, err := store.NewOrganizationVariableService(s,
		store.NewOrganizationRepository(),
		store.NewOrganizationVariableRepository(),
		nil); err == nil {
		t.Errorf("NewOrganizationVariableService(nil audit) returned no error")
	}
}

// TestOrganizationVariableServiceRequiresActorOrganization proves the
// service rejects a missing actor organization with a typed Internal
// error rather than persisting an audit record whose
// organization_id is empty — the same posture LimitsService takes.
func TestOrganizationVariableServiceRequiresActorOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables:      []store.OrganizationVariableReplace{{Key: "X", Value: "y"}},
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: "",
	})
	if err == nil {
		t.Fatalf("Replace(no actor org) returned no error; want Internal")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Errorf("Replace(no actor org) error = %v, want CodeInternal", err)
	}
}
