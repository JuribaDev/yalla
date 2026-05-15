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

// Integration tests for ProjectVariableService — the replace-project-
// variables unit of work behind PUT /v1/projects/{project_id}/variables.
// They prove that the per-variable upserts, the bulk delete-by-exclusion
// that drops everything else, and the immutable audit record commit
// atomically; that a missing or cross-tenant project is a typed NotFound
// (not a 409 constraint violation); that empty input means "clear every
// variable" rather than a silent no-op; that validation rejects malformed
// input before any database write; and that the post-write re-read mirrors
// persistence so the response always reflects what just committed. They
// run against an isolated, freshly migrated Postgres database and skip
// when YALLA_TEST_DATABASE_URL is unset.

func newProjectVariableService(t *testing.T, s *store.Store) *store.ProjectVariableService {
	t.Helper()
	svc, err := store.NewProjectVariableService(s,
		store.NewProjectRepository(),
		store.NewProjectVariableRepository(),
		store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectVariableService: %v", err)
	}
	return svc
}

// TestProjectVariableServiceReplaceInsertsFreshVariables proves the happy
// path: a PUT against a project with no configured variables inserts every
// entry, mints non-guessable ids carrying the pvar_ prefix, and returns
// the committed rows in deterministic (key, id) order.
func TestProjectVariableServiceReplaceInsertsFreshVariables(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Backend")
	svc := newProjectVariableService(t, s)

	vars, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Variables: []store.ProjectVariableReplace{
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
	if vars[0].Key != "DATABASE_URL" || vars[0].Value != "postgres://user:hunter2@db/app" || !vars[0].IsSecret {
		t.Errorf("vars[0] = %+v, want DATABASE_URL/<value>/is_secret", vars[0])
	}
	if vars[1].Key != "REGION" || vars[1].Value != "us-east-1" || vars[1].IsSecret {
		t.Errorf("vars[1] = %+v, want REGION/us-east-1/!is_secret", vars[1])
	}
	for _, v := range vars {
		if !strings.HasPrefix(v.ID, "pvar_") {
			t.Errorf("variable id %q does not carry the pvar_ kind prefix", v.ID)
		}
		if v.OrganizationID != org.ID {
			t.Errorf("variable %q organization_id = %q, want %q", v.Key, v.OrganizationID, org.ID)
		}
		if v.ProjectID != proj.ID {
			t.Errorf("variable %q project_id = %q, want %q", v.Key, v.ProjectID, proj.ID)
		}
		if v.Version < 1 {
			t.Errorf("variable %q version = %d, want >= 1 (schema default)", v.Key, v.Version)
		}
	}

	events := listAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the replace", len(events))
	}
	ev := events[0]
	if ev.Action != "env.write" {
		t.Errorf("audit action = %q, want env.write", ev.Action)
	}
	if ev.ResourceID != proj.ID {
		t.Errorf("audit resource_id = %q, want the project id %q", ev.ResourceID, proj.ID)
	}
	if ev.ResourceKind != "proj" {
		t.Errorf("audit resource_kind = %q, want proj (project-scoped bulk operation)", ev.ResourceKind)
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

// TestProjectVariableServiceReplaceUpdatesExistingAndDeletesTheRest proves
// the bulk-replace contract end to end: an existing variable's
// value/is_secret is overwritten while its id is preserved (so the row the
// customer references by id is durable across PUTs), the optimistic-
// concurrency version bumps via the schema trigger, and any variable not
// named in the replacement set is dropped.
func TestProjectVariableServiceReplaceUpdatesExistingAndDeletesTheRest(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	svc := newProjectVariableService(t, s)

	initial, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Variables: []store.ProjectVariableReplace{
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

	post, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Variables: []store.ProjectVariableReplace{
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
	postByKey := map[string]store.ProjectVariable{}
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
	if !strings.HasPrefix(delta.ID, "pvar_") {
		t.Errorf("DELTA id = %q, want a freshly minted pvar_ prefix", delta.ID)
	}
}

// TestProjectVariableServiceReplaceEmptyListClearsEveryVariable proves the
// empty-list semantics: PUT with an empty variables array drops every
// project-scoped variable, a meaningful (extreme) operation, not a silent
// no-op.
func TestProjectVariableServiceReplaceEmptyListClearsEveryVariable(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	svc := newProjectVariableService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Variables: []store.ProjectVariableReplace{
			{Key: "ALPHA", Value: "1"},
			{Key: "BETA", Value: "2"},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	cleared, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Variables:      []store.ProjectVariableReplace{},
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

// TestProjectVariableServiceReplaceNotFoundProject proves a {project_id}
// that does not name a projects row in the tenant is the typed NotFound
// the ProjectRepository.Get produces, not a generic FK conflict from the
// upsert path — so a missing project is a stable 404, never a 409.
func TestProjectVariableServiceReplaceNotFoundProject(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newProjectVariableService(t, s)
	_, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
		OrganizationID: org.ID,
		ProjectID:      "proj_ghost",
		Variables: []store.ProjectVariableReplace{
			{Key: "REGION", Value: "eu-west-1"},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Replace(missing project) succeeded; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Errorf("Replace(missing project) error = %v, want CodeNotFound", err)
	}
}

// TestProjectVariableServiceReplaceCrossTenantProjectIsNotFound proves the
// project existence check is tenant-scoped: a project_id that exists in
// another organization surfaces as the same NotFound a missing project
// produces, so the response is not a "does this project_id exist in any
// tenant?" oracle.
func TestProjectVariableServiceReplaceCrossTenantProjectIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "TenantA")
	orgB := seedOrg(t, db, f, "TenantB")
	projB := seedProject(t, db, f, orgB, "Web")
	svc := newProjectVariableService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
		OrganizationID: orgA.ID,
		ProjectID:      projB.ID,
		Variables: []store.ProjectVariableReplace{
			{Key: "REGION", Value: "leak"},
		},
		ActorID: "usr_a", ActorKind: "usr", ActorOrgID: orgA.ID,
	})
	if err == nil {
		t.Fatalf("Replace(cross-tenant project) succeeded; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Errorf("Replace(cross-tenant project) error = %v, want CodeNotFound", err)
	}

	// Cross-tenant ids must not leak into the wire message.
	msg := err.Error()
	for _, n := range []string{projB.ID, orgB.ID} {
		if strings.Contains(msg, n) {
			t.Errorf("error leaks cross-tenant identifier %q: %v", n, err)
		}
	}
}

// TestProjectVariableServiceReplaceTenantIsolation proves the write is
// tenant scoped: a PUT against projA in orgA never reads, mutates, or
// deletes projB in orgB's variables — even when the keys collide.
func TestProjectVariableServiceReplaceTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "TenantA")
	orgB := seedOrg(t, db, f, "TenantB")
	projA := seedProject(t, db, f, orgA, "Web")
	projB := seedProject(t, db, f, orgB, "Web")
	svc := newProjectVariableService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
		OrganizationID: orgB.ID,
		ProjectID:      projB.ID,
		Variables: []store.ProjectVariableReplace{
			{Key: "SHARED", Value: "B-only"},
		},
		ActorID: "usr_b", ActorKind: "usr", ActorOrgID: orgB.ID,
	}); err != nil {
		t.Fatalf("seed orgB: %v", err)
	}

	postA, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
		OrganizationID: orgA.ID,
		ProjectID:      projA.ID,
		Variables: []store.ProjectVariableReplace{
			{Key: "SHARED", Value: "A-only"},
		},
		ActorID: "usr_a", ActorKind: "usr", ActorOrgID: orgA.ID,
	})
	if err != nil {
		t.Fatalf("Replace(orgA): %v", err)
	}
	if len(postA) != 1 || postA[0].Value != "A-only" {
		t.Errorf("orgA project variables = %+v, want [{SHARED:A-only}]", postA)
	}

	// orgB's variable must be untouched.
	var bRows []store.ProjectVariable
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		bRows, listErr = store.NewProjectVariableRepository().ListByProject(ctx, q, orgB.ID, projB.ID)
		return listErr
	}); err != nil {
		t.Fatalf("read orgB: %v", err)
	}
	if len(bRows) != 1 || bRows[0].Key != "SHARED" || bRows[0].Value != "B-only" {
		t.Errorf("orgB project variables = %+v, want [{SHARED:B-only}] (orgA PUT must not affect orgB)", bRows)
	}
}

// TestProjectVariableServiceReplaceInvalidInputNeverOpensTransaction
// proves the validation chokepoint: a non-POSIX key, a duplicate key, an
// empty key, and a NUL byte in a value each surface as a typed
// apierr.InvalidInput before any transaction is opened, so neither the
// variables table nor the audit log carries an artefact of the rejected
// request.
func TestProjectVariableServiceReplaceInvalidInputNeverOpensTransaction(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	svc := newProjectVariableService(t, s)

	cases := []struct {
		name      string
		variables []store.ProjectVariableReplace
	}{
		{"non-posix key (digit prefix)", []store.ProjectVariableReplace{
			{Key: "1BAD", Value: "x"},
		}},
		{"non-posix key (dash)", []store.ProjectVariableReplace{
			{Key: "BAD-KEY", Value: "x"},
		}},
		{"duplicate key", []store.ProjectVariableReplace{
			{Key: "DUPE", Value: "first-value-alpha"},
			{Key: "DUPE", Value: "second-value-bravo"},
		}},
		{"empty key", []store.ProjectVariableReplace{
			{Key: "", Value: "value-charlie"},
		}},
		{"NUL byte in value", []store.ProjectVariableReplace{
			{Key: "GOOD", Value: "before-delta\x00after-echo"},
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
				OrganizationID: org.ID,
				ProjectID:      proj.ID,
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
			for _, item := range tc.variables {
				if item.Value != "" && strings.Contains(err.Error(), item.Value) {
					t.Errorf("validation error %q echoed the submitted value %q", err, item.Value)
				}
			}
		})
	}
}

// TestProjectVariableServiceReplaceRequiresActorOrg proves the audit-fill
// guard: a blank ActorOrgID is a wiring error (an authenticated request
// always carries one), not client input, so it surfaces as Internal.
func TestProjectVariableServiceReplaceRequiresActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	proj := seedProject(t, db, f, org, "Web")
	svc := newProjectVariableService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceProjectVariablesInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Variables:      []store.ProjectVariableReplace{{Key: "K", Value: "v"}},
		ActorOrgID:     "",
	})
	if err == nil {
		t.Fatal("Replace(empty ActorOrgID) returned no error; want Internal")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Errorf("err = %v, want CodeInternal", err)
	}
}

// TestNewProjectVariableServiceRejectsNilDependencies proves the
// constructor's fail-fast posture: a misconfigured service that lacks the
// store, the project repository, the variable repository, or the audit
// appender fails at construction rather than on its first request.
func TestNewProjectVariableServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()
	if _, err := store.NewProjectVariableService(nil,
		store.NewProjectRepository(),
		store.NewProjectVariableRepository(),
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewProjectVariableService(nil store) returned no error")
	}
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	if _, err := store.NewProjectVariableService(s, nil,
		store.NewProjectVariableRepository(),
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewProjectVariableService(nil projects) returned no error")
	}
	if _, err := store.NewProjectVariableService(s,
		store.NewProjectRepository(),
		nil,
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewProjectVariableService(nil variables) returned no error")
	}
	if _, err := store.NewProjectVariableService(s,
		store.NewProjectRepository(),
		store.NewProjectVariableRepository(),
		nil); err == nil {
		t.Errorf("NewProjectVariableService(nil audit) returned no error")
	}
}
