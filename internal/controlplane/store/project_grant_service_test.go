package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// violationFor scans the FieldViolations attached to err for one whose
// Field matches field exactly. Tests assert against this rather than
// err.Error() so they pin the structured field path the wire renders.
func violationFor(err error, field string) (apierr.FieldViolation, bool) {
	vv, ok := apierr.ViolationsOf(err)
	if !ok {
		return apierr.FieldViolation{}, false
	}
	for _, v := range vv {
		if v.Field == field {
			return v, true
		}
	}
	return apierr.FieldViolation{}, false
}

// Integration tests for ProjectGrantService — the replace-project-grants
// unit of work behind PUT /v1/projects/{project_id}/grants. They prove
// that the per-grant upserts, the bulk delete-by-exclusion that drops
// everything else, and the immutable audit record commit atomically; that
// a missing project is a typed NotFound (not a 409 constraint violation);
// that empty input means "clear every grant" rather than a silent no-op;
// that validation rejects malformed input before any database write; that
// the post-write re-read mirrors persistence so the response always
// reflects what just committed; and that a cross-tenant project_id can
// never reveal another tenant's grants. They run against an isolated,
// freshly migrated Postgres database and skip when YALLA_TEST_DATABASE_URL
// is unset.

func newProjectGrantService(t *testing.T, s *store.Store) *store.ProjectGrantService {
	t.Helper()
	svc, err := store.NewProjectGrantService(s,
		store.NewProjectRepository(),
		store.NewProjectGrantRepository(),
		store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectGrantService: %v", err)
	}
	return svc
}

// strptr returns a *string pointing at v. It is the test-only counterpart
// of the store layer's internal nullable-scope helpers — used here to
// build (environment_id, service_id) pointers without sprinkling locals
// across every test.
func strptr(v string) *string { return &v }

// TestProjectGrantServiceReplaceInsertsFreshGrants is the happy path: a
// PUT against a project with no configured grants inserts every entry,
// mints non-guessable ids carrying the pgrnt_ prefix, and returns the
// committed rows in deterministic order. The grants surface a mix of
// scope tuples (project-only, environment-scoped, service-scoped) so the
// nullable-pointer projection is exercised end to end.
func TestProjectGrantServiceReplaceInsertsFreshGrants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "GrantsSvcAlpha")
	proj := seedProject(t, db, f, org, "Backend")

	svc := newProjectGrantService(t, s)

	grants, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_ada", PrincipalKind: "usr", Role: "developer"},
			{PrincipalID: "sa_ci", PrincipalKind: "sa", Role: "ci", EnvironmentID: strptr("env_staging")},
			{PrincipalID: "sa_ci", PrincipalKind: "sa", Role: "developer", EnvironmentID: strptr("env_prod"), ServiceID: strptr("svc_web")},
		},
		ActorID:    "usr_admin",
		ActorKind:  "usr",
		ActorOrgID: org.ID,
		RequestID:  "req_test_alpha",
	})
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if len(grants) != 3 {
		t.Fatalf("grants len = %d, want 3", len(grants))
	}
	// IDs must carry the pgrnt_ prefix and be unique.
	seenIDs := map[string]bool{}
	for _, g := range grants {
		if !strings.HasPrefix(g.ID, "pgrnt_") {
			t.Errorf("grant id %q missing pgrnt_ prefix", g.ID)
		}
		if seenIDs[g.ID] {
			t.Errorf("duplicate grant id %q", g.ID)
		}
		seenIDs[g.ID] = true
		if g.OrganizationID != org.ID || g.ProjectID != proj.ID {
			t.Errorf("grant %s tenant scope = (%q, %q), want (%q, %q)", g.ID, g.OrganizationID, g.ProjectID, org.ID, proj.ID)
		}
		if g.Version != 1 {
			t.Errorf("grant %s version = %d, want 1 on INSERT", g.ID, g.Version)
		}
	}

	// Deterministic order: (principal_id ASC, environment_id ASC NULLS FIRST,
	// service_id ASC NULLS FIRST, id ASC) — sa_ci/null/null does not exist,
	// so sa_ci/env_prod/svc_web sorts after sa_ci/env_staging/null.
	if grants[0].PrincipalID != "sa_ci" || grants[0].EnvironmentID == nil || *grants[0].EnvironmentID != "env_prod" {
		t.Errorf("grants[0] = %+v, want sa_ci/env_prod first", grants[0])
	}
	if grants[1].PrincipalID != "sa_ci" || grants[1].EnvironmentID == nil || *grants[1].EnvironmentID != "env_staging" {
		t.Errorf("grants[1] = %+v, want sa_ci/env_staging", grants[1])
	}
	if grants[2].PrincipalID != "usr_ada" || grants[2].EnvironmentID != nil {
		t.Errorf("grants[2] = %+v, want usr_ada project-scoped", grants[2])
	}

	// Audit record carries action project.grants.write, decision allowed,
	// resource = the target project, and metadata records counts (never
	// principal ids, roles, environment, or service identifiers).
	var auditCount int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM audit_events
		   WHERE organization_id = $1 AND action = 'project.grants.write'
		     AND resource_kind = 'proj' AND resource_id = $2
		     AND decision = 'allowed'
		     AND metadata->>'grant_count' = '3'
		     AND metadata->>'environment_scope_count' = '1'
		     AND metadata->>'service_scope_count' = '1'
		     AND metadata->>'project_scope_count' = '1'`,
		org.ID, proj.ID).Scan(&auditCount); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit_events count = %d, want 1", auditCount)
	}
}

// TestProjectGrantServiceReplaceUpsertOnSameScopeTupleMutatesRole proves
// the idempotency contract: a second Replace whose grants share the same
// scope tuple as the first updates the role in place (the bump_version
// trigger refreshes version) rather than appending a new row.
func TestProjectGrantServiceReplaceUpsertOnSameScopeTupleMutatesRole(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UpsertAcme")
	proj := seedProject(t, db, f, org, "Web")
	svc := newProjectGrantService(t, s)

	first, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_ada", PrincipalKind: "usr", Role: "viewer"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("first Replace: %v", err)
	}
	if len(first) != 1 || first[0].Role != "viewer" || first[0].Version != 1 {
		t.Fatalf("first[0] = %+v, want viewer/v1", first[0])
	}
	originalID := first[0].ID

	second, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_ada", PrincipalKind: "usr", Role: "admin"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("second Replace: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("second len = %d, want 1 (upsert must not append a new row)", len(second))
	}
	if second[0].ID != originalID {
		t.Errorf("second[0].id = %q, want preserved %q", second[0].ID, originalID)
	}
	if second[0].Role != "admin" {
		t.Errorf("second[0].role = %q, want admin", second[0].Role)
	}
	if second[0].Version <= first[0].Version {
		t.Errorf("second[0].version = %d, want greater than first %d (bump_version on UPDATE)", second[0].Version, first[0].Version)
	}
}

// TestProjectGrantServiceReplaceDeletesByExclusion proves the second half
// of the replace contract: grants present in the prior state but absent
// from the replacement set are dropped, and the response reflects the
// post-write state only.
func TestProjectGrantServiceReplaceDeletesByExclusion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ExclusionAcme")
	proj := seedProject(t, db, f, org, "Edge")
	svc := newProjectGrantService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_keep", PrincipalKind: "usr", Role: "developer"},
			{PrincipalID: "usr_drop", PrincipalKind: "usr", Role: "viewer"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	after, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_keep", PrincipalKind: "usr", Role: "developer"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("post-drop Replace: %v", err)
	}
	if len(after) != 1 {
		t.Fatalf("after len = %d, want 1", len(after))
	}
	if after[0].PrincipalID != "usr_keep" {
		t.Errorf("after[0] = %+v, want usr_keep retained", after[0])
	}

	// Verify the dropped row is gone from the database.
	var droppedCount int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM project_grants
		   WHERE organization_id = $1 AND project_id = $2 AND principal_id = 'usr_drop'`,
		org.ID, proj.ID).Scan(&droppedCount); err != nil {
		t.Fatalf("query dropped: %v", err)
	}
	if droppedCount != 0 {
		t.Errorf("project_grants count for dropped principal = %d, want 0", droppedCount)
	}
}

// TestProjectGrantServiceReplaceEmptyListClearsEveryGrant proves a PUT
// with grants:[] is an explicit clear — not a silent no-op. Every prior
// grant is removed and the response is the deterministic empty slice.
func TestProjectGrantServiceReplaceEmptyListClearsEveryGrant(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ClearAcme")
	proj := seedProject(t, db, f, org, "Lambda")
	svc := newProjectGrantService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_one", PrincipalKind: "usr", Role: "developer"},
			{PrincipalID: "usr_two", PrincipalKind: "usr", Role: "viewer"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	after, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants:         []store.ProjectGrantReplace{},
		ActorID:        "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("clear Replace: %v", err)
	}
	if len(after) != 0 {
		t.Errorf("after len = %d, want 0 (explicit clear must drop every grant)", len(after))
	}

	var remaining int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM project_grants WHERE organization_id = $1 AND project_id = $2`,
		org.ID, proj.ID).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 0 {
		t.Errorf("project_grants remaining = %d, want 0", remaining)
	}
}

// TestProjectGrantServiceReplaceNotFoundProject proves a project_id that
// does not exist (in any tenant) surfaces as the typed apierr.NotFound,
// not a generic FK conflict, and that no audit record is written for
// the rolled-back transaction.
func TestProjectGrantServiceReplaceNotFoundProject(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "NotFoundAcme")
	svc := newProjectGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      "prj_doesnotexist",
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_one", PrincipalKind: "usr", Role: "developer"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Replace(missing project) = nil err; want apierr.NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v; want yerr CodeNotFound", err)
	}

	// No audit record was committed because the existence check failed
	// inside the transaction — the audit append happens after the upserts
	// and is rolled back with them.
	var auditCount int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM audit_events
		   WHERE action = 'project.grants.write' AND resource_id = 'prj_doesnotexist'`,
	).Scan(&auditCount); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if auditCount != 0 {
		t.Errorf("audit count for missing project = %d, want 0 (must roll back with the tx)", auditCount)
	}
}

// TestProjectGrantServiceReplaceCrossTenantProjectIsNotFound proves a
// project_id that belongs to another tenant is rejected as NotFound
// against the actor's own organization (never as a 409 or a leak of the
// foreign project's grants).
func TestProjectGrantServiceReplaceCrossTenantProjectIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "TenantA")
	orgB := seedOrg(t, db, f, "TenantB")
	projB := seedProject(t, db, f, orgB, "Vault")
	svc := newProjectGrantService(t, s)

	// Actor authenticates as orgA but submits projB.ID — the same shape a
	// cross-tenant smuggling attempt would take if the policy layer were
	// somehow bypassed. The persistence layer rejects it.
	_, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: orgA.ID,
		ProjectID:      projB.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_intruder", PrincipalKind: "usr", Role: "owner"},
		},
		ActorID: "usr_intruder", ActorKind: "usr", ActorOrgID: orgA.ID,
	})
	if err == nil {
		t.Fatalf("cross-tenant Replace returned nil error; want NotFound")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("err = %v; want yerr CodeNotFound", err)
	}

	// projB's grants table is still empty (no row leaked through).
	var projBCount int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM project_grants WHERE organization_id = $1 AND project_id = $2`,
		orgB.ID, projB.ID).Scan(&projBCount); err != nil {
		t.Fatalf("count tenantB grants: %v", err)
	}
	if projBCount != 0 {
		t.Errorf("tenantB grants count = %d, want 0 (cross-tenant write must not reach the row)", projBCount)
	}
}

// TestProjectGrantServiceReplaceRejectsInvalidPrincipalKind proves the
// closed-set check surfaces an apierr.InvalidInput naming the offending
// field path before any database write.
func TestProjectGrantServiceReplaceRejectsInvalidPrincipalKind(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "InvalidKindAcme")
	proj := seedProject(t, db, f, org, "API")
	svc := newProjectGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_a", PrincipalKind: "robot", Role: "developer"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Replace(invalid kind) = nil err; want apierr.InvalidInput")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("err = %v; want yerr CodeInvalidInput", err)
	}
	if _, ok := violationFor(err, "grants[0].principal_kind"); !ok {
		t.Errorf("err = %v; want a FieldViolation naming grants[0].principal_kind", err)
	}

	// No row reached the database.
	var n int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM project_grants WHERE organization_id = $1 AND project_id = $2`,
		org.ID, proj.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("project_grants count = %d, want 0 (validation runs before any write)", n)
	}
}

// TestProjectGrantServiceReplaceRejectsUnknownRole proves an unknown role
// (a value outside the six built-ins) is rejected as InvalidInput naming
// the offending field path, before any database write.
func TestProjectGrantServiceReplaceRejectsUnknownRole(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "UnknownRoleAcme")
	proj := seedProject(t, db, f, org, "Gateway")
	svc := newProjectGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_a", PrincipalKind: "usr", Role: "ghost"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Replace(unknown role) = nil err; want InvalidInput")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("err = %v; want yerr CodeInvalidInput", err)
	}
	if _, ok := violationFor(err, "grants[0].role"); !ok {
		t.Errorf("err = %v; want a FieldViolation naming grants[0].role", err)
	}
}

// TestProjectGrantServiceReplaceRejectsDuplicateScopeTuple proves the
// in-memory dedup matches the SQL unique index: two entries naming the
// same (principal_id, environment_id, service_id) target are rejected
// before any database write, so the upsert can never observe a duplicate
// row from the caller side.
func TestProjectGrantServiceReplaceRejectsDuplicateScopeTuple(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "DupAcme")
	proj := seedProject(t, db, f, org, "Worker")
	svc := newProjectGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_a", PrincipalKind: "usr", Role: "developer"},
			{PrincipalID: "usr_a", PrincipalKind: "usr", Role: "viewer"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Replace(duplicate scope) = nil err; want InvalidInput")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("err = %v; want yerr CodeInvalidInput", err)
	}
}

// TestProjectGrantServiceReplaceRejectsServiceWithoutEnvironment proves
// the hierarchical scope rule: a service-scoped grant must also name its
// parent environment_id. Allowing a service-only grant would leave the
// audit and wire layers without a coherent (env, svc) parent pair.
func TestProjectGrantServiceReplaceRejectsServiceWithoutEnvironment(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "SvcOnlyAcme")
	proj := seedProject(t, db, f, org, "Edge")
	svc := newProjectGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_a", PrincipalKind: "usr", Role: "developer", ServiceID: strptr("svc_web")},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Replace(service-only) = nil err; want InvalidInput")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("err = %v; want yerr CodeInvalidInput", err)
	}
	if _, ok := violationFor(err, "grants[0].environment_id"); !ok {
		t.Errorf("err = %v; want a FieldViolation naming grants[0].environment_id", err)
	}
}

// TestProjectGrantServiceReplaceRejectsBlankActorOrg proves the
// actor-organization invariant: an empty ActorOrgID would file the audit
// record under an empty tenant, so the service rejects it as Internal
// (a wiring error, not client input).
func TestProjectGrantServiceReplaceRejectsBlankActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "WiringAcme")
	proj := seedProject(t, db, f, org, "Beta")
	svc := newProjectGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceProjectGrantsInput{
		OrganizationID: org.ID,
		ProjectID:      proj.ID,
		Grants: []store.ProjectGrantReplace{
			{PrincipalID: "usr_a", PrincipalKind: "usr", Role: "developer"},
		},
		ActorID: "usr_admin", ActorKind: "usr",
	})
	if err == nil {
		t.Fatalf("Replace(blank actor org) = nil err; want Internal")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Fatalf("err = %v; want yerr CodeInternal", err)
	}
}

// TestNewProjectGrantServiceRejectsNilDependencies proves the constructor's
// fail-fast posture: a misconfigured service that lacks the store, the
// project repository, the grant repository, or the audit appender fails at
// construction rather than on its first request — mirroring
// NewOrganizationVariableService and NewLimitsService.
func TestNewProjectGrantServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()

	if _, err := store.NewProjectGrantService(nil,
		store.NewProjectRepository(),
		store.NewProjectGrantRepository(),
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewProjectGrantService(nil store) returned no error")
	}
	// Build a real store via the test pool so the other nil-checks have a
	// real dependency in the non-checked slots.
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	if _, err := store.NewProjectGrantService(s, nil,
		store.NewProjectGrantRepository(),
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewProjectGrantService(nil projects) returned no error")
	}
	if _, err := store.NewProjectGrantService(s,
		store.NewProjectRepository(),
		nil,
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewProjectGrantService(nil grants) returned no error")
	}
	if _, err := store.NewProjectGrantService(s,
		store.NewProjectRepository(),
		store.NewProjectGrantRepository(),
		nil); err == nil {
		t.Errorf("NewProjectGrantService(nil audit) returned no error")
	}
}
