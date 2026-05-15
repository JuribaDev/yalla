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

// Integration tests for EnvironmentGrantService — the
// replace-environment-grants unit of work behind PUT
// /v1/environments/{environment_id}/grants. They prove that the per-grant
// upserts, the bulk delete-by-exclusion that drops everything else, and
// the immutable audit record commit atomically; that a missing environment
// is a typed NotFound (not a 409 constraint violation); that empty input
// means "clear every grant" rather than a silent no-op; that validation
// rejects malformed input before any database write; that the post-write
// re-read mirrors persistence so the response always reflects what just
// committed; and that a cross-tenant environment_id can never reveal
// another tenant's grants. They run against an isolated, freshly migrated
// Postgres database and skip when YALLA_TEST_DATABASE_URL is unset.

func newEnvironmentGrantService(t *testing.T, s *store.Store) *store.EnvironmentGrantService {
	t.Helper()
	svc, err := store.NewEnvironmentGrantService(s,
		store.NewEnvironmentRepository(),
		store.NewEnvironmentGrantRepository(),
		store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentGrantService: %v", err)
	}
	return svc
}

// TestEnvironmentGrantServiceReplaceInsertsFreshGrants is the happy path:
// a PUT against an environment with no configured grants inserts every
// entry, mints non-guessable ids carrying the egrnt_ prefix, and returns
// the committed rows in deterministic order. The grants surface a mix of
// scope tuples (environment-scoped, service-scoped) so the nullable-pointer
// projection is exercised end to end.
func TestEnvironmentGrantServiceReplaceInsertsFreshGrants(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvGrantsSvcAlpha")
	proj := seedProject(t, db, f, org, "Backend")
	env := seedEnvironment(t, db, f, proj, "Prod")

	svc := newEnvironmentGrantService(t, s)

	grants, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants: []store.EnvironmentGrantReplace{
			{PrincipalID: "usr_ada", PrincipalKind: "usr", Role: "developer"},
			{PrincipalID: "sa_ci", PrincipalKind: "sa", Role: "ci", ServiceID: strptr("svc_web")},
		},
		ActorID:    "usr_admin",
		ActorKind:  "usr",
		ActorOrgID: org.ID,
		RequestID:  "req_test_egrnt_alpha",
	})
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if len(grants) != 2 {
		t.Fatalf("grants len = %d, want 2", len(grants))
	}
	// IDs must carry the egrnt_ prefix and be unique.
	seenIDs := map[string]bool{}
	for _, g := range grants {
		if !strings.HasPrefix(g.ID, "egrnt_") {
			t.Errorf("grant id %q missing egrnt_ prefix", g.ID)
		}
		if seenIDs[g.ID] {
			t.Errorf("duplicate grant id %q", g.ID)
		}
		seenIDs[g.ID] = true
		if g.OrganizationID != org.ID || g.EnvironmentID != env.ID {
			t.Errorf("grant %s tenant scope = (%q, %q), want (%q, %q)", g.ID, g.OrganizationID, g.EnvironmentID, org.ID, env.ID)
		}
		if g.Version != 1 {
			t.Errorf("grant %s version = %d, want 1 on INSERT", g.ID, g.Version)
		}
	}

	// Deterministic order: (principal_id ASC, service_id ASC NULLS FIRST,
	// id ASC). sa_ci/svc_web sorts before usr_ada (sa < usr lexically).
	if grants[0].PrincipalID != "sa_ci" || grants[0].ServiceID == nil || *grants[0].ServiceID != "svc_web" {
		t.Errorf("grants[0] = %+v, want sa_ci/svc_web first", grants[0])
	}
	if grants[1].PrincipalID != "usr_ada" || grants[1].ServiceID != nil {
		t.Errorf("grants[1] = %+v, want usr_ada environment-scoped", grants[1])
	}

	// Audit record carries action environment.grants.write, decision
	// allowed, resource = the target environment, and metadata records
	// counts (never principal ids, roles, or service identifiers).
	var auditCount int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM audit_events
		   WHERE organization_id = $1 AND action = 'environment.grants.write'
		     AND resource_kind = 'env' AND resource_id = $2
		     AND decision = 'allowed'
		     AND metadata->>'grant_count' = '2'
		     AND metadata->>'environment_scope_count' = '1'
		     AND metadata->>'service_scope_count' = '1'`,
		org.ID, env.ID).Scan(&auditCount); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("audit_events count = %d, want 1", auditCount)
	}
}

// TestEnvironmentGrantServiceReplaceUpsertOnSameScopeTupleMutatesRole
// proves the idempotency contract: a second Replace whose grants share the
// same scope tuple as the first updates the role in place (the
// bump_version trigger refreshes version) rather than appending a new row.
func TestEnvironmentGrantServiceReplaceUpsertOnSameScopeTupleMutatesRole(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvUpsertAcme")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "Staging")
	svc := newEnvironmentGrantService(t, s)

	first, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants: []store.EnvironmentGrantReplace{
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

	second, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants: []store.EnvironmentGrantReplace{
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

// TestEnvironmentGrantServiceReplaceDeletesByExclusion proves the second
// half of the replace contract: grants present in the prior state but
// absent from the replacement set are dropped, and the response reflects
// the post-write state only.
func TestEnvironmentGrantServiceReplaceDeletesByExclusion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvExclusionAcme")
	proj := seedProject(t, db, f, org, "Edge")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := newEnvironmentGrantService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants: []store.EnvironmentGrantReplace{
			{PrincipalID: "usr_keep", PrincipalKind: "usr", Role: "developer"},
			{PrincipalID: "usr_drop", PrincipalKind: "usr", Role: "viewer"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	after, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants: []store.EnvironmentGrantReplace{
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
		`SELECT count(*) FROM environment_grants
		   WHERE organization_id = $1 AND environment_id = $2 AND principal_id = 'usr_drop'`,
		org.ID, env.ID).Scan(&droppedCount); err != nil {
		t.Fatalf("query dropped: %v", err)
	}
	if droppedCount != 0 {
		t.Errorf("environment_grants count for dropped principal = %d, want 0", droppedCount)
	}
}

// TestEnvironmentGrantServiceReplaceEmptyListClearsEveryGrant proves a PUT
// with grants:[] is an explicit clear — not a silent no-op. Every prior
// grant is removed and the response is the deterministic empty slice.
func TestEnvironmentGrantServiceReplaceEmptyListClearsEveryGrant(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvClearAcme")
	proj := seedProject(t, db, f, org, "Lambda")
	env := seedEnvironment(t, db, f, proj, "Stage")
	svc := newEnvironmentGrantService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants: []store.EnvironmentGrantReplace{
			{PrincipalID: "usr_one", PrincipalKind: "usr", Role: "developer"},
			{PrincipalID: "usr_two", PrincipalKind: "usr", Role: "viewer"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	after, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants:         []store.EnvironmentGrantReplace{},
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
		`SELECT count(*) FROM environment_grants WHERE organization_id = $1 AND environment_id = $2`,
		org.ID, env.ID).Scan(&remaining); err != nil {
		t.Fatalf("count remaining: %v", err)
	}
	if remaining != 0 {
		t.Errorf("environment_grants remaining = %d, want 0", remaining)
	}
}

// TestEnvironmentGrantServiceReplaceNotFoundEnvironment proves an
// environment_id that does not exist (in any tenant) surfaces as the typed
// apierr.NotFound, not a generic FK conflict, and that no audit record is
// written for the rolled-back transaction.
func TestEnvironmentGrantServiceReplaceNotFoundEnvironment(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvNotFoundAcme")
	svc := newEnvironmentGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  "env_doesnotexist",
		Grants: []store.EnvironmentGrantReplace{
			{PrincipalID: "usr_one", PrincipalKind: "usr", Role: "developer"},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Replace(missing environment) = nil err; want apierr.NotFound")
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
		   WHERE action = 'environment.grants.write' AND resource_id = 'env_doesnotexist'`,
	).Scan(&auditCount); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if auditCount != 0 {
		t.Errorf("audit count for missing environment = %d, want 0 (must roll back with the tx)", auditCount)
	}
}

// TestEnvironmentGrantServiceReplaceCrossTenantEnvironmentIsNotFound proves
// an environment_id that belongs to another tenant is rejected as NotFound
// against the actor's own organization (never as a 409 or a leak of the
// foreign environment's grants).
func TestEnvironmentGrantServiceReplaceCrossTenantEnvironmentIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "EnvTenantA")
	orgB := seedOrg(t, db, f, "EnvTenantB")
	projB := seedProject(t, db, f, orgB, "Vault")
	envB := seedEnvironment(t, db, f, projB, "Locked")
	svc := newEnvironmentGrantService(t, s)

	// Actor authenticates as orgA but submits envB.ID — the same shape a
	// cross-tenant smuggling attempt would take if the policy layer were
	// somehow bypassed. The persistence layer rejects it.
	_, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: orgA.ID,
		EnvironmentID:  envB.ID,
		Grants: []store.EnvironmentGrantReplace{
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

	// envB's grants table is still empty (no row leaked through).
	var envBCount int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM environment_grants WHERE organization_id = $1 AND environment_id = $2`,
		orgB.ID, envB.ID).Scan(&envBCount); err != nil {
		t.Fatalf("count tenantB grants: %v", err)
	}
	if envBCount != 0 {
		t.Errorf("tenantB grants count = %d, want 0 (cross-tenant write must not reach the row)", envBCount)
	}
}

// TestEnvironmentGrantServiceReplaceRejectsInvalidPrincipalKind proves the
// closed-set check surfaces an apierr.InvalidInput naming the offending
// field path before any database write.
func TestEnvironmentGrantServiceReplaceRejectsInvalidPrincipalKind(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvInvalidKindAcme")
	proj := seedProject(t, db, f, org, "API")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := newEnvironmentGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants: []store.EnvironmentGrantReplace{
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
		`SELECT count(*) FROM environment_grants WHERE organization_id = $1 AND environment_id = $2`,
		org.ID, env.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("environment_grants count = %d, want 0 (validation runs before any write)", n)
	}
}

// TestEnvironmentGrantServiceReplaceRejectsUnknownRole proves an unknown
// role (a value outside the six built-ins) is rejected as InvalidInput
// naming the offending field path, before any database write.
func TestEnvironmentGrantServiceReplaceRejectsUnknownRole(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvUnknownRoleAcme")
	proj := seedProject(t, db, f, org, "Gateway")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := newEnvironmentGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants: []store.EnvironmentGrantReplace{
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

// TestEnvironmentGrantServiceReplaceRejectsDuplicateScopeTuple proves the
// in-memory dedup matches the SQL unique index: two entries naming the
// same (principal_id, service_id) target are rejected before any database
// write, so the upsert can never observe a duplicate row from the caller
// side.
func TestEnvironmentGrantServiceReplaceRejectsDuplicateScopeTuple(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvDupAcme")
	proj := seedProject(t, db, f, org, "Worker")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := newEnvironmentGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants: []store.EnvironmentGrantReplace{
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

// TestEnvironmentGrantServiceReplaceRejectsBlankActorOrg proves the
// actor-organization invariant: an empty ActorOrgID would file the audit
// record under an empty tenant, so the service rejects it as Internal (a
// wiring error, not client input).
func TestEnvironmentGrantServiceReplaceRejectsBlankActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvWiringAcme")
	proj := seedProject(t, db, f, org, "Beta")
	env := seedEnvironment(t, db, f, proj, "Prod")
	svc := newEnvironmentGrantService(t, s)

	_, err := svc.Replace(ctx, store.ReplaceEnvironmentGrantsInput{
		OrganizationID: org.ID,
		EnvironmentID:  env.ID,
		Grants: []store.EnvironmentGrantReplace{
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

// TestNewEnvironmentGrantServiceRejectsNilDependencies proves the
// constructor's fail-fast posture: a misconfigured service that lacks the
// store, the environment repository, the grant repository, or the audit
// appender fails at construction rather than on its first request —
// mirroring NewProjectGrantService.
func TestNewEnvironmentGrantServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()

	if _, err := store.NewEnvironmentGrantService(nil,
		store.NewEnvironmentRepository(),
		store.NewEnvironmentGrantRepository(),
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewEnvironmentGrantService(nil store) returned no error")
	}
	// Build a real store via the test pool so the other nil-checks have a
	// real dependency in the non-checked slots.
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	if _, err := store.NewEnvironmentGrantService(s, nil,
		store.NewEnvironmentGrantRepository(),
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewEnvironmentGrantService(nil environments) returned no error")
	}
	if _, err := store.NewEnvironmentGrantService(s,
		store.NewEnvironmentRepository(),
		nil,
		store.NewAuditRepository()); err == nil {
		t.Errorf("NewEnvironmentGrantService(nil grants) returned no error")
	}
	if _, err := store.NewEnvironmentGrantService(s,
		store.NewEnvironmentRepository(),
		store.NewEnvironmentGrantRepository(),
		nil); err == nil {
		t.Errorf("NewEnvironmentGrantService(nil audit) returned no error")
	}
}
