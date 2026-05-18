package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// seedDomainProject inserts a project row owned by orgID whose id is a real,
// canonical domain id (the testutil factory deliberately uses non-canonical
// prefixes, which the service's input validation correctly rejects). It
// returns the id.
func seedDomainProject(t *testing.T, db *testutil.DB, orgID string) string {
	t.Helper()
	id := domain.MustNewID(domain.KindProject).String()
	slug := "prj-" + id[len(id)-12:]
	if _, err := db.Exec(context.Background(),
		`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		id, orgID, slug, "Test Project"); err != nil {
		t.Fatalf("seed domain project: %v", err)
	}
	return id
}

// seedDomainEnvironment inserts an environment row owned by (orgID, projectID)
// whose id is a real, canonical domain id. It returns the id and slug.
func seedDomainEnvironment(t *testing.T, db *testutil.DB, orgID, projectID, slug string) string {
	t.Helper()
	id := domain.MustNewID(domain.KindEnvironment).String()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO environments (id, organization_id, project_id, slug, display_name) VALUES ($1, $2, $3, $4, $5)`,
		id, orgID, projectID, slug, "Test Environment"); err != nil {
		t.Fatalf("seed domain environment: %v", err)
	}
	return id
}

// Integration tests for EnvironmentService.Clone — the reference unit-of-work
// orchestrator for environment cloning. They prove that the source environment
// read, in-transaction authorization, quota reservation, desired-state write,
// provisioning-job enqueue, and audit append all share one transaction: a
// failure in any step rolls every other step back, and the checks cannot be
// bypassed. They also prove the new environment inherits the source's
// project_id, a source scheduled for teardown is rejected as Conflict, the
// tenant boundary is structural (a cross-tenant source surfaces as NotFound),
// and validation runs before any transaction is opened.

// newCloneEnvironmentInput builds a valid CloneEnvironmentInput for the
// (orgID, sourceEnvID) pair. ActorOrgID matches OrganizationID because the
// production wire path always pins the audit record to the principal's home
// organization — the tenant the principal authenticated into and the tenant
// the new environment is owned by.
func newCloneEnvironmentInput(orgID, sourceEnvID string) store.CloneEnvironmentInput {
	return store.CloneEnvironmentInput{
		OrganizationID:      orgID,
		SourceEnvironmentID: sourceEnvID,
		NewEnvironmentID:    domain.MustNewID(domain.KindEnvironment).String(),
		NewSlug:             "production-clone",
		NewDisplayName:      "Production Clone",
		ActorID:             "usr_ada",
		ActorKind:           "usr",
		ActorOrgID:          orgID,
		RequestID:           "req_env_clone",
		CorrelationID:       "corr_env_clone",
	}
}

// TestEnvironmentServiceCloneSuccess proves the orchestrator reads the source
// environment, calls the in-tx Authorize / Quota / JobEnqueue ports, inserts
// the new row inheriting the source's project_id, and commits an
// environment.create audit row inside the same transaction. The audit row
// must include a cloned_from metadata field naming the source environment so
// the provenance of the new row is captured.
func TestEnvironmentServiceCloneSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	projID := seedDomainProject(t, db, orgID)
	srcID := seedDomainEnvironment(t, db, orgID, projID, "production")

	svc, authz, quota, jobs := newEnvironmentSvc(t, s)

	in := newCloneEnvironmentInput(orgID, srcID)
	cloned, err := svc.Clone(ctx, in)
	if err != nil {
		t.Fatalf("Clone returned %v, want nil", err)
	}
	if cloned.ID != in.NewEnvironmentID {
		t.Errorf("Clone returned id %q, want %q", cloned.ID, in.NewEnvironmentID)
	}
	if cloned.OrganizationID != orgID {
		t.Errorf("Clone returned org %q, want %q", cloned.OrganizationID, orgID)
	}
	if cloned.ProjectID != projID {
		t.Errorf("Clone returned project %q, want %q (inherited from source)", cloned.ProjectID, projID)
	}
	if cloned.Slug != "production-clone" || cloned.DisplayName != "Production Clone" {
		t.Errorf("Clone returned %+v, want slug=production-clone display=Production Clone", cloned)
	}
	if cloned.Version != 1 {
		t.Errorf("Clone returned version %d, want 1", cloned.Version)
	}
	if cloned.DeletionScheduledAt != nil {
		t.Error("Clone returned a row with deletion_scheduled_at set; a freshly-cloned row must be live")
	}

	// Clone composes Create-like steps; all three in-tx ports must be invoked.
	if authz.calls != 1 || quota.calls != 1 || jobs.calls != 1 {
		t.Errorf("step calls = authz:%d quota:%d jobs:%d, want 1 each", authz.calls, quota.calls, jobs.calls)
	}

	if !environmentExists(ctx, t, s, orgID, projID, in.NewEnvironmentID) {
		t.Error("Clone succeeded but the cloned environment row was not committed")
	}

	events := listEnvironmentAuditEvents(t, s, orgID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the clone", len(events))
	}
	ev := events[0]
	if ev.Action != "environment.create" {
		t.Errorf("audit action = %q, want environment.create", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != cloned.ID {
		t.Errorf("audit resource_id = %q, want the cloned environment id %q", ev.ResourceID, cloned.ID)
	}
	if ev.ResourceKind != string(domain.KindEnvironment) {
		t.Errorf("audit resource_kind = %q, want %q", ev.ResourceKind, domain.KindEnvironment)
	}
	if got := ev.Metadata["slug"]; got != in.NewSlug {
		t.Errorf("audit metadata[slug] = %q, want %q", got, in.NewSlug)
	}
	if got := ev.Metadata["project_id"]; got != projID {
		t.Errorf("audit metadata[project_id] = %q, want %q", got, projID)
	}
	if got := ev.Metadata["cloned_from"]; got != srcID {
		t.Errorf("audit metadata[cloned_from] = %q, want %q (source environment id)", got, srcID)
	}
}

// TestEnvironmentServiceCloneSourceNotFound proves an unknown source
// environment_id surfaces as NotFound — never reveals another tenant's data,
// never writes the new row, never enqueues a job, and never writes an audit
// row.
func TestEnvironmentServiceCloneSourceNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	svc, authz, quota, jobs := newEnvironmentSvc(t, s)

	in := newCloneEnvironmentInput(orgID, domain.MustNewID(domain.KindEnvironment).String())
	_, err := svc.Clone(ctx, in)
	if err == nil {
		t.Fatal("Clone of an unknown source returned nil; want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("code = %v, want %s", err, yerr.CodeNotFound)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("authz/quota/jobs ran for an unknown source: authz=%d quota=%d jobs=%d", authz.calls, quota.calls, jobs.calls)
	}
	if events := listEnvironmentAuditEvents(t, s, orgID); len(events) != 0 {
		t.Errorf("audit events = %d, want 0 (no audit for a NotFound clone)", len(events))
	}
}

// TestEnvironmentServiceCloneIsTenantScoped proves a cross-tenant source
// environment_id surfaces as NotFound, never reveals the other tenant's
// environment, and never writes any state to either tenant.
func TestEnvironmentServiceCloneIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	orgA := seedDomainOrg(t, db)
	projA := seedDomainProject(t, db, orgA)
	envA := seedDomainEnvironment(t, db, orgA, projA, "production")

	orgB := seedDomainOrg(t, db)
	svc, authz, quota, jobs := newEnvironmentSvc(t, s)

	// Tenant B caller, tenant A's environment as the source.
	in := newCloneEnvironmentInput(orgB, envA)
	_, err := svc.Clone(ctx, in)
	if err == nil {
		t.Fatal("cross-tenant Clone error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("code = %v, want %s", err, yerr.CodeNotFound)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("authz/quota/jobs ran for a cross-tenant clone: authz=%d quota=%d jobs=%d", authz.calls, quota.calls, jobs.calls)
	}
	// Neither tenant should have any audit record from the rejected attempt.
	if events := listEnvironmentAuditEvents(t, s, orgA); len(events) != 0 {
		t.Errorf("tenant A audit events = %d, want 0", len(events))
	}
	if events := listEnvironmentAuditEvents(t, s, orgB); len(events) != 0 {
		t.Errorf("tenant B audit events = %d, want 0", len(events))
	}
}

// TestEnvironmentServiceCloneSourceScheduledForDeletion proves a source whose
// deletion is already scheduled is rejected as Conflict — a lifecycle-dead row
// is not a valid clone source. The new row must not be written, no audit row
// must be appended, and no provisioning job must be enqueued.
func TestEnvironmentServiceCloneSourceScheduledForDeletion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	projID := seedDomainProject(t, db, orgID)
	srcID := seedDomainEnvironment(t, db, orgID, projID, "production")

	svc, authz, quota, jobs := newEnvironmentSvc(t, s)

	// First, schedule the source for deletion through the same service
	// so the lifecycle stamp is committed identically to the production path.
	if _, err := svc.ScheduleDeletion(ctx, newDeleteEnvironmentInput(orgID, srcID)); err != nil {
		t.Fatalf("seed ScheduleDeletion: %v", err)
	}
	authz.calls = 0
	quota.calls = 0
	jobs.calls = 0
	beforeEvents := len(listEnvironmentAuditEvents(t, s, orgID))

	in := newCloneEnvironmentInput(orgID, srcID)
	_, err := svc.Clone(ctx, in)
	if err == nil {
		t.Fatal("Clone of a scheduled-for-deletion source error = nil, want Conflict")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Errorf("code = %v, want %s", err, yerr.CodeConflict)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("authz/quota/jobs ran for a dead-source clone: authz=%d quota=%d jobs=%d", authz.calls, quota.calls, jobs.calls)
	}
	if environmentExists(ctx, t, s, orgID, projID, in.NewEnvironmentID) {
		t.Error("Clone wrote the new environment despite the dead source")
	}
	afterEvents := len(listEnvironmentAuditEvents(t, s, orgID))
	if afterEvents != beforeEvents {
		t.Errorf("audit events grew from %d to %d after the rejected clone; the dead-source path must roll back", beforeEvents, afterEvents)
	}
}

// TestEnvironmentServiceCloneAuthorizationFailure proves a denied in-tx
// authorize rolls the whole transaction back: the new row is never written,
// the quota reservation is rolled back, the provisioning job is rolled back,
// and no audit row is appended.
func TestEnvironmentServiceCloneAuthorizationFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	projID := seedDomainProject(t, db, orgID)
	srcID := seedDomainEnvironment(t, db, orgID, projID, "production")

	authz := &recordingAuthorizer{err: apierr.Forbidden("denied")}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	in := newCloneEnvironmentInput(orgID, srcID)
	if _, cloneErr := svc.Clone(ctx, in); cloneErr == nil {
		t.Fatal("Clone returned nil for a denied authorize; want PermissionDenied")
	}
	if quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("quota/jobs ran after the authz denial: quota=%d jobs=%d", quota.calls, jobs.calls)
	}
	if environmentExists(ctx, t, s, orgID, projID, in.NewEnvironmentID) {
		t.Error("Clone wrote the new environment despite a denied authorize")
	}
	if events := listEnvironmentAuditEvents(t, s, orgID); len(events) != 0 {
		t.Errorf("audit events = %d, want 0 after a denied authorize", len(events))
	}
}

// TestEnvironmentServiceCloneQuotaFailureRollsBack proves an exhausted quota
// rolls the whole transaction back: the new row is never written, the
// provisioning job is rolled back, and no audit row is appended.
func TestEnvironmentServiceCloneQuotaFailureRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	projID := seedDomainProject(t, db, orgID)
	srcID := seedDomainEnvironment(t, db, orgID, projID, "production")

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{err: apierr.QuotaExceeded("environments", 0)}
	jobs := &recordingJobs{}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	in := newCloneEnvironmentInput(orgID, srcID)
	if _, cloneErr := svc.Clone(ctx, in); cloneErr == nil {
		t.Fatal("Clone returned nil for an exhausted quota; want QuotaExhausted")
	}
	if jobs.calls != 0 {
		t.Errorf("jobs ran after a quota denial: jobs=%d", jobs.calls)
	}
	if environmentExists(ctx, t, s, orgID, projID, in.NewEnvironmentID) {
		t.Error("Clone wrote the new environment despite an exhausted quota")
	}
	if events := listEnvironmentAuditEvents(t, s, orgID); len(events) != 0 {
		t.Errorf("audit events = %d, want 0 after an exhausted quota", len(events))
	}
}

// TestEnvironmentServiceCloneSlugConflict proves a slug that already exists
// in the source's project rolls the whole transaction back as a typed
// Conflict — the unique (project_id, slug) constraint must surface as a
// stable 409 without leaking the constraint name, and no audit row may be
// appended for the rolled-back clone.
func TestEnvironmentServiceCloneSlugConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	projID := seedDomainProject(t, db, orgID)
	srcID := seedDomainEnvironment(t, db, orgID, projID, "production")
	// Seed an environment with the slug the clone will try to take.
	_ = seedDomainEnvironment(t, db, orgID, projID, "staging")

	svc, _, _, _ := newEnvironmentSvc(t, s)

	in := newCloneEnvironmentInput(orgID, srcID)
	in.NewSlug = "staging" // collides with the seeded env above.

	_, err := svc.Clone(ctx, in)
	if err == nil {
		t.Fatal("Clone with a duplicate slug returned nil; want Conflict")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Errorf("code = %v, want %s", err, yerr.CodeConflict)
	}
	if environmentExists(ctx, t, s, orgID, projID, in.NewEnvironmentID) {
		t.Error("Clone wrote the new environment despite a slug conflict")
	}
	// listEnvironmentAuditEvents must not include an environment.create
	// audit event for this org — the clone rolled back.
	for _, ev := range listEnvironmentAuditEvents(t, s, orgID) {
		if ev.Action == "environment.create" {
			t.Errorf("audit event %+v leaked for a rolled-back clone", ev)
		}
	}
}

// TestEnvironmentServiceCloneValidationFailure proves an invalid input is
// rejected before any transaction is opened — no audit row, no env row.
// Each subtest names exactly which field violation the caller should learn
// without leaking the submitted value.
func TestEnvironmentServiceCloneValidationFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)

	orgID := seedDomainOrg(t, db)
	projID := seedDomainProject(t, db, orgID)
	srcID := seedDomainEnvironment(t, db, orgID, projID, "production")

	svc, _, _, _ := newEnvironmentSvc(t, s)

	cases := []struct {
		name  string
		mut   func(*store.CloneEnvironmentInput)
		field string
	}{
		{
			name:  "invalid organization id",
			mut:   func(in *store.CloneEnvironmentInput) { in.OrganizationID = "not-an-org-id" },
			field: "organization_id",
		},
		{
			name:  "invalid source environment id",
			mut:   func(in *store.CloneEnvironmentInput) { in.SourceEnvironmentID = "not-an-env-id" },
			field: "source_environment_id",
		},
		{
			name:  "invalid new environment id",
			mut:   func(in *store.CloneEnvironmentInput) { in.NewEnvironmentID = "not-an-env-id" },
			field: "environment_id",
		},
		{
			name: "same source and new id",
			mut: func(in *store.CloneEnvironmentInput) {
				in.NewEnvironmentID = in.SourceEnvironmentID
			},
			field: "environment_id",
		},
		{
			name:  "invalid slug",
			mut:   func(in *store.CloneEnvironmentInput) { in.NewSlug = "Not A Slug" },
			field: "slug",
		},
		{
			name:  "blank display name",
			mut:   func(in *store.CloneEnvironmentInput) { in.NewDisplayName = "" },
			field: "display_name",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := newCloneEnvironmentInput(orgID, srcID)
			tc.mut(&in)
			_, err := svc.Clone(context.Background(), in)
			if err == nil {
				t.Fatalf("%s: error = nil, want InvalidInput", tc.name)
			}
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Fatalf("%s: code = %v, want %s", tc.name, err, yerr.CodeValidation)
			}
			violations, ok := apierr.ViolationsOf(err)
			if !ok || len(violations) == 0 {
				t.Fatalf("%s: error carried no field violations: ok=%v", tc.name, ok)
			}
			found := false
			for _, v := range violations {
				if v.Field == tc.field {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: violations = %+v, want a violation on field %q", tc.name, violations, tc.field)
			}
		})
	}
}

// TestEnvironmentServiceCloneRequiresActorOrg proves a wiring error — an
// authenticated request that nonetheless reaches the service with no actor
// organization — is rejected as Internal before any database work runs, so
// the audit row can never miss the tenant column it is filed under.
func TestEnvironmentServiceCloneRequiresActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)

	orgID := seedDomainOrg(t, db)
	projID := seedDomainProject(t, db, orgID)
	srcID := seedDomainEnvironment(t, db, orgID, projID, "production")

	svc, _, _, _ := newEnvironmentSvc(t, s)

	in := newCloneEnvironmentInput(orgID, srcID)
	in.ActorOrgID = ""

	_, err := svc.Clone(context.Background(), in)
	if err == nil {
		t.Fatal("missing actor org error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Errorf("code = %v, want %s", err, yerr.CodeInternal)
	}
}
