package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for EnvironmentService — the reference unit-of-work
// orchestrator for environment creation. They prove that the parent-project
// existence check, in-transaction authorization, quota reservation,
// desired-state write, provisioning-job enqueue, and audit append all share
// one transaction: a failure in any step rolls every other step back, and
// the checks cannot be bypassed. The Authorizer, QuotaReserver, and
// JobEnqueuer dependencies are exercised through the same recording* fakes
// used by ProjectService tests so the matrix of failure modes is uniform
// across creation orchestrators.

// newCreateEnvironmentInput builds a valid CreateEnvironmentInput for the
// (orgID, projectID) pair. ActorOrgID matches OrganizationID because the
// production wire path always pins the audit record to the principal's
// home organization, which is the tenant the principal authenticated
// into and the tenant the new environment is owned by.
func newCreateEnvironmentInput(orgID, projectID string) store.CreateEnvironmentInput {
	return store.CreateEnvironmentInput{
		OrganizationID: orgID,
		ProjectID:      projectID,
		EnvironmentID:  domain.MustNewID(domain.KindEnvironment).String(),
		Slug:           "production",
		DisplayName:    "Production",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_test_env",
		CorrelationID:  "corr_test_env",
	}
}

// listEnvironmentAuditEvents returns every audit event filed under
// organizationID — used by the success path test to prove the audit row
// commits inside the same transaction as the environment insert.
func listEnvironmentAuditEvents(t *testing.T, s *store.Store, organizationID string) []store.AuditEvent {
	t.Helper()
	var events []store.AuditEvent
	if err := s.Read(context.Background(), func(ctx context.Context, q store.Querier) error {
		var readErr error
		events, readErr = store.NewAuditRepository().ListByOrganization(ctx, q, organizationID, 50)
		return readErr
	}); err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	return events
}

// environmentExists reports whether an environment row identified by
// (orgID, projectID) with the given id is visible — used to assert commit
// and rollback outcomes.
func environmentExists(ctx context.Context, t *testing.T, s *store.Store, orgID, projectID, environmentID string) bool {
	t.Helper()
	repo := store.NewEnvironmentRepository()
	var found bool
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		envs, listErr := repo.ListByProject(ctx, q, orgID, projectID)
		if listErr != nil {
			return listErr
		}
		for _, e := range envs {
			if e.ID == environmentID {
				found = true
				return nil
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("environmentExists check: %v", err)
	}
	return found
}

func TestEnvironmentServiceCreateSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcSuccess")
	proj := seedProject(t, db, f, org, "Web")

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	in := newCreateEnvironmentInput(org.ID, proj.ID)
	created, err := svc.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create returned %v, want nil", err)
	}
	if created.ID != in.EnvironmentID || created.OrganizationID != org.ID || created.ProjectID != proj.ID {
		t.Errorf("Create returned %+v, want id %q in (%q,%q)", created, in.EnvironmentID, org.ID, proj.ID)
	}
	if created.Slug != "production" || created.DisplayName != "Production" || created.Version != 1 {
		t.Errorf("Create returned %+v, want slug=production, display=Production, version=1", created)
	}
	if authz.calls != 1 || quota.calls != 1 || jobs.calls != 1 {
		t.Errorf("step calls = authz:%d quota:%d jobs:%d, want 1 each", authz.calls, quota.calls, jobs.calls)
	}
	if !environmentExists(ctx, t, s, org.ID, proj.ID, in.EnvironmentID) {
		t.Error("Create succeeded but the environment row was not committed")
	}

	events := listEnvironmentAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the create", len(events))
	}
	ev := events[0]
	if ev.Action != "environment.create" {
		t.Errorf("audit action = %q, want environment.create", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != created.ID {
		t.Errorf("audit resource_id = %q, want the created environment id %q", ev.ResourceID, created.ID)
	}
	if ev.ResourceKind != string(domain.KindEnvironment) {
		t.Errorf("audit resource_kind = %q, want %q", ev.ResourceKind, domain.KindEnvironment)
	}
	if ev.ActorID != "usr_ada" || ev.ActorKind != "usr" {
		t.Errorf("audit actor = %q/%q, want usr_ada/usr", ev.ActorID, ev.ActorKind)
	}
	if ev.RequestID != "req_test_env" || ev.CorrelationID != "corr_test_env" {
		t.Errorf("audit correlation = %q/%q, want req_test_env/corr_test_env", ev.RequestID, ev.CorrelationID)
	}
	if got := ev.Metadata["slug"]; got != in.Slug {
		t.Errorf("audit metadata[slug] = %q, want %q", got, in.Slug)
	}
	if got := ev.Metadata["project_id"]; got != proj.ID {
		t.Errorf("audit metadata[project_id] = %q, want %q", got, proj.ID)
	}
}

// TestEnvironmentServiceCreateRequiresActorOrg proves a wiring error — an
// authenticated request that nonetheless reaches the service with no actor
// organization — is rejected as Internal before any database work runs, so
// the audit row can never miss the tenant column it is filed under.
func TestEnvironmentServiceCreateRequiresActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "EnvSvcActorOrg")
	proj := seedProject(t, db, f, org, "Web")

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	in := newCreateEnvironmentInput(org.ID, proj.ID)
	in.ActorOrgID = ""

	_, createErr := svc.Create(context.Background(), in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeInternal {
		t.Fatalf("Create(no actor org) error code = %v, want %s", createErr, yerr.CodeInternal)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("missing actor org still opened the transaction: authz:%d quota:%d jobs:%d",
			authz.calls, quota.calls, jobs.calls)
	}
}

func TestEnvironmentServiceCreateValidationFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	in := newCreateEnvironmentInput(
		domain.MustNewID(domain.KindOrganization).String(),
		domain.MustNewID(domain.KindProject).String(),
	)
	in.Slug = "Not A Slug!"
	in.DisplayName = ""

	_, createErr := svc.Create(context.Background(), in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("Create(invalid) error code = %v, want %s", createErr, yerr.CodeInvalidInput)
	}
	violations, ok := apierr.ViolationsOf(createErr)
	if !ok || len(violations) == 0 {
		t.Fatalf("Create(invalid) carried no field violations: ok=%v", ok)
	}
	// The violation message must name the offending field, never echo the
	// submitted value — a leaked value here would be a redaction regression.
	for _, v := range violations {
		if v.Field == "" {
			t.Errorf("violation %+v missing field name", v)
		}
		if v.Reason == "Not A Slug!" {
			t.Errorf("violation reason echoes submitted slug value: %q", v.Reason)
		}
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("validation failure still opened the transaction: authz:%d quota:%d jobs:%d",
			authz.calls, quota.calls, jobs.calls)
	}
}

// TestEnvironmentServiceCreateRejectsCrossTenantProject proves that the
// parent-project existence check is tenant-scoped: a project id that
// exists but belongs to a different organization surfaces as a typed
// apierr.NotFound, never as 403 or a 500 — the same shape the GET
// reader returns, so the boundary is identical on read and write.
func TestEnvironmentServiceCreateRejectsCrossTenantProject(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "EnvSvcCrossA")
	orgB := seedOrg(t, db, f, "EnvSvcCrossB")
	projB := seedProject(t, db, f, orgB, "B")

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	// (attacker home org id = orgA, foreign project id = projB.ID).
	in := newCreateEnvironmentInput(orgA.ID, projB.ID)
	_, createErr := svc.Create(ctx, in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Create(crossTenant) error code = %v, want %s", createErr, yerr.CodeNotFound)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("a cross-tenant project still ran authorize/quota/jobs: authz:%d quota:%d jobs:%d",
			authz.calls, quota.calls, jobs.calls)
	}
	if environmentExists(ctx, t, s, orgB.ID, projB.ID, in.EnvironmentID) {
		t.Error("a cross-tenant create still persisted an environment in the victim tenant")
	}
}

// TestEnvironmentServiceCreateUnknownProject proves that an unknown
// project id under the caller's own organization surfaces as
// apierr.NotFound without authorizing, reserving quota, or enqueueing —
// the project existence check runs first and short-circuits.
func TestEnvironmentServiceCreateUnknownProject(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "EnvSvcUnknownProj")

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	in := newCreateEnvironmentInput(org.ID, domain.MustNewID(domain.KindProject).String())
	_, createErr := svc.Create(context.Background(), in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Create(unknownProject) error code = %v, want %s", createErr, yerr.CodeNotFound)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("an unknown project still ran authorize/quota/jobs: authz:%d quota:%d jobs:%d",
			authz.calls, quota.calls, jobs.calls)
	}
}

func TestEnvironmentServiceCreateAuthorizationFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcAuthzDenied")
	proj := seedProject(t, db, f, org, "Web")

	authz := &recordingAuthorizer{err: apierr.Forbidden("environment.create denied")}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	in := newCreateEnvironmentInput(org.ID, proj.ID)
	_, createErr := svc.Create(ctx, in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeForbidden {
		t.Fatalf("Create error code = %v, want %s", createErr, yerr.CodeForbidden)
	}
	if quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("a denied authorization still ran later steps: quota:%d jobs:%d", quota.calls, jobs.calls)
	}
	if environmentExists(ctx, t, s, org.ID, proj.ID, in.EnvironmentID) {
		t.Error("a denied authorization still persisted the environment row")
	}
}

func TestEnvironmentServiceCreateQuotaFailureRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcQuotaDenied")
	proj := seedProject(t, db, f, org, "Web")

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{err: apierr.QuotaExceeded("environments", 3)}
	jobs := &recordingJobs{}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	in := newCreateEnvironmentInput(org.ID, proj.ID)
	_, createErr := svc.Create(ctx, in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("Create error code = %v, want %s", createErr, yerr.CodeQuotaExceeded)
	}
	if jobs.calls != 0 {
		t.Errorf("an exhausted quota still enqueued a job: jobs:%d", jobs.calls)
	}
	if environmentExists(ctx, t, s, org.ID, proj.ID, in.EnvironmentID) {
		t.Error("an exhausted quota still persisted the environment row")
	}
}

// TestEnvironmentServiceCreateEnqueueFailureRollsBack is the core
// transaction test: the desired-state write succeeds, but the
// provisioning-job enqueue — the next step of the unit of work — fails.
// The whole transaction must roll back, so the environment row that was
// already written inside the transaction is never committed. The system
// can never persist a resource without its job.
func TestEnvironmentServiceCreateEnqueueFailureRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcEnqueueRollback")
	proj := seedProject(t, db, f, org, "Web")

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{err: errors.New("durable job queue write failed")}
	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	in := newCreateEnvironmentInput(org.ID, proj.ID)
	if _, createErr := svc.Create(ctx, in); createErr == nil {
		t.Fatal("Create returned nil, want the enqueue failure")
	}
	if authz.calls != 1 || quota.calls != 1 || jobs.calls != 1 {
		t.Errorf("step calls = authz:%d quota:%d jobs:%d, want 1 each (the write must run before enqueue)",
			authz.calls, quota.calls, jobs.calls)
	}
	if environmentExists(ctx, t, s, org.ID, proj.ID, in.EnvironmentID) {
		t.Error("the environment row written before a failed enqueue was not rolled back")
	}

	// And the audit row written inside the same transaction is rolled back
	// too: a failed job enqueue must not leave a misleading audit trail
	// claiming an environment was created.
	if events := listEnvironmentAuditEvents(t, s, org.ID); len(events) != 0 {
		t.Errorf("audit events after rolled-back create = %d, want 0 (got %+v)", len(events), events)
	}
}

func TestEnvironmentServiceCreateConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "EnvSvcConflict")
	proj := seedProject(t, db, f, org, "Web")

	svc, err := store.NewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewEnvironmentService: %v", err)
	}

	first := newCreateEnvironmentInput(org.ID, proj.ID)
	if _, err := svc.Create(ctx, first); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	// Same slug, new environment id, same project.
	second := newCreateEnvironmentInput(org.ID, proj.ID)
	second.Slug = first.Slug
	_, createErr := svc.Create(ctx, second)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate-slug Create error code = %v, want %s", createErr, yerr.CodeConflict)
	}
	if environmentExists(ctx, t, s, org.ID, proj.ID, second.EnvironmentID) {
		t.Error("a conflicting Create still persisted the second environment row")
	}
}

func TestNewEnvironmentServiceRejectsNilDependencies(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	envRepo := store.NewEnvironmentRepository()
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	audit := store.NewAuditRepository()

	cases := []struct {
		name string
		ctor func() (*store.EnvironmentService, error)
	}{
		{"nil store", func() (*store.EnvironmentService, error) {
			return store.NewEnvironmentService(nil, repo, envRepo, authz, quota, jobs, audit)
		}},
		{"nil project repo", func() (*store.EnvironmentService, error) {
			return store.NewEnvironmentService(s, nil, envRepo, authz, quota, jobs, audit)
		}},
		{"nil env repo", func() (*store.EnvironmentService, error) {
			return store.NewEnvironmentService(s, repo, nil, authz, quota, jobs, audit)
		}},
		{"nil authz", func() (*store.EnvironmentService, error) {
			return store.NewEnvironmentService(s, repo, envRepo, nil, quota, jobs, audit)
		}},
		{"nil quota", func() (*store.EnvironmentService, error) {
			return store.NewEnvironmentService(s, repo, envRepo, authz, nil, jobs, audit)
		}},
		{"nil jobs", func() (*store.EnvironmentService, error) {
			return store.NewEnvironmentService(s, repo, envRepo, authz, quota, nil, audit)
		}},
		{"nil audit", func() (*store.EnvironmentService, error) {
			return store.NewEnvironmentService(s, repo, envRepo, authz, quota, jobs, nil)
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, err := tc.ctor()
			if err == nil {
				t.Fatalf("NewEnvironmentService(%s) returned svc=%v, err=nil; want a typed error", tc.name, svc)
			}
		})
	}
}
