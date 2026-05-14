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

// Integration tests for ProjectService — the reference unit-of-work
// orchestrator. They prove that the authorization, quota, write, and
// provisioning-job-enqueue steps share one transaction: a failure in any step
// rolls every other step back, and the checks cannot be bypassed. The
// authorization, quota, and job dependencies are exercised with recording
// fakes; the real implementations land in later stories.

// recordingAuthorizer is a fake Authorizer that records call count and returns
// a configured error.
type recordingAuthorizer struct {
	err   error
	calls int
}

func (a *recordingAuthorizer) Authorize(_ context.Context, _ store.Querier, _, _ string) error {
	a.calls++
	return a.err
}

// recordingQuota is a fake QuotaReserver that records call count and returns a
// configured error.
type recordingQuota struct {
	err   error
	calls int
}

func (q *recordingQuota) Reserve(_ context.Context, _ *store.Tx, _, _ string) error {
	q.calls++
	return q.err
}

// recordingJobs is a fake JobEnqueuer that records call count and returns a
// configured error.
type recordingJobs struct {
	err   error
	calls int
}

func (j *recordingJobs) Enqueue(_ context.Context, _ *store.Tx, _, _, _ string) error {
	j.calls++
	return j.err
}

// seedDomainOrg inserts an organization whose id is a real, canonical domain
// id (the testutil factory deliberately uses non-canonical prefixes, which the
// service's input validation correctly rejects). It returns the id.
func seedDomainOrg(t *testing.T, db *testutil.DB) string {
	t.Helper()
	id := domain.MustNewID(domain.KindOrganization).String()
	slug := "org-" + id[len(id)-12:]
	if _, err := db.Exec(context.Background(),
		`INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`,
		id, slug, "Test Organization"); err != nil {
		t.Fatalf("seed domain organization: %v", err)
	}
	return id
}

// newCreateInput builds a valid CreateProjectInput for org.
func newCreateInput(orgID string) store.CreateProjectInput {
	return store.CreateProjectInput{
		OrganizationID: orgID,
		ProjectID:      domain.MustNewID(domain.KindProject).String(),
		Slug:           "web-api",
		DisplayName:    "Web API",
	}
}

// projectExists reports whether a project row identified by (orgID, projectID)
// is visible — used to assert commit and rollback outcomes.
func projectExists(ctx context.Context, t *testing.T, s *store.Store, repo *store.ProjectRepository, orgID, projectID string) bool {
	t.Helper()
	var found bool
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.Get(ctx, q, orgID, projectID)
		if getErr == nil {
			found = true
			return nil
		}
		if yerr.From(getErr).Code == yerr.CodeNotFound {
			return nil
		}
		return getErr
	})
	if err != nil {
		t.Fatalf("projectExists check: %v", err)
	}
	return found
}

func TestProjectServiceCreateSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewProjectService(s, repo, authz, quota, jobs)
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	in := newCreateInput(orgID)

	created, err := svc.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create returned %v, want nil", err)
	}
	if created.ID != in.ProjectID || created.OrganizationID != orgID {
		t.Errorf("Create returned %+v, want id %q in org %q", created, in.ProjectID, orgID)
	}
	if authz.calls != 1 || quota.calls != 1 || jobs.calls != 1 {
		t.Errorf("step calls = authz:%d quota:%d jobs:%d, want 1 each", authz.calls, quota.calls, jobs.calls)
	}
	if !projectExists(ctx, t, s, repo, orgID, in.ProjectID) {
		t.Error("Create succeeded but the project row was not committed")
	}
}

func TestProjectServiceCreateValidationFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewProjectService(s, store.NewProjectRepository(), authz, quota, jobs)
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}

	in := newCreateInput(domain.MustNewID(domain.KindOrganization).String())
	in.Slug = "Not A Slug!"
	in.DisplayName = ""

	_, createErr := svc.Create(context.Background(), in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("Create(invalid) error code = %v, want %s", createErr, yerr.CodeInvalidInput)
	}
	if violations, ok := apierr.ViolationsOf(createErr); !ok || len(violations) == 0 {
		t.Errorf("Create(invalid) carried no field violations: ok=%v", ok)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("validation failure still opened the transaction: authz:%d quota:%d jobs:%d",
			authz.calls, quota.calls, jobs.calls)
	}
}

func TestProjectServiceCreateAuthorizationFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	authz := &recordingAuthorizer{err: apierr.Forbidden("project.create denied")}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewProjectService(s, repo, authz, quota, jobs)
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	in := newCreateInput(orgID)

	_, createErr := svc.Create(ctx, in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeForbidden {
		t.Fatalf("Create error code = %v, want %s", createErr, yerr.CodeForbidden)
	}
	if quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("a denied authorization still ran later steps: quota:%d jobs:%d", quota.calls, jobs.calls)
	}
	if projectExists(ctx, t, s, repo, orgID, in.ProjectID) {
		t.Error("a denied authorization still persisted the project row")
	}
}

func TestProjectServiceCreateQuotaFailureRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{err: apierr.QuotaExceeded("projects", 5)}
	jobs := &recordingJobs{}
	svc, err := store.NewProjectService(s, repo, authz, quota, jobs)
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	in := newCreateInput(orgID)

	_, createErr := svc.Create(ctx, in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeQuotaExceeded {
		t.Fatalf("Create error code = %v, want %s", createErr, yerr.CodeQuotaExceeded)
	}
	if jobs.calls != 0 {
		t.Errorf("an exhausted quota still enqueued a job: jobs:%d", jobs.calls)
	}
	if projectExists(ctx, t, s, repo, orgID, in.ProjectID) {
		t.Error("an exhausted quota still persisted the project row")
	}
}

// TestProjectServiceCreateEnqueueFailureRollsBack is the core transaction
// test: the desired-state write succeeds, but the provisioning-job enqueue —
// the last step of the unit of work — fails. The whole transaction must roll
// back, so the project row that was already written inside the transaction is
// never committed. The system can never persist a resource without its job.
func TestProjectServiceCreateEnqueueFailureRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{err: errors.New("durable job queue write failed")}
	svc, err := store.NewProjectService(s, repo, authz, quota, jobs)
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	in := newCreateInput(orgID)

	if _, createErr := svc.Create(ctx, in); createErr == nil {
		t.Fatal("Create returned nil, want the enqueue failure")
	}
	if authz.calls != 1 || quota.calls != 1 || jobs.calls != 1 {
		t.Errorf("step calls = authz:%d quota:%d jobs:%d, want 1 each (the write must run before enqueue)",
			authz.calls, quota.calls, jobs.calls)
	}
	if projectExists(ctx, t, s, repo, orgID, in.ProjectID) {
		t.Error("the project row written before a failed enqueue was not rolled back")
	}

	var count int
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var cErr error
		count, cErr = repo.CountByOrganization(ctx, q, orgID)
		return cErr
	}); err != nil {
		t.Fatalf("count after rollback: %v", err)
	}
	if count != 0 {
		t.Errorf("project count after rolled-back create = %d, want 0", count)
	}
}

func TestProjectServiceCreateConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{})
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	first := newCreateInput(orgID)
	if _, err := svc.Create(ctx, first); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	// Same slug, new project id, same organization.
	second := newCreateInput(orgID)
	second.Slug = first.Slug
	_, createErr := svc.Create(ctx, second)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate-slug Create error code = %v, want %s", createErr, yerr.CodeConflict)
	}
	if projectExists(ctx, t, s, repo, orgID, second.ProjectID) {
		t.Error("a conflicting Create still persisted the second project row")
	}
}
