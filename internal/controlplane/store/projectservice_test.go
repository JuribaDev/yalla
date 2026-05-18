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

func (q *recordingQuota) ReserveAmount(_ context.Context, _ *store.Tx, _, _ string, _ int64) error {
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

// newCreateInput builds a valid CreateProjectInput for org. ActorOrgID is the
// principal's home organization — the tenant the audit record is filed under
// — so seeding it with the resource organization matches the production wire
// path where a member of org creates a project in their own org.
func newCreateInput(orgID string) store.CreateProjectInput {
	return store.CreateProjectInput{
		OrganizationID: orgID,
		ProjectID:      domain.MustNewID(domain.KindProject).String(),
		Slug:           "web-api",
		DisplayName:    "Web API",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	}
}

// listProjectAuditEvents returns every audit event filed under organizationID
// — used by the success path test to prove the audit row commits inside the
// same transaction as the project insert.
func listProjectAuditEvents(t *testing.T, s *store.Store, organizationID string) []store.AuditEvent {
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
	svc, err := store.NewProjectService(s, repo, authz, quota, jobs, store.NewAuditRepository())
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

	// The audit record commits inside the same transaction as the insert: a
	// created project can never exist without its audit trail.
	events := listProjectAuditEvents(t, s, orgID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the create", len(events))
	}
	ev := events[0]
	if ev.Action != "project.create" {
		t.Errorf("audit action = %q, want project.create", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != created.ID {
		t.Errorf("audit resource_id = %q, want the created project id %q", ev.ResourceID, created.ID)
	}
	if ev.ActorID != "usr_ada" || ev.ActorKind != "usr" {
		t.Errorf("audit actor = %q/%q, want usr_ada/usr", ev.ActorID, ev.ActorKind)
	}
	if ev.RequestID != "req_test" || ev.CorrelationID != "corr_test" {
		t.Errorf("audit correlation = %q/%q, want req_test/corr_test", ev.RequestID, ev.CorrelationID)
	}
	if got := ev.Metadata["slug"]; got != in.Slug {
		t.Errorf("audit metadata[slug] = %q, want %q", got, in.Slug)
	}
}

// TestProjectServiceCreateRequiresActorOrg proves a wiring error — an
// authenticated request that nonetheless reaches the service with no actor
// organization — is rejected as Internal before any database work runs, so
// the audit row can never miss the tenant column it is filed under.
func TestProjectServiceCreateRequiresActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewProjectService(s, repo, authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}

	orgID := seedDomainOrg(t, db)
	in := newCreateInput(orgID)
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

func TestProjectServiceCreateValidationFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc, err := store.NewProjectService(s, store.NewProjectRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}

	in := newCreateInput(domain.MustNewID(domain.KindOrganization).String())
	in.Slug = "Not A Slug!"
	in.DisplayName = ""

	_, createErr := svc.Create(context.Background(), in)
	if ye := yerr.From(createErr); ye.Code != yerr.CodeValidation {
		t.Fatalf("Create(invalid) error code = %v, want %s", createErr, yerr.CodeValidation)
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
	svc, err := store.NewProjectService(s, repo, authz, quota, jobs, store.NewAuditRepository())
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
	svc, err := store.NewProjectService(s, repo, authz, quota, jobs, store.NewAuditRepository())
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
	svc, err := store.NewProjectService(s, repo, authz, quota, jobs, store.NewAuditRepository())
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
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
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

// newUpdateInput builds a partial-update UpdateProjectInput for project
// projectID inside orgID. Slug and DisplayName are nil by default; the
// caller flips them on per test.
func newUpdateInput(orgID, projectID string) store.UpdateProjectInput {
	return store.UpdateProjectInput{
		OrganizationID: orgID,
		ProjectID:      projectID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_test_update",
		CorrelationID:  "corr_test_update",
	}
}

// strPtr returns a pointer to s — used to populate the optional Slug and
// DisplayName fields of UpdateProjectInput in test payloads.
func strPtr(s string) *string { return &s }

// TestProjectServiceUpdateSuccess proves the update-project unit of work
// commits desired-state and the immutable audit record in one transaction:
// the row is mutated, its version is bumped, and an audit event filed under
// the actor's home organization names the new resource — all visible after
// the Write tx commits.
func TestProjectServiceUpdateSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	ctx := context.Background()

	orgID := seedDomainOrg(t, db)
	create := newCreateInput(orgID)
	created, err := svc.Create(ctx, create)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	in := newUpdateInput(orgID, created.ID)
	in.Slug = strPtr("web-v2")
	in.DisplayName = strPtr("Web v2")
	updated, err := svc.Update(ctx, in)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Slug != "web-v2" || updated.DisplayName != "Web v2" {
		t.Errorf("updated = %+v, want slug=web-v2 display_name=Web v2", updated)
	}
	if updated.Version <= created.Version {
		t.Errorf("version not bumped: %d <= %d", updated.Version, created.Version)
	}

	events := listProjectAuditEvents(t, s, orgID)
	// Newest event is the update; the create event sits at index 1.
	if len(events) < 2 {
		t.Fatalf("audit events len = %d, want >= 2", len(events))
	}
	updateEvent := events[0]
	if updateEvent.Action != "project.update" {
		t.Errorf("audit action = %q, want project.update", updateEvent.Action)
	}
	if updateEvent.ResourceID != created.ID {
		t.Errorf("audit resource_id = %q, want %q", updateEvent.ResourceID, created.ID)
	}
	if got := updateEvent.Metadata["updated_fields"]; got != "slug,display_name" {
		t.Errorf("audit metadata updated_fields = %q, want slug,display_name", got)
	}
}

// TestProjectServiceUpdateRejectsEmptyPatch proves an Update that names no
// updatable field is a typed validation failure raised before any
// transaction is opened — a mutation that changes nothing is a client
// error, not a silent success that would write a misleading audit record.
func TestProjectServiceUpdateRejectsEmptyPatch(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	orgID := seedDomainOrg(t, db)
	created, err := svc.Create(context.Background(), newCreateInput(orgID))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	in := newUpdateInput(orgID, created.ID)
	_, updErr := svc.Update(context.Background(), in)
	if updErr == nil {
		t.Fatal("empty-patch Update error = nil, want InvalidInput")
	}
	if ye := yerr.From(updErr); ye.Code != yerr.CodeValidation {
		t.Fatalf("empty-patch Update error code = %v, want %s", updErr, yerr.CodeValidation)
	}
}

// TestProjectServiceUpdateNotFound proves an unknown {project_id} surfaces
// as a deterministic NotFound — the tenant-scoped repository query never
// reveals another tenant's row, even for the inner Get pre-check.
func TestProjectServiceUpdateNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	orgID := seedDomainOrg(t, db)
	ghost := domain.MustNewID(domain.KindProject).String()

	in := newUpdateInput(orgID, ghost)
	in.DisplayName = strPtr("Ghost")
	_, updErr := svc.Update(context.Background(), in)
	if updErr == nil {
		t.Fatal("Update(unknown id) error = nil, want NotFound")
	}
	if ye := yerr.From(updErr); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Update(unknown id) error code = %v, want %s", updErr, yerr.CodeNotFound)
	}
}

// TestProjectServiceUpdateStaleIfMatch proves a stale If-Match precondition
// rolls the transaction back as ConflictStale carrying the row's current
// version — the audit record is never written and the row is unchanged.
func TestProjectServiceUpdateStaleIfMatch(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	ctx := context.Background()
	orgID := seedDomainOrg(t, db)
	created, err := svc.Create(ctx, newCreateInput(orgID))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	stale := int64(99)
	in := newUpdateInput(orgID, created.ID)
	in.DisplayName = strPtr("Stale Update")
	in.IfMatchVersion = &stale
	_, updErr := svc.Update(ctx, in)
	if updErr == nil {
		t.Fatal("stale-version Update error = nil, want ConflictStale")
	}
	ye := yerr.From(updErr)
	if ye.Code != yerr.CodeConflict {
		t.Fatalf("stale-version Update code = %v, want %s", updErr, yerr.CodeConflict)
	}
	if got := ye.Details["current_version"]; got != "1" {
		t.Errorf("Details[current_version] = %q, want 1", got)
	}

	// The row was not touched: only the create audit event exists.
	if events := listProjectAuditEvents(t, s, orgID); len(events) != 1 {
		t.Errorf("audit events after stale update = %d, want 1 (only create)", len(events))
	}
}

// TestProjectServiceUpdateInvalidSlug proves a syntactically invalid slug
// in the patch is rejected as a typed validation failure before any
// transaction is opened — the field path is "slug", never the submitted
// value.
func TestProjectServiceUpdateInvalidSlug(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	orgID := seedDomainOrg(t, db)
	created, err := svc.Create(context.Background(), newCreateInput(orgID))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	in := newUpdateInput(orgID, created.ID)
	in.Slug = strPtr("Not A Slug")
	_, updErr := svc.Update(context.Background(), in)
	if updErr == nil {
		t.Fatal("invalid-slug Update error = nil, want InvalidInput")
	}
	if ye := yerr.From(updErr); ye.Code != yerr.CodeValidation {
		t.Fatalf("invalid-slug Update code = %v, want %s", updErr, yerr.CodeValidation)
	}
}
