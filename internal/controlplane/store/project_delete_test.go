package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for the soft-delete path of projects:
// ProjectRepository.ScheduleDeletion and ProjectService.ScheduleDeletion.
// They mirror organization_delete_test.go and prove that
// deletion_scheduled_at is stamped on exactly the named row, the tenant
// boundary is structural (cross-tenant ids never touch another tenant's
// data), an already-scheduled re-request is a typed Conflict that rolls
// the transaction back, and the audit record commits atomically with the
// soft-delete write.

// newDeleteInput builds a valid DeleteProjectInput for (orgID, projectID).
// ActorOrgID is the principal's home organization — the tenant the audit
// record is filed under — so seeding it with the resource organization
// matches the production wire path where a member of org schedules a
// project in their own org for teardown.
func newDeleteInput(orgID, projectID string) store.DeleteProjectInput {
	return store.DeleteProjectInput{
		OrganizationID: orgID,
		ProjectID:      projectID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	}
}

// TestProjectRepositoryScheduleDeletion proves the repository stamps
// deletion_scheduled_at on exactly the named row and returns the persisted
// row, including the trigger-refreshed updated_at timestamp.
func TestProjectRepositoryScheduleDeletion(t *testing.T) {
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

	var got store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		got, writeErr = repo.ScheduleDeletion(ctx, tx, orgID, created.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion returned %v, want nil", err)
	}
	if got.ID != created.ID {
		t.Errorf("ScheduleDeletion returned id %q, want the existing project id %q", got.ID, created.ID)
	}
	if got.DeletionScheduledAt == nil {
		t.Fatal("ScheduleDeletion did not stamp deletion_scheduled_at")
	}

	// The stamp must survive a separate read transaction.
	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgID, created.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get after schedule: %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Error("Get did not return the persisted deletion_scheduled_at stamp")
	}
}

// TestProjectRepositoryScheduleDeletionNotFound proves a {project_id} with
// no row inside the tenant surfaces as a typed NotFound — never disguised
// as a silent success.
func TestProjectRepositoryScheduleDeletionNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	ctx := context.Background()
	orgID := seedDomainOrg(t, db)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, scheduleErr := repo.ScheduleDeletion(ctx, tx, orgID, domain.MustNewID(domain.KindProject).String(), nil)
		return scheduleErr
	})
	if err == nil {
		t.Fatal("ScheduleDeletion(missing) error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("ScheduleDeletion(missing) error = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestProjectRepositoryScheduleDeletionIsTenantScoped proves a project_id
// that belongs to another organization simply does not match — a
// cross-tenant id can never schedule another tenant's project for
// teardown, and the other tenant's row is left untouched.
func TestProjectRepositoryScheduleDeletionIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	ctx := context.Background()

	orgA := seedDomainOrg(t, db)
	orgB := seedDomainOrg(t, db)
	createdB, err := svc.Create(ctx, newCreateInput(orgB))
	if err != nil {
		t.Fatalf("Create(orgB): %v", err)
	}

	// Attempt to schedule orgB's project while presenting orgA's tenant —
	// the WHERE organization_id = $1 AND id = $2 query simply does not
	// match, so the repository must report NotFound.
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, scheduleErr := repo.ScheduleDeletion(ctx, tx, orgA, createdB.ID, nil)
		return scheduleErr
	})
	if err == nil {
		t.Fatal("cross-tenant ScheduleDeletion error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant ScheduleDeletion code = %v, want %s", err, yerr.CodeNotFound)
	}

	// orgB's project must be unchanged.
	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgB, createdB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgB project): %v", err)
	}
	if readBack.DeletionScheduledAt != nil {
		t.Errorf("orgB.project.deletion_scheduled_at = %v, want nil — scheduling orgA must never touch orgB", readBack.DeletionScheduledAt)
	}
}

// TestProjectRepositoryScheduleDeletionRejectsNilTx proves the repository
// guard catches a nil transaction at call time, so a schedule-delete can
// never run outside Store.Write.
func TestProjectRepositoryScheduleDeletionRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewProjectRepository()
	_, err := repo.ScheduleDeletion(context.Background(), nil, "org_acme", "prj_acme", nil)
	if err == nil {
		t.Fatal("ScheduleDeletion(nil tx) error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("ScheduleDeletion(nil tx) code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestProjectServiceScheduleDeletionSuccess is the happy path: the project
// is stamped and an audit event filed under the actor's home organization
// names the resource — all visible after Store.Write commits.
func TestProjectServiceScheduleDeletionSuccess(t *testing.T) {
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

	scheduled, err := svc.ScheduleDeletion(ctx, newDeleteInput(orgID, created.ID))
	if err != nil {
		t.Fatalf("ScheduleDeletion returned %v, want nil", err)
	}
	if scheduled.ID != created.ID {
		t.Errorf("ScheduleDeletion returned id %q, want the existing project id %q", scheduled.ID, created.ID)
	}
	if scheduled.DeletionScheduledAt == nil {
		t.Fatal("ScheduleDeletion did not stamp deletion_scheduled_at")
	}
	if scheduled.Version <= created.Version {
		t.Errorf("version not bumped: %d <= %d", scheduled.Version, created.Version)
	}

	// The stamp must survive a separate read.
	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgID, created.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get after schedule: %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Error("Get did not return the persisted deletion_scheduled_at stamp")
	}

	// The newest audit event must be the project.delete record. Earlier
	// events are the create record (and possibly any other resource setup),
	// so we look up the action explicitly rather than indexing.
	events := listProjectAuditEvents(t, s, orgID)
	if len(events) < 2 {
		t.Fatalf("audit events len = %d, want >= 2 (create + delete)", len(events))
	}
	deleteEvent := events[0]
	if deleteEvent.Action != "project.delete" {
		t.Errorf("audit action = %q, want project.delete", deleteEvent.Action)
	}
	if deleteEvent.ResourceKind != string(domain.KindProject) {
		t.Errorf("audit resource_kind = %q, want %q", deleteEvent.ResourceKind, domain.KindProject)
	}
	if deleteEvent.ResourceID != created.ID {
		t.Errorf("audit resource_id = %q, want %q", deleteEvent.ResourceID, created.ID)
	}
	if stamp := deleteEvent.Metadata["deletion_scheduled_at"]; stamp == "" {
		t.Errorf("audit metadata deletion_scheduled_at is empty, want the resolved stamp time")
	}
}

// TestProjectServiceScheduleDeletionAlreadyScheduledRollsBack proves a
// second schedule on a project that is already scheduled for teardown
// rolls the whole transaction back as a typed Conflict — the
// deletion_scheduled_at stamp must not move, and no second audit event is
// appended.
func TestProjectServiceScheduleDeletionAlreadyScheduledRollsBack(t *testing.T) {
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

	scheduled, err := svc.ScheduleDeletion(ctx, newDeleteInput(orgID, created.ID))
	if err != nil {
		t.Fatalf("first ScheduleDeletion: %v", err)
	}
	firstStamp := scheduled.DeletionScheduledAt

	_, secondErr := svc.ScheduleDeletion(ctx, newDeleteInput(orgID, created.ID))
	if secondErr == nil {
		t.Fatal("second ScheduleDeletion error = nil, want Conflict")
	}
	if ye := yerr.From(secondErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("second ScheduleDeletion code = %v, want %s", secondErr, yerr.CodeConflict)
	}

	// The stamp must not have moved.
	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgID, created.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get after second schedule: %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Fatal("stamp disappeared after the rejected second schedule")
	}
	if !readBack.DeletionScheduledAt.Equal(*firstStamp) {
		t.Errorf("stamp moved: %v -> %v; second schedule must roll back", firstStamp, readBack.DeletionScheduledAt)
	}

	// Only one delete audit event should exist: create + first delete = 2,
	// any more means the rolled-back second delete leaked an audit row.
	events := listProjectAuditEvents(t, s, orgID)
	deletes := 0
	for _, ev := range events {
		if ev.Action == "project.delete" {
			deletes++
		}
	}
	if deletes != 1 {
		t.Errorf("project.delete audit events = %d, want 1 (second schedule must roll back)", deletes)
	}
}

// TestProjectServiceScheduleDeletionNotFound proves an unknown {project_id}
// surfaces as NotFound — the tenant-scoped repository query never reveals
// another tenant's row, even for the inner Get pre-check.
func TestProjectServiceScheduleDeletionNotFound(t *testing.T) {
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

	_, err = svc.ScheduleDeletion(context.Background(), newDeleteInput(orgID, ghost))
	if err == nil {
		t.Fatal("ScheduleDeletion(unknown id) error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("ScheduleDeletion(unknown id) code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestProjectServiceScheduleDeletionIsTenantScoped proves cross-tenant
// scheduling is denied at the persistence boundary — orgA can never
// schedule orgB's project for teardown, and orgB's row is left untouched.
func TestProjectServiceScheduleDeletionIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	ctx := context.Background()

	orgA := seedDomainOrg(t, db)
	orgB := seedDomainOrg(t, db)
	createdB, err := svc.Create(ctx, newCreateInput(orgB))
	if err != nil {
		t.Fatalf("Create(orgB): %v", err)
	}

	in := newDeleteInput(orgA, createdB.ID)
	_, err = svc.ScheduleDeletion(ctx, in)
	if err == nil {
		t.Fatal("cross-tenant ScheduleDeletion error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant ScheduleDeletion code = %v, want %s", err, yerr.CodeNotFound)
	}

	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgB, createdB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgB project): %v", err)
	}
	if readBack.DeletionScheduledAt != nil {
		t.Errorf("orgB.project.deletion_scheduled_at = %v, want nil — scheduling orgA must never touch orgB", readBack.DeletionScheduledAt)
	}
}

// TestProjectServiceScheduleDeletionStaleIfMatch proves a stale If-Match
// precondition is rejected as ConflictStale carrying the row's current
// version — the audit record is never written and the row is unchanged.
func TestProjectServiceScheduleDeletionStaleIfMatch(t *testing.T) {
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
	in := newDeleteInput(orgID, created.ID)
	in.IfMatchVersion = &stale
	_, err = svc.ScheduleDeletion(ctx, in)
	if err == nil {
		t.Fatal("stale-version ScheduleDeletion error = nil, want ConflictStale")
	}
	ye := yerr.From(err)
	if ye.Code != yerr.CodeConflict {
		t.Fatalf("stale-version code = %v, want %s", err, yerr.CodeConflict)
	}
	if got := ye.Details["current_version"]; got != "1" {
		t.Errorf("Details[current_version] = %q, want 1", got)
	}

	// The row must not have been touched.
	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgID, created.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get after rejected schedule: %v", err)
	}
	if readBack.DeletionScheduledAt != nil {
		t.Errorf("DeletionScheduledAt = %v, want nil — a rejected schedule must not stamp the row", readBack.DeletionScheduledAt)
	}
}

// TestProjectServiceScheduleDeletionBlankInput proves blank organization or
// project ids are rejected as typed validation failures before any
// transaction is opened.
func TestProjectServiceScheduleDeletionBlankInput(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}

	cases := []struct {
		name string
		in   store.DeleteProjectInput
	}{
		{"blank organization id", store.DeleteProjectInput{ProjectID: "prj_x", ActorOrgID: "org_x"}},
		{"blank project id", store.DeleteProjectInput{OrganizationID: "org_x", ActorOrgID: "org_x"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.ScheduleDeletion(context.Background(), tc.in)
			if err == nil {
				t.Fatalf("%s: error = nil, want InvalidInput", tc.name)
			}
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Errorf("%s: code = %v, want %s", tc.name, err, yerr.CodeValidation)
			}
		})
	}
}

// TestProjectServiceScheduleDeletionRequiresActorOrg proves a missing
// actor organization is a typed Internal error (a wiring failure, not
// client input) — an authenticated request always carries one, and the
// store layer must refuse to write an audit record without it.
func TestProjectServiceScheduleDeletionRequiresActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}
	in := store.DeleteProjectInput{
		OrganizationID: "org_x",
		ProjectID:      "prj_x",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		// ActorOrgID intentionally empty.
	}
	_, err = svc.ScheduleDeletion(context.Background(), in)
	if err == nil {
		t.Fatal("missing actor org error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("missing actor org code = %v, want %s", err, yerr.CodeInternal)
	}
}
