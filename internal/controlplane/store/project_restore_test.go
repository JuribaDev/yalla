package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for the soft-delete restore path of projects:
// ProjectRepository.Restore and ProjectService.Restore. They mirror
// project_delete_test.go and prove that deletion_scheduled_at is cleared on
// exactly the named row, the tenant boundary is structural (cross-tenant
// ids never touch another tenant's row), the audit record is committed
// atomically with the clear-stamp write, and the restore is rejected as
// Conflict when the project was never scheduled for deletion.

// newRestoreInput builds a valid RestoreProjectInput for (orgID, projectID).
// ActorOrgID is the principal's home organization — the tenant the audit
// record is filed under — so seeding it with the resource organization
// matches the production wire path where a member of org restores a project
// in their own org from soft-deletion.
func newRestoreInput(orgID, projectID string) store.RestoreProjectInput {
	return store.RestoreProjectInput{
		OrganizationID: orgID,
		ProjectID:      projectID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	}
}

// TestProjectRepositoryRestore proves the repository clears
// deletion_scheduled_at on exactly the named row and returns the persisted
// row, including the trigger-refreshed updated_at timestamp.
func TestProjectRepositoryRestore(t *testing.T) {
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
	if _, err := svc.ScheduleDeletion(ctx, newDeleteInput(orgID, created.ID)); err != nil {
		t.Fatalf("ScheduleDeletion: %v", err)
	}

	var got store.Project
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		got, writeErr = repo.Restore(ctx, tx, orgID, created.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Restore returned %v, want nil", err)
	}
	if got.ID != created.ID {
		t.Errorf("Restore returned id %q, want the existing project id %q", got.ID, created.ID)
	}
	if got.DeletionScheduledAt != nil {
		t.Errorf("Restore did not clear deletion_scheduled_at: %v", got.DeletionScheduledAt)
	}

	// The cleared stamp must survive a separate read transaction.
	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgID, created.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get after restore: %v", err)
	}
	if readBack.DeletionScheduledAt != nil {
		t.Error("Get returned a still-stamped deletion_scheduled_at after restore")
	}
}

// TestProjectRepositoryRestoreIsTenantScoped proves the repository's
// WHERE organization_id clause makes a cross-tenant restore impossible:
// orgA cannot restore orgB's project — the query simply does not match — a
// cross-tenant id can never restore another tenant's project, and the
// other tenant's row is left untouched.
func TestProjectRepositoryRestoreIsTenantScoped(t *testing.T) {
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
	if _, err := svc.ScheduleDeletion(ctx, newDeleteInput(orgB, createdB.ID)); err != nil {
		t.Fatalf("ScheduleDeletion(orgB): %v", err)
	}

	// Attempt to restore orgB's project while presenting orgA's tenant —
	// the WHERE organization_id = $1 AND id = $2 query simply does not
	// match, so the repository must report NotFound.
	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, restoreErr := repo.Restore(ctx, tx, orgA, createdB.ID, nil)
		return restoreErr
	})
	if err == nil {
		t.Fatal("cross-tenant Restore error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Restore code = %v, want %s", err, yerr.CodeNotFound)
	}

	// orgB's project must still be soft-deleted.
	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgB, createdB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgB project): %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Errorf("orgB.project.deletion_scheduled_at cleared by cross-tenant restore; want stamp preserved")
	}
}

// TestProjectRepositoryRestoreRejectsNilTx proves the repository guard
// catches a nil transaction at call time, so a restore can never run
// outside Store.Write.
func TestProjectRepositoryRestoreRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewProjectRepository()
	_, err := repo.Restore(context.Background(), nil, "org_acme", "prj_acme", nil)
	if err == nil {
		t.Fatal("Restore(nil tx) error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Restore(nil tx) code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestProjectServiceRestoreSuccess is the happy path: a soft-deleted
// project is restored to live state and an audit event filed under the
// actor's home organization names the resource — all visible after
// Store.Write commits.
func TestProjectServiceRestoreSuccess(t *testing.T) {
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
		t.Fatalf("ScheduleDeletion: %v", err)
	}
	if scheduled.DeletionScheduledAt == nil {
		t.Fatal("test setup: ScheduleDeletion did not stamp deletion_scheduled_at")
	}

	restored, err := svc.Restore(ctx, newRestoreInput(orgID, created.ID))
	if err != nil {
		t.Fatalf("Restore returned %v, want nil", err)
	}
	if restored.ID != created.ID {
		t.Errorf("Restore returned id %q, want the existing project id %q", restored.ID, created.ID)
	}
	if restored.DeletionScheduledAt != nil {
		t.Errorf("Restore did not clear deletion_scheduled_at: %v", restored.DeletionScheduledAt)
	}
	if restored.Version <= scheduled.Version {
		t.Errorf("version not bumped: %d <= %d", restored.Version, scheduled.Version)
	}

	// The cleared stamp must survive a separate read.
	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgID, created.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get after restore: %v", err)
	}
	if readBack.DeletionScheduledAt != nil {
		t.Error("Get returned a still-stamped deletion_scheduled_at after restore")
	}

	// The newest audit event must be the project.restore record. Earlier
	// events are create + delete; restore is the third.
	events := listProjectAuditEvents(t, s, orgID)
	if len(events) < 3 {
		t.Fatalf("audit events len = %d, want >= 3 (create + delete + restore)", len(events))
	}
	restoreEvent := events[0]
	if restoreEvent.Action != "project.restore" {
		t.Errorf("audit action = %q, want project.restore", restoreEvent.Action)
	}
	if restoreEvent.ResourceKind != string(domain.KindProject) {
		t.Errorf("audit resource_kind = %q, want %q", restoreEvent.ResourceKind, domain.KindProject)
	}
	if restoreEvent.ResourceID != created.ID {
		t.Errorf("audit resource_id = %q, want %q", restoreEvent.ResourceID, created.ID)
	}
	if stamp := restoreEvent.Metadata["deletion_scheduled_at"]; stamp == "" {
		t.Errorf("audit metadata deletion_scheduled_at is empty, want the prior stamp captured before restore")
	}
}

// TestProjectServiceRestoreNotScheduledRollsBack proves a restore on a
// project that was never scheduled for deletion rolls the whole
// transaction back as a typed Conflict — no audit record is appended.
func TestProjectServiceRestoreNotScheduledRollsBack(t *testing.T) {
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

	_, restoreErr := svc.Restore(ctx, newRestoreInput(orgID, created.ID))
	if restoreErr == nil {
		t.Fatal("Restore(live project) error = nil, want Conflict")
	}
	if ye := yerr.From(restoreErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("Restore(live project) code = %v, want %s", restoreErr, yerr.CodeConflict)
	}

	// No project.restore audit event must have been appended.
	events := listProjectAuditEvents(t, s, orgID)
	for _, ev := range events {
		if ev.Action == "project.restore" {
			t.Errorf("project.restore audit event leaked from rolled-back restore: %+v", ev)
		}
	}
}

// TestProjectServiceRestoreNotFound proves an unknown {project_id} surfaces
// as NotFound — the tenant-scoped repository query never reveals another
// tenant's row, even for the inner Get pre-check.
func TestProjectServiceRestoreNotFound(t *testing.T) {
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

	_, err = svc.Restore(context.Background(), newRestoreInput(orgID, ghost))
	if err == nil {
		t.Fatal("Restore(unknown id) error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Restore(unknown id) code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestProjectServiceRestoreIsTenantScoped proves cross-tenant restore is
// denied at the persistence boundary — orgA can never restore orgB's
// project, and orgB's row is left untouched.
func TestProjectServiceRestoreIsTenantScoped(t *testing.T) {
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
	if _, err := svc.ScheduleDeletion(ctx, newDeleteInput(orgB, createdB.ID)); err != nil {
		t.Fatalf("ScheduleDeletion(orgB): %v", err)
	}

	in := newRestoreInput(orgA, createdB.ID)
	_, err = svc.Restore(ctx, in)
	if err == nil {
		t.Fatal("cross-tenant Restore error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Restore code = %v, want %s", err, yerr.CodeNotFound)
	}

	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgB, createdB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get(orgB project): %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Errorf("orgB.project.deletion_scheduled_at cleared by cross-tenant restore; want stamp preserved")
	}
}

// TestProjectServiceRestoreStaleIfMatch proves a stale If-Match
// precondition is rejected as ConflictStale carrying the row's current
// version — the audit record is never written and the row is unchanged.
func TestProjectServiceRestoreStaleIfMatch(t *testing.T) {
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
	if _, err := svc.ScheduleDeletion(ctx, newDeleteInput(orgID, created.ID)); err != nil {
		t.Fatalf("ScheduleDeletion: %v", err)
	}

	stale := int64(99)
	in := newRestoreInput(orgID, created.ID)
	in.IfMatchVersion = &stale
	_, err = svc.Restore(ctx, in)
	if err == nil {
		t.Fatal("stale-version Restore error = nil, want ConflictStale")
	}
	ye := yerr.From(err)
	if ye.Code != yerr.CodeConflict {
		t.Fatalf("stale-version code = %v, want %s", err, yerr.CodeConflict)
	}
	if got := ye.Details["current_version"]; got == "" {
		t.Errorf("Details[current_version] is empty, want the row's authoritative version")
	}

	// The row must not have been touched.
	var readBack store.Project
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.Get(ctx, q, orgID, created.ID)
		return readErr
	}); err != nil {
		t.Fatalf("Get after rejected restore: %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Errorf("orgID.project.deletion_scheduled_at cleared by rejected stale-version restore; want stamp preserved")
	}

	// No project.restore audit event must exist.
	events := listProjectAuditEvents(t, s, orgID)
	for _, ev := range events {
		if ev.Action == "project.restore" {
			t.Errorf("project.restore audit event leaked from rolled-back restore: %+v", ev)
		}
	}
}

// TestProjectServiceRestoreBlankInputRejected proves a blank
// OrganizationID or ProjectID is a typed InvalidInput raised before the
// transaction is ever opened.
func TestProjectServiceRestoreBlankInputRejected(t *testing.T) {
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
		in   store.RestoreProjectInput
	}{
		{name: "blank org", in: store.RestoreProjectInput{OrganizationID: "", ProjectID: "prj_acme", ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: "org_acme"}},
		{name: "blank project", in: store.RestoreProjectInput{OrganizationID: "org_acme", ProjectID: "", ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: "org_acme"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Restore(context.Background(), tc.in)
			if err == nil {
				t.Fatalf("Restore(%s) error = nil, want InvalidInput", tc.name)
			}
			if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
				t.Fatalf("Restore(%s) code = %v, want %s", tc.name, err, yerr.CodeValidation)
			}
		})
	}
}

// TestProjectServiceRestoreBlankActorOrgIsInternal proves a missing actor
// organization is a wiring error reported as Internal — an authenticated
// request always carries one.
func TestProjectServiceRestoreBlankActorOrgIsInternal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewProjectRepository()
	svc, err := store.NewProjectService(s, repo, &recordingAuthorizer{}, &recordingQuota{}, &recordingJobs{}, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewProjectService: %v", err)
	}

	in := newRestoreInput("org_acme", "prj_acme")
	in.ActorOrgID = ""
	_, err = svc.Restore(context.Background(), in)
	if err == nil {
		t.Fatal("Restore(blank actor org) error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Restore(blank actor org) code = %v, want %s", err, yerr.CodeInternal)
	}
}
