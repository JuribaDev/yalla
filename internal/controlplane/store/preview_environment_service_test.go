package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func seedPreviewServiceProject(t *testing.T, db *testutil.DB, orgID string) string {
	t.Helper()
	id := domain.MustNewID(domain.KindProject).String()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO projects (id, organization_id, slug, display_name) VALUES ($1, $2, $3, $4)`,
		id, orgID, "web-"+id[len(id)-8:], "Web"); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return id
}

func seedPreviewServiceEnvironment(t *testing.T, db *testutil.DB, orgID, projectID, slug, kind string) string {
	t.Helper()
	id := domain.MustNewID(domain.KindEnvironment).String()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO environments (id, organization_id, project_id, slug, display_name, kind)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, orgID, projectID, slug, "Source "+slug, kind); err != nil {
		t.Fatalf("seed environment: %v", err)
	}
	return id
}

func newPreviewService(t *testing.T, s *store.Store, authz *recordingAuthorizer, quota *recordingQuota, jobs *recordingJobs) *store.PreviewEnvironmentService {
	t.Helper()
	svc, err := store.NewPreviewEnvironmentService(s, store.NewProjectRepository(), store.NewEnvironmentRepository(), store.NewPreviewEnvironmentRepository(), authz, quota, jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewPreviewEnvironmentService: %v", err)
	}
	return svc
}

func TestPreviewEnvironmentServiceCreateWritesPreviewCloneJobAndAudit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	orgID := seedDomainOrg(t, db)
	projectID := seedPreviewServiceProject(t, db, orgID)
	sourceID := seedPreviewServiceEnvironment(t, db, orgID, projectID, "prod", store.EnvironmentKindStandard)

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc := newPreviewService(t, s, authz, quota, jobs)
	expires := time.Now().UTC().Add(48 * time.Hour)
	in := store.CreatePreviewEnvironmentInput{
		OrganizationID:      orgID,
		ProjectID:           projectID,
		PreviewID:           domain.MustNewID(domain.KindPreviewEnvironment).String(),
		EnvironmentID:       domain.MustNewID(domain.KindEnvironment).String(),
		SourceEnvironmentID: sourceID,
		Slug:                "pr-42",
		DisplayName:         "PR 42",
		ChangeRef:           "refs/pull/42/head",
		ExpiresAt:           &expires,
		ActorID:             "usr_ada",
		ActorKind:           "usr",
		ActorOrgID:          orgID,
		RequestID:           "req_preview_create",
		CorrelationID:       "corr_preview_create",
	}

	created, err := svc.Create(ctx, in)
	if err != nil {
		t.Fatalf("Create preview: %v", err)
	}

	if created.ID != in.PreviewID || created.EnvironmentID != in.EnvironmentID || created.SourceEnvironmentID != sourceID {
		t.Fatalf("created preview = %+v, want ids from input/source", created)
	}
	if created.Status != store.PreviewEnvironmentStatusPending {
		t.Errorf("status = %q, want pending", created.Status)
	}
	if authz.calls != 1 {
		t.Errorf("authz calls = %d, want 1", authz.calls)
	}
	if quota.calls != 2 {
		t.Errorf("quota calls = %d, want 2 (environments + preview_environments)", quota.calls)
	}
	if jobs.calls != 1 {
		t.Errorf("jobs calls = %d, want 1", jobs.calls)
	}

	var cloned store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		cloned, getErr = store.NewEnvironmentRepository().GetByID(ctx, q, orgID, in.EnvironmentID)
		return getErr
	}); err != nil {
		t.Fatalf("read cloned environment: %v", err)
	}
	if cloned.ProjectID != projectID || cloned.Kind != store.EnvironmentKindPreview || cloned.Slug != "pr-42" {
		t.Errorf("cloned environment = %+v, want preview clone under project", cloned)
	}

	events := listProjectAuditEvents(t, s, orgID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].Action != "preview.create" || events[0].ResourceID != in.PreviewID || events[0].RequestID != in.RequestID {
		t.Errorf("audit event = %+v, want preview.create for created preview", events[0])
	}
}

func TestPreviewEnvironmentServiceCreateRejectsSourceOutsideProject(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	orgID := seedDomainOrg(t, db)
	projectA := seedPreviewServiceProject(t, db, orgID)
	projectB := seedPreviewServiceProject(t, db, orgID)
	sourceB := seedPreviewServiceEnvironment(t, db, orgID, projectB, "prod-b", store.EnvironmentKindStandard)

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc := newPreviewService(t, s, authz, quota, jobs)

	_, err := svc.Create(ctx, store.CreatePreviewEnvironmentInput{
		OrganizationID:      orgID,
		ProjectID:           projectA,
		PreviewID:           domain.MustNewID(domain.KindPreviewEnvironment).String(),
		EnvironmentID:       domain.MustNewID(domain.KindEnvironment).String(),
		SourceEnvironmentID: sourceB,
		Slug:                "pr-43",
		DisplayName:         "PR 43",
		ChangeRef:           "refs/pull/43/head",
		ActorID:             "usr_ada",
		ActorKind:           "usr",
		ActorOrgID:          orgID,
		RequestID:           "req_preview_cross_project",
		CorrelationID:       "corr_preview_cross_project",
	})
	if yerr.From(err).Code != yerr.CodeNotFound {
		t.Fatalf("Create source outside project error = %v, want E_NOT_FOUND", err)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("side-effect calls after source scope failure = authz:%d quota:%d jobs:%d, want all zero", authz.calls, quota.calls, jobs.calls)
	}

	var count int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM preview_environments WHERE organization_id = $1 AND project_id = $2`,
		orgID, projectA).Scan(&count); err != nil {
		t.Fatalf("count preview rows: %v", err)
	}
	if count != 0 {
		t.Errorf("preview rows for projectA = %d, want 0", count)
	}
}

func TestPreviewEnvironmentServiceListProjectPreviewsVerifiesParentProject(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	orgA := seedDomainOrg(t, db)
	orgB := seedDomainOrg(t, db)
	projectA := seedPreviewServiceProject(t, db, orgA)
	projectB := seedPreviewServiceProject(t, db, orgB)
	sourceA := seedPreviewServiceEnvironment(t, db, orgA, projectA, "prod-a", store.EnvironmentKindStandard)
	sourceB := seedPreviewServiceEnvironment(t, db, orgB, projectB, "prod-b", store.EnvironmentKindStandard)

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc := newPreviewService(t, s, authz, quota, jobs)

	created, err := svc.Create(ctx, store.CreatePreviewEnvironmentInput{
		OrganizationID:      orgA,
		ProjectID:           projectA,
		PreviewID:           domain.MustNewID(domain.KindPreviewEnvironment).String(),
		EnvironmentID:       domain.MustNewID(domain.KindEnvironment).String(),
		SourceEnvironmentID: sourceA,
		Slug:                "pr-44",
		DisplayName:         "PR 44",
		ChangeRef:           "refs/pull/44/head",
		ActorID:             "usr_ada",
		ActorKind:           "usr",
		ActorOrgID:          orgA,
		RequestID:           "req_preview_list",
		CorrelationID:       "corr_preview_list",
	})
	if err != nil {
		t.Fatalf("Create orgA preview: %v", err)
	}
	if _, err := svc.Create(ctx, store.CreatePreviewEnvironmentInput{
		OrganizationID:      orgB,
		ProjectID:           projectB,
		PreviewID:           domain.MustNewID(domain.KindPreviewEnvironment).String(),
		EnvironmentID:       domain.MustNewID(domain.KindEnvironment).String(),
		SourceEnvironmentID: sourceB,
		Slug:                "pr-44-b",
		DisplayName:         "PR 44 B",
		ChangeRef:           "refs/pull/44/head",
		ActorID:             "usr_bea",
		ActorKind:           "usr",
		ActorOrgID:          orgB,
		RequestID:           "req_preview_list_b",
		CorrelationID:       "corr_preview_list_b",
	}); err != nil {
		t.Fatalf("Create orgB preview: %v", err)
	}

	listed, err := svc.ListProjectPreviews(ctx, orgA, projectA)
	if err != nil {
		t.Fatalf("ListProjectPreviews orgA/projectA: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("listed previews = %+v, want only %s", listed, created.ID)
	}

	crossTenant, err := svc.ListProjectPreviews(ctx, orgA, projectB)
	if err == nil {
		t.Fatalf("ListProjectPreviews orgA/projectB returned %+v, want E_NOT_FOUND", crossTenant)
	}
	if yerr.From(err).Code != yerr.CodeNotFound {
		t.Fatalf("ListProjectPreviews orgA/projectB error = %v, want E_NOT_FOUND", err)
	}
}

func TestPreviewEnvironmentServiceScheduleDeletionWritesJobAndAudit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	orgID := seedDomainOrg(t, db)
	projectID := seedPreviewServiceProject(t, db, orgID)
	sourceID := seedPreviewServiceEnvironment(t, db, orgID, projectID, "prod-delete", store.EnvironmentKindStandard)

	authz := &recordingAuthorizer{}
	quota := &recordingQuota{}
	jobs := &recordingJobs{}
	svc := newPreviewService(t, s, authz, quota, jobs)

	created, err := svc.Create(ctx, store.CreatePreviewEnvironmentInput{
		OrganizationID:      orgID,
		ProjectID:           projectID,
		PreviewID:           domain.MustNewID(domain.KindPreviewEnvironment).String(),
		EnvironmentID:       domain.MustNewID(domain.KindEnvironment).String(),
		SourceEnvironmentID: sourceID,
		Slug:                "pr-delete",
		DisplayName:         "PR delete",
		ChangeRef:           "refs/pull/delete/head",
		ActorID:             "usr_ada",
		ActorKind:           "usr",
		ActorOrgID:          orgID,
		RequestID:           "req_preview_create_delete",
		CorrelationID:       "corr_preview_create_delete",
	})
	if err != nil {
		t.Fatalf("Create preview: %v", err)
	}

	scheduled, err := svc.ScheduleDeletion(ctx, store.DeletePreviewEnvironmentInput{
		OrganizationID: orgID,
		ProjectID:      projectID,
		PreviewID:      created.ID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_preview_delete",
		CorrelationID:  "corr_preview_delete",
	})
	if err != nil {
		t.Fatalf("ScheduleDeletion preview: %v", err)
	}

	if scheduled.ID != created.ID || scheduled.EnvironmentID != created.EnvironmentID || scheduled.SourceEnvironmentID != sourceID {
		t.Fatalf("scheduled preview = %+v, want same preview identity", scheduled)
	}
	if scheduled.Status != store.PreviewEnvironmentStatusDeleting {
		t.Errorf("status = %q, want deleting", scheduled.Status)
	}
	if scheduled.DeletionScheduledAt == nil {
		t.Fatal("deletion_scheduled_at = nil, want database timestamp")
	}
	if jobs.calls != 2 {
		t.Errorf("jobs calls = %d, want 2 (create + delete)", jobs.calls)
	}
	if quota.calls != 2 {
		t.Errorf("quota calls = %d, want 2 from create only", quota.calls)
	}

	events := listProjectAuditEvents(t, s, orgID)
	if len(events) != 2 {
		t.Fatalf("audit events = %d, want create + delete", len(events))
	}
	deleteEvent := events[1]
	if deleteEvent.Action != "preview.delete" || deleteEvent.ResourceID != created.ID || deleteEvent.RequestID != "req_preview_delete" {
		t.Errorf("delete audit event = %+v, want preview.delete for scheduled preview", deleteEvent)
	}
}

func TestPreviewEnvironmentServiceCreateValidationCollectsFields(t *testing.T) {
	t.Parallel()

	svcInput := store.CreatePreviewEnvironmentInput{
		OrganizationID:      "not-an-org",
		ProjectID:           "not-a-project",
		PreviewID:           "not-a-preview",
		EnvironmentID:       "not-an-env",
		SourceEnvironmentID: "not-a-source",
		Slug:                "Bad Slug",
		DisplayName:         "",
		ChangeRef:           "",
		ActorOrgID:          "org_missing",
	}
	_, err := (&store.PreviewEnvironmentService{}).Create(context.Background(), svcInput)
	if yerr.From(err).Code != yerr.CodeInvalidInput {
		t.Fatalf("Create invalid input error = %v, want E_INVALID_INPUT", err)
	}
	violations, ok := apierr.ViolationsOf(err)
	if !ok {
		t.Fatalf("ViolationsOf(%v) returned ok=false", err)
	}
	if len(violations) < 8 {
		t.Fatalf("violations = %+v, want validation to collect all invalid fields", violations)
	}
}
