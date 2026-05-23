package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for PreviewEnvironmentRepository's CRUD invariants
// (BE-0479). Tenant-isolation gets its own PRD story; this file pins the
// single-tenant lifecycle and database invariants.

type previewEnvironmentTxRollbackSentinel struct{}

func (previewEnvironmentTxRollbackSentinel) Error() string {
	return "rollback preview environment test transaction"
}

func previewEnvironmentFixture(orgID, projectID, environmentID, sourceEnvironmentID, displayName string) store.PreviewEnvironment {
	return store.PreviewEnvironment{
		ID:                  domain.MustNewID(domain.KindPreviewEnvironment).String(),
		OrganizationID:      orgID,
		ProjectID:           projectID,
		EnvironmentID:       environmentID,
		SourceEnvironmentID: sourceEnvironmentID,
		DisplayName:         displayName,
		ChangeRef:           "refs/pull/42/head",
	}
}

func seedEnvironmentWithKind(t *testing.T, db *testutil.DB, f *testutil.Factory, proj testutil.Project, label, kind string) testutil.Environment {
	t.Helper()
	env := f.Environment(proj, label)
	if _, err := db.Exec(context.Background(),
		`INSERT INTO environments (id, organization_id, project_id, slug, display_name, kind)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		env.ID, env.OrganizationID, env.ProjectID, env.Slug, env.Name, kind); err != nil {
		t.Fatalf("seed environment with kind: %v", err)
	}
	return env
}

func insertPreviewEnvironment(ctx context.Context, t *testing.T, s *store.Store, repo *store.PreviewEnvironmentRepository, p store.PreviewEnvironment) store.PreviewEnvironment {
	t.Helper()
	var stored store.PreviewEnvironment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, p)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("insert preview environment: %v", err)
	}
	return stored
}

func getPreviewEnvironment(ctx context.Context, t *testing.T, s *store.Store, repo *store.PreviewEnvironmentRepository, orgID, projectID, previewID string) store.PreviewEnvironment {
	t.Helper()
	var got store.PreviewEnvironment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		row, err := repo.GetByID(ctx, q, orgID, projectID, previewID)
		if err != nil {
			return err
		}
		got = row
		return nil
	}); err != nil {
		t.Fatalf("GetByID(%q): %v", previewID, err)
	}
	return got
}

func listPreviewEnvironments(ctx context.Context, t *testing.T, s *store.Store, repo *store.PreviewEnvironmentRepository, orgID, projectID string) []store.PreviewEnvironment {
	t.Helper()
	var got []store.PreviewEnvironment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, err := repo.ListByProject(ctx, q, orgID, projectID)
		if err != nil {
			return err
		}
		got = rows
		return nil
	}); err != nil {
		t.Fatalf("ListByProject(%q, %q): %v", orgID, projectID, err)
	}
	return got
}

func countPreviewEnvironmentsForProject(ctx context.Context, t *testing.T, db *testutil.DB, orgID, projectID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM preview_environments WHERE organization_id = $1 AND project_id = $2`,
		orgID, projectID).Scan(&count); err != nil {
		t.Fatalf("count preview_environments: %v", err)
	}
	return count
}

func assertPreviewEnvironmentSameIdentity(t *testing.T, got, want store.PreviewEnvironment) {
	t.Helper()
	if got.ID != want.ID ||
		got.OrganizationID != want.OrganizationID ||
		got.ProjectID != want.ProjectID ||
		got.EnvironmentID != want.EnvironmentID ||
		got.SourceEnvironmentID != want.SourceEnvironmentID {
		t.Fatalf("identity = (id=%q org=%q project=%q env=%q source=%q), want (id=%q org=%q project=%q env=%q source=%q)",
			got.ID, got.OrganizationID, got.ProjectID, got.EnvironmentID, got.SourceEnvironmentID,
			want.ID, want.OrganizationID, want.ProjectID, want.EnvironmentID, want.SourceEnvironmentID)
	}
}

func TestPreviewEnvironmentRepositoryInsertRowShape(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "preview-insert")
	proj := seedProject(t, db, f, org, "web")
	source := seedEnvironment(t, db, f, proj, "staging")
	preview := seedEnvironmentWithKind(t, db, f, proj, "preview", store.EnvironmentKindPreview)
	want := previewEnvironmentFixture(org.ID, proj.ID, preview.ID, source.ID, "Preview 42")

	got := insertPreviewEnvironment(ctx, t, s, repo, want)
	reloaded := getPreviewEnvironment(ctx, t, s, repo, org.ID, proj.ID, got.ID)

	assertPreviewEnvironmentSameIdentity(t, got, want)
	assertPreviewEnvironmentSameIdentity(t, reloaded, got)
	if got.DisplayName != want.DisplayName || got.ChangeRef != want.ChangeRef {
		t.Errorf("mutable fields = (%q, %q), want (%q, %q)", got.DisplayName, got.ChangeRef, want.DisplayName, want.ChangeRef)
	}
	if reloaded.DisplayName != got.DisplayName || reloaded.ChangeRef != got.ChangeRef || reloaded.Status != got.Status || reloaded.Version != got.Version {
		t.Errorf("reloaded row = %+v, want persisted row %+v", reloaded, got)
	}
	if got.Status != store.PreviewEnvironmentStatusPending {
		t.Errorf("status = %q, want %q", got.Status, store.PreviewEnvironmentStatusPending)
	}
	if got.Version != 1 {
		t.Errorf("version = %d, want 1", got.Version)
	}
	if got.DeletionScheduledAt != nil {
		t.Errorf("deletion_scheduled_at = %v, want nil", got.DeletionScheduledAt)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("timestamps must be database-populated, got created_at=%v updated_at=%v", got.CreatedAt, got.UpdatedAt)
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("created_at=%v updated_at=%v, want equal on fresh INSERT", got.CreatedAt, got.UpdatedAt)
	}
}

func TestPreviewEnvironmentRepositoryListByProjectOrdersDeterministically(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "preview-list")
	proj := seedProject(t, db, f, org, "web")
	source := seedEnvironment(t, db, f, proj, "staging")
	for _, name := range []string{"charlie", "alpha", "bravo"} {
		env := seedEnvironmentWithKind(t, db, f, proj, name, store.EnvironmentKindPreview)
		insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(org.ID, proj.ID, env.ID, source.ID, name))
	}

	got := listPreviewEnvironments(ctx, t, s, repo, org.ID, proj.ID)
	if len(got) != 3 {
		t.Fatalf("ListByProject returned %d rows, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		prev, curr := got[i-1], got[i]
		if curr.CreatedAt.Before(prev.CreatedAt) || (curr.CreatedAt.Equal(prev.CreatedAt) && curr.ID < prev.ID) {
			t.Fatalf("ListByProject order regressed at %d: previous=%+v current=%+v", i, prev, curr)
		}
	}
}

func TestPreviewEnvironmentRepositoryUpdateBumpsVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "preview-update")
	proj := seedProject(t, db, f, org, "web")
	source := seedEnvironment(t, db, f, proj, "staging")
	preview := seedEnvironmentWithKind(t, db, f, proj, "preview", store.EnvironmentKindPreview)
	current := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(org.ID, proj.ID, preview.ID, source.ID, "Preview 42"))

	expiresAt := current.CreatedAt.Add(2 * time.Hour)
	time.Sleep(time.Millisecond)
	desired := current
	desired.DisplayName = "Preview 43"
	desired.ChangeRef = "refs/pull/43/head"
	desired.ExpiresAt = &expiresAt
	version := current.Version

	var updated store.PreviewEnvironment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Update(ctx, tx, desired, &version)
		if err != nil {
			return err
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}

	assertPreviewEnvironmentSameIdentity(t, updated, current)
	if updated.DisplayName != desired.DisplayName || updated.ChangeRef != desired.ChangeRef {
		t.Errorf("updated fields = (%q, %q), want (%q, %q)", updated.DisplayName, updated.ChangeRef, desired.DisplayName, desired.ChangeRef)
	}
	if updated.ExpiresAt == nil || !updated.ExpiresAt.Equal(expiresAt) {
		t.Errorf("expires_at = %v, want %v", updated.ExpiresAt, expiresAt)
	}
	if updated.Status != current.Status || updated.DeletionScheduledAt != nil {
		t.Errorf("worker/lifecycle fields changed during metadata update: status=%q deletion_scheduled_at=%v", updated.Status, updated.DeletionScheduledAt)
	}
	if updated.Version != current.Version+1 {
		t.Errorf("version = %d, want %d", updated.Version, current.Version+1)
	}
	if !updated.CreatedAt.Equal(current.CreatedAt) {
		t.Errorf("created_at changed from %v to %v", current.CreatedAt, updated.CreatedAt)
	}
	if !updated.UpdatedAt.After(current.UpdatedAt) {
		t.Errorf("updated_at = %v, want after baseline %v", updated.UpdatedAt, current.UpdatedAt)
	}
}

func TestPreviewEnvironmentRepositoryUpdateStaleVersionIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "preview-stale")
	proj := seedProject(t, db, f, org, "web")
	source := seedEnvironment(t, db, f, proj, "staging")
	preview := seedEnvironmentWithKind(t, db, f, proj, "preview", store.EnvironmentKindPreview)
	current := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(org.ID, proj.ID, preview.ID, source.ID, "Preview 42"))
	stale := current.Version - 1
	current.DisplayName = "Preview stale"

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Update(ctx, tx, current, &stale)
		return err
	})
	wantErrCode(t, err, yerr.CodeConflict)
}

func TestPreviewEnvironmentRepositoryScheduleDeletionSetsLifecycleFields(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "preview-delete")
	proj := seedProject(t, db, f, org, "web")
	source := seedEnvironment(t, db, f, proj, "staging")
	preview := seedEnvironmentWithKind(t, db, f, proj, "preview", store.EnvironmentKindPreview)
	current := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(org.ID, proj.ID, preview.ID, source.ID, "Preview 42"))
	version := current.Version

	var scheduled store.PreviewEnvironment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.ScheduleDeletion(ctx, tx, org.ID, proj.ID, current.ID, &version)
		if err != nil {
			return err
		}
		scheduled = row
		return nil
	}); err != nil {
		t.Fatalf("ScheduleDeletion returned %v, want nil", err)
	}

	assertPreviewEnvironmentSameIdentity(t, scheduled, current)
	if scheduled.Status != store.PreviewEnvironmentStatusDeleting {
		t.Errorf("status = %q, want %q", scheduled.Status, store.PreviewEnvironmentStatusDeleting)
	}
	if scheduled.DeletionScheduledAt == nil {
		t.Fatalf("deletion_scheduled_at = nil, want timestamp")
	}
	if scheduled.Version != current.Version+1 {
		t.Errorf("version = %d, want %d", scheduled.Version, current.Version+1)
	}
}

func TestPreviewEnvironmentRepositoryDeleteByIDRemovesRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "preview-hard-delete")
	proj := seedProject(t, db, f, org, "web")
	source := seedEnvironment(t, db, f, proj, "staging")
	preview := seedEnvironmentWithKind(t, db, f, proj, "preview", store.EnvironmentKindPreview)
	current := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(org.ID, proj.ID, preview.ID, source.ID, "Preview 42"))
	version := current.Version

	var deleted store.PreviewEnvironment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.DeleteByID(ctx, tx, org.ID, proj.ID, current.ID, &version)
		if err != nil {
			return err
		}
		deleted = row
		return nil
	}); err != nil {
		t.Fatalf("DeleteByID returned %v, want nil", err)
	}
	assertPreviewEnvironmentSameIdentity(t, deleted, current)
	if got := countPreviewEnvironmentsForProject(ctx, t, db, org.ID, proj.ID); got != 0 {
		t.Errorf("preview_environments count = %d, want 0", got)
	}
}

func TestPreviewEnvironmentRepositoryRejectsConstraintViolations(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "preview-constraints")
	proj := seedProject(t, db, f, org, "web")
	source := seedEnvironment(t, db, f, proj, "staging")
	preview := seedEnvironmentWithKind(t, db, f, proj, "preview", store.EnvironmentKindPreview)

	tests := []struct {
		name   string
		mutate func(*store.PreviewEnvironment)
	}{
		{
			name: "unknown_project",
			mutate: func(p *store.PreviewEnvironment) {
				p.ProjectID = domain.MustNewID(domain.KindProject).String()
			},
		},
		{
			name: "blank_display_name",
			mutate: func(p *store.PreviewEnvironment) {
				p.DisplayName = ""
			},
		},
		{
			name: "blank_change_ref",
			mutate: func(p *store.PreviewEnvironment) {
				p.ChangeRef = ""
			},
		},
		{
			name: "wrapped_environment_must_be_preview_kind",
			mutate: func(p *store.PreviewEnvironment) {
				standard := seedEnvironment(t, db, f, proj, "standard-preview-wrapper")
				p.EnvironmentID = standard.ID
			},
		},
		{
			name: "wrapped_environment_cannot_equal_source",
			mutate: func(p *store.PreviewEnvironment) {
				p.EnvironmentID = p.SourceEnvironmentID
			},
		},
		{
			name: "duplicate_environment",
			mutate: func(p *store.PreviewEnvironment) {
				insertPreviewEnvironment(ctx, t, s, repo, *p)
				p.ID = domain.MustNewID(domain.KindPreviewEnvironment).String()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := previewEnvironmentFixture(org.ID, proj.ID, preview.ID, source.ID, "Preview 42 "+tc.name)
			tc.mutate(&row)
			err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, err := repo.Insert(ctx, tx, row)
				return err
			})
			wantErrCode(t, err, yerr.CodeConflict)
		})
	}
}

func TestPreviewEnvironmentRepositoryInsertRollback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "preview-rollback")
	proj := seedProject(t, db, f, org, "web")
	source := seedEnvironment(t, db, f, proj, "staging")
	preview := seedEnvironmentWithKind(t, db, f, proj, "preview", store.EnvironmentKindPreview)
	row := previewEnvironmentFixture(org.ID, proj.ID, preview.ID, source.ID, "Preview 42")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := repo.Insert(ctx, tx, row); err != nil {
			return err
		}
		return previewEnvironmentTxRollbackSentinel{}
	})
	var sentinel previewEnvironmentTxRollbackSentinel
	if !errors.As(err, &sentinel) {
		t.Fatalf("Write returned %v, want rollback sentinel", err)
	}
	if got := countPreviewEnvironmentsForProject(ctx, t, db, org.ID, proj.ID); got != 0 {
		t.Errorf("preview_environments count after rollback = %d, want 0", got)
	}
}

func TestPreviewEnvironmentRepositoryNilTxGuards(t *testing.T) {
	t.Parallel()
	repo := store.NewPreviewEnvironmentRepository()
	ctx := context.Background()

	if _, err := repo.Insert(ctx, nil, store.PreviewEnvironment{}); err == nil {
		t.Fatalf("Insert nil tx returned nil error")
	} else {
		wantErrCode(t, err, yerr.CodeInternal)
	}
	if _, err := repo.Update(ctx, nil, store.PreviewEnvironment{}, nil); err == nil {
		t.Fatalf("Update nil tx returned nil error")
	} else {
		wantErrCode(t, err, yerr.CodeInternal)
	}
	if _, err := repo.ScheduleDeletion(ctx, nil, "org_missing", "proj_missing", "penv_missing", nil); err == nil {
		t.Fatalf("ScheduleDeletion nil tx returned nil error")
	} else {
		wantErrCode(t, err, yerr.CodeInternal)
	}
	if _, err := repo.DeleteByID(ctx, nil, "org_missing", "proj_missing", "penv_missing", nil); err == nil {
		t.Fatalf("DeleteByID nil tx returned nil error")
	} else {
		wantErrCode(t, err, yerr.CodeInternal)
	}
}
