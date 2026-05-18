package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for preview_environments
// (BE-0480). preview_environments is a project-scoped lifecycle wrapper
// around a concrete preview-kind environments row. Every repository method
// must predicate on (organization_id, project_id[, id]); the wrapped
// environment_id is not sufficient tenant scope.
//
// What is intentionally delegated:
//   - CRUD row shape, database constraints, optimistic versioning, transaction
//     rollback, nil-Tx guards, and the preview-kind trigger are proved by
//     preview_environment_repository_invariants_test.go (BE-0479).
//   - HTTP envelopes and policy decisions are pinned by endpoint contract and
//     policy-matrix suites.

type previewEnvironmentTenantFixture struct {
	orgA     testutil.Organization
	orgB     testutil.Organization
	projA    testutil.Project
	projB    testutil.Project
	sourceA  testutil.Environment
	sourceB  testutil.Environment
	previewA testutil.Environment
	previewB testutil.Environment
}

func seedPreviewEnvironmentTenantFixture(t *testing.T, db *testutil.DB, f *testutil.Factory) previewEnvironmentTenantFixture {
	t.Helper()
	orgA := seedOrg(t, db, f, "preview-tenant-a")
	orgB := seedOrg(t, db, f, "preview-tenant-b")
	projA := seedProject(t, db, f, orgA, "web")
	projB := seedProject(t, db, f, orgB, "web")
	sourceA := seedEnvironment(t, db, f, projA, "staging")
	sourceB := seedEnvironment(t, db, f, projB, "staging")
	previewA := seedEnvironmentWithKind(t, db, f, projA, "preview", store.EnvironmentKindPreview)
	previewB := seedEnvironmentWithKind(t, db, f, projB, "preview", store.EnvironmentKindPreview)
	return previewEnvironmentTenantFixture{
		orgA:     orgA,
		orgB:     orgB,
		projA:    projA,
		projB:    projB,
		sourceA:  sourceA,
		sourceB:  sourceB,
		previewA: previewA,
		previewB: previewB,
	}
}

func countPreviewEnvironmentsForOrg(ctx context.Context, t *testing.T, db *testutil.DB, orgID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM preview_environments WHERE organization_id = $1`,
		orgID).Scan(&count); err != nil {
		t.Fatalf("count preview_environments for org %q: %v", orgID, err)
	}
	return count
}

func assertPreviewEnvironmentByteIdentical(t *testing.T, label string, baseline, after store.PreviewEnvironment) {
	t.Helper()
	if after.ID != baseline.ID ||
		after.OrganizationID != baseline.OrganizationID ||
		after.ProjectID != baseline.ProjectID ||
		after.EnvironmentID != baseline.EnvironmentID ||
		after.SourceEnvironmentID != baseline.SourceEnvironmentID {
		t.Errorf("%s: identity drifted: got id=%q org=%q project=%q env=%q source=%q, want id=%q org=%q project=%q env=%q source=%q",
			label,
			after.ID, after.OrganizationID, after.ProjectID, after.EnvironmentID, after.SourceEnvironmentID,
			baseline.ID, baseline.OrganizationID, baseline.ProjectID, baseline.EnvironmentID, baseline.SourceEnvironmentID)
	}
	if after.DisplayName != baseline.DisplayName {
		t.Errorf("%s: display_name = %q, want %q", label, after.DisplayName, baseline.DisplayName)
	}
	if after.ChangeRef != baseline.ChangeRef {
		t.Errorf("%s: change_ref = %q, want %q", label, after.ChangeRef, baseline.ChangeRef)
	}
	if after.Status != baseline.Status {
		t.Errorf("%s: status = %q, want %q", label, after.Status, baseline.Status)
	}
	assertTimePtrEqual(t, label+": expires_at", baseline.ExpiresAt, after.ExpiresAt)
	assertTimePtrEqual(t, label+": deletion_scheduled_at", baseline.DeletionScheduledAt, after.DeletionScheduledAt)
	if after.Version != baseline.Version {
		t.Errorf("%s: version = %d, want %d - a peer-tenant UPDATE/DELETE matched the bystander row",
			label, after.Version, baseline.Version)
	}
	if !after.CreatedAt.Equal(baseline.CreatedAt) {
		t.Errorf("%s: created_at = %v, want %v", label, after.CreatedAt, baseline.CreatedAt)
	}
	if !after.UpdatedAt.Equal(baseline.UpdatedAt) {
		t.Errorf("%s: updated_at = %v, want %v - a peer-tenant UPDATE matched the bystander row",
			label, after.UpdatedAt, baseline.UpdatedAt)
	}
}

func TestPreviewEnvironmentRepositoryListByProjectIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedPreviewEnvironmentTenantFixture(t, db, f)

	rowA := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgA.ID, fixture.projA.ID, fixture.previewA.ID, fixture.sourceA.ID, "Preview shared"))
	rowB := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgB.ID, fixture.projB.ID, fixture.previewB.ID, fixture.sourceB.ID, "Preview shared"))
	previewB2 := seedEnvironmentWithKind(t, db, f, fixture.projB, "preview-two", store.EnvironmentKindPreview)
	rowB2 := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgB.ID, fixture.projB.ID, previewB2.ID, fixture.sourceB.ID, "Preview shared"))

	listA := listPreviewEnvironments(ctx, t, s, repo, fixture.orgA.ID, fixture.projA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByProject(orgA, projA) returned %d rows, want exactly 1 - orgB preview rows leaked or changed orgA's apparent page size", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != fixture.orgA.ID || listA[0].ProjectID != fixture.projA.ID {
		t.Errorf("ListByProject(orgA, projA)[0] = %+v, want orgA row %+v", listA[0], rowA)
	}

	listB := listPreviewEnvironments(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID)
	if len(listB) != 2 {
		t.Fatalf("ListByProject(orgB, projB) returned %d rows, want exactly 2", len(listB))
	}
	if listB[0].ID != rowB.ID || listB[1].ID != rowB2.ID {
		t.Errorf("ListByProject(orgB, projB) order = [%q, %q], want created_at/id deterministic order [%q, %q]",
			listB[0].ID, listB[1].ID, rowB.ID, rowB2.ID)
	}
	for _, row := range listB {
		if row.ID == rowA.ID || row.OrganizationID != fixture.orgB.ID || row.ProjectID != fixture.projB.ID {
			t.Errorf("ListByProject(orgB, projB) row = %+v, want only orgB/projB rows", row)
		}
	}

	crossTenant := listPreviewEnvironments(ctx, t, s, repo, fixture.orgA.ID, fixture.projB.ID)
	if len(crossTenant) != 0 {
		t.Errorf("ListByProject(orgA, projB) returned %d rows, want 0 - orgB preview rows leaked through a cross-tenant project_id", len(crossTenant))
	}
	if crossTenant == nil {
		t.Error("ListByProject(orgA, projB) returned nil; the repository contract is a non-nil empty slice")
	}
}

func TestPreviewEnvironmentRepositoryGetByIDCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedPreviewEnvironmentTenantFixture(t, db, f)

	rowB := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgB.ID, fixture.projB.ID, fixture.previewB.ID, fixture.sourceB.ID, "Preview get"))
	baselineB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.GetByID(ctx, q, fixture.orgA.ID, fixture.projB.ID, rowB.ID)
		return getErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)
	assertPreviewEnvironmentByteIdentical(t, "GetByID(orgA, projB, previewB) bystander orgB", baselineB, afterB)
}

func TestPreviewEnvironmentRepositoryUpdateCrossTenantIsNotFoundAndDoesNotTouchBystanders(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedPreviewEnvironmentTenantFixture(t, db, f)

	rowA := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgA.ID, fixture.projA.ID, fixture.previewA.ID, fixture.sourceA.ID, "Preview A"))
	rowB := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgB.ID, fixture.projB.ID, fixture.previewB.ID, fixture.sourceB.ID, "Preview B"))
	baselineA := getPreviewEnvironment(ctx, t, s, repo, fixture.orgA.ID, fixture.projA.ID, rowA.ID)
	baselineB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)

	desired := baselineB
	desired.OrganizationID = fixture.orgA.ID
	desired.DisplayName = "Cross-tenant update attempt"
	desired.ChangeRef = "refs/pull/999/head"
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updateErr := repo.Update(ctx, tx, desired, nil)
		return updateErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterA := getPreviewEnvironment(ctx, t, s, repo, fixture.orgA.ID, fixture.projA.ID, rowA.ID)
	afterB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)
	assertPreviewEnvironmentByteIdentical(t, "Update(orgA, projB, previewB) orgA peer", baselineA, afterA)
	assertPreviewEnvironmentByteIdentical(t, "Update(orgA, projB, previewB) orgB bystander", baselineB, afterB)
}

func TestPreviewEnvironmentRepositoryScheduleDeletionCrossTenantIsNotFoundAndDoesNotTouchBystanders(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedPreviewEnvironmentTenantFixture(t, db, f)

	rowA := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgA.ID, fixture.projA.ID, fixture.previewA.ID, fixture.sourceA.ID, "Preview A"))
	rowB := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgB.ID, fixture.projB.ID, fixture.previewB.ID, fixture.sourceB.ID, "Preview B"))
	baselineA := getPreviewEnvironment(ctx, t, s, repo, fixture.orgA.ID, fixture.projA.ID, rowA.ID)
	baselineB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, scheduleErr := repo.ScheduleDeletion(ctx, tx, fixture.orgA.ID, fixture.projB.ID, rowB.ID, nil)
		return scheduleErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterA := getPreviewEnvironment(ctx, t, s, repo, fixture.orgA.ID, fixture.projA.ID, rowA.ID)
	afterB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)
	assertPreviewEnvironmentByteIdentical(t, "ScheduleDeletion(orgA, projB, previewB) orgA peer", baselineA, afterA)
	assertPreviewEnvironmentByteIdentical(t, "ScheduleDeletion(orgA, projB, previewB) orgB bystander", baselineB, afterB)
}

func TestPreviewEnvironmentRepositoryDeleteCrossTenantIsNotFoundAndDoesNotTouchBystanders(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedPreviewEnvironmentTenantFixture(t, db, f)

	rowA := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgA.ID, fixture.projA.ID, fixture.previewA.ID, fixture.sourceA.ID, "Preview A"))
	rowB := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgB.ID, fixture.projB.ID, fixture.previewB.ID, fixture.sourceB.ID, "Preview B"))
	baselineA := getPreviewEnvironment(ctx, t, s, repo, fixture.orgA.ID, fixture.projA.ID, rowA.ID)
	baselineB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, deleteErr := repo.DeleteByID(ctx, tx, fixture.orgA.ID, fixture.projB.ID, rowB.ID, nil)
		return deleteErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterA := getPreviewEnvironment(ctx, t, s, repo, fixture.orgA.ID, fixture.projA.ID, rowA.ID)
	afterB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)
	assertPreviewEnvironmentByteIdentical(t, "DeleteByID(orgA, projB, previewB) orgA peer", baselineA, afterA)
	assertPreviewEnvironmentByteIdentical(t, "DeleteByID(orgA, projB, previewB) orgB bystander", baselineB, afterB)
	if count := countPreviewEnvironmentsForOrg(ctx, t, db, fixture.orgB.ID); count != 1 {
		t.Errorf("orgB preview_environments count after cross-tenant delete = %d, want 1", count)
	}
	if count := countPreviewEnvironmentsForOrg(ctx, t, db, fixture.orgA.ID); count != 1 {
		t.Errorf("orgA preview_environments count after cross-tenant delete = %d, want 1", count)
	}
}

func TestPreviewEnvironmentRepositorySoftDeletedRowsRemainTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedPreviewEnvironmentTenantFixture(t, db, f)

	rowA := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgA.ID, fixture.projA.ID, fixture.previewA.ID, fixture.sourceA.ID, "Preview A"))
	rowB := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgB.ID, fixture.projB.ID, fixture.previewB.ID, fixture.sourceB.ID, "Preview B"))
	versionB := rowB.Version
	var scheduledB store.PreviewEnvironment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var scheduleErr error
		scheduledB, scheduleErr = repo.ScheduleDeletion(ctx, tx, fixture.orgB.ID, fixture.projB.ID, rowB.ID, &versionB)
		return scheduleErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion(orgB, previewB): %v", err)
	}
	if scheduledB.DeletionScheduledAt == nil || scheduledB.Status != store.PreviewEnvironmentStatusDeleting {
		t.Fatalf("scheduled orgB preview = %+v, want deleting with deletion_scheduled_at", scheduledB)
	}

	listA := listPreviewEnvironments(ctx, t, s, repo, fixture.orgA.ID, fixture.projA.ID)
	if len(listA) != 1 || listA[0].ID != rowA.ID {
		t.Fatalf("ListByProject(orgA, projA) = %+v, want only orgA preview row", listA)
	}

	crossTenant := listPreviewEnvironments(ctx, t, s, repo, fixture.orgA.ID, fixture.projB.ID)
	if len(crossTenant) != 0 {
		t.Fatalf("ListByProject(orgA, projB) returned %+v, want empty even when orgB row is soft-deleted", crossTenant)
	}
	if crossTenant == nil {
		t.Fatal("ListByProject(orgA, projB) returned nil; want non-nil empty slice")
	}

	gotB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)
	assertPreviewEnvironmentByteIdentical(t, "soft-deleted owner read", scheduledB, gotB)

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.GetByID(ctx, q, fixture.orgA.ID, fixture.projB.ID, rowB.ID)
		return getErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)
}

func TestPreviewEnvironmentRepositoryCrossTenantIDCollisionIsConflictAndSideEffectFree(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPreviewEnvironmentRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedPreviewEnvironmentTenantFixture(t, db, f)

	rowB := insertPreviewEnvironment(ctx, t, s, repo, previewEnvironmentFixture(
		fixture.orgB.ID, fixture.projB.ID, fixture.previewB.ID, fixture.sourceB.ID, "Preview B"))
	baselineB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)

	rowA := previewEnvironmentFixture(fixture.orgA.ID, fixture.projA.ID, fixture.previewA.ID, fixture.sourceA.ID, "Preview A")
	rowA.ID = rowB.ID
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insertErr := repo.Insert(ctx, tx, rowA)
		return insertErr
	})
	wantErrCode(t, err, yerr.CodeConflict)

	afterB := getPreviewEnvironment(ctx, t, s, repo, fixture.orgB.ID, fixture.projB.ID, rowB.ID)
	assertPreviewEnvironmentByteIdentical(t, "Insert duplicate id across tenants bystander orgB", baselineB, afterB)
	if count := countPreviewEnvironmentsForOrg(ctx, t, db, fixture.orgA.ID); count != 0 {
		t.Errorf("orgA preview_environments count after duplicate-id insert = %d, want 0", count)
	}

	// Prove the orgA fixture can still insert when the id is globally unique;
	// the previous conflict must be from the global PK, not a broken fixture.
	rowA.ID = domain.MustNewID(domain.KindPreviewEnvironment).String()
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, insertErr := repo.Insert(ctx, tx, rowA)
		return insertErr
	}); err != nil {
		t.Fatalf("Insert(orgA unique id) after duplicate-id conflict: %v", err)
	}
}
