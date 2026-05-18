package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Repository-layer tenant-isolation tests for service_backups (PRD
// backup_schedules, BE-0478). service_backups is a service-scoped leaf table:
// every row carries organization_id plus a composite FK to its parent service,
// and every repository method predicates on (organization_id, service_id[, id]).
//
// What is intentionally delegated:
//   - CRUD row shape, optimistic versioning, transaction rollback, schema
//     constraints, worker-state preservation, and parent cascade are proved by
//     service_backup_repository_invariants_test.go (BE-0477).
//   - service_backups has no soft-delete column; DeleteByID is a hard delete
//     that returns the removed row snapshot.
//   - HTTP envelopes and policy decisions are pinned by endpoint contract and
//     policy-matrix suites.

type serviceBackupTenantFixture struct {
	orgA testutil.Organization
	orgB testutil.Organization
	svcA testutil.Service
	svcB testutil.Service
}

func seedServiceBackupTenantFixture(t *testing.T, db *testutil.DB, f *testutil.Factory) serviceBackupTenantFixture {
	t.Helper()
	orgA := seedOrg(t, db, f, "backup-tenant-a")
	orgB := seedOrg(t, db, f, "backup-tenant-b")
	projA := seedProject(t, db, f, orgA, "web-a")
	projB := seedProject(t, db, f, orgB, "web-b")
	envA := seedEnvironment(t, db, f, projA, "production-a")
	envB := seedEnvironment(t, db, f, projB, "production-b")
	svcA := seedService(t, db, f, envA, "api-a")
	svcB := seedService(t, db, f, envB, "api-b")
	return serviceBackupTenantFixture{
		orgA: orgA,
		orgB: orgB,
		svcA: svcA,
		svcB: svcB,
	}
}

func countServiceBackupsForOrg(ctx context.Context, t *testing.T, db *testutil.DB, orgID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM service_backups WHERE organization_id = $1`,
		orgID).Scan(&count); err != nil {
		t.Fatalf("count service_backups for org %q: %v", orgID, err)
	}
	return count
}

func assertServiceBackupByteIdentical(t *testing.T, label string, baseline, after store.ServiceBackup) {
	t.Helper()
	if after.ID != baseline.ID || after.OrganizationID != baseline.OrganizationID || after.ServiceID != baseline.ServiceID {
		t.Errorf("%s: identity drifted: got id=%q org=%q service=%q, want id=%q org=%q service=%q",
			label, after.ID, after.OrganizationID, after.ServiceID, baseline.ID, baseline.OrganizationID, baseline.ServiceID)
	}
	if after.DisplayName != baseline.DisplayName {
		t.Errorf("%s: display_name = %q, want %q", label, after.DisplayName, baseline.DisplayName)
	}
	if after.Schedule != baseline.Schedule {
		t.Errorf("%s: schedule = %q, want %q", label, after.Schedule, baseline.Schedule)
	}
	if after.RetentionCount != baseline.RetentionCount {
		t.Errorf("%s: retention_count = %d, want %d", label, after.RetentionCount, baseline.RetentionCount)
	}
	if after.Enabled != baseline.Enabled {
		t.Errorf("%s: enabled = %v, want %v", label, after.Enabled, baseline.Enabled)
	}
	if after.Status != baseline.Status {
		t.Errorf("%s: status = %q, want %q", label, after.Status, baseline.Status)
	}
	assertTimePtrEqual(t, label+": last_run_at", baseline.LastRunAt, after.LastRunAt)
	assertTimePtrEqual(t, label+": last_succeeded_at", baseline.LastSucceededAt, after.LastSucceededAt)
	if after.Version != baseline.Version {
		t.Errorf("%s: version = %d, want %d - a peer-tenant UPDATE matched the bystander row",
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

func TestServiceBackupRepositoryListByServiceIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceBackupTenantFixture(t, db, f)

	rowA := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(fixture.orgA.ID, fixture.svcA.ID, "nightly"))
	rowB1 := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(fixture.orgB.ID, fixture.svcB.ID, "nightly"))
	rowB2 := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(fixture.orgB.ID, fixture.svcB.ID, "weekly"))

	listA := listServiceBackups(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID)
	if len(listA) != 1 {
		t.Fatalf("ListByService(orgA, svcA) returned %d rows, want exactly 1 - orgB backups leaked or changed orgA's apparent page size", len(listA))
	}
	if listA[0].ID != rowA.ID || listA[0].OrganizationID != fixture.orgA.ID || listA[0].ServiceID != fixture.svcA.ID {
		t.Errorf("ListByService(orgA, svcA)[0] = %+v, want orgA row %+v", listA[0], rowA)
	}

	listB := listServiceBackups(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID)
	if len(listB) != 2 {
		t.Fatalf("ListByService(orgB, svcB) returned %d rows, want exactly 2", len(listB))
	}
	for _, row := range listB {
		if row.ID == rowA.ID || row.OrganizationID != fixture.orgB.ID || row.ServiceID != fixture.svcB.ID {
			t.Errorf("ListByService(orgB, svcB) row = %+v, want only orgB/svcB rows", row)
		}
	}
	if listB[0].ID != rowB1.ID || listB[1].ID != rowB2.ID {
		t.Errorf("ListByService(orgB, svcB) order = [%q, %q], want created_at/id deterministic order [%q, %q]",
			listB[0].ID, listB[1].ID, rowB1.ID, rowB2.ID)
	}

	crossTenant := listServiceBackups(ctx, t, s, repo, fixture.orgA.ID, fixture.svcB.ID)
	if len(crossTenant) != 0 {
		t.Errorf("ListByService(orgA, svcB) returned %d rows, want 0 - orgB service backups leaked through a cross-tenant service_id", len(crossTenant))
	}
	if crossTenant == nil {
		t.Error("ListByService(orgA, svcB) returned nil; the repository contract is a non-nil empty slice")
	}
}

func TestServiceBackupRepositoryGetByIDCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceBackupTenantFixture(t, db, f)

	rowB := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(fixture.orgB.ID, fixture.svcB.ID, "get-cross"))
	baselineB := getServiceBackup(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)

	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.GetByID(ctx, q, fixture.orgA.ID, fixture.svcB.ID, rowB.ID)
		return getErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterB := getServiceBackup(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)
	assertServiceBackupByteIdentical(t, "GetByID(orgA, svcB, backupB) bystander orgB", baselineB, afterB)
}

func TestServiceBackupRepositoryUpdateCrossTenantIsNotFoundAndDoesNotTouchBystanders(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceBackupTenantFixture(t, db, f)

	rowA := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(fixture.orgA.ID, fixture.svcA.ID, "update-a"))
	rowB := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(fixture.orgB.ID, fixture.svcB.ID, "update-b"))
	baselineA := getServiceBackup(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID, rowA.ID)
	baselineB := getServiceBackup(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)

	desired := baselineB
	desired.OrganizationID = fixture.orgA.ID
	desired.DisplayName = "cross-tenant-attempt"
	desired.Schedule = "0 4 * * *"
	desired.RetentionCount = 30
	desired.Enabled = false
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updateErr := repo.Update(ctx, tx, desired, nil)
		return updateErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterA := getServiceBackup(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID, rowA.ID)
	afterB := getServiceBackup(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)
	assertServiceBackupByteIdentical(t, "Update(orgA, svcB, backupB) orgA peer", baselineA, afterA)
	assertServiceBackupByteIdentical(t, "Update(orgA, svcB, backupB) orgB bystander", baselineB, afterB)
}

func TestServiceBackupRepositoryMarkPendingCrossTenantIsNotFoundAndDoesNotTouchBystanders(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceBackupTenantFixture(t, db, f)

	rowA := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(fixture.orgA.ID, fixture.svcA.ID, "pending-a"))
	rowBFixture := serviceBackupFixture(fixture.orgB.ID, fixture.svcB.ID, "pending-b")
	rowBFixture.Status = store.ServiceBackupStatusDisabled
	rowB := insertServiceBackup(ctx, t, s, repo, rowBFixture)
	baselineA := getServiceBackup(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID, rowA.ID)
	baselineB := getServiceBackup(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, pendingErr := repo.MarkPending(ctx, tx, fixture.orgA.ID, fixture.svcB.ID, rowB.ID)
		return pendingErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterA := getServiceBackup(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID, rowA.ID)
	afterB := getServiceBackup(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)
	assertServiceBackupByteIdentical(t, "MarkPending(orgA, svcB, backupB) orgA peer", baselineA, afterA)
	assertServiceBackupByteIdentical(t, "MarkPending(orgA, svcB, backupB) orgB bystander", baselineB, afterB)
}

func TestServiceBackupRepositoryDeleteCrossTenantIsNotFoundAndDoesNotTouchBystanders(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceBackupTenantFixture(t, db, f)

	rowA := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(fixture.orgA.ID, fixture.svcA.ID, "delete-a"))
	rowB := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(fixture.orgB.ID, fixture.svcB.ID, "delete-b"))
	baselineA := getServiceBackup(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID, rowA.ID)
	baselineB := getServiceBackup(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, deleteErr := repo.DeleteByID(ctx, tx, fixture.orgA.ID, fixture.svcB.ID, rowB.ID, nil)
		return deleteErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterA := getServiceBackup(ctx, t, s, repo, fixture.orgA.ID, fixture.svcA.ID, rowA.ID)
	afterB := getServiceBackup(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)
	assertServiceBackupByteIdentical(t, "DeleteByID(orgA, svcB, backupB) orgA peer", baselineA, afterA)
	assertServiceBackupByteIdentical(t, "DeleteByID(orgA, svcB, backupB) orgB bystander", baselineB, afterB)
	if count := countServiceBackupsForOrg(ctx, t, db, fixture.orgB.ID); count != 1 {
		t.Errorf("orgB service_backups count after cross-tenant delete = %d, want 1", count)
	}
	if count := countServiceBackupsForOrg(ctx, t, db, fixture.orgA.ID); count != 1 {
		t.Errorf("orgA service_backups count after cross-tenant delete = %d, want 1", count)
	}
}

func TestServiceBackupReaderListBackupsCrossTenantServiceIDIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	reader, err := store.NewServiceBackupReader(s)
	if err != nil {
		t.Fatalf("NewServiceBackupReader: %v", err)
	}
	f := testutil.NewFactory(t)
	ctx := context.Background()
	fixture := seedServiceBackupTenantFixture(t, db, f)

	rowB := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(fixture.orgB.ID, fixture.svcB.ID, "reader-b"))
	baselineB := getServiceBackup(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)

	_, err = reader.ListBackups(ctx, store.ListServiceBackupsInput{
		OrganizationID: fixture.orgA.ID,
		ServiceID:      fixture.svcB.ID,
	})
	wantErrCode(t, err, yerr.CodeNotFound)

	afterB := getServiceBackup(ctx, t, s, repo, fixture.orgB.ID, fixture.svcB.ID, rowB.ID)
	assertServiceBackupByteIdentical(t, "ServiceBackupReader.ListBackups(orgA, svcB) bystander orgB", baselineB, afterB)
}
