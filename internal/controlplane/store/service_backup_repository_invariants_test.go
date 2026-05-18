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

// Integration tests for ServiceBackupRepository's CRUD invariants (BE-0477).
// Tenant-isolation gets its own PRD story; this file pins the single-row
// lifecycle guarantees every caller depends on.

type serviceBackupTxRollbackSentinel struct{}

func (serviceBackupTxRollbackSentinel) Error() string {
	return "rollback service backup test transaction"
}

func serviceBackupFixture(orgID, serviceID, displayName string) store.ServiceBackup {
	return store.ServiceBackup{
		ID:             domain.MustNewID(domain.KindServiceBackup).String(),
		OrganizationID: orgID,
		ServiceID:      serviceID,
		DisplayName:    displayName,
		Schedule:       "0 2 * * *",
		RetentionCount: 7,
		Enabled:        true,
	}
}

func insertServiceBackup(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceBackupRepository, b store.ServiceBackup) store.ServiceBackup {
	t.Helper()
	var stored store.ServiceBackup
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Insert(ctx, tx, b)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("insert service backup: %v", err)
	}
	return stored
}

func getServiceBackup(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceBackupRepository, orgID, serviceID, backupID string) store.ServiceBackup {
	t.Helper()
	var got store.ServiceBackup
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		row, err := repo.GetByID(ctx, q, orgID, serviceID, backupID)
		if err != nil {
			return err
		}
		got = row
		return nil
	}); err != nil {
		t.Fatalf("GetByID(%q): %v", backupID, err)
	}
	return got
}

func listServiceBackups(ctx context.Context, t *testing.T, s *store.Store, repo *store.ServiceBackupRepository, orgID, serviceID string) []store.ServiceBackup {
	t.Helper()
	var got []store.ServiceBackup
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		rows, err := repo.ListByService(ctx, q, orgID, serviceID)
		if err != nil {
			return err
		}
		got = rows
		return nil
	}); err != nil {
		t.Fatalf("ListByService(%q, %q): %v", orgID, serviceID, err)
	}
	return got
}

func countServiceBackupsForService(ctx context.Context, t *testing.T, db *testutil.DB, orgID, serviceID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM service_backups WHERE organization_id = $1 AND service_id = $2`,
		orgID, serviceID).Scan(&count); err != nil {
		t.Fatalf("count service_backups: %v", err)
	}
	return count
}

func assertServiceBackupSameIdentity(t *testing.T, got, want store.ServiceBackup) {
	t.Helper()
	if got.ID != want.ID ||
		got.OrganizationID != want.OrganizationID ||
		got.ServiceID != want.ServiceID {
		t.Fatalf("identity = (id=%q org=%q svc=%q), want (id=%q org=%q svc=%q)",
			got.ID, got.OrganizationID, got.ServiceID, want.ID, want.OrganizationID, want.ServiceID)
	}
}

func TestServiceBackupRepositoryInsertZeroRetentionUsesDefault(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "backup-default")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "database")
	want := serviceBackupFixture(org.ID, svc.ID, "nightly")
	want.RetentionCount = 0

	got := insertServiceBackup(ctx, t, s, repo, want)

	assertServiceBackupSameIdentity(t, got, want)
	if got.RetentionCount != 7 {
		t.Errorf("retention_count = %d, want schema default 7", got.RetentionCount)
	}
	if got.Status != store.ServiceBackupStatusPending {
		t.Errorf("status = %q, want %q", got.Status, store.ServiceBackupStatusPending)
	}
	if got.Version != 1 {
		t.Errorf("version = %d, want 1", got.Version)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("timestamps must be database-populated, got created_at=%v updated_at=%v", got.CreatedAt, got.UpdatedAt)
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("created_at=%v updated_at=%v, want equal on fresh INSERT", got.CreatedAt, got.UpdatedAt)
	}
}

func TestServiceBackupRepositoryListByServiceOrdersDeterministically(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "backup-list")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(org.ID, svc.ID, "alpha"))
	insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(org.ID, svc.ID, "bravo"))
	insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(org.ID, svc.ID, "charlie"))

	got := listServiceBackups(ctx, t, s, repo, org.ID, svc.ID)
	if len(got) != 3 {
		t.Fatalf("ListByService returned %d rows, want 3", len(got))
	}
	for i := 1; i < len(got); i++ {
		prev, curr := got[i-1], got[i]
		if curr.CreatedAt.Before(prev.CreatedAt) || (curr.CreatedAt.Equal(prev.CreatedAt) && curr.ID < prev.ID) {
			t.Fatalf("ListByService order regressed at %d: previous=%+v current=%+v", i, prev, curr)
		}
	}
}

func TestServiceBackupRepositoryUpdateBumpsVersionAndPreservesWorkerState(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "backup-update")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	baseline := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(org.ID, svc.ID, "nightly"))

	lastRun := baseline.CreatedAt.Add(time.Minute)
	lastSuccess := baseline.CreatedAt.Add(2 * time.Minute)
	if _, err := db.Exec(ctx,
		`UPDATE service_backups
		    SET status = 'succeeded',
		        last_run_at = $4,
		        last_succeeded_at = $5
		  WHERE organization_id = $1 AND service_id = $2 AND id = $3`,
		org.ID, svc.ID, baseline.ID, lastRun, lastSuccess); err != nil {
		t.Fatalf("seed worker state: %v", err)
	}
	current := getServiceBackup(ctx, t, s, repo, org.ID, svc.ID, baseline.ID)

	time.Sleep(time.Millisecond)
	desired := current
	desired.DisplayName = "weekly"
	desired.Schedule = "0 3 * * 0"
	desired.RetentionCount = 14
	desired.Enabled = false
	version := current.Version

	var updated store.ServiceBackup
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

	assertServiceBackupSameIdentity(t, updated, current)
	if updated.DisplayName != desired.DisplayName || updated.Schedule != desired.Schedule || updated.RetentionCount != desired.RetentionCount || updated.Enabled != desired.Enabled {
		t.Errorf("updated mutable fields = %+v, want %+v", updated, desired)
	}
	if updated.Status != current.Status || updated.LastRunAt == nil || updated.LastSucceededAt == nil || !updated.LastRunAt.Equal(*current.LastRunAt) || !updated.LastSucceededAt.Equal(*current.LastSucceededAt) {
		t.Errorf("worker state changed during customer update: got status=%q last_run_at=%v last_succeeded_at=%v, want status=%q last_run_at=%v last_succeeded_at=%v",
			updated.Status, updated.LastRunAt, updated.LastSucceededAt, current.Status, current.LastRunAt, current.LastSucceededAt)
	}
	if updated.Version != current.Version+1 {
		t.Errorf("updated version = %d, want %d", updated.Version, current.Version+1)
	}
	if !updated.CreatedAt.Equal(current.CreatedAt) {
		t.Errorf("created_at changed from %v to %v", current.CreatedAt, updated.CreatedAt)
	}
	if !updated.UpdatedAt.After(current.UpdatedAt) {
		t.Errorf("updated_at = %v, want after baseline %v", updated.UpdatedAt, current.UpdatedAt)
	}
}

func TestServiceBackupRepositoryUpdateStaleVersionIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "backup-stale")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	baseline := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(org.ID, svc.ID, "nightly"))

	desired := baseline
	desired.DisplayName = "weekly"
	stale := baseline.Version + 99
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, updateErr := repo.Update(ctx, tx, desired, &stale)
		return updateErr
	})
	wantErrCode(t, err, yerr.CodeConflict)

	got := getServiceBackup(ctx, t, s, repo, org.ID, svc.ID, baseline.ID)
	if got != baseline {
		t.Errorf("stale Update mutated row: got %+v, want %+v", got, baseline)
	}
}

func TestServiceBackupRepositoryMarkPendingBumpsVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "backup-pending")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	baseline := insertServiceBackup(ctx, t, s, repo, store.ServiceBackup{
		ID:             domain.MustNewID(domain.KindServiceBackup).String(),
		OrganizationID: org.ID,
		ServiceID:      svc.ID,
		DisplayName:    "disabled",
		Schedule:       "0 2 * * *",
		RetentionCount: 7,
		Enabled:        true,
		Status:         store.ServiceBackupStatusDisabled,
	})

	time.Sleep(time.Millisecond)
	var updated store.ServiceBackup
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.MarkPending(ctx, tx, org.ID, svc.ID, baseline.ID)
		if err != nil {
			return err
		}
		updated = row
		return nil
	}); err != nil {
		t.Fatalf("MarkPending returned %v, want nil", err)
	}

	if updated.Status != store.ServiceBackupStatusPending {
		t.Errorf("status = %q, want %q", updated.Status, store.ServiceBackupStatusPending)
	}
	if updated.Version != baseline.Version+1 {
		t.Errorf("version = %d, want %d", updated.Version, baseline.Version+1)
	}
	if !updated.UpdatedAt.After(baseline.UpdatedAt) {
		t.Errorf("updated_at = %v, want after %v", updated.UpdatedAt, baseline.UpdatedAt)
	}
}

func TestServiceBackupRepositoryDeleteReturnsSnapshotAndRemovesRow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "backup-delete")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	baseline := insertServiceBackup(ctx, t, s, repo, serviceBackupFixture(org.ID, svc.ID, "nightly"))
	version := baseline.Version

	var deleted store.ServiceBackup
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.DeleteByID(ctx, tx, org.ID, svc.ID, baseline.ID, &version)
		if err != nil {
			return err
		}
		deleted = row
		return nil
	}); err != nil {
		t.Fatalf("DeleteByID returned %v, want nil", err)
	}
	if deleted != baseline {
		t.Errorf("deleted snapshot = %+v, want %+v", deleted, baseline)
	}
	if count := countServiceBackupsForService(ctx, t, db, org.ID, svc.ID); count != 0 {
		t.Errorf("service_backups row count = %d, want 0 after delete", count)
	}
	err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, getErr := repo.GetByID(ctx, q, org.ID, svc.ID, baseline.ID)
		return getErr
	})
	wantErrCode(t, err, yerr.CodeNotFound)
}

func TestServiceBackupRepositoryConstraintViolationsAreTypedConflicts(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "backup-constraints")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")

	tests := []struct {
		name string
		row  store.ServiceBackup
	}{
		{
			name: "blank display name",
			row: func() store.ServiceBackup {
				b := serviceBackupFixture(org.ID, svc.ID, "")
				return b
			}(),
		},
		{
			name: "blank schedule",
			row: func() store.ServiceBackup {
				b := serviceBackupFixture(org.ID, svc.ID, "blank schedule")
				b.Schedule = ""
				return b
			}(),
		},
		{
			name: "retention below minimum",
			row: func() store.ServiceBackup {
				b := serviceBackupFixture(org.ID, svc.ID, "bad retention")
				b.RetentionCount = -1
				return b
			}(),
		},
		{
			name: "unknown status",
			row: func() store.ServiceBackup {
				b := serviceBackupFixture(org.ID, svc.ID, "bad status")
				b.Status = "done"
				return b
			}(),
		},
		{
			name: "unknown service",
			row:  serviceBackupFixture(org.ID, domain.MustNewID(domain.KindService).String(), "unknown service"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, insertErr := repo.Insert(ctx, tx, tt.row)
				return insertErr
			})
			wantErrCode(t, err, yerr.CodeConflict)
		})
	}
}

func TestServiceBackupRepositoryRollsBackTransaction(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceBackupRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "backup-rollback")
	proj := seedProject(t, db, f, org, "web")
	env := seedEnvironment(t, db, f, proj, "production")
	svc := seedService(t, db, f, env, "api")
	row := serviceBackupFixture(org.ID, svc.ID, "nightly")

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, insertErr := repo.Insert(ctx, tx, row); insertErr != nil {
			return insertErr
		}
		return serviceBackupTxRollbackSentinel{}
	})
	var sentinel serviceBackupTxRollbackSentinel
	if !errors.As(err, &sentinel) {
		t.Fatalf("Write error = %v, want serviceBackupTxRollbackSentinel", err)
	}
	if count := countServiceBackupsForService(ctx, t, db, org.ID, svc.ID); count != 0 {
		t.Errorf("service_backups row count after rollback = %d, want 0", count)
	}
}

func TestServiceBackupRepositoryNilTxGuards(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceBackupRepository()
	ctx := context.Background()

	_, err := repo.Insert(ctx, nil, store.ServiceBackup{})
	wantErrCode(t, err, yerr.CodeInternal)
	_, err = repo.Update(ctx, nil, store.ServiceBackup{}, nil)
	wantErrCode(t, err, yerr.CodeInternal)
	_, err = repo.MarkPending(ctx, nil, "", "", "")
	wantErrCode(t, err, yerr.CodeInternal)
	_, err = repo.DeleteByID(ctx, nil, "", "", "", nil)
	wantErrCode(t, err, yerr.CodeInternal)
}
