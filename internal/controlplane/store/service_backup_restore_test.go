package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestServiceBackupServiceRestoreEnqueuesDurableJobAndAuditAtomically(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()
	org := seedOrg(t, db, f, "restore-org")
	proj := seedProject(t, db, f, org, "restore-project")
	env := seedEnvironment(t, db, f, proj, "restore-env")
	svcRow := seedService(t, db, f, env, "restore-db")

	backupRepo := store.NewServiceBackupRepository()
	backup := serviceBackupFixture(org.ID, svcRow.ID, "nightly")
	backup.Status = store.ServiceBackupStatusSucceeded
	backup = insertServiceBackup(ctx, t, s, backupRepo, backup)

	jobs := &recordingJobs{}
	svc, err := store.NewServiceBackupService(
		s,
		store.NewServiceRepository(),
		backupRepo,
		&recordingAuthorizer{},
		&recordingQuota{},
		jobs,
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewServiceBackupService: %v", err)
	}

	got, err := svc.Restore(ctx, store.RestoreServiceBackupInput{
		OrganizationID: org.ID,
		ServiceID:      svcRow.ID,
		BackupID:       backup.ID,
		ActorID:        "usr_restore",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
		RequestID:      "req_restore",
		CorrelationID:  "corr_restore",
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got.ID != backup.ID || got.Status != store.ServiceBackupStatusSucceeded {
		t.Fatalf("restored backup = %+v, want succeeded backup %q", got, backup.ID)
	}
	if jobs.calls != 1 {
		t.Fatalf("job enqueue calls = %d, want 1", jobs.calls)
	}
	if len(jobs.inputs) != 1 {
		t.Fatalf("job inputs = %#v, want one", jobs.inputs)
	}
	in := jobs.inputs[0]
	if in.JobKind != "restore_backup" || in.OrganizationID != org.ID || in.ServiceID != svcRow.ID || in.ResourceID != backup.ID {
		t.Fatalf("job input = %+v", in)
	}

	events := listProjectAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].Action != "backup.restore" || events[0].ResourceID != backup.ID {
		t.Fatalf("audit event = %+v", events[0])
	}
}
