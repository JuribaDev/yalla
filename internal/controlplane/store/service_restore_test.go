package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for the soft-delete restore path of services:
// ServiceRepository.Restore and ServiceService.Restore. They mirror
// project_restore_test.go and prove that deletion_scheduled_at is
// cleared on exactly the named row, the tenant boundary is structural
// (cross-tenant ids never touch another tenant's row), the audit
// record is committed atomically with the clear-stamp write, and the
// restore is rejected as Conflict when the service was never scheduled
// for deletion.

// newDeleteServiceInput builds a valid DeleteServiceInput for
// (orgID, serviceID). ActorOrgID mirrors OrganizationID — the
// production wire path always pins the audit record to the principal's
// home organization.
func newDeleteServiceInput(orgID, serviceID string) store.DeleteServiceInput {
	return store.DeleteServiceInput{
		OrganizationID: orgID,
		ServiceID:      serviceID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_svc_delete",
		CorrelationID:  "corr_svc_delete",
	}
}

// newRestoreServiceInput builds a valid RestoreServiceInput for
// (orgID, serviceID). ActorOrgID matches OrganizationID to mirror the
// production wire path where a member of org restores a service in
// their own tenant.
func newRestoreServiceInput(orgID, serviceID string) store.RestoreServiceInput {
	return store.RestoreServiceInput{
		OrganizationID: orgID,
		ServiceID:      serviceID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_svc_restore",
		CorrelationID:  "corr_svc_restore",
	}
}

// TestServiceRepositoryRestore proves the repository clears
// deletion_scheduled_at on exactly the named row and returns the
// persisted row, including the trigger-refreshed updated_at
// timestamp.
func TestServiceRepositoryRestore(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	svc, _, _, _ := newServiceSvc(t, s)
	ctx := context.Background()

	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "SvcRepoRestore")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcSeed := seedService(t, db, f, env, "api")

	if _, err := svc.ScheduleDeletion(ctx, newDeleteServiceInput(org.ID, svcSeed.ID)); err != nil {
		t.Fatalf("ScheduleDeletion: %v", err)
	}

	var got store.Service
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		got, writeErr = repo.Restore(ctx, tx, org.ID, svcSeed.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("Restore returned %v, want nil", err)
	}
	if got.ID != svcSeed.ID {
		t.Errorf("Restore returned id %q, want the existing service id %q", got.ID, svcSeed.ID)
	}
	if got.DeletionScheduledAt != nil {
		t.Errorf("Restore did not clear deletion_scheduled_at: %v", got.DeletionScheduledAt)
	}
	if got.ProjectID != svcSeed.ProjectID || got.EnvironmentID != svcSeed.EnvironmentID {
		t.Errorf("parent identity drifted: project=%q env=%q want (%q,%q)", got.ProjectID, got.EnvironmentID, svcSeed.ProjectID, svcSeed.EnvironmentID)
	}

	// The cleared stamp must survive a separate read transaction.
	var readBack store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.GetByID(ctx, q, org.ID, svcSeed.ID)
		return readErr
	}); err != nil {
		t.Fatalf("GetByID after restore: %v", err)
	}
	if readBack.DeletionScheduledAt != nil {
		t.Error("GetByID returned a still-stamped deletion_scheduled_at after restore")
	}
}

// TestServiceRepositoryRestoreIsTenantScoped proves the repository's
// WHERE organization_id clause makes a cross-tenant restore
// impossible: orgA cannot restore orgB's service — the query simply
// does not match — a cross-tenant id can never restore another
// tenant's service, and the other tenant's row is left untouched.
func TestServiceRepositoryRestoreIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewServiceRepository()
	svc, _, _, _ := newServiceSvc(t, s)
	ctx := context.Background()

	f := testutil.NewFactory(t)
	orgA := seedOrg(t, db, f, "SvcRestoreTenantA")
	orgB := seedOrg(t, db, f, "SvcRestoreTenantB")
	projB := seedProject(t, db, f, orgB, "Web")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcB := seedService(t, db, f, envB, "api")
	if _, err := svc.ScheduleDeletion(ctx, newDeleteServiceInput(orgB.ID, svcB.ID)); err != nil {
		t.Fatalf("ScheduleDeletion(orgB): %v", err)
	}

	// Attempt to restore orgB's service while presenting orgA's tenant
	// — the WHERE organization_id = $1 AND id = $2 query simply does
	// not match, so the repository must report NotFound.
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, restoreErr := repo.Restore(ctx, tx, orgA.ID, svcB.ID, nil)
		return restoreErr
	})
	if err == nil {
		t.Fatal("cross-tenant Restore error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Restore code = %v, want %s", err, yerr.CodeNotFound)
	}

	// orgB's service must still be soft-deleted.
	var readBack store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.GetByID(ctx, q, orgB.ID, svcB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("GetByID(orgB service): %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Errorf("orgB.service.deletion_scheduled_at cleared by cross-tenant restore; want stamp preserved")
	}
}

// TestServiceRepositoryRestoreRejectsNilTx proves the repository guard
// catches a nil transaction at call time, so a restore can never run
// outside Store.Write.
func TestServiceRepositoryRestoreRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewServiceRepository()
	_, err := repo.Restore(context.Background(), nil, "org_acme", "svc_acme", nil)
	if err == nil {
		t.Fatal("Restore(nil tx) error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Restore(nil tx) code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestServiceServiceRestoreSuccess is the happy path: a soft-deleted
// service is restored to live state and an audit event filed under
// the actor's home organization names the resource — all visible
// after Store.Write commits.
func TestServiceServiceRestoreSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	svc, authz, quota, jobs := newServiceSvc(t, s)
	ctx := context.Background()

	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "SvcSvcRestoreSuccess")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcSeed := seedService(t, db, f, env, "api")

	scheduled, err := svc.ScheduleDeletion(ctx, newDeleteServiceInput(org.ID, svcSeed.ID))
	if err != nil {
		t.Fatalf("ScheduleDeletion: %v", err)
	}
	if scheduled.DeletionScheduledAt == nil {
		t.Fatal("test setup: ScheduleDeletion did not stamp deletion_scheduled_at")
	}

	restored, err := svc.Restore(ctx, newRestoreServiceInput(org.ID, svcSeed.ID))
	if err != nil {
		t.Fatalf("Restore returned %v, want nil", err)
	}
	if restored.ID != svcSeed.ID {
		t.Errorf("Restore returned id %q, want the existing service id %q", restored.ID, svcSeed.ID)
	}
	if restored.DeletionScheduledAt != nil {
		t.Errorf("Restore did not clear deletion_scheduled_at: %v", restored.DeletionScheduledAt)
	}
	if restored.Version <= scheduled.Version {
		t.Errorf("version not bumped: %d <= %d", restored.Version, scheduled.Version)
	}
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("Restore unexpectedly ran in-tx ports: authz=%d quota=%d jobs=%d", authz.calls, quota.calls, jobs.calls)
	}

	// The cleared stamp must survive a separate read.
	repo := store.NewServiceRepository()
	var readBack store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.GetByID(ctx, q, org.ID, svcSeed.ID)
		return readErr
	}); err != nil {
		t.Fatalf("GetByID after restore: %v", err)
	}
	if readBack.DeletionScheduledAt != nil {
		t.Error("GetByID returned a still-stamped deletion_scheduled_at after restore")
	}

	// The newest audit event must be the service.restore record.
	// Earlier events are delete then restore — newest first.
	events := listServiceAuditEvents(t, s, org.ID)
	if len(events) < 2 {
		t.Fatalf("audit events len = %d, want >= 2 (delete + restore)", len(events))
	}
	restoreEvent := events[0]
	if restoreEvent.Action != "service.restore" {
		t.Errorf("audit action = %q, want service.restore", restoreEvent.Action)
	}
	if restoreEvent.ResourceKind != string(domain.KindService) {
		t.Errorf("audit resource_kind = %q, want %q", restoreEvent.ResourceKind, domain.KindService)
	}
	if restoreEvent.ResourceID != svcSeed.ID {
		t.Errorf("audit resource_id = %q, want %q", restoreEvent.ResourceID, svcSeed.ID)
	}
	if restoreEvent.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", restoreEvent.Decision)
	}
	if stamp := restoreEvent.Metadata["deletion_scheduled_at"]; stamp == "" {
		t.Errorf("audit metadata deletion_scheduled_at is empty, want the prior stamp captured before restore")
	}
}

// TestServiceServiceRestoreNotScheduledRollsBack proves a restore on
// a service that was never scheduled for deletion rolls the whole
// transaction back as a typed Conflict — no audit record is appended.
func TestServiceServiceRestoreNotScheduledRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	svc, _, _, _ := newServiceSvc(t, s)
	ctx := context.Background()

	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "SvcSvcRestoreNotScheduled")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcSeed := seedService(t, db, f, env, "api")

	_, restoreErr := svc.Restore(ctx, newRestoreServiceInput(org.ID, svcSeed.ID))
	if restoreErr == nil {
		t.Fatal("Restore(live service) error = nil, want Conflict")
	}
	if ye := yerr.From(restoreErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("Restore(live service) code = %v, want %s", restoreErr, yerr.CodeConflict)
	}

	// No service.restore audit event must have been appended.
	events := listServiceAuditEvents(t, s, org.ID)
	for _, ev := range events {
		if ev.Action == "service.restore" {
			t.Errorf("service.restore audit event leaked from rolled-back restore: %+v", ev)
		}
	}
}

// TestServiceServiceRestoreNotFound proves an unknown {service_id}
// surfaces as NotFound — the tenant-scoped repository query never
// reveals another tenant's row, even for the inner GetByID
// pre-check.
func TestServiceServiceRestoreNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	svc, _, _, _ := newServiceSvc(t, s)

	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "SvcSvcRestoreNotFound")
	ghost := domain.MustNewID(domain.KindService).String()

	_, err := svc.Restore(context.Background(), newRestoreServiceInput(org.ID, ghost))
	if err == nil {
		t.Fatal("Restore(unknown id) error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Restore(unknown id) code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestServiceServiceRestoreIsTenantScoped proves cross-tenant restore
// is denied at the persistence boundary — orgA can never restore
// orgB's service, and orgB's row is left untouched.
func TestServiceServiceRestoreIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	svc, _, _, _ := newServiceSvc(t, s)
	ctx := context.Background()

	f := testutil.NewFactory(t)
	orgA := seedOrg(t, db, f, "SvcSvcRestoreCrossA")
	orgB := seedOrg(t, db, f, "SvcSvcRestoreCrossB")
	projB := seedProject(t, db, f, orgB, "Web")
	envB := seedEnvironment(t, db, f, projB, "production")
	svcB := seedService(t, db, f, envB, "api")
	if _, err := svc.ScheduleDeletion(ctx, newDeleteServiceInput(orgB.ID, svcB.ID)); err != nil {
		t.Fatalf("ScheduleDeletion(orgB): %v", err)
	}

	in := newRestoreServiceInput(orgA.ID, svcB.ID)
	_, err := svc.Restore(ctx, in)
	if err == nil {
		t.Fatal("cross-tenant Restore error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Restore code = %v, want %s", err, yerr.CodeNotFound)
	}

	repo := store.NewServiceRepository()
	var readBack store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.GetByID(ctx, q, orgB.ID, svcB.ID)
		return readErr
	}); err != nil {
		t.Fatalf("GetByID(orgB service): %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Errorf("orgB.service.deletion_scheduled_at cleared by cross-tenant restore; want stamp preserved")
	}
}

// TestServiceServiceRestoreStaleIfMatch proves a stale If-Match
// precondition is rejected as ConflictStale carrying the row's
// current version — the audit record is never written and the row is
// unchanged.
func TestServiceServiceRestoreStaleIfMatch(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	svc, _, _, _ := newServiceSvc(t, s)
	ctx := context.Background()

	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "SvcSvcRestoreStale")
	proj := seedProject(t, db, f, org, "Web")
	env := seedEnvironment(t, db, f, proj, "production")
	svcSeed := seedService(t, db, f, env, "api")
	if _, err := svc.ScheduleDeletion(ctx, newDeleteServiceInput(org.ID, svcSeed.ID)); err != nil {
		t.Fatalf("ScheduleDeletion: %v", err)
	}

	stale := int64(99)
	in := newRestoreServiceInput(org.ID, svcSeed.ID)
	in.IfMatchVersion = &stale
	_, err := svc.Restore(ctx, in)
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
	repo := store.NewServiceRepository()
	var readBack store.Service
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.GetByID(ctx, q, org.ID, svcSeed.ID)
		return readErr
	}); err != nil {
		t.Fatalf("GetByID after rejected restore: %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Errorf("service.deletion_scheduled_at cleared by rejected stale-version restore; want stamp preserved")
	}

	// No service.restore audit event must exist.
	events := listServiceAuditEvents(t, s, org.ID)
	for _, ev := range events {
		if ev.Action == "service.restore" {
			t.Errorf("service.restore audit event leaked from rolled-back restore: %+v", ev)
		}
	}
}

// TestServiceServiceRestoreBlankInputRejected proves a blank
// OrganizationID or ServiceID is a typed InvalidInput raised before
// the transaction is ever opened.
func TestServiceServiceRestoreBlankInputRejected(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	svc, _, _, _ := newServiceSvc(t, s)

	cases := []struct {
		name string
		in   store.RestoreServiceInput
	}{
		{name: "blank org", in: store.RestoreServiceInput{OrganizationID: "", ServiceID: "svc_acme", ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: "org_acme"}},
		{name: "blank service", in: store.RestoreServiceInput{OrganizationID: "org_acme", ServiceID: "", ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: "org_acme"}},
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

// TestServiceServiceRestoreBlankActorOrgIsInternal proves a missing
// actor organization is a wiring error reported as Internal — an
// authenticated request always carries one.
func TestServiceServiceRestoreBlankActorOrgIsInternal(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	svc, _, _, _ := newServiceSvc(t, s)

	in := newRestoreServiceInput("org_acme", "svc_acme")
	in.ActorOrgID = ""
	_, err := svc.Restore(context.Background(), in)
	if err == nil {
		t.Fatal("Restore(blank actor org) error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Restore(blank actor org) code = %v, want %s", err, yerr.CodeInternal)
	}
}
