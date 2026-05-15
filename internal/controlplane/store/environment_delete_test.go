package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for the soft-delete path of environments:
// EnvironmentRepository.ScheduleDeletion and
// EnvironmentService.ScheduleDeletion. They mirror project_delete_test.go
// and prove that deletion_scheduled_at is stamped on exactly the named
// row, the tenant boundary is structural (cross-tenant ids never touch
// another tenant's data), an already-scheduled re-request is a typed
// Conflict that rolls the transaction back, and the audit record commits
// atomically with the soft-delete write.

// newDeleteEnvironmentInput builds a valid DeleteEnvironmentInput for
// (orgID, environmentID). ActorOrgID is the principal's home organization
// — the tenant the audit record is filed under — so seeding it with the
// resource organization matches the production wire path where a member
// of org schedules an environment in their own org for teardown.
func newDeleteEnvironmentInput(orgID, environmentID string) store.DeleteEnvironmentInput {
	return store.DeleteEnvironmentInput{
		OrganizationID: orgID,
		EnvironmentID:  environmentID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgID,
		RequestID:      "req_env_delete",
		CorrelationID:  "corr_env_delete",
	}
}

// TestEnvironmentRepositoryScheduleDeletion proves the repository stamps
// deletion_scheduled_at on exactly the named row and returns the persisted
// row, including the trigger-refreshed updated_at timestamp and the
// bumped version.
func TestEnvironmentRepositoryScheduleDeletion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentRepository()
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "EnvRepoSchedDel")
	proj := seedProject(t, db, f, org, "Web")
	envSeed := seedEnvironment(t, db, f, proj, "production")

	var got store.Environment
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		got, writeErr = repo.ScheduleDeletion(ctx, tx, org.ID, envSeed.ID, nil)
		return writeErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion returned %v, want nil", err)
	}
	if got.ID != envSeed.ID {
		t.Errorf("ScheduleDeletion returned id %q, want %q", got.ID, envSeed.ID)
	}
	if got.DeletionScheduledAt == nil {
		t.Fatal("ScheduleDeletion did not stamp deletion_scheduled_at")
	}
	if got.Version <= 1 {
		t.Errorf("version not bumped: %d", got.Version)
	}

	// The stamp must survive a separate read.
	var readBack store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		readBack, readErr = repo.GetByID(ctx, q, org.ID, envSeed.ID)
		return readErr
	}); err != nil {
		t.Fatalf("GetByID after schedule: %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Error("GetByID did not return the persisted deletion_scheduled_at stamp")
	}
}

// TestEnvironmentRepositoryScheduleDeletionNotFound proves an unknown
// {environment_id} surfaces as a typed NotFound — never disguised as a
// silent success.
func TestEnvironmentRepositoryScheduleDeletionNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentRepository()
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "EnvRepoSchedDelNF")

	writeErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, org.ID, "env_does_not_exist", nil)
		return err
	})
	if writeErr == nil {
		t.Fatal("ScheduleDeletion(unknown env) error = nil, want NotFound")
	}
	if ye := yerr.From(writeErr); ye.Code != yerr.CodeNotFound {
		t.Errorf("code = %v, want %s", writeErr, yerr.CodeNotFound)
	}
}

// TestEnvironmentRepositoryScheduleDeletionIsTenantScoped proves a
// cross-tenant {environment_id} never schedules another organization's
// environment for teardown. The tenant-scoped UPDATE matches no rows and
// surfaces as NotFound, and the other tenant's row is left untouched.
func TestEnvironmentRepositoryScheduleDeletionIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewEnvironmentRepository()
	ctx := context.Background()
	fA := testutil.NewFactory(t)
	fB := testutil.NewFactory(t)

	orgA := seedOrg(t, db, fA, "EnvRepoTenantA")
	projA := seedProject(t, db, fA, orgA, "Web")
	envA := seedEnvironment(t, db, fA, projA, "production")

	orgB := seedOrg(t, db, fB, "EnvRepoTenantB")

	// Tenant B tries to schedule deletion on tenant A's env.
	writeErr := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.ScheduleDeletion(ctx, tx, orgB.ID, envA.ID, nil)
		return err
	})
	if writeErr == nil {
		t.Fatal("cross-tenant ScheduleDeletion error = nil, want NotFound")
	}
	if ye := yerr.From(writeErr); ye.Code != yerr.CodeNotFound {
		t.Errorf("code = %v, want %s", writeErr, yerr.CodeNotFound)
	}

	// Tenant A's env must still be live.
	var readBack store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		readBack, rErr = repo.GetByID(ctx, q, orgA.ID, envA.ID)
		return rErr
	}); err != nil {
		t.Fatalf("GetByID(orgA env): %v", err)
	}
	if readBack.DeletionScheduledAt != nil {
		t.Error("tenant A's env was scheduled for deletion by a tenant B request")
	}
}

// TestEnvironmentRepositoryScheduleDeletionRejectsNilTx proves a nil
// transaction is rejected as Internal — a wiring error, not a silent no-op.
func TestEnvironmentRepositoryScheduleDeletionRejectsNilTx(t *testing.T) {
	t.Parallel()
	repo := store.NewEnvironmentRepository()
	_, err := repo.ScheduleDeletion(context.Background(), nil, "org_x", "env_x", nil)
	if err == nil {
		t.Fatal("nil tx ScheduleDeletion error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Errorf("nil tx code = %v, want %s", err, yerr.CodeInternal)
	}
}

// TestEnvironmentServiceScheduleDeletionSuccess proves the orchestrator
// stamps deletion_scheduled_at, bumps the version, files an environment.delete
// audit row inside the same transaction, and records the resolved stamp
// time in the audit metadata.
func TestEnvironmentServiceScheduleDeletionSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "EnvSvcSchedDelOK")
	proj := seedProject(t, db, f, org, "Web")
	envSeed := seedEnvironment(t, db, f, proj, "production")

	svc, authz, quota, jobs := newEnvironmentSvc(t, s)

	scheduled, err := svc.ScheduleDeletion(ctx, newDeleteEnvironmentInput(org.ID, envSeed.ID))
	if err != nil {
		t.Fatalf("ScheduleDeletion: %v", err)
	}
	if scheduled.ID != envSeed.ID {
		t.Errorf("scheduled.ID = %q, want %q", scheduled.ID, envSeed.ID)
	}
	if scheduled.DeletionScheduledAt == nil {
		t.Fatal("scheduled.DeletionScheduledAt is nil, want the resolved stamp time")
	}
	if scheduled.Version <= 1 {
		t.Errorf("version not bumped: %d", scheduled.Version)
	}
	// The delete path must not invoke the in-tx Authorize / Quota /
	// JobEnqueue ports; the HTTP boundary is authoritative.
	if authz.calls != 0 || quota.calls != 0 || jobs.calls != 0 {
		t.Errorf("delete path unexpectedly ran in-tx ports: authz=%d quota=%d jobs=%d", authz.calls, quota.calls, jobs.calls)
	}

	events := listEnvironmentAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the schedule", len(events))
	}
	ev := events[0]
	if ev.Action != "environment.delete" {
		t.Errorf("audit action = %q, want environment.delete", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != envSeed.ID {
		t.Errorf("audit resource_id = %q, want %q", ev.ResourceID, envSeed.ID)
	}
	if ev.ResourceKind != string(domain.KindEnvironment) {
		t.Errorf("audit resource_kind = %q, want %q", ev.ResourceKind, domain.KindEnvironment)
	}
	if stamp := ev.Metadata["deletion_scheduled_at"]; stamp == "" {
		t.Errorf("audit metadata deletion_scheduled_at is empty, want the resolved stamp time")
	}
}

// TestEnvironmentServiceScheduleDeletionAlreadyScheduledRollsBack proves a
// second schedule on an environment that is already scheduled for teardown
// rolls the whole transaction back as a typed Conflict: the
// deletion_scheduled_at stamp must not move, and no second audit event is
// appended.
func TestEnvironmentServiceScheduleDeletionAlreadyScheduledRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "EnvSvcSchedDelDup")
	proj := seedProject(t, db, f, org, "Web")
	envSeed := seedEnvironment(t, db, f, proj, "production")

	svc, _, _, _ := newEnvironmentSvc(t, s)

	scheduled, err := svc.ScheduleDeletion(ctx, newDeleteEnvironmentInput(org.ID, envSeed.ID))
	if err != nil {
		t.Fatalf("first ScheduleDeletion: %v", err)
	}
	firstStamp := scheduled.DeletionScheduledAt
	if firstStamp == nil {
		t.Fatal("first ScheduleDeletion returned a nil stamp")
	}

	_, secondErr := svc.ScheduleDeletion(ctx, newDeleteEnvironmentInput(org.ID, envSeed.ID))
	if secondErr == nil {
		t.Fatal("second ScheduleDeletion error = nil, want Conflict")
	}
	if ye := yerr.From(secondErr); ye.Code != yerr.CodeConflict {
		t.Fatalf("second ScheduleDeletion code = %v, want %s", secondErr, yerr.CodeConflict)
	}

	// The stamp must not have moved.
	repo := store.NewEnvironmentRepository()
	var readBack store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		readBack, rErr = repo.GetByID(ctx, q, org.ID, envSeed.ID)
		return rErr
	}); err != nil {
		t.Fatalf("GetByID after second schedule: %v", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Fatal("stamp disappeared after the rejected second schedule")
	}
	if !readBack.DeletionScheduledAt.Equal(*firstStamp) {
		t.Errorf("stamp moved: %v -> %v; second schedule must roll back", firstStamp, readBack.DeletionScheduledAt)
	}

	// Only one environment.delete audit event should exist; any more
	// means the rolled-back second schedule leaked an audit row.
	events := listEnvironmentAuditEvents(t, s, org.ID)
	deletes := 0
	for _, ev := range events {
		if ev.Action == "environment.delete" {
			deletes++
		}
	}
	if deletes != 1 {
		t.Errorf("environment.delete audit events = %d, want 1 (second schedule must roll back)", deletes)
	}
}

// TestEnvironmentServiceScheduleDeletionNotFound proves an unknown
// {environment_id} surfaces as NotFound at the orchestrator boundary —
// the tenant-scoped inner Get pre-check returns NotFound without writing
// any audit row.
func TestEnvironmentServiceScheduleDeletionNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "EnvSvcSchedDelNF")
	svc, _, _, _ := newEnvironmentSvc(t, s)

	_, err := svc.ScheduleDeletion(ctx, newDeleteEnvironmentInput(org.ID, "env_does_not_exist"))
	if err == nil {
		t.Fatal("unknown env ScheduleDeletion error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("unknown env code = %v, want %s", err, yerr.CodeNotFound)
	}

	events := listEnvironmentAuditEvents(t, s, org.ID)
	if len(events) != 0 {
		t.Errorf("audit events = %d, want 0 (no audit for a NotFound delete)", len(events))
	}
}

// TestEnvironmentServiceScheduleDeletionIsTenantScoped proves a
// cross-tenant {environment_id} surfaces as NotFound at the orchestrator
// boundary, never reveals the other tenant's environment, and never
// writes an audit row.
func TestEnvironmentServiceScheduleDeletionIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	fA := testutil.NewFactory(t)
	fB := testutil.NewFactory(t)

	orgA := seedOrg(t, db, fA, "EnvSvcTenantA")
	projA := seedProject(t, db, fA, orgA, "Web")
	envA := seedEnvironment(t, db, fA, projA, "production")

	orgB := seedOrg(t, db, fB, "EnvSvcTenantB")
	svc, _, _, _ := newEnvironmentSvc(t, s)

	_, err := svc.ScheduleDeletion(ctx, newDeleteEnvironmentInput(orgB.ID, envA.ID))
	if err == nil {
		t.Fatal("cross-tenant ScheduleDeletion error = nil, want NotFound")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("code = %v, want %s", err, yerr.CodeNotFound)
	}

	// Tenant A's env must still be live.
	repo := store.NewEnvironmentRepository()
	var readBack store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		readBack, rErr = repo.GetByID(ctx, q, orgA.ID, envA.ID)
		return rErr
	}); err != nil {
		t.Fatalf("GetByID(orgA env): %v", err)
	}
	if readBack.DeletionScheduledAt != nil {
		t.Error("tenant A's env was scheduled for deletion by a tenant B request")
	}
	// And tenant B must have no audit row from the rejected attempt.
	events := listEnvironmentAuditEvents(t, s, orgB.ID)
	if len(events) != 0 {
		t.Errorf("tenant B audit events = %d, want 0", len(events))
	}
}

// TestEnvironmentServiceScheduleDeletionStaleIfMatch proves the version
// pre-check surfaces a stale If-Match BEFORE the already-scheduled check —
// the caller learns "your view of the version is stale" with the row's
// authoritative version under details.current_version, instead of an
// already-scheduled or not-found message that races with concurrent
// edits the caller did not see.
func TestEnvironmentServiceScheduleDeletionStaleIfMatch(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)

	org := seedOrg(t, db, f, "EnvSvcSchedDelStale")
	proj := seedProject(t, db, f, org, "Web")
	envSeed := seedEnvironment(t, db, f, proj, "production")

	svc, _, _, _ := newEnvironmentSvc(t, s)

	stale := int64(99)
	in := newDeleteEnvironmentInput(org.ID, envSeed.ID)
	in.IfMatchVersion = &stale

	_, err := svc.ScheduleDeletion(ctx, in)
	if err == nil {
		t.Fatal("stale If-Match ScheduleDeletion error = nil, want ConflictStale")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Errorf("code = %v, want %s", err, yerr.CodeConflict)
	}

	// The env must remain live (no soft-delete stamp).
	repo := store.NewEnvironmentRepository()
	var readBack store.Environment
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		readBack, rErr = repo.GetByID(ctx, q, org.ID, envSeed.ID)
		return rErr
	}); err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if readBack.DeletionScheduledAt != nil {
		t.Error("env was scheduled for deletion despite a stale If-Match")
	}
}

// TestEnvironmentServiceScheduleDeletionBlankInput proves a blank
// OrganizationID or EnvironmentID is a typed InvalidInput raised before
// any transaction is opened. The store layer must never write nor read
// for a partially-formed request.
func TestEnvironmentServiceScheduleDeletionBlankInput(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	svc, _, _, _ := newEnvironmentSvc(t, s)

	cases := []struct {
		name string
		in   store.DeleteEnvironmentInput
	}{
		{"blank organization id", store.DeleteEnvironmentInput{EnvironmentID: "env_x", ActorOrgID: "org_x"}},
		{"blank environment id", store.DeleteEnvironmentInput{OrganizationID: "org_x", ActorOrgID: "org_x"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := svc.ScheduleDeletion(context.Background(), tc.in)
			if err == nil {
				t.Fatalf("%s: error = nil, want InvalidInput", tc.name)
			}
			if ye := yerr.From(err); ye.Code != yerr.CodeInvalidInput {
				t.Errorf("%s: code = %v, want %s", tc.name, err, yerr.CodeInvalidInput)
			}
		})
	}
}

// TestEnvironmentServiceScheduleDeletionRequiresActorOrg proves a missing
// actor organization is a typed Internal error (a wiring failure, not
// client input) — an authenticated request always carries one, and the
// store layer must refuse to write an audit record without it.
func TestEnvironmentServiceScheduleDeletionRequiresActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	svc, _, _, _ := newEnvironmentSvc(t, s)

	in := store.DeleteEnvironmentInput{
		OrganizationID: "org_x",
		EnvironmentID:  "env_x",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		// ActorOrgID intentionally empty.
	}
	_, err := svc.ScheduleDeletion(context.Background(), in)
	if err == nil {
		t.Fatal("missing actor org error = nil, want Internal")
	}
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("missing actor org code = %v, want %s", err, yerr.CodeInternal)
	}
}
