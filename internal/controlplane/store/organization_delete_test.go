package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for the schedule-deletion path of OrganizationRepository
// and OrganizationService — the soft-delete unit of work behind DELETE
// /v1/organizations/{org_id} (BE-0058). They prove deletion_scheduled_at is
// stamped atomically with the immutable audit record, that a missing {org_id}
// is a typed NotFound that leaves no audit record, that re-scheduling an
// organization already scheduled for deletion rolls the whole transaction back
// as a typed Conflict, and that one tenant's scheduling never touches another's
// row. They run against an isolated, freshly migrated Postgres database and
// skip when YALLA_TEST_DATABASE_URL is unset.

// TestOrganizationRepositoryScheduleDeletion proves the repository stamps
// deletion_scheduled_at on exactly the named row and returns the persisted
// timestamp.
func TestOrganizationRepositoryScheduleDeletion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme-co")

	var got store.Organization
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var writeErr error
		got, writeErr = repo.ScheduleDeletion(ctx, tx, org.ID)
		return writeErr
	}); err != nil {
		t.Fatalf("ScheduleDeletion returned %v, want nil", err)
	}
	if got.ID != org.ID {
		t.Errorf("ScheduleDeletion returned id %q, want the existing organization id %q", got.ID, org.ID)
	}
	if got.DeletionScheduledAt == nil {
		t.Fatal("ScheduleDeletion did not stamp deletion_scheduled_at")
	}

	// The stamp is the source of truth: a read-back must observe it.
	reader, err := store.NewOrganizationReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationReader: %v", err)
	}
	readBack, err := reader.GetOrganization(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrganization(scheduled) returned %v, want the scheduled row", err)
	}
	if readBack.DeletionScheduledAt == nil {
		t.Error("GetOrganization did not return the persisted deletion_scheduled_at stamp")
	}
}

// TestOrganizationRepositoryScheduleDeletionNotFound proves an {org_id} with no
// row is the typed NotFound the repository produces — the same shape one tenant
// sees for another tenant's (unknown-to-it) id.
func TestOrganizationRepositoryScheduleDeletionNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewOrganizationRepository()
	ctx := context.Background()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, scheduleErr := repo.ScheduleDeletion(ctx, tx, "org_does_not_exist")
		return scheduleErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("ScheduleDeletion(missing) error = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestOrganizationServiceScheduleDeletion is the happy path: the organization is
// stamped for deletion and an immutable organization.delete audit record is
// committed atomically with it, filed under the actor's organization and naming
// the scheduled organization as its resource.
func TestOrganizationServiceScheduleDeletion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme-co")
	svc := newOrganizationService(t, s)

	scheduled, err := svc.ScheduleDeletion(ctx, store.DeleteOrganizationInput{
		OrganizationID: org.ID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	})
	if err != nil {
		t.Fatalf("ScheduleDeletion returned %v, want nil", err)
	}
	if scheduled.ID != org.ID {
		t.Errorf("ScheduleDeletion returned id %q, want the existing organization id %q", scheduled.ID, org.ID)
	}
	if scheduled.DeletionScheduledAt == nil {
		t.Fatal("ScheduleDeletion did not stamp deletion_scheduled_at")
	}

	// The mutation is the source of truth: it must be readable back.
	reader, err := store.NewOrganizationReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationReader: %v", err)
	}
	got, err := reader.GetOrganization(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrganization(scheduled) returned %v, want the scheduled row", err)
	}
	if got.DeletionScheduledAt == nil {
		t.Error("GetOrganization did not return the persisted deletion_scheduled_at stamp")
	}

	// The audit record is filed under the actor's organization and names the
	// scheduled organization as its resource.
	events := listAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the scheduled deletion", len(events))
	}
	ev := events[0]
	if ev.Action != "organization.delete" {
		t.Errorf("audit action = %q, want organization.delete", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != org.ID {
		t.Errorf("audit resource_id = %q, want the scheduled organization id %q", ev.ResourceID, org.ID)
	}
	if ev.ActorID != "usr_ada" || ev.ActorKind != "usr" {
		t.Errorf("audit actor = %q/%q, want usr_ada/usr", ev.ActorID, ev.ActorKind)
	}
	if ev.RequestID != "req_test" || ev.CorrelationID != "corr_test" {
		t.Errorf("audit correlation = %q/%q, want req_test/corr_test", ev.RequestID, ev.CorrelationID)
	}
	stamp := ev.Metadata["deletion_scheduled_at"]
	if stamp == "" {
		t.Errorf("audit metadata deletion_scheduled_at is empty, want the resolved stamp time")
	} else if _, parseErr := time.Parse(time.RFC3339Nano, stamp); parseErr != nil {
		t.Errorf("audit metadata deletion_scheduled_at = %q, want an RFC 3339 timestamp: %v", stamp, parseErr)
	}
}

// TestOrganizationServiceScheduleDeletionNotFound proves an {org_id} with no row
// is the typed NotFound the repository produces — and no audit record is
// written for a deletion that never happened.
func TestOrganizationServiceScheduleDeletionNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	actor := seedOrg(t, db, f, "actor-co")
	svc := newOrganizationService(t, s)

	_, err := svc.ScheduleDeletion(ctx, store.DeleteOrganizationInput{
		OrganizationID: "org_does_not_exist",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("ScheduleDeletion of a missing organization error = %v, want %s", err, yerr.CodeNotFound)
	}
	if events := listAuditEvents(t, s, actor.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want zero — a not-found deletion must leave no audit record", len(events))
	}
}

// TestOrganizationServiceScheduleDeletionAlreadyScheduledRollsBack proves a
// second schedule request for an already-scheduled organization rolls the whole
// transaction back as a typed Conflict, so the audit log can never name a
// deletion that did not change the resource's state — exactly one audit record
// survives, from the first schedule.
func TestOrganizationServiceScheduleDeletionAlreadyScheduledRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme-co")
	svc := newOrganizationService(t, s)

	in := store.DeleteOrganizationInput{
		OrganizationID: org.ID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	}
	if _, err := svc.ScheduleDeletion(ctx, in); err != nil {
		t.Fatalf("first ScheduleDeletion returned %v, want nil", err)
	}

	_, err := svc.ScheduleDeletion(ctx, in)
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("second ScheduleDeletion error = %v, want %s", err, yerr.CodeConflict)
	}
	if events := listAuditEvents(t, s, org.ID); len(events) != 1 {
		t.Errorf("audit events = %d, want exactly one — the rolled-back second schedule must leave no audit record", len(events))
	}
}

// TestOrganizationServiceScheduleDeletionIsTenantScoped proves scheduling one
// tenant's organization for deletion never touches another tenant's row.
func TestOrganizationServiceScheduleDeletionIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	svc := newOrganizationService(t, s)

	if _, err := svc.ScheduleDeletion(ctx, store.DeleteOrganizationInput{
		OrganizationID: orgA.ID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgA.ID,
	}); err != nil {
		t.Fatalf("ScheduleDeletion(orgA) returned %v, want nil", err)
	}

	reader, err := store.NewOrganizationReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationReader: %v", err)
	}
	gotB, err := reader.GetOrganization(ctx, orgB.ID)
	if err != nil {
		t.Fatalf("GetOrganization(orgB) returned %v, want orgB's row", err)
	}
	if gotB.DeletionScheduledAt != nil {
		t.Errorf("orgB.deletion_scheduled_at = %v, want nil — scheduling orgA must never touch orgB", gotB.DeletionScheduledAt)
	}
}

// TestOrganizationServiceScheduleDeletionBlankOrganizationID proves a blank
// organization id is a typed validation failure raised before any transaction
// is opened, so no audit record is written.
func TestOrganizationServiceScheduleDeletionBlankOrganizationID(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	actor := seedOrg(t, db, f, "actor-co")
	svc := newOrganizationService(t, s)

	_, err := svc.ScheduleDeletion(ctx, store.DeleteOrganizationInput{
		OrganizationID: "   ",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("blank-id ScheduleDeletion error = %v, want %s", err, yerr.CodeInvalidInput)
	}
	if events := listAuditEvents(t, s, actor.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want zero — an invalid request must never open a transaction", len(events))
	}
}

// TestOrganizationServiceScheduleDeletionRequiresActorOrganization proves a
// missing actor organization is a typed error, not a silent write: an
// authenticated request always carries one, so its absence is a wiring fault.
func TestOrganizationServiceScheduleDeletionRequiresActorOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme-co")
	svc := newOrganizationService(t, s)

	_, err := svc.ScheduleDeletion(ctx, store.DeleteOrganizationInput{
		OrganizationID: org.ID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     "",
	})
	if err == nil {
		t.Fatal("ScheduleDeletion with no actor organization returned nil, want a typed error")
	}
}
