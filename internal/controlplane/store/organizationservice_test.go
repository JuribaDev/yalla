package store_test

import (
	"context"
	"testing"

	controljobs "github.com/JuribaDev/yalla/internal/controlplane/jobs"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for OrganizationService — the create-organization unit of
// work behind POST /v1/organizations. They prove the organization row and its
// immutable audit record are committed atomically, that a slug conflict rolls
// the whole transaction back (no orphaned audit record), and that an invalid
// request never opens a transaction. They run against an isolated, freshly
// migrated Postgres database and skip when YALLA_TEST_DATABASE_URL is unset.

func newOrganizationService(t *testing.T, s *store.Store) *store.OrganizationService {
	t.Helper()
	return newOrganizationServiceWithJobs(t, s, &recordingJobs{})
}

func newOrganizationServiceWithJobs(t *testing.T, s *store.Store, jobs *recordingJobs) *store.OrganizationService {
	t.Helper()
	svc, err := store.NewOrganizationService(s, store.NewOrganizationRepository(), jobs, store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewOrganizationService: %v", err)
	}
	return svc
}

func listAuditEvents(t *testing.T, s *store.Store, organizationID string) []store.AuditEvent {
	t.Helper()
	var events []store.AuditEvent
	if err := s.Read(context.Background(), func(ctx context.Context, q store.Querier) error {
		var readErr error
		events, readErr = store.NewAuditRepository().ListByOrganization(ctx, q, organizationID, 50)
		return readErr
	}); err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	return events
}

func TestOrganizationServiceCreate(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	actor := seedOrg(t, db, f, "actor-co")
	jobs := &recordingJobs{}
	svc := newOrganizationServiceWithJobs(t, s, jobs)

	created, err := svc.Create(ctx, store.CreateOrganizationInput{
		Slug:          "acme",
		DisplayName:   "Acme, Inc.",
		ActorID:       "usr_ada",
		ActorKind:     "usr",
		ActorOrgID:    actor.ID,
		RequestID:     "req_test",
		CorrelationID: "corr_test",
	})
	if err != nil {
		t.Fatalf("Create returned %v, want nil", err)
	}
	if created.ID == "" || created.Slug != "acme" || created.DisplayName != "Acme, Inc." {
		t.Errorf("Create returned %+v, want a minted id with slug acme / name Acme, Inc.", created)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Error("Create did not return the database-assigned timestamps")
	}
	if jobs.calls != 1 {
		t.Fatalf("job enqueue calls = %d, want 1", jobs.calls)
	}
	if len(jobs.inputs) != 1 {
		t.Fatalf("job enqueue inputs = %d, want 1", len(jobs.inputs))
	}
	job := jobs.inputs[0]
	if job.OrganizationID != created.ID || job.ResourceID != created.ID {
		t.Errorf("job target = org:%q resource:%q, want created organization %q", job.OrganizationID, job.ResourceID, created.ID)
	}
	if job.JobKind != controljobs.TypeEnsureDokployOrganization {
		t.Errorf("job kind = %q, want %q", job.JobKind, controljobs.TypeEnsureDokployOrganization)
	}
	if job.RequestID != "req_test" || job.CorrelationID != "corr_test" {
		t.Errorf("job correlation = %q/%q, want req_test/corr_test", job.RequestID, job.CorrelationID)
	}

	// The organization row is the source of truth: it must be readable back.
	reader, err := store.NewOrganizationReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationReader: %v", err)
	}
	got, err := reader.GetOrganization(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetOrganization(created) returned %v, want the created row", err)
	}
	if got.ID != created.ID || got.Slug != "acme" {
		t.Errorf("GetOrganization returned %+v, want the created row", got)
	}

	// The audit record is filed under the actor's organization and names the
	// created organization as its resource.
	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the create", len(events))
	}
	ev := events[0]
	if ev.Action != "organization.create" {
		t.Errorf("audit action = %q, want organization.create", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != created.ID {
		t.Errorf("audit resource_id = %q, want the created organization id %q", ev.ResourceID, created.ID)
	}
	if ev.ActorID != "usr_ada" || ev.ActorKind != "usr" {
		t.Errorf("audit actor = %q/%q, want usr_ada/usr", ev.ActorID, ev.ActorKind)
	}
	if ev.RequestID != "req_test" || ev.CorrelationID != "corr_test" {
		t.Errorf("audit correlation = %q/%q, want req_test/corr_test", ev.RequestID, ev.CorrelationID)
	}
	if ev.Metadata["slug"] != "acme" {
		t.Errorf("audit metadata slug = %q, want acme", ev.Metadata["slug"])
	}
}

func TestOrganizationServiceCreateSlugConflictRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	actor := seedOrg(t, db, f, "actor-co")
	svc := newOrganizationService(t, s)

	in := store.CreateOrganizationInput{
		Slug:        "acme",
		DisplayName: "Acme, Inc.",
		ActorID:     "usr_ada",
		ActorKind:   "usr",
		ActorOrgID:  actor.ID,
	}
	if _, err := svc.Create(ctx, in); err != nil {
		t.Fatalf("first Create returned %v, want nil", err)
	}

	// A second create with the same globally-unique slug must conflict.
	in.DisplayName = "Acme Two"
	_, err := svc.Create(ctx, in)
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate-slug Create error = %v, want %s", err, yerr.CodeConflict)
	}

	// The failed create rolled the whole transaction back: no second audit
	// record exists, so the audit log can never name a create that never
	// committed.
	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 1 {
		t.Errorf("audit events = %d, want exactly one — the rolled-back create must leave no audit record", len(events))
	}
}

func TestOrganizationServiceCreateInvalidInputNeverOpensTransaction(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	actor := seedOrg(t, db, f, "actor-co")
	svc := newOrganizationService(t, s)

	_, err := svc.Create(ctx, store.CreateOrganizationInput{
		Slug:        "Not A Slug",
		DisplayName: "Acme",
		ActorID:     "usr_ada",
		ActorKind:   "usr",
		ActorOrgID:  actor.ID,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Fatalf("invalid-slug Create error = %v, want %s", err, yerr.CodeValidation)
	}
	if events := listAuditEvents(t, s, actor.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want zero — an invalid request must never open a transaction", len(events))
	}
}

func TestOrganizationServiceCreateRequiresActorOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	svc := newOrganizationService(t, s)
	_, err := svc.Create(ctx, store.CreateOrganizationInput{
		Slug:        "acme",
		DisplayName: "Acme",
		ActorID:     "usr_ada",
		ActorKind:   "usr",
		ActorOrgID:  "",
	})
	if err == nil {
		t.Fatal("Create with no actor organization returned nil, want a typed error")
	}
}

// ptrString returns a pointer to s — the optional-field shape an
// UpdateOrganizationInput uses to distinguish "field omitted" from "field set".
func ptrString(s string) *string { return &s }

// TestOrganizationServiceUpdate is the happy path for the update-organization
// unit of work behind PATCH /v1/organizations/{org_id}: the supplied fields are
// applied to the existing row and an immutable audit record naming the actor is
// committed in the same transaction.
func TestOrganizationServiceUpdate(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme-co")
	svc := newOrganizationService(t, s)

	updated, err := svc.Update(ctx, store.UpdateOrganizationInput{
		OrganizationID: org.ID,
		Slug:           ptrString("acme-worldwide"),
		DisplayName:    ptrString("  Acme Worldwide  "),
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	})
	if err != nil {
		t.Fatalf("Update returned %v, want nil", err)
	}
	if updated.ID != org.ID {
		t.Errorf("Update returned id %q, want the existing organization id %q", updated.ID, org.ID)
	}
	if updated.Slug != "acme-worldwide" {
		t.Errorf("Update slug = %q, want acme-worldwide", updated.Slug)
	}
	if updated.DisplayName != "Acme Worldwide" {
		t.Errorf("Update display_name = %q, want the trimmed %q", updated.DisplayName, "Acme Worldwide")
	}
	if !updated.UpdatedAt.After(updated.CreatedAt) {
		t.Errorf("Update did not advance updated_at: created=%s updated=%s", updated.CreatedAt, updated.UpdatedAt)
	}

	// The mutation is the source of truth: it must be readable back.
	reader, err := store.NewOrganizationReader(s)
	if err != nil {
		t.Fatalf("NewOrganizationReader: %v", err)
	}
	got, err := reader.GetOrganization(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrganization(updated) returned %v, want the updated row", err)
	}
	if got.Slug != "acme-worldwide" || got.DisplayName != "Acme Worldwide" {
		t.Errorf("GetOrganization returned %+v, want the updated slug/display_name", got)
	}

	// The audit record is filed under the actor's organization and names the
	// updated organization as its resource.
	events := listAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the update", len(events))
	}
	ev := events[0]
	if ev.Action != "organization.update" {
		t.Errorf("audit action = %q, want organization.update", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != org.ID {
		t.Errorf("audit resource_id = %q, want the updated organization id %q", ev.ResourceID, org.ID)
	}
	if ev.ActorID != "usr_ada" || ev.ActorKind != "usr" {
		t.Errorf("audit actor = %q/%q, want usr_ada/usr", ev.ActorID, ev.ActorKind)
	}
	if ev.RequestID != "req_test" || ev.CorrelationID != "corr_test" {
		t.Errorf("audit correlation = %q/%q, want req_test/corr_test", ev.RequestID, ev.CorrelationID)
	}
	if ev.Metadata["updated_fields"] != "slug,display_name" {
		t.Errorf("audit metadata updated_fields = %q, want %q", ev.Metadata["updated_fields"], "slug,display_name")
	}
}

// TestOrganizationServiceUpdateNotFound proves an {org_id} with no row is the
// typed NotFound the repository produces — and no audit record is written for a
// mutation that never happened.
func TestOrganizationServiceUpdateNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	actor := seedOrg(t, db, f, "actor-co")
	svc := newOrganizationService(t, s)

	_, err := svc.Update(ctx, store.UpdateOrganizationInput{
		OrganizationID: "org_does_not_exist",
		DisplayName:    ptrString("Ghost"),
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("Update of a missing organization error = %v, want %s", err, yerr.CodeNotFound)
	}
	if events := listAuditEvents(t, s, actor.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want zero — a not-found update must leave no audit record", len(events))
	}
}

// TestOrganizationServiceUpdateSlugConflictRollsBack proves a slug that
// collides with another organization rolls the whole transaction back as a
// typed Conflict, so the audit log can never name an update that never
// committed.
func TestOrganizationServiceUpdateSlugConflictRollsBack(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "org-a")
	orgB := seedOrg(t, db, f, "org-b")
	svc := newOrganizationService(t, s)

	_, err := svc.Update(ctx, store.UpdateOrganizationInput{
		OrganizationID: orgA.ID,
		Slug:           ptrString(orgB.Slug),
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgA.ID,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("conflicting-slug Update error = %v, want %s", err, yerr.CodeConflict)
	}
	if events := listAuditEvents(t, s, orgA.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want zero — the rolled-back update must leave no audit record", len(events))
	}
}

// TestOrganizationServiceUpdateInvalidInputNeverOpensTransaction proves an
// invalid patch — here a non-canonical slug — is rejected before any
// transaction is opened, so no audit record is written.
func TestOrganizationServiceUpdateInvalidInputNeverOpensTransaction(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme-co")
	svc := newOrganizationService(t, s)

	_, err := svc.Update(ctx, store.UpdateOrganizationInput{
		OrganizationID: org.ID,
		Slug:           ptrString("Not A Slug"),
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Fatalf("invalid-slug Update error = %v, want %s", err, yerr.CodeValidation)
	}
	if events := listAuditEvents(t, s, org.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want zero — an invalid request must never open a transaction", len(events))
	}
}

// TestOrganizationServiceUpdateRequiresActorOrganization proves a missing actor
// organization is a typed error, not a silent write: an authenticated request
// always carries one, so its absence is a wiring fault.
func TestOrganizationServiceUpdateRequiresActorOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "acme-co")
	svc := newOrganizationService(t, s)

	_, err := svc.Update(ctx, store.UpdateOrganizationInput{
		OrganizationID: org.ID,
		DisplayName:    ptrString("Acme"),
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     "",
	})
	if err == nil {
		t.Fatal("Update with no actor organization returned nil, want a typed error")
	}
}
