package store_test

import (
	"context"
	"testing"

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
	svc, err := store.NewOrganizationService(s, store.NewOrganizationRepository(), store.NewAuditRepository())
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
	svc := newOrganizationService(t, s)

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
	if ye := yerr.From(err); ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("invalid-slug Create error = %v, want %s", err, yerr.CodeInvalidInput)
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
