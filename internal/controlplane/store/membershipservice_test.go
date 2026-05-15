package store_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for MembershipService — the add-member unit of work
// behind POST /v1/organizations/{org_id}/members. They prove the memberships
// row and its immutable audit record are committed atomically, that a
// duplicate (organization_id, user_id) rolls the whole transaction back (no
// orphaned audit record), that a missing organization or user surfaces as a
// typed NotFound, and that an invalid request never opens a transaction.
// They run against an isolated, freshly migrated Postgres database and skip
// when YALLA_TEST_DATABASE_URL is unset.

func newMembershipService(t *testing.T, s *store.Store) *store.MembershipService {
	t.Helper()
	svc, err := store.NewMembershipService(
		s,
		store.NewOrganizationRepository(),
		store.NewMembershipRepository(),
		store.NewAuditRepository(),
	)
	if err != nil {
		t.Fatalf("NewMembershipService: %v", err)
	}
	return svc
}

func TestMembershipServiceAdd(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, target, "grace")
	svc := newMembershipService(t, s)

	added, err := svc.Add(ctx, store.AddMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		Role:           "admin",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	})
	if err != nil {
		t.Fatalf("Add returned %v, want nil", err)
	}
	if added.OrganizationID != target.ID || added.UserID != userID {
		t.Errorf("Add returned %+v, want a membership of %q in %q", added, userID, target.ID)
	}
	if added.Role != "admin" {
		t.Errorf("Add role = %q, want admin", added.Role)
	}
	if added.RoleVersion != 1 {
		t.Errorf("Add role_version = %d, want the schema default 1", added.RoleVersion)
	}
	if added.CreatedAt.IsZero() || added.UpdatedAt.IsZero() {
		t.Error("Add did not return the database-assigned timestamps")
	}
	if added.Email == "" || added.UserDisplayName == "" {
		t.Errorf("Add returned %+v, want email/display_name joined from the users row", added)
	}

	// The membership is readable back through the ListByOrganization path the
	// GET endpoint uses.
	reader, err := store.NewMembershipReader(s)
	if err != nil {
		t.Fatalf("NewMembershipReader: %v", err)
	}
	members, err := reader.ListMembers(ctx, target.ID)
	if err != nil {
		t.Fatalf("ListMembers(target) returned %v, want nil", err)
	}
	if len(members) != 1 || members[0].UserID != userID || members[0].Role != "admin" {
		t.Errorf("ListMembers returned %+v, want exactly the added admin membership", members)
	}

	// The audit record is filed under the actor's organization and names the
	// added user as its resource. The metadata captures the target tenant and
	// the role — both non-secret.
	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the add", len(events))
	}
	ev := events[0]
	if ev.Action != "members.manage" {
		t.Errorf("audit action = %q, want members.manage", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != userID {
		t.Errorf("audit resource_id = %q, want the added user id %q", ev.ResourceID, userID)
	}
	if ev.ActorID != "usr_ada" || ev.ActorKind != "usr" {
		t.Errorf("audit actor = %q/%q, want usr_ada/usr", ev.ActorID, ev.ActorKind)
	}
	if ev.Metadata["organization_id"] != target.ID {
		t.Errorf("audit metadata organization_id = %q, want the target org id %q",
			ev.Metadata["organization_id"], target.ID)
	}
	if ev.Metadata["role"] != "admin" {
		t.Errorf("audit metadata role = %q, want admin", ev.Metadata["role"])
	}
}

func TestMembershipServiceAddDuplicateIsConflict(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, target, "grace")
	seedMembership(t, db, target.ID, userID, "admin", 1)
	svc := newMembershipService(t, s)

	_, err := svc.Add(ctx, store.AddMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		Role:           "member",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeConflict {
		t.Fatalf("Add error = %v, want a typed E_CONFLICT", err)
	}

	// The audit record must not have been written: a duplicate must roll the
	// whole transaction back, never leaving an orphaned trail for an event
	// that did not happen.
	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 0 {
		t.Errorf("audit events for actor = %d, want 0 — duplicate must roll the audit record back too", len(events))
	}
}

func TestMembershipServiceAddMissingUserIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "actor-co")
	// A valid-looking user id that has no row in the users table. The
	// service must surface this as a typed NotFound (404), not a
	// foreign-key-violation Conflict (409).
	missingUser := testutil.NewFactory(t).User(target, "ghost").ID
	svc := newMembershipService(t, s)

	_, err := svc.Add(ctx, store.AddMembershipInput{
		OrganizationID: target.ID,
		UserID:         missingUser,
		Role:           "member",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("Add error = %v, want a typed E_NOT_FOUND for the missing user", err)
	}

	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 0 {
		t.Errorf("audit events for actor = %d, want 0 — a missing user must not leave an audit trail", len(events))
	}
}

func TestMembershipServiceAddMissingOrganizationIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	actor := seedOrg(t, db, f, "actor-co")
	hostOrg := seedOrg(t, db, f, "host")
	userID := seedUser(t, db, f, hostOrg, "ada")
	missingOrg := f.Organization("ghost").ID
	svc := newMembershipService(t, s)

	_, err := svc.Add(ctx, store.AddMembershipInput{
		OrganizationID: missingOrg,
		UserID:         userID,
		Role:           "member",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("Add error = %v, want a typed E_NOT_FOUND for the missing organization", err)
	}

	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 0 {
		t.Errorf("audit events for actor = %d, want 0 — a missing organization must not leave an audit trail", len(events))
	}
}

// TestMembershipServiceAddIsTenantScoped proves the audit record is filed
// under the *actor's* organization, while the membership row is created in
// the target organization. A support principal or a deliberate cross-tenant
// add (when the policy layer authorises it) must still leave its audit trail
// in the actor's home tenant.
func TestMembershipServiceAddIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "support-co")
	userID := seedUser(t, db, f, target, "ada")
	svc := newMembershipService(t, s)

	if _, err := svc.Add(ctx, store.AddMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		Role:           "admin",
		ActorID:        "usr_support",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	}); err != nil {
		t.Fatalf("Add returned %v, want nil", err)
	}

	// The audit row lives in the actor's tenant, not the target tenant.
	if got := len(listAuditEvents(t, s, actor.ID)); got != 1 {
		t.Errorf("actor audit events = %d, want 1", got)
	}
	if got := len(listAuditEvents(t, s, target.ID)); got != 0 {
		t.Errorf("target audit events = %d, want 0 — the audit record is filed under the actor, not the target", got)
	}
}

// TestMembershipServiceAddRejectsBlankActorOrg proves the wiring guard: an
// authenticated request always carries an actor organization; reaching this
// layer without one is reported as Internal rather than a misleading
// validation failure.
func TestMembershipServiceAddRejectsBlankActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, target, "ada")
	svc := newMembershipService(t, s)

	_, err := svc.Add(ctx, store.AddMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		Role:           "admin",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     "  ",
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Fatalf("Add error = %v, want a typed E_INTERNAL", err)
	}
}
