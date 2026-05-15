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

// TestMembershipServiceUpdateMember is the happy path for the role-change
// unit of work: a valid request updates the role, atomically bumps the row's
// role_version (so every outstanding session for the member is invalidated),
// and writes one audit record carrying the previous role and the new role.
func TestMembershipServiceUpdateMember(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, target, "grace")
	seedMembership(t, db, target.ID, userID, "member", 3)
	svc := newMembershipService(t, s)

	updated, err := svc.UpdateMember(ctx, store.UpdateMembershipInput{
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
		t.Fatalf("UpdateMember returned %v, want nil", err)
	}
	if updated.OrganizationID != target.ID || updated.UserID != userID {
		t.Errorf("UpdateMember returned %+v, want a membership of %q in %q", updated, userID, target.ID)
	}
	if updated.Role != "admin" {
		t.Errorf("UpdateMember role = %q, want admin", updated.Role)
	}
	if updated.RoleVersion != 4 {
		t.Errorf("UpdateMember role_version = %d, want 4 (3 + 1)", updated.RoleVersion)
	}
	if updated.Email == "" || updated.UserDisplayName == "" {
		t.Errorf("UpdateMember returned %+v, want email/display_name joined from the users row", updated)
	}

	// Re-read through the production reader path the GET endpoint uses to
	// prove the row is persisted exactly as returned.
	reader, err := store.NewMembershipReader(s)
	if err != nil {
		t.Fatalf("NewMembershipReader: %v", err)
	}
	read, err := reader.GetMember(ctx, target.ID, userID)
	if err != nil {
		t.Fatalf("GetMember returned %v, want nil", err)
	}
	if read.Role != "admin" || read.RoleVersion != 4 {
		t.Errorf("re-read membership = %+v, want role admin / role_version 4", read)
	}

	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the update", len(events))
	}
	ev := events[0]
	if ev.Action != "members.manage" {
		t.Errorf("audit action = %q, want members.manage", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != userID {
		t.Errorf("audit resource_id = %q, want the updated user id %q", ev.ResourceID, userID)
	}
	if ev.Metadata["organization_id"] != target.ID {
		t.Errorf("audit metadata organization_id = %q, want the target org id %q",
			ev.Metadata["organization_id"], target.ID)
	}
	if ev.Metadata["previous_role"] != "member" {
		t.Errorf("audit metadata previous_role = %q, want member", ev.Metadata["previous_role"])
	}
	if ev.Metadata["role"] != "admin" {
		t.Errorf("audit metadata role = %q, want admin", ev.Metadata["role"])
	}
}

// TestMembershipServiceUpdateMemberSameRoleStillBumpsVersion proves the
// invariant that a successful PATCH always bumps role_version — even when the
// new role equals the current role. The role_version is what backs session
// revocation, and a no-op patch that pretends to succeed but does not sweep
// sessions would be a silent security hole. The CHECK and write happen
// unconditionally; the validator already rejected a blank role.
func TestMembershipServiceUpdateMemberSameRoleStillBumpsVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, target, "grace")
	seedMembership(t, db, target.ID, userID, "admin", 7)
	svc := newMembershipService(t, s)

	updated, err := svc.UpdateMember(ctx, store.UpdateMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		Role:           "admin",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	if err != nil {
		t.Fatalf("UpdateMember returned %v, want nil", err)
	}
	if updated.Role != "admin" {
		t.Errorf("role = %q, want admin (unchanged)", updated.Role)
	}
	if updated.RoleVersion != 8 {
		t.Errorf("role_version = %d, want 8 (7 + 1) — a successful PATCH must always sweep sessions",
			updated.RoleVersion)
	}
}

// TestMembershipServiceUpdateMemberMissingIsNotFound proves a membership that
// does not exist is the typed NotFound the GET endpoint uses, never disguised
// as a 5xx, and the audit record is rolled back with the unit of work.
func TestMembershipServiceUpdateMemberMissingIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, target, "grace") // the user exists, but no membership row
	svc := newMembershipService(t, s)

	_, err := svc.UpdateMember(ctx, store.UpdateMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		Role:           "admin",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("UpdateMember error = %v, want a typed E_NOT_FOUND for the missing membership", err)
	}

	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 0 {
		t.Errorf("audit events for actor = %d, want 0 — a missing membership must not leave an audit trail", len(events))
	}
}

// TestMembershipServiceUpdateMemberCrossTenantIsNotFound proves the
// persistence layer's tenant guard: a user id paired with the wrong
// organization is the same deterministic NotFound as a missing row, so a
// caller can never tell whether the user is a member of another tenant
// through this layer. The HTTP layer's policy engine has already rejected a
// cross-tenant {org_id} as 403; this guards the persistence layer when the
// auth/policy layers are bypassed (support principals, internal tooling).
func TestMembershipServiceUpdateMemberCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "alpha")
	orgB := seedOrg(t, db, f, "beta")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, userID, "owner", 1)
	svc := newMembershipService(t, s)

	_, err := svc.UpdateMember(ctx, store.UpdateMembershipInput{
		OrganizationID: orgB.ID, // wrong tenant
		UserID:         userID,
		Role:           "admin",
		ActorID:        "usr_support",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("UpdateMember error = %v, want a typed E_NOT_FOUND for the cross-tenant id", err)
	}

	// orgA's membership row must be untouched: a cross-tenant PATCH cannot
	// reach into another tenant's data even on the role_version field.
	reader, err := store.NewMembershipReader(s)
	if err != nil {
		t.Fatalf("NewMembershipReader: %v", err)
	}
	live, err := reader.GetMember(ctx, orgA.ID, userID)
	if err != nil {
		t.Fatalf("GetMember(orgA) returned %v, want nil", err)
	}
	if live.Role != "owner" || live.RoleVersion != 1 {
		t.Errorf("orgA membership after cross-tenant PATCH = %+v, want role owner / role_version 1 — unchanged", live)
	}
}

// TestMembershipServiceUpdateMemberInvalidIsValidationError proves an invalid
// request never opens a transaction: the validator returns InvalidInput and
// the membership row, including its role_version, is untouched.
func TestMembershipServiceUpdateMemberInvalidIsValidationError(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, target, "grace")
	seedMembership(t, db, target.ID, userID, "member", 1)
	svc := newMembershipService(t, s)

	_, err := svc.UpdateMember(ctx, store.UpdateMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		Role:           "emperor", // unknown
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("UpdateMember error = %v, want a typed E_INVALID_INPUT", err)
	}

	reader, err := store.NewMembershipReader(s)
	if err != nil {
		t.Fatalf("NewMembershipReader: %v", err)
	}
	live, err := reader.GetMember(ctx, target.ID, userID)
	if err != nil {
		t.Fatalf("GetMember returned %v, want nil", err)
	}
	if live.Role != "member" || live.RoleVersion != 1 {
		t.Errorf("membership after invalid PATCH = %+v, want role member / role_version 1 — unchanged", live)
	}
}

// TestMembershipServiceUpdateMemberRejectsBlankActorOrg proves the wiring
// guard: an authenticated request always carries an actor organization;
// reaching this layer without one is reported as Internal rather than a
// misleading validation failure.
func TestMembershipServiceUpdateMemberRejectsBlankActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, target, "grace")
	seedMembership(t, db, target.ID, userID, "admin", 1)
	svc := newMembershipService(t, s)

	_, err := svc.UpdateMember(ctx, store.UpdateMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		Role:           "owner",
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     "  ",
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Fatalf("UpdateMember error = %v, want a typed E_INTERNAL", err)
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

// TestMembershipServiceRemove is the happy path: a valid request removes the
// memberships row, returns the OrganizationMember as it stood at removal
// time, and commits an immutable audit record naming the actor in the same
// transaction.
func TestMembershipServiceRemove(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, target, "grace")
	seedMembership(t, db, target.ID, userID, "admin", 4)
	svc := newMembershipService(t, s)

	removed, err := svc.Remove(ctx, store.RemoveMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
		RequestID:      "req_test",
		CorrelationID:  "corr_test",
	})
	if err != nil {
		t.Fatalf("Remove returned %v, want nil", err)
	}
	if removed.OrganizationID != target.ID || removed.UserID != userID {
		t.Errorf("Remove returned %+v, want a membership of %q in %q", removed, userID, target.ID)
	}
	if removed.Role != "admin" || removed.RoleVersion != 4 {
		t.Errorf("Remove returned %+v, want the row as it stood at removal time (role admin / role_version 4)",
			removed)
	}
	if removed.Email == "" || removed.UserDisplayName == "" {
		t.Errorf("Remove returned %+v, want email/display_name joined from the users row", removed)
	}

	// The memberships row must be gone: a re-read through the production
	// reader path surfaces a typed NotFound.
	reader, err := store.NewMembershipReader(s)
	if err != nil {
		t.Fatalf("NewMembershipReader: %v", err)
	}
	_, err = reader.GetMember(ctx, target.ID, userID)
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("GetMember after Remove returned %v, want a typed E_NOT_FOUND — the row must be gone", err)
	}

	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the removal", len(events))
	}
	ev := events[0]
	if ev.Action != "members.manage" {
		t.Errorf("audit action = %q, want members.manage", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != userID {
		t.Errorf("audit resource_id = %q, want the removed user id %q", ev.ResourceID, userID)
	}
	if ev.Metadata["organization_id"] != target.ID {
		t.Errorf("audit metadata organization_id = %q, want the target org id %q",
			ev.Metadata["organization_id"], target.ID)
	}
	if ev.Metadata["role"] != "admin" {
		t.Errorf("audit metadata role = %q, want the role held at removal time (admin)",
			ev.Metadata["role"])
	}
}

// TestMembershipServiceRemoveMissingIsNotFound proves a membership that does
// not exist is the typed NotFound the GET endpoint uses, never disguised as
// a 5xx, and the audit record is rolled back with the unit of work.
func TestMembershipServiceRemoveMissingIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, target, "grace") // the user exists, but no membership row
	svc := newMembershipService(t, s)

	_, err := svc.Remove(ctx, store.RemoveMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("Remove error = %v, want a typed E_NOT_FOUND for the missing membership", err)
	}

	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 0 {
		t.Errorf("audit events for actor = %d, want 0 — a missing membership must not leave an audit trail",
			len(events))
	}
}

// TestMembershipServiceRemoveCrossTenantIsNotFound proves the persistence
// layer's tenant guard: a user id paired with the wrong organization is the
// same deterministic NotFound as a missing row, and the original tenant's
// row is left untouched — a caller cannot tell whether the user is a
// member of another tenant through this layer.
func TestMembershipServiceRemoveCrossTenantIsNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "alpha")
	orgB := seedOrg(t, db, f, "beta")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, orgA, "ada")
	seedMembership(t, db, orgA.ID, userID, "owner", 1)
	svc := newMembershipService(t, s)

	_, err := svc.Remove(ctx, store.RemoveMembershipInput{
		OrganizationID: orgB.ID, // wrong tenant
		UserID:         userID,
		ActorID:        "usr_support",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("Remove error = %v, want a typed E_NOT_FOUND for the cross-tenant id", err)
	}

	// orgA's membership row must be untouched: a cross-tenant DELETE cannot
	// reach into another tenant's data.
	reader, err := store.NewMembershipReader(s)
	if err != nil {
		t.Fatalf("NewMembershipReader: %v", err)
	}
	live, err := reader.GetMember(ctx, orgA.ID, userID)
	if err != nil {
		t.Fatalf("GetMember(orgA) returned %v, want nil", err)
	}
	if live.Role != "owner" || live.RoleVersion != 1 {
		t.Errorf("orgA membership after cross-tenant DELETE = %+v, want role owner / role_version 1 — unchanged",
			live)
	}

	// And no audit row may exist under the actor's home tenant.
	events := listAuditEvents(t, s, actor.ID)
	if len(events) != 0 {
		t.Errorf("audit events for actor = %d, want 0 — a cross-tenant DELETE must not leave an audit trail",
			len(events))
	}
}

// TestMembershipServiceRemoveInvalidIsValidationError proves an invalid
// request never opens a transaction: the validator returns InvalidInput and
// the membership row, including its role_version, is untouched.
func TestMembershipServiceRemoveInvalidIsValidationError(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	actor := seedOrg(t, db, f, "actor-co")
	userID := seedUser(t, db, f, target, "grace")
	seedMembership(t, db, target.ID, userID, "member", 1)
	svc := newMembershipService(t, s)

	_, err := svc.Remove(ctx, store.RemoveMembershipInput{
		OrganizationID: target.ID,
		UserID:         "not-an-id", // malformed
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     actor.ID,
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeInvalidInput {
		t.Fatalf("Remove error = %v, want a typed E_INVALID_INPUT", err)
	}

	reader, err := store.NewMembershipReader(s)
	if err != nil {
		t.Fatalf("NewMembershipReader: %v", err)
	}
	live, err := reader.GetMember(ctx, target.ID, userID)
	if err != nil {
		t.Fatalf("GetMember returned %v, want nil", err)
	}
	if live.Role != "member" || live.RoleVersion != 1 {
		t.Errorf("membership after invalid DELETE = %+v, want role member / role_version 1 — unchanged",
			live)
	}
}

// TestMembershipServiceRemoveRejectsBlankActorOrg proves the wiring guard:
// an authenticated request always carries an actor organization; reaching
// this layer without one is reported as Internal rather than a misleading
// validation failure.
func TestMembershipServiceRemoveRejectsBlankActorOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "acme")
	userID := seedUser(t, db, f, target, "grace")
	seedMembership(t, db, target.ID, userID, "admin", 1)
	svc := newMembershipService(t, s)

	_, err := svc.Remove(ctx, store.RemoveMembershipInput{
		OrganizationID: target.ID,
		UserID:         userID,
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     "  ",
	})
	var ye *yerr.Error
	if !stderrors.As(err, &ye) || ye.Code != yerr.CodeInternal {
		t.Fatalf("Remove error = %v, want a typed E_INTERNAL", err)
	}
}
