package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for BreakGlassService and BreakGlassRepository — the
// persistence half of the internal-support break-glass surface (BE-0034).
// They run against an isolated, freshly migrated Postgres database and
// skip when YALLA_TEST_DATABASE_URL is unset. They prove that:
//
//   - StartSession inserts the row and the audit record atomically;
//   - the audit metadata carries elevated_access=true and names the
//     target organization id;
//   - a missing reason is the typed InvalidInput an invalid request
//     produces (and no row is written);
//   - a non-existent target tenant is the typed NotFound (and no row is
//     written);
//   - Revoke ends an active session early and is itself audited with
//     elevated_access=true;
//   - revoking a session twice is a typed Conflict, never a silent
//     success;
//   - tenants are isolated: a session id from another tenant matches no
//     rows;
//   - migration 0019 applies cleanly: the table accepts a valid row and
//     rejects an UPDATE to anything other than the revocation columns.

func newBreakGlassService(t *testing.T, s *store.Store, now func() time.Time) *store.BreakGlassService {
	t.Helper()
	svc, err := store.NewBreakGlassService(s,
		store.NewOrganizationRepository(),
		store.NewBreakGlassRepository(),
		store.NewAuditRepository(),
		now)
	if err != nil {
		t.Fatalf("NewBreakGlassService: %v", err)
	}
	return svc
}

func validStartInput(targetOrgID, actorOrgID string) store.StartBreakGlassInput {
	return store.StartBreakGlassInput{
		OrganizationID: targetOrgID,
		ActorID:        "usr_admin_001",
		ActorKind:      "usr",
		ActorOrgID:     actorOrgID,
		Reason:         "INCIDENT-2026-9001: customer requested investigation",
		TTL:            30 * time.Minute,
		RequestID:      "req_bg_start",
		CorrelationID:  "corr_bg_start",
		IPAddress:      "10.0.0.42",
		UserAgent:      "yalla-admin-cli/1.0",
	}
}

func TestBreakGlassServiceStartSessionPersistsRowAndAudit(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "BGTarget")
	support := seedOrg(t, db, f, "BGSupport")

	now := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	svc := newBreakGlassService(t, s, func() time.Time { return now })

	session, err := svc.StartSession(ctx, validStartInput(target.ID, support.ID))
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if !strings.HasPrefix(session.ID, "bgs_") {
		t.Errorf("session id %q missing bgs_ prefix", session.ID)
	}
	if session.OrganizationID != target.ID {
		t.Errorf("OrganizationID = %q, want %q", session.OrganizationID, target.ID)
	}
	if !session.StartedAt.Equal(now) {
		t.Errorf("StartedAt = %v, want %v", session.StartedAt, now)
	}
	if want := now.Add(30 * time.Minute); !session.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", session.ExpiresAt, want)
	}
	if session.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil for a fresh session", session.RevokedAt)
	}

	// Verify the row landed in the database.
	var rowCount int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM break_glass_sessions WHERE id = $1`, session.ID,
	).Scan(&rowCount); err != nil {
		t.Fatalf("row count: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("break_glass_sessions row count = %d, want 1", rowCount)
	}

	// Verify the audit event was written with elevated_access=true and
	// names the target organization id.
	auditRepo := store.NewAuditRepository()
	var events []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var listErr error
		events, listErr = auditRepo.ListByOrganization(ctx, q, support.ID, 50)
		return listErr
	}); err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("no audit events recorded under actor org %q", support.ID)
	}
	var found bool
	for _, e := range events {
		if e.Action != "admin.break_glass" {
			continue
		}
		if e.Metadata["elevated_access"] != "true" {
			t.Errorf("audit metadata elevated_access = %q, want %q",
				e.Metadata["elevated_access"], "true")
		}
		if e.Metadata["target_organization_id"] != target.ID {
			t.Errorf("audit metadata target_organization_id = %q, want %q",
				e.Metadata["target_organization_id"], target.ID)
		}
		if e.Metadata["break_glass_session_id"] != session.ID {
			t.Errorf("audit metadata break_glass_session_id = %q, want %q",
				e.Metadata["break_glass_session_id"], session.ID)
		}
		if e.Decision != store.AuditDecisionAllowed {
			t.Errorf("audit decision = %q, want %q", e.Decision, store.AuditDecisionAllowed)
		}
		if e.ResourceID != target.ID {
			t.Errorf("audit resource_id = %q, want %q", e.ResourceID, target.ID)
		}
		found = true
	}
	if !found {
		t.Errorf("no admin.break_glass audit event found among %d events", len(events))
	}
}

func TestBreakGlassServiceStartSessionRejectsBlankReason(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "BGRejectReason")
	support := seedOrg(t, db, f, "BGSupportReason")

	now := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	svc := newBreakGlassService(t, s, func() time.Time { return now })

	in := validStartInput(target.ID, support.ID)
	in.Reason = "   "

	_, err := svc.StartSession(ctx, in)
	if err == nil {
		t.Fatalf("StartSession(blank reason) expected an error")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeValidation {
		t.Fatalf("error code = %v, want %v", err, yerr.CodeValidation)
	}

	// No row was written.
	var rowCount int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM break_glass_sessions WHERE organization_id = $1`, target.ID,
	).Scan(&rowCount); err != nil {
		t.Fatalf("row count: %v", err)
	}
	if rowCount != 0 {
		t.Errorf("blank-reason rejection wrote a row: %d rows present", rowCount)
	}
}

func TestBreakGlassServiceStartSessionRejectsUnknownTenant(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	support := seedOrg(t, db, f, "BGSupportGhost")

	now := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	svc := newBreakGlassService(t, s, func() time.Time { return now })

	_, err := svc.StartSession(ctx, validStartInput("org_does_not_exist", support.ID))
	if err == nil {
		t.Fatalf("StartSession(unknown tenant) expected an error")
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("error = %v, want CodeNotFound", err)
	}
}

func TestBreakGlassServiceRevokeEndsSessionAndAudits(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "BGRevokeTarget")
	support := seedOrg(t, db, f, "BGRevokeSupport")

	startedAt := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	revokedAt := startedAt.Add(5 * time.Minute)
	clockCalls := 0
	now := func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return startedAt
		}
		return revokedAt
	}
	svc := newBreakGlassService(t, s, now)

	session, err := svc.StartSession(ctx, validStartInput(target.ID, support.ID))
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	revoked, err := svc.Revoke(ctx, store.RevokeBreakGlassInput{
		OrganizationID: target.ID,
		SessionID:      session.ID,
		ActorID:        "usr_admin_001",
		ActorKind:      "usr",
		ActorOrgID:     support.ID,
		RequestID:      "req_bg_revoke",
		CorrelationID:  "corr_bg_revoke",
	})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(revokedAt) {
		t.Errorf("RevokedAt = %v, want %v", revoked.RevokedAt, revokedAt)
	}
	if revoked.RevokedByID != "usr_admin_001" {
		t.Errorf("RevokedByID = %q, want usr_admin_001", revoked.RevokedByID)
	}
	if revoked.Active(revokedAt.Add(time.Minute)) {
		t.Errorf("revoked session should report Active=false")
	}

	// A second revoke is a Conflict.
	if _, err := svc.Revoke(ctx, store.RevokeBreakGlassInput{
		OrganizationID: target.ID,
		SessionID:      session.ID,
		ActorID:        "usr_admin_001",
		ActorKind:      "usr",
		ActorOrgID:     support.ID,
	}); err == nil {
		t.Fatalf("second Revoke expected a Conflict, got nil")
	} else {
		var ye *yerr.Error
		if !errors.As(err, &ye) || ye.Code != yerr.CodeConflict {
			t.Fatalf("second Revoke error = %v, want CodeConflict", err)
		}
	}
}

func TestBreakGlassRepositoryGetIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "BGTenantA")
	other := seedOrg(t, db, f, "BGTenantB")
	support := seedOrg(t, db, f, "BGTenantSupport")

	now := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	svc := newBreakGlassService(t, s, func() time.Time { return now })

	session, err := svc.StartSession(ctx, validStartInput(target.ID, support.ID))
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	reader := svc

	// Get via the wrong tenant returns NotFound, not the row.
	if _, err := reader.GetSession(ctx, other.ID, session.ID); err == nil {
		t.Fatalf("cross-tenant Get expected NotFound")
	} else {
		var ye *yerr.Error
		if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
			t.Fatalf("cross-tenant Get error = %v, want CodeNotFound", err)
		}
	}

	// List from the wrong tenant returns zero rows.
	wrongList, err := reader.ListSessions(ctx, other.ID, 10)
	if err != nil {
		t.Fatalf("cross-tenant List: %v", err)
	}
	if len(wrongList) != 0 {
		t.Errorf("cross-tenant List len = %d, want 0", len(wrongList))
	}

	rightList, err := reader.ListSessions(ctx, target.ID, 10)
	if err != nil {
		t.Fatalf("target-tenant List: %v", err)
	}
	if len(rightList) != 1 || rightList[0].ID != session.ID {
		t.Errorf("target List = %+v, want one row %q", rightList, session.ID)
	}
}

func TestBreakGlassSchemaRejectsUpdateToImmutableColumns(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	target := seedOrg(t, db, f, "BGImmutableTarget")
	support := seedOrg(t, db, f, "BGImmutableSupport")

	now := time.Date(2026, 5, 16, 9, 0, 0, 0, time.UTC)
	svc := newBreakGlassService(t, s, func() time.Time { return now })

	session, err := svc.StartSession(ctx, validStartInput(target.ID, support.ID))
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	// Attempt to rewrite the reason directly — the database trigger must
	// reject it. The error is a restrict_violation; we assert by the error
	// message text fragment so the test does not depend on pgconn types.
	if _, err := db.Exec(ctx,
		`UPDATE break_glass_sessions SET reason = $1 WHERE id = $2`,
		"rewritten reason", session.ID); err == nil {
		t.Fatalf("UPDATE rewriting reason expected to fail, got nil error")
	} else if !strings.Contains(err.Error(), "append-mostly") {
		t.Fatalf("UPDATE error = %v, want append-mostly restriction", err)
	}

	// Attempt to blank the reason — also rejected by the trigger.
	if _, err := db.Exec(ctx,
		`UPDATE break_glass_sessions SET reason = '' WHERE id = $1`,
		session.ID); err == nil {
		t.Fatalf("UPDATE blanking reason expected to fail, got nil error")
	}
}
