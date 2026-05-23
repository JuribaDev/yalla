package store_test

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/jackc/pgx/v5/pgconn"
)

// Integration tests for AuditRepository — the immutable audit log. They prove
// the append surface, tenant-scoped reads, that a cross-tenant organization id
// reveals nothing, and that a written audit record cannot be altered: the
// audit_events table rejects every UPDATE at the database level. They run
// against an isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset.

// auditEventFixture builds a valid store.AuditEvent for orgID. The metadata is
// already redacted — redaction is the audit service's job, not the
// repository's, so these tests feed clean values.
func auditEventFixture(orgID string) store.AuditEvent {
	return store.AuditEvent{
		OrganizationID: orgID,
		ActorID:        "usr_actor_0001",
		ActorKind:      "usr",
		Action:         "project.create",
		ResourceKind:   "proj",
		ResourceID:     "proj_resource_0001",
		Decision:       store.AuditDecisionAllowed,
		Reason:         "allowed_by_role",
		RequestID:      "req-audit-1",
		CorrelationID:  "corr-audit-1",
		IPAddress:      "203.0.113.7",
		UserAgent:      "yalla-cli/1.0",
		Metadata:       map[string]string{"field": "replicas", "from": "1", "to": "3"},
	}
}

// appendAudit persists e through Store.Write and returns the stored row.
func appendAudit(ctx context.Context, t *testing.T, s *store.Store, repo *store.AuditRepository, e store.AuditEvent) store.AuditEvent {
	t.Helper()
	var stored store.AuditEvent
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		row, err := repo.Append(ctx, tx, e)
		if err != nil {
			return err
		}
		stored = row
		return nil
	}); err != nil {
		t.Fatalf("append audit event: %v", err)
	}
	return stored
}

func TestAuditRepositoryAppendAndList(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")

	first := auditEventFixture(org.ID)
	stored := appendAudit(ctx, t, s, repo, first)
	if stored.ID == "" {
		t.Fatal("Append did not mint an id for a blank-id event")
	}
	if stored.OccurredAt.IsZero() || stored.CreatedAt.IsZero() {
		t.Error("Append did not return database-assigned timestamps")
	}
	if stored.Decision != store.AuditDecisionAllowed || stored.Reason != "allowed_by_role" {
		t.Errorf("stored decision = %q/%q, want allowed/allowed_by_role", stored.Decision, stored.Reason)
	}
	if stored.Metadata["field"] != "replicas" || stored.Metadata["to"] != "3" {
		t.Errorf("stored metadata = %v, want the fixture metadata round-tripped", stored.Metadata)
	}

	// A second, denied event with no actor — an unauthenticated request is
	// still audited.
	denied := auditEventFixture(org.ID)
	denied.Decision = store.AuditDecisionDenied
	denied.Reason = "denied_no_principal"
	denied.ActorID = ""
	denied.ActorKind = ""
	denied.Metadata = nil
	appendAudit(ctx, t, s, repo, denied)

	var listed []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		listed, rErr = repo.ListByOrganization(ctx, q, org.ID, 50)
		return rErr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("ListByOrganization returned %d events, want 2", len(listed))
	}
	// Newest first: the denied event was appended last.
	if listed[0].Decision != store.AuditDecisionDenied {
		t.Errorf("ListByOrganization[0].Decision = %q, want denied (newest first)", listed[0].Decision)
	}
	if listed[0].ActorID != "" || listed[0].ActorKind != "" {
		t.Errorf("denied unauthenticated event carried an actor: id=%q kind=%q", listed[0].ActorID, listed[0].ActorKind)
	}
	if len(listed[0].Metadata) != 0 {
		t.Errorf("denied event metadata = %v, want empty", listed[0].Metadata)
	}
}

func TestAuditRepositoryListTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")

	appendAudit(ctx, t, s, repo, auditEventFixture(orgA.ID))
	appendAudit(ctx, t, s, repo, auditEventFixture(orgA.ID))
	appendAudit(ctx, t, s, repo, auditEventFixture(orgB.ID))

	var listedA []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		listedA, rErr = repo.ListByOrganization(ctx, q, orgA.ID, 50)
		return rErr
	}); err != nil {
		t.Fatalf("ListByOrganization(orgA): %v", err)
	}
	if len(listedA) != 2 {
		t.Fatalf("orgA audit count = %d, want 2 (orgB's event must not be visible)", len(listedA))
	}
	for _, e := range listedA {
		if e.OrganizationID != orgA.ID {
			t.Errorf("ListByOrganization(orgA) returned an event for org %q", e.OrganizationID)
		}
	}
}

// TestAuditRepositoryAppendImmutability proves the core "immutable audit log"
// guarantee: once an audit record is written, it cannot be altered. The store
// package exposes no update method at all, and the audit_events table rejects
// every UPDATE at the database level — so even a direct SQL console cannot
// tamper with the trail.
func TestAuditRepositoryAppendImmutability(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	stored := appendAudit(ctx, t, s, repo, auditEventFixture(org.ID))

	_, err := db.Exec(ctx,
		`UPDATE audit_events SET reason = 'tampered' WHERE id = $1`, stored.ID)
	if err == nil {
		t.Fatal("UPDATE on audit_events succeeded; the table must be append-only")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("UPDATE on audit_events error = %v, want a *pgconn.PgError", err)
	}

	// The row is unchanged: the rejected UPDATE left no trace.
	var listed []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var rErr error
		listed, rErr = repo.ListByOrganization(ctx, q, org.ID, 10)
		return rErr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(listed) != 1 || listed[0].Reason != "allowed_by_role" {
		t.Fatalf("after a rejected UPDATE the audit record changed: %+v", listed)
	}
}

// TestAuditUpdateBlockedByDatabaseTriggerWithRestrictViolation is the
// load-bearing runtime half of the BE-0353 security-verification
// two-test pattern. The static half (audit_tamper_static_test.go and
// the migrate-package sibling) pins the SOURCE-level shape of the
// invariant. This test pins the WIRE-level shape: the rejection
// surfaces as SQLSTATE `restrict_violation` (23001) with the exact
// canonical message the migration RAISEs ("audit_events is
// append-only: UPDATE is not permitted"). A future refactor that
// silently downgrades the errcode to `internal_error` or renames the
// message will be caught here.
//
// Both per-row (WHERE id = $1) and table-wide (no WHERE) UPDATE
// shapes are exercised, because the trigger is FOR EACH ROW: a
// regression that converts the trigger to STATEMENT scope would
// silently allow the table-wide form. Every column of the original
// AuditEvent is asserted byte-identical after each rejected attempt
// so a partial mutation that somehow leaked through would be caught.
func TestAuditUpdateBlockedByDatabaseTriggerWithRestrictViolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	original := appendAudit(ctx, t, s, repo, auditEventFixture(org.ID))

	cases := []struct {
		name string
		sql  string
		args []any
	}{
		{
			name: "UPDATE by id",
			sql:  `UPDATE audit_events SET reason = 'tampered_by_id' WHERE id = $1`,
			args: []any{original.ID},
		},
		{
			name: "UPDATE by organization_id",
			sql:  `UPDATE audit_events SET reason = 'tampered_by_org' WHERE organization_id = $1`,
			args: []any{org.ID},
		},
		{
			name: "table-wide UPDATE without WHERE",
			sql:  `UPDATE audit_events SET reason = 'tampered_wide'`,
			args: nil,
		},
		{
			name: "UPDATE that also rewrites metadata",
			sql:  `UPDATE audit_events SET metadata = '{"field":"replicas","from":"1","to":"99"}'::jsonb WHERE id = $1`,
			args: []any{original.ID},
		},
		{
			name: "UPDATE that would reclassify the verdict",
			sql:  `UPDATE audit_events SET decision = 'denied', reason = 'reclassified' WHERE id = $1`,
			args: []any{original.ID},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := db.Exec(ctx, tc.sql, tc.args...)
			if err == nil {
				t.Fatalf("UPDATE %q succeeded; audit_events must be append-only", tc.name)
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) {
				t.Fatalf("UPDATE error = %v, want *pgconn.PgError so the wire errcode can be asserted", err)
			}
			if pgErr.Code != "23001" {
				t.Errorf("pgErr.Code = %q, want %q (SQLSTATE restrict_violation) — the migration RAISEs this errcode by name; a different code means the trigger was changed",
					pgErr.Code, "23001")
			}
			const wantMessage = "audit_events is append-only: UPDATE is not permitted"
			if !strings.Contains(pgErr.Message, wantMessage) {
				t.Errorf("pgErr.Message = %q, want it to contain %q", pgErr.Message, wantMessage)
			}
			// The error must NOT echo the would-be new value, the
			// row id, the org id, or any other variable input — the
			// trigger function is intentionally identifier-free so
			// nothing about the rejected mutation leaks into the
			// log channel.
			redactionProbes := []string{
				"tampered_by_id", "tampered_by_org", "tampered_wide",
				"reclassified", original.ID, org.ID,
			}
			for _, probe := range redactionProbes {
				if probe == "" {
					continue
				}
				if strings.Contains(pgErr.Message, probe) {
					t.Errorf("pgErr.Message = %q must not echo caller input %q — the trigger's wire surface is value-free",
						pgErr.Message, probe)
				}
			}

			// The row is byte-identical to the original. Every
			// column matters: a partial mutation that landed on
			// (say) `metadata` but not `reason` would still be
			// tampering.
			var listed []store.AuditEvent
			if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
				var rErr error
				listed, rErr = repo.ListByOrganization(ctx, q, org.ID, 10)
				return rErr
			}); err != nil {
				t.Fatalf("ListByOrganization after rejected UPDATE: %v", err)
			}
			if len(listed) != 1 {
				t.Fatalf("after a rejected UPDATE the audit log has %d rows, want 1", len(listed))
			}
			assertAuditEventByteIdentical(t, original, listed[0])
		})
	}
}

// assertAuditEventByteIdentical compares every column of an
// AuditEvent pair and emits a single diagnostic per drift. It is the
// runtime backstop for the BEFORE UPDATE trigger: even if the
// rejection somehow leaked a partial mutation through, the byte-
// level snapshot comparison would catch it.
func assertAuditEventByteIdentical(t *testing.T, want, got store.AuditEvent) {
	t.Helper()
	if got.ID != want.ID {
		t.Errorf("ID drift: got %q, want %q", got.ID, want.ID)
	}
	if got.OrganizationID != want.OrganizationID {
		t.Errorf("OrganizationID drift: got %q, want %q", got.OrganizationID, want.OrganizationID)
	}
	if got.ActorID != want.ActorID {
		t.Errorf("ActorID drift: got %q, want %q", got.ActorID, want.ActorID)
	}
	if got.ActorKind != want.ActorKind {
		t.Errorf("ActorKind drift: got %q, want %q", got.ActorKind, want.ActorKind)
	}
	if got.Action != want.Action {
		t.Errorf("Action drift: got %q, want %q", got.Action, want.Action)
	}
	if got.ResourceKind != want.ResourceKind {
		t.Errorf("ResourceKind drift: got %q, want %q", got.ResourceKind, want.ResourceKind)
	}
	if got.ResourceID != want.ResourceID {
		t.Errorf("ResourceID drift: got %q, want %q", got.ResourceID, want.ResourceID)
	}
	if got.Decision != want.Decision {
		t.Errorf("Decision drift: got %q, want %q", got.Decision, want.Decision)
	}
	if got.Reason != want.Reason {
		t.Errorf("Reason drift: got %q, want %q", got.Reason, want.Reason)
	}
	if got.RequestID != want.RequestID {
		t.Errorf("RequestID drift: got %q, want %q", got.RequestID, want.RequestID)
	}
	if got.CorrelationID != want.CorrelationID {
		t.Errorf("CorrelationID drift: got %q, want %q", got.CorrelationID, want.CorrelationID)
	}
	if got.IPAddress != want.IPAddress {
		t.Errorf("IPAddress drift: got %q, want %q", got.IPAddress, want.IPAddress)
	}
	if got.UserAgent != want.UserAgent {
		t.Errorf("UserAgent drift: got %q, want %q", got.UserAgent, want.UserAgent)
	}
	if !maps.Equal(got.Metadata, want.Metadata) {
		t.Errorf("Metadata drift: got %v, want %v", got.Metadata, want.Metadata)
	}
	if !got.OccurredAt.Equal(want.OccurredAt) {
		t.Errorf("OccurredAt drift: got %s, want %s", got.OccurredAt, want.OccurredAt)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("CreatedAt drift: got %s, want %s", got.CreatedAt, want.CreatedAt)
	}
}

// TestAuditRepositoryAppendCrossTenantOrgRejected proves an audit event cannot
// be filed under an organization that does not exist: the organization_id
// foreign key rejects it, so a forged or stale org id cannot smuggle a row
// into the log.
func TestAuditRepositoryAppendCrossTenantOrgRejected(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewAuditRepository()
	ctx := context.Background()

	e := auditEventFixture("org_does_not_exist_0001")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, appendErr := repo.Append(ctx, tx, e)
		return appendErr
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("Append(unknown org) error code = %v, want %s", err, yerr.CodeConflict)
	}
}
