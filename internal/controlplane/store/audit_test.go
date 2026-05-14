package store_test

import (
	"context"
	"errors"
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
