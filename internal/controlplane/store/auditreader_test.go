package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Integration tests for the AuditEventReader adapter — the persistence
// surface httpapi.listAuditEventsHandler reads through. They prove the
// adapter wires AuditRepository.ListByOrganization through Store.Read,
// that the tenant-scoping guarantees the repository proves are inherited
// by the adapter, and that the constructor fails fast on a nil store.
// They run against an isolated, freshly migrated Postgres database and
// skip when YALLA_TEST_DATABASE_URL is unset.

// TestAuditEventReaderListByOrganization proves the adapter wires the
// repository through Store.Read: a seeded audit row is returned to the
// caller, newest first, and the order matches the repository contract.
func TestAuditEventReaderListByOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderAuditAcme")
	repo := store.NewAuditRepository()
	first := appendAudit(ctx, t, s, repo, auditEventFixture(org.ID))
	second := appendAudit(ctx, t, s, repo, store.AuditEvent{
		OrganizationID: org.ID,
		ActorID:        "usr_actor_0002",
		ActorKind:      "usr",
		Action:         "limits.write",
		ResourceKind:   "organization",
		ResourceID:     org.ID,
		Decision:       store.AuditDecisionAllowed,
		Reason:         "allowed_by_role",
		RequestID:      "req-audit-2",
		Metadata:       map[string]string{"updated_resources": "projects"},
	})

	reader, err := store.NewAuditEventReader(s)
	if err != nil {
		t.Fatalf("NewAuditEventReader: %v", err)
	}

	got, err := reader.ListByOrganization(ctx, org.ID, 0)
	if err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (got %+v)", len(got), got)
	}
	// occurred_at DESC, id DESC — the second insert occurred at or after
	// the first, so it comes back first.
	if got[0].ID != second.ID {
		t.Errorf("got[0].ID = %q, want %q (newest first)", got[0].ID, second.ID)
	}
	if got[1].ID != first.ID {
		t.Errorf("got[1].ID = %q, want %q", got[1].ID, first.ID)
	}
}

// TestAuditEventReaderIsTenantScoped proves the adapter inherits the
// repository's tenant scoping: an organization id from another tenant
// matches no rows, never another organization's audit trail.
func TestAuditEventReaderIsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "ReaderAuditA")
	orgB := seedOrg(t, db, f, "ReaderAuditB")
	repo := store.NewAuditRepository()
	appendAudit(ctx, t, s, repo, auditEventFixture(orgA.ID))
	appendAudit(ctx, t, s, repo, auditEventFixture(orgB.ID))

	reader, err := store.NewAuditEventReader(s)
	if err != nil {
		t.Fatalf("NewAuditEventReader: %v", err)
	}

	gotA, err := reader.ListByOrganization(ctx, orgA.ID, 0)
	if err != nil {
		t.Fatalf("orgA: %v", err)
	}
	if len(gotA) != 1 || gotA[0].OrganizationID != orgA.ID {
		t.Fatalf("orgA listing = %+v, want a single row scoped to orgA", gotA)
	}
	gotB, err := reader.ListByOrganization(ctx, orgB.ID, 0)
	if err != nil {
		t.Fatalf("orgB: %v", err)
	}
	if len(gotB) != 1 || gotB[0].OrganizationID != orgB.ID {
		t.Fatalf("orgB listing = %+v, want a single row scoped to orgB", gotB)
	}
}

// TestAuditEventReaderReturnsEmptyForUnknownOrg proves a tenant with no
// audit history (or a cross-tenant id that does not match any row)
// surfaces as a deterministic empty list, mirroring every list endpoint
// the HTTP layer serves.
func TestAuditEventReaderReturnsEmptyForUnknownOrg(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	reader, err := store.NewAuditEventReader(s)
	if err != nil {
		t.Fatalf("NewAuditEventReader: %v", err)
	}
	got, err := reader.ListByOrganization(ctx, "org_no_such_tenant", 0)
	if err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d rows for an unknown org, want 0", len(got))
	}
}

// TestNewAuditEventReaderRejectsNilStore proves a misconfigured adapter
// fails at construction rather than on its first request.
func TestNewAuditEventReaderRejectsNilStore(t *testing.T) {
	t.Parallel()

	if _, err := store.NewAuditEventReader(nil); err == nil {
		t.Error("NewAuditEventReader(nil) returned no error; want a nil-store error")
	}
}
