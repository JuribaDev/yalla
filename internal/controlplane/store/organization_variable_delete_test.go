package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for OrganizationVariableService.Delete — the
// delete-organization-variable unit of work behind DELETE
// /v1/organizations/{org_id}/variables/{key}. They prove that the
// in-transaction delete + audit commit atomically, that a cross-tenant
// key is indistinguishable from a missing row, that the returned
// snapshot reflects the row at the moment of removal, that the row is
// physically gone after commit, and that audit metadata records only
// the variable's stable id — never the customer-supplied key or value.
// They run against an isolated, freshly migrated Postgres database and
// skip when YALLA_TEST_DATABASE_URL is unset.

// TestOrganizationVariableServiceDeleteRemovesRowAndReturnsSnapshot is
// the happy path: a Delete against a configured key returns the row's
// snapshot (id, key, value, is_secret, version) exactly as it stood at
// the moment of removal, files an audit record naming the variable's
// id, and the row is physically gone afterwards.
func TestOrganizationVariableServiceDeleteRemovesRowAndReturnsSnapshot(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	initial, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "REGION", Value: "us-east-1", IsSecret: false},
			{Key: "DATABASE_URL", Value: "postgres://user:hunter2@db/app", IsSecret: true},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("seed Replace: %v", err)
	}
	if len(initial) != 2 {
		t.Fatalf("seed Replace returned %d variables, want 2", len(initial))
	}
	var seeded store.OrganizationVariable
	for _, v := range initial {
		if v.Key == "DATABASE_URL" {
			seeded = v
		}
	}
	if seeded.ID == "" {
		t.Fatalf("seed Replace did not return DATABASE_URL row: %+v", initial)
	}

	deleted, err := svc.Delete(ctx, store.DeleteOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            "DATABASE_URL",
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
		RequestID: "req_d", CorrelationID: "corr_d",
	})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if deleted.ID != seeded.ID {
		t.Errorf("deleted.id = %q, want the seeded id %q (Delete must return the snapshot it removed)", deleted.ID, seeded.ID)
	}
	if deleted.Key != "DATABASE_URL" {
		t.Errorf("deleted.key = %q, want DATABASE_URL", deleted.Key)
	}
	if revealVariableValue(deleted) != "postgres://user:hunter2@db/app" {
		t.Errorf("deleted.value = %q, want the value at the moment of removal", revealVariableValue(deleted))
	}
	if !deleted.IsSecret {
		t.Errorf("deleted.is_secret = false, want true (the snapshot must reflect the row at removal)")
	}

	// Audit: the most recent event after the Delete names the variable's
	// stable id and never the customer-supplied key or value. We check
	// the audit log BEFORE issuing any further state-changing call so
	// the Delete event is structurally at index 0 (newest-first ORDER BY
	// occurred_at DESC, id DESC).
	events := listAuditEvents(t, s, org.ID)
	if len(events) < 2 {
		t.Fatalf("audit events = %d, want at least two (seed Replace + Delete)", len(events))
	}
	ev := events[0]
	if ev.Action != "env.write" {
		t.Errorf("audit action = %q, want env.write", ev.Action)
	}
	if ev.ResourceKind != "org" {
		t.Errorf("audit resource_kind = %q, want org (Delete files under organization scope)", ev.ResourceKind)
	}
	if ev.ResourceID != org.ID {
		t.Errorf("audit resource_id = %q, want the organization id %q", ev.ResourceID, org.ID)
	}
	if got := ev.Metadata["variable_id"]; got != seeded.ID {
		t.Errorf("audit metadata.variable_id = %q, want %q", got, seeded.ID)
	}
	for k, v := range ev.Metadata {
		if strings.Contains(v, "DATABASE_URL") || strings.Contains(v, "hunter2") || strings.Contains(v, "postgres://") {
			t.Errorf("audit metadata[%q] = %q leaks a customer-supplied variable name or value", k, v)
		}
	}

	// The row is physically gone after Delete — the lowest-precedence
	// variable hierarchy means a deleted org-scoped variable no longer
	// participates in renderer resolution. Probing through a second
	// Replace would file an extra audit event, so we read through
	// ListByOrganization on a *Tx-less read instead.
	var remaining []store.OrganizationVariable
	if rerr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var lerr error
		remaining, lerr = store.NewOrganizationVariableRepository().ListByOrganization(ctx, q, org.ID)
		return lerr
	}); rerr != nil {
		t.Fatalf("post-Delete read: %v", rerr)
	}
	for _, v := range remaining {
		if v.Key == "DATABASE_URL" {
			t.Errorf("DATABASE_URL still present after Delete: %+v", v)
		}
	}
}

// TestOrganizationVariableServiceDeleteNotFoundForMissingKey proves a
// Delete against a key that does not exist in this tenant is the typed
// NotFound the repository produces — never a 5xx, never a misleading
// "deleted nothing successfully" — and the audit record is rolled back
// with it, so an audit trail can never name a deletion that did not
// happen.
func TestOrganizationVariableServiceDeleteNotFoundForMissingKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	_, err := svc.Delete(ctx, store.DeleteOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            "NEVER_SET",
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Delete returned no error for a missing key, want NotFound")
	}
	if got, want := yerr.From(err).Code, yerr.CodeNotFound; got != want {
		t.Errorf("error code = %q, want %q; err = %v", got, want, err)
	}

	// The audit record must NOT exist — a deletion that did not happen
	// cannot leave an audit trail behind.
	events := listAuditEvents(t, s, org.ID)
	for _, ev := range events {
		if ev.Action == "env.write" {
			t.Errorf("audit event filed for a failed Delete: %+v", ev)
		}
	}
}

// TestOrganizationVariableServiceDeleteTenantIsolation proves a key
// that exists in another tenant is indistinguishable from a missing
// row — the tenant-scoped DELETE filters by organization_id first, so
// a cross-tenant {key} is reported as the typed NotFound the
// repository produces, and the OTHER tenant's row is left intact.
func TestOrganizationVariableServiceDeleteTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	acme := seedOrg(t, db, f, "Acme")
	rival := seedOrg(t, db, f, "Rival")
	svc := newOrgVariableService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: rival.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "RIVAL_SECRET", Value: "do-not-touch", IsSecret: true},
		},
		ActorID: "usr_rival", ActorKind: "usr", ActorOrgID: rival.ID,
	}); err != nil {
		t.Fatalf("seed rival Replace: %v", err)
	}

	// Acme owner attempting to delete a key that belongs to Rival is
	// indistinguishable from a missing key from the auditable surface.
	_, err := svc.Delete(ctx, store.DeleteOrganizationVariableInput{
		OrganizationID: acme.ID,
		Key:            "RIVAL_SECRET",
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: acme.ID,
	})
	if err == nil {
		t.Fatalf("Delete returned no error for a cross-tenant key, want NotFound")
	}
	if got, want := yerr.From(err).Code, yerr.CodeNotFound; got != want {
		t.Errorf("error code = %q, want %q; err = %v", got, want, err)
	}

	// The rival's row must still be present. Read directly through the
	// repository so we don't file another audit event in the rival's
	// tenant.
	var rivalAfter []store.OrganizationVariable
	if rerr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var lerr error
		rivalAfter, lerr = store.NewOrganizationVariableRepository().ListByOrganization(ctx, q, rival.ID)
		return lerr
	}); rerr != nil {
		t.Fatalf("rival post-attempt read: %v", rerr)
	}
	if len(rivalAfter) != 1 || rivalAfter[0].Key != "RIVAL_SECRET" {
		t.Errorf("rival tenant lost its row after cross-tenant Delete: %+v", rivalAfter)
	}
}

// TestOrganizationVariableServiceDeleteRejectsBlankOrgID proves the
// pre-tx validation guard: a blank organization id is rejected as a
// stable InvalidInput before any transaction opens, so a malformed
// caller can never reach the audit table.
func TestOrganizationVariableServiceDeleteRejectsBlankOrgID(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	svc := newOrgVariableService(t, s)

	_, err := svc.Delete(ctx, store.DeleteOrganizationVariableInput{
		OrganizationID: "   ",
		Key:            "REGION",
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: "org_acme",
	})
	if err == nil {
		t.Fatalf("Delete returned no error for blank organization id, want InvalidInput")
	}
	if got, want := yerr.From(err).Code, yerr.CodeValidation; got != want {
		t.Errorf("error code = %q, want %q; err = %v", got, want, err)
	}
}

// TestOrganizationVariableServiceDeleteRejectsNonPOSIXKey proves the
// pre-tx validation guard: a key that is not a POSIX environment
// variable name is rejected as a stable InvalidInput before any
// transaction opens — the same shape rule the PATCH endpoint enforces,
// so a key shape that PATCH rejects cannot reach the DELETE store
// either.
func TestOrganizationVariableServiceDeleteRejectsNonPOSIXKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	svc := newOrgVariableService(t, s)

	_, err := svc.Delete(ctx, store.DeleteOrganizationVariableInput{
		OrganizationID: "org_acme",
		Key:            "1starts_with_digit",
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: "org_acme",
	})
	if err == nil {
		t.Fatalf("Delete returned no error for non-POSIX key, want InvalidInput")
	}
	if got, want := yerr.From(err).Code, yerr.CodeValidation; got != want {
		t.Errorf("error code = %q, want %q; err = %v", got, want, err)
	}
}

// TestOrganizationVariableServiceDeleteRejectsBlankActorOrgID proves
// the audit-record wiring guard: a blank actor organization id is
// rejected as a typed Internal before any database work runs, so an
// audit-less mutation can never reach the database.
func TestOrganizationVariableServiceDeleteRejectsBlankActorOrgID(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	svc := newOrgVariableService(t, s)

	_, err := svc.Delete(ctx, store.DeleteOrganizationVariableInput{
		OrganizationID: "org_acme",
		Key:            "REGION",
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: "  ",
	})
	if err == nil {
		t.Fatalf("Delete returned no error for blank actor org id, want Internal")
	}
	if got, want := yerr.From(err).Code, yerr.CodeInternal; got != want {
		t.Errorf("error code = %q, want %q; err = %v", got, want, err)
	}
}
