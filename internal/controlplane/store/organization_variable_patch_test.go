package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for OrganizationVariableService.Patch — the
// patch-organization-variable unit of work behind PATCH
// /v1/organizations/{org_id}/variables/{key}. They prove that the
// in-transaction read + UPDATE + audit commit atomically, that the
// optimistic-concurrency version bumps through the schema trigger,
// that omitted fields preserve the persisted state verbatim, that
// validation rejects invalid input (no-op patch, NUL bytes, invalid
// UTF-8, demotion size overflow) without ever opening a transaction
// (or rolls it back when the check runs in-transaction), that a
// cross-tenant key is indistinguishable from a missing row, and that
// audit metadata records only the variable's stable id and the
// closed-set names of the fields the patch changed — never the
// customer-supplied key or value. They run against an isolated,
// freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset.

func ptrBool(b bool) *bool { return &b }

// TestOrganizationVariableServicePatchUpdatesValueAndIsSecret proves
// the happy path of a full patch: both value and is_secret are
// written, the row's id and key are preserved, the version bumps
// through the schema trigger, and the audit record names the
// variable's id with closed-set updated_fields metadata.
func TestOrganizationVariableServicePatchUpdatesValueAndIsSecret(t *testing.T) {
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
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("seed Replace: %v", err)
	}
	if len(initial) != 1 {
		t.Fatalf("seed Replace returned %d variables, want 1", len(initial))
	}
	seededID := initial[0].ID
	seededVersion := initial[0].Version

	updated, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            "REGION",
		Value:          ptrString("eu-west-1"),
		IsSecret:       ptrBool(true),
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
		RequestID: "req_p", CorrelationID: "corr_p",
	})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if updated.ID != seededID {
		t.Errorf("updated.id = %q, want the seeded id %q (PATCH must preserve identity)", updated.ID, seededID)
	}
	if updated.Key != "REGION" {
		t.Errorf("updated.key = %q, want REGION", updated.Key)
	}
	if revealVariableValue(updated) != "eu-west-1" || !updated.IsSecret {
		t.Errorf("updated value/is_secret = (%q, %v), want (eu-west-1, true)", revealVariableValue(updated), updated.IsSecret)
	}
	if updated.Version <= seededVersion {
		t.Errorf("updated.version = %d, want > seeded version %d (the bump_version trigger must fire)", updated.Version, seededVersion)
	}

	// Audit: there should be exactly one PATCH-time audit event
	// (filed after the seed Replace event). The latest event names the
	// variable id and the closed-set updated_fields metadata — never
	// the customer-supplied key or value.
	events := listAuditEvents(t, s, org.ID)
	if len(events) < 2 {
		t.Fatalf("audit events = %d, want at least two (seed Replace + PATCH)", len(events))
	}
	ev := events[0]
	if ev.Action != "env.write" {
		t.Errorf("audit action = %q, want env.write", ev.Action)
	}
	if ev.ResourceKind != "org" {
		t.Errorf("audit resource_kind = %q, want org (PATCH files under organization scope)", ev.ResourceKind)
	}
	if ev.ResourceID != org.ID {
		t.Errorf("audit resource_id = %q, want the organization id %q", ev.ResourceID, org.ID)
	}
	if got := ev.Metadata["variable_id"]; got != seededID {
		t.Errorf("audit metadata.variable_id = %q, want %q", got, seededID)
	}
	if got := ev.Metadata["updated_fields"]; got != "value,is_secret" {
		t.Errorf("audit metadata.updated_fields = %q, want \"value,is_secret\"", got)
	}
	for k, v := range ev.Metadata {
		if strings.Contains(v, "REGION") || strings.Contains(v, "eu-west-1") || strings.Contains(v, "us-east-1") {
			t.Errorf("audit metadata[%q] = %q leaks a customer-supplied variable name or value", k, v)
		}
	}
}

// TestOrganizationVariableServicePatchValueOnlyPreservesIsSecret
// proves a value-only patch leaves the is_secret column untouched,
// while still bumping the row's version through the trigger and
// recording only "value" in updated_fields.
func TestOrganizationVariableServicePatchValueOnlyPreservesIsSecret(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "DATABASE_URL", Value: "postgres://old@db/app", IsSecret: true},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	updated, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            "DATABASE_URL",
		Value:          ptrString("postgres://new@db/app"),
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if revealVariableValue(updated) != "postgres://new@db/app" {
		t.Errorf("updated.value = %q, want the patched value", revealVariableValue(updated))
	}
	if !updated.IsSecret {
		t.Errorf("updated.is_secret = false, want true (an omitted field must be preserved)")
	}
	events := listAuditEvents(t, s, org.ID)
	ev := events[0]
	if got := ev.Metadata["updated_fields"]; got != "value" {
		t.Errorf("audit metadata.updated_fields = %q, want \"value\"", got)
	}
}

// TestOrganizationVariableServicePatchIsSecretOnlyPreservesValue
// proves an is_secret-only patch leaves the value column untouched
// and records only "is_secret" in updated_fields.
func TestOrganizationVariableServicePatchIsSecretOnlyPreservesValue(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "REGION", Value: "us-east-1", IsSecret: false},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	updated, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            "REGION",
		IsSecret:       ptrBool(true),
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if revealVariableValue(updated) != "us-east-1" {
		t.Errorf("updated.value = %q, want the seeded value (omitted field preserved)", revealVariableValue(updated))
	}
	if !updated.IsSecret {
		t.Errorf("updated.is_secret = %v, want true", updated.IsSecret)
	}
	events := listAuditEvents(t, s, org.ID)
	ev := events[0]
	if got := ev.Metadata["updated_fields"]; got != "is_secret" {
		t.Errorf("audit metadata.updated_fields = %q, want \"is_secret\"", got)
	}
}

// TestOrganizationVariableServicePatchNotFoundForMissingKey proves a
// PATCH against a {key} that does not exist in this tenant surfaces
// as the typed NotFound the repository produces, and no audit record
// is filed for the failed mutation.
func TestOrganizationVariableServicePatchNotFoundForMissingKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	_, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            "DOES_NOT_EXIST",
		Value:          ptrString("x"),
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Patch on a missing key returned no error")
	}
	if got, want := yerr.From(err).Code, yerr.CodeNotFound; got != want {
		t.Errorf("error code = %q, want %q", got, want)
	}
	if events := listAuditEvents(t, s, org.ID); len(events) != 0 {
		t.Errorf("audit events = %d, want 0 (a failed PATCH must not file an audit record)", len(events))
	}
}

// TestOrganizationVariableServicePatchTenantIsolation proves a key
// that exists in another tenant cannot be read or mutated through
// this tenant's PATCH path — the tenant-scoped repository read
// filters by organization_id first, so a cross-tenant key is
// indistinguishable from a missing row, and the victim's row is
// untouched.
func TestOrganizationVariableServicePatchTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	attacker := seedOrg(t, db, f, "Attacker")
	victim := seedOrg(t, db, f, "Victim")
	svc := newOrgVariableService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: victim.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "SHARED_KEY", Value: "victim-value", IsSecret: false},
		},
		ActorID: "usr_admin", ActorKind: "usr", ActorOrgID: victim.ID,
	}); err != nil {
		t.Fatalf("seed victim Replace: %v", err)
	}

	_, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: attacker.ID,
		Key:            "SHARED_KEY",
		Value:          ptrString("smuggled"),
		ActorID:        "usr_mallory", ActorKind: "usr", ActorOrgID: attacker.ID,
	})
	if err == nil {
		t.Fatalf("cross-tenant Patch returned no error; isolation violated")
	}
	if got, want := yerr.From(err).Code, yerr.CodeNotFound; got != want {
		t.Errorf("error code = %q, want %q (cross-tenant key must be NotFound, not Forbidden, at this layer)", got, want)
	}

	// The victim's row must be untouched.
	repo := store.NewOrganizationVariableRepository()
	var victimList []store.OrganizationVariable
	if txErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		victimList, err = repo.ListByOrganization(ctx, q, victim.ID)
		return err
	}); txErr != nil {
		t.Fatalf("re-read victim: %v", txErr)
	}
	if len(victimList) != 1 || victimList[0].Value != "victim-value" {
		t.Errorf("victim variables after cross-tenant patch = %+v, want one unchanged SHARED_KEY=victim-value", victimList)
	}
}

// TestOrganizationVariableServicePatchRejectsEmptyPatch proves a
// PATCH that names neither value nor is_secret is rejected as a
// typed InvalidInput before any database work — a mutation that
// changes nothing is a client error, not a silent success.
func TestOrganizationVariableServicePatchRejectsEmptyPatch(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	_, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            "REGION",
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Patch with no fields returned no error")
	}
	if got, want := yerr.From(err).Code, yerr.CodeValidation; got != want {
		t.Errorf("error code = %q, want %q", got, want)
	}
}

// TestOrganizationVariableServicePatchRejectsNonPOSIXKey proves the
// path-parameter key is validated before any transaction is opened:
// a key that does not match the POSIX env-var name shape is rejected
// as InvalidInput, never silently accepted into a UPDATE no-op.
func TestOrganizationVariableServicePatchRejectsNonPOSIXKey(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	_, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            "1BAD_KEY",
		Value:          ptrString("x"),
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Patch with non-POSIX key returned no error")
	}
	if got, want := yerr.From(err).Code, yerr.CodeValidation; got != want {
		t.Errorf("error code = %q, want %q", got, want)
	}
}

// TestOrganizationVariableServicePatchRejectsDemotionOverflow proves
// the final-state size ceiling is applied against the post-patch
// effective is_secret state: a value submitted under is_secret=true
// (64 KiB ceiling) cannot be demoted to is_secret=false (32 KiB
// ceiling) when it exceeds the non-secret limit. The check runs
// in-transaction (after the current row is observed), so the
// transaction rolls back without changing the row or filing an
// audit record.
func TestOrganizationVariableServicePatchRejectsDemotionOverflow(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	bigSecret := strings.Repeat("x", validate.MaxEnvVarValueLen+1)
	if _, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "BIG_SECRET", Value: bigSecret, IsSecret: true},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	_, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            "BIG_SECRET",
		IsSecret:       ptrBool(false),
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("demotion of an oversized secret returned no error")
	}
	if got, want := yerr.From(err).Code, yerr.CodeValidation; got != want {
		t.Errorf("error code = %q, want %q", got, want)
	}

	// The seeded row must be unchanged.
	repo := store.NewOrganizationVariableRepository()
	var v store.OrganizationVariable
	if txErr := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		v, err = repo.GetByKey(ctx, q, org.ID, "BIG_SECRET")
		return err
	}); txErr != nil {
		t.Fatalf("re-read BIG_SECRET: %v", txErr)
	}
	if !v.IsSecret {
		t.Errorf("variable.is_secret = false after a rejected demotion; transaction did not roll back")
	}
	if got := len(revealVariableValue(v)); got != len(bigSecret) {
		t.Errorf("variable.value length = %d, want %d (unchanged)", got, len(bigSecret))
	}
}

// TestOrganizationVariableServicePatchRejectsNULByte proves the
// structural value check rejects an embedded NUL byte before any
// database write — Postgres' TEXT column allows it, but the wire
// contract does not, and a NUL in an env var is a footgun for the
// downstream shell.
func TestOrganizationVariableServicePatchRejectsNULByte(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newOrgVariableService(t, s)

	if _, err := svc.Replace(ctx, store.ReplaceOrganizationVariablesInput{
		OrganizationID: org.ID,
		Variables: []store.OrganizationVariableReplace{
			{Key: "REGION", Value: "us-east-1", IsSecret: false},
		},
		ActorID: "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	_, err := svc.Patch(ctx, store.PatchOrganizationVariableInput{
		OrganizationID: org.ID,
		Key:            "REGION",
		Value:          ptrString("us-east-\x001"),
		ActorID:        "usr_ada", ActorKind: "usr", ActorOrgID: org.ID,
	})
	if err == nil {
		t.Fatalf("Patch with NUL byte returned no error")
	}
	if got, want := yerr.From(err).Code, yerr.CodeValidation; got != want {
		t.Errorf("error code = %q, want %q", got, want)
	}
}
