package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Integration tests for LimitsService — the update-organization-limits unit
// of work behind PATCH /v1/organizations/{org_id}/limits. They prove the
// organization-scoped policy upserts and the immutable audit record are
// committed atomically, that a missing tenant is a typed NotFound (not a
// 409 constraint violation), that overrides win over plan defaults in the
// post-write re-read, and that the read is tenant scoped. They run against
// an isolated, freshly migrated Postgres database and skip when
// YALLA_TEST_DATABASE_URL is unset.

func newLimitsService(t *testing.T, s *store.Store) *store.LimitsService {
	t.Helper()
	svc, err := store.NewLimitsService(s, store.NewOrganizationRepository(),
		store.NewQuotaRepository(), store.NewAuditRepository(), nil)
	if err != nil {
		t.Fatalf("NewLimitsService: %v", err)
	}
	return svc
}

// TestLimitsServiceUpsertsOrganizationOverrides is the happy path: a fresh
// PATCH carrying two distinct resources inserts two organization-scoped
// policies and the post-write re-read reports them in deterministic
// (alphabetical) order, with the organization scope source.
func TestLimitsServiceUpsertsOrganizationOverrides(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newLimitsService(t, s)

	limits, err := svc.UpdateLimits(ctx, store.UpdateLimitsInput{
		OrganizationID: org.ID,
		Items: []store.LimitUpdate{
			{Resource: store.QuotaResourceProjects, LimitValue: 25},
			{Resource: store.QuotaResourceServices, LimitValue: 100, EnforcementMode: store.EnforcementModeSoft},
		},
		ActorID:       "usr_ada",
		ActorKind:     "usr",
		ActorOrgID:    org.ID,
		RequestID:     "req_t",
		CorrelationID: "corr_t",
	})
	if err != nil {
		t.Fatalf("UpdateLimits: %v", err)
	}
	if len(limits) != 2 {
		t.Fatalf("post-write limits = %+v, want two entries", limits)
	}
	// Alphabetical order: projects then services.
	if limits[0].Resource != store.QuotaResourceProjects || limits[0].LimitValue != 25 ||
		limits[0].Scope != store.QuotaScopeOrganization || limits[0].EnforcementMode != store.EnforcementModeHard {
		t.Errorf("limits[0] = %+v, want projects/25/hard/organization", limits[0])
	}
	if limits[1].Resource != store.QuotaResourceServices || limits[1].LimitValue != 100 ||
		limits[1].Scope != store.QuotaScopeOrganization || limits[1].EnforcementMode != store.EnforcementModeSoft {
		t.Errorf("limits[1] = %+v, want services/100/soft/organization", limits[1])
	}

	// Exactly one audit record, filed under the actor's organization, with
	// the limits.write action and a deterministic value-free metadata
	// projection of the affected resources.
	events := listAuditEvents(t, s, org.ID)
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want exactly one for the upsert", len(events))
	}
	ev := events[0]
	if ev.Action != "limits.write" {
		t.Errorf("audit action = %q, want limits.write", ev.Action)
	}
	if ev.Decision != store.AuditDecisionAllowed {
		t.Errorf("audit decision = %q, want allowed", ev.Decision)
	}
	if ev.ResourceID != org.ID {
		t.Errorf("audit resource_id = %q, want the target organization id", ev.ResourceID)
	}
	if ev.ActorID != "usr_ada" || ev.ActorKind != "usr" {
		t.Errorf("audit actor = %q/%q, want usr_ada/usr", ev.ActorID, ev.ActorKind)
	}
	if ev.Metadata["updated_resources"] != "projects,services" {
		t.Errorf("audit metadata updated_resources = %q, want the sorted closed-set names", ev.Metadata["updated_resources"])
	}
}

// TestLimitsServiceUpdateOverridesExistingOverride proves the upsert
// overwrites an existing organization-scoped policy: the row keeps its id
// (one row remains in the partial unique index per resource) but its
// limit_value and enforcement_mode reflect the new values.
func TestLimitsServiceUpdateOverridesExistingOverride(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	seedOrgPolicy(t, db, "qp_org_projects_initial", org.ID, "projects", 10)
	svc := newLimitsService(t, s)

	if _, err := svc.UpdateLimits(ctx, store.UpdateLimitsInput{
		OrganizationID: org.ID,
		Items:          []store.LimitUpdate{{Resource: store.QuotaResourceProjects, LimitValue: 99, EnforcementMode: store.EnforcementModeMetered}},
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	}); err != nil {
		t.Fatalf("UpdateLimits: %v", err)
	}

	// The partial unique index guarantees there is exactly one
	// organization-scoped row per (org, resource).
	var count int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM quota_policies
		   WHERE scope_kind = 'organization'
		     AND organization_id = $1
		     AND resource = 'projects'`,
		org.ID).Scan(&count); err != nil {
		t.Fatalf("count org overrides: %v", err)
	}
	if count != 1 {
		t.Errorf("organization override row count = %d, want exactly 1 after upsert", count)
	}

	var (
		limit int64
		mode  string
	)
	if err := db.QueryRow(ctx,
		`SELECT limit_value, enforcement_mode FROM quota_policies
		   WHERE scope_kind = 'organization'
		     AND organization_id = $1
		     AND resource = 'projects'`,
		org.ID).Scan(&limit, &mode); err != nil {
		t.Fatalf("read updated row: %v", err)
	}
	if limit != 99 || mode != "metered" {
		t.Errorf("updated row = (%d, %s), want (99, metered)", limit, mode)
	}
}

// TestLimitsServiceOverrideBeatsPlanDefaultInReadback proves the post-write
// re-read applies the same "organization override wins over plan default"
// resolution rule the read-side LimitsReader does. A new override on a
// resource that already has a plan default replaces the plan_default
// projection.
func TestLimitsServiceOverrideBeatsPlanDefaultInReadback(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	seedPlanPolicy(t, db, "qp_plan_projects_pd", store.DefaultPlan, "projects", 5)
	svc := newLimitsService(t, s)

	limits, err := svc.UpdateLimits(ctx, store.UpdateLimitsInput{
		OrganizationID: org.ID,
		Items:          []store.LimitUpdate{{Resource: store.QuotaResourceProjects, LimitValue: 200}},
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if err != nil {
		t.Fatalf("UpdateLimits: %v", err)
	}
	if len(limits) != 1 || limits[0].LimitValue != 200 || limits[0].Scope != store.QuotaScopeOrganization {
		t.Errorf("limits = %+v, want a single projects=200/organization entry (override beats plan default)", limits)
	}
}

// TestLimitsServiceNotFoundOrganization proves a missing tenant surfaces as
// the typed NotFound the rest of the API returns — not a FK-violation 409
// — so the granular error distinction described in the routes contract
// holds end to end.
func TestLimitsServiceNotFoundOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()

	svc := newLimitsService(t, s)
	_, err := svc.UpdateLimits(ctx, store.UpdateLimitsInput{
		OrganizationID: "org_does_not_exist",
		Items:          []store.LimitUpdate{{Resource: store.QuotaResourceProjects, LimitValue: 1}},
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     "org_actor",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Errorf("error code = %v, want %s", err, yerr.CodeNotFound)
	}
}

// TestLimitsServiceTenantIsolation proves the upsert is tenant scoped:
// updating org A's limits never touches org B's row, even when both
// organizations carry a quota_policies override for the same resource.
func TestLimitsServiceTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "AcmeA")
	orgB := seedOrg(t, db, f, "AcmeB")
	seedOrgPolicy(t, db, "qp_org_projects_iso_a", orgA.ID, "projects", 10)
	seedOrgPolicy(t, db, "qp_org_projects_iso_b", orgB.ID, "projects", 50)
	svc := newLimitsService(t, s)

	if _, err := svc.UpdateLimits(ctx, store.UpdateLimitsInput{
		OrganizationID: orgA.ID,
		Items:          []store.LimitUpdate{{Resource: store.QuotaResourceProjects, LimitValue: 999}},
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     orgA.ID,
	}); err != nil {
		t.Fatalf("UpdateLimits(orgA): %v", err)
	}

	// Org B's row is untouched.
	var limit int64
	if err := db.QueryRow(ctx,
		`SELECT limit_value FROM quota_policies
		   WHERE scope_kind = 'organization' AND organization_id = $1 AND resource = 'projects'`,
		orgB.ID).Scan(&limit); err != nil {
		t.Fatalf("read orgB row: %v", err)
	}
	if limit != 50 {
		t.Errorf("orgB projects limit = %d, want untouched 50", limit)
	}
}

// TestLimitsServiceInvalidInputNeverOpensTransaction proves validation runs
// before the transaction is opened: an invalid request never writes a row
// and never appends an audit record.
func TestLimitsServiceInvalidInputNeverOpensTransaction(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newLimitsService(t, s)

	_, err := svc.UpdateLimits(ctx, store.UpdateLimitsInput{
		OrganizationID: org.ID,
		Items:          []store.LimitUpdate{{Resource: store.QuotaResource("nope"), LimitValue: 1}},
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Fatalf("error code = %v, want %s", err, yerr.CodeValidation)
	}
	if events := listAuditEvents(t, s, org.ID); len(events) != 0 {
		t.Errorf("audit events = %d after invalid input, want 0", len(events))
	}
	var count int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM quota_policies WHERE organization_id = $1`,
		org.ID).Scan(&count); err != nil {
		t.Fatalf("count org policies: %v", err)
	}
	if count != 0 {
		t.Errorf("org policy rows = %d after invalid input, want 0", count)
	}
}

// TestLimitsServiceRequiresActorOrganization proves a missing ActorOrgID is
// reported as Internal — it's a wiring error in the HTTP layer, not client
// input.
func TestLimitsServiceRequiresActorOrganization(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	svc := newLimitsService(t, s)

	_, err := svc.UpdateLimits(ctx, store.UpdateLimitsInput{
		OrganizationID: org.ID,
		Items:          []store.LimitUpdate{{Resource: store.QuotaResourceProjects, LimitValue: 1}},
		ActorID:        "usr_ada",
		ActorKind:      "usr",
		ActorOrgID:     "",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Errorf("error code = %v, want %s", err, yerr.CodeInternal)
	}
}
