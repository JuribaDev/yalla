package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

// Integration tests for LimitsReader and QuotaRepository.ListEffectiveLimits —
// the persistence half of GET /v1/organizations/{org_id}/limits (BE-0094).
// They run against an isolated, freshly migrated Postgres database and skip
// when YALLA_TEST_DATABASE_URL is unset. They prove organization overrides
// beat plan defaults, that unconfigured resources are omitted, that the read
// is tenant scoped, that resources are returned in deterministic order, and
// that the LimitsReader adapter composes the repository through Store.Read
// rather than issuing its own SQL.

// TestQuotaRepositoryListEffectiveLimitsResolution proves the resolution
// rule: for each resource that has any policy at the tenant's scope, the
// organization override is preferred over the plan default, and the wire
// shape carries the scope that produced the value.
func TestQuotaRepositoryListEffectiveLimitsResolution(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Acme")
	// projects: plan default 3, organization override 10 -> override wins.
	seedPlanPolicy(t, db, "qp_plan_projects_a", "starter", "projects", 3)
	seedOrgPolicy(t, db, "qp_org_projects_a", org.ID, "projects", 10)
	// services: plan default only.
	seedPlanPolicy(t, db, "qp_plan_services_a", "starter", "services", 25)
	// domains: organization override only (no plan default).
	seedOrgPolicy(t, db, "qp_org_domains_a", org.ID, "domains", 7)

	var got []store.EffectiveQuotaLimit
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.ListEffectiveLimits(ctx, q, org.ID, "starter")
		return err
	}); err != nil {
		t.Fatalf("ListEffectiveLimits: %v", err)
	}

	if len(got) != 3 {
		t.Fatalf("len = %d, want 3; got = %+v", len(got), got)
	}
	// DISTINCT ON (resource) + ORDER BY resource yields deterministic
	// alphabetical resource order: domains, projects, services.
	want := []store.EffectiveQuotaLimit{
		{Resource: store.QuotaResourceDomains, LimitValue: 7, EnforcementMode: store.EnforcementModeHard, Scope: store.QuotaScopeOrganization},
		{Resource: store.QuotaResourceProjects, LimitValue: 10, EnforcementMode: store.EnforcementModeHard, Scope: store.QuotaScopeOrganization},
		{Resource: store.QuotaResourceServices, LimitValue: 25, EnforcementMode: store.EnforcementModeHard, Scope: store.QuotaScopePlanDefault},
	}
	for i, w := range want {
		if got[i].Resource != w.Resource || got[i].LimitValue != w.LimitValue || got[i].EnforcementMode != w.EnforcementMode || got[i].Scope != w.Scope {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], w)
		}
	}
}

// TestQuotaRepositoryListEffectiveLimitsEmptyWhenNoPolicy proves an
// organization with no plan default and no override receives no rows — the
// resource is unconstrained and the wire response will omit it.
func TestQuotaRepositoryListEffectiveLimitsEmptyWhenNoPolicy(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "Bare")

	var got []store.EffectiveQuotaLimit
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.ListEffectiveLimits(ctx, q, org.ID, "starter")
		return err
	}); err != nil {
		t.Fatalf("ListEffectiveLimits: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0; got = %+v", len(got), got)
	}
}

// TestQuotaRepositoryListEffectiveLimitsTenantScoped proves the read is
// tenant scoped: org A's override is never returned for org B, even when
// both organizations share the same plan and resource.
func TestQuotaRepositoryListEffectiveLimitsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	repo := store.NewQuotaRepository()
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "AcmeA")
	orgB := seedOrg(t, db, f, "AcmeB")
	// Org A has an override; both organizations inherit the plan default.
	seedPlanPolicy(t, db, "qp_plan_projects_b", "starter", "projects", 3)
	seedOrgPolicy(t, db, "qp_org_projects_b", orgA.ID, "projects", 50)

	var (
		gotA []store.EffectiveQuotaLimit
		gotB []store.EffectiveQuotaLimit
	)
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		a, err := repo.ListEffectiveLimits(ctx, q, orgA.ID, "starter")
		if err != nil {
			return err
		}
		gotA = a
		b, err := repo.ListEffectiveLimits(ctx, q, orgB.ID, "starter")
		if err != nil {
			return err
		}
		gotB = b
		return nil
	}); err != nil {
		t.Fatalf("ListEffectiveLimits: %v", err)
	}

	if len(gotA) != 1 || gotA[0].LimitValue != 50 || gotA[0].Scope != store.QuotaScopeOrganization {
		t.Errorf("orgA = %+v, want one organization override of 50", gotA)
	}
	if len(gotB) != 1 || gotB[0].LimitValue != 3 || gotB[0].Scope != store.QuotaScopePlanDefault {
		t.Errorf("orgB = %+v, want one plan default of 3 (org A's override must not leak)", gotB)
	}
}

// TestLimitsReaderListEffectiveLimits proves the LimitsReader adapter wires
// the repository through Store.Read and the configured PlanLookup — passing
// nil falls back to DefaultPlan, so the lookup observes the same plan name
// the deployment seeded with.
func TestLimitsReaderListEffectiveLimits(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderAcme")
	// Plan default for the DefaultPlan placeholder.
	seedPlanPolicy(t, db, "qp_plan_projects_r", store.DefaultPlan, "projects", 5)
	seedOrgPolicy(t, db, "qp_org_services_r", org.ID, "services", 99)

	reader, err := store.NewLimitsReader(s, nil)
	if err != nil {
		t.Fatalf("NewLimitsReader: %v", err)
	}
	got, err := reader.ListEffectiveLimits(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListEffectiveLimits: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2; got = %+v", len(got), got)
	}
	// Resources are returned in alphabetical order: projects then services.
	if got[0].Resource != store.QuotaResourceProjects || got[0].LimitValue != 5 || got[0].Scope != store.QuotaScopePlanDefault {
		t.Errorf("projects entry = %+v, want plan default of 5", got[0])
	}
	if got[1].Resource != store.QuotaResourceServices || got[1].LimitValue != 99 || got[1].Scope != store.QuotaScopeOrganization {
		t.Errorf("services entry = %+v, want organization override of 99", got[1])
	}
}

// TestLimitsReaderRespectsCustomPlanLookup proves the constructor wires the
// PlanLookup function: the adapter resolves the plan name through it inside
// the same read transaction, so plan/limits pairs are always coherent.
func TestLimitsReaderRespectsCustomPlanLookup(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "ReaderPlan")
	// Seed plan defaults for two named plans; the custom lookup must pick
	// the right one.
	seedPlanPolicy(t, db, "qp_plan_starter_p", "starter", "projects", 5)
	seedPlanPolicy(t, db, "qp_plan_pro_p", "pro", "projects", 50)

	reader, err := store.NewLimitsReader(s, func(_ context.Context, _ store.Querier, _ string) (string, error) {
		return "pro", nil
	})
	if err != nil {
		t.Fatalf("NewLimitsReader: %v", err)
	}
	got, err := reader.ListEffectiveLimits(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListEffectiveLimits: %v", err)
	}
	if len(got) != 1 || got[0].LimitValue != 50 {
		t.Errorf("got = %+v, want a single projects entry of 50 (pro plan default)", got)
	}
}

func TestLimitsReaderUsesCurrentSubscriptionEntitlementsWithUsageAndResetPeriod(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	pricing := store.NewPricingPlanRepository()
	subs := store.NewSubscriptionRepository()
	f := testutil.NewFactory(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	org := seedOrg(t, db, f, "EntitledLimits")
	plan := seededPlan(ctx, t, s, pricing, "starter")
	projectLimit := int64(2)
	upsertEntitlementOrFail(ctx, t, s, pricing, store.UpsertPlanEntitlementInput{
		PlanID:          plan.ID,
		EntitlementKey:  "projects",
		LimitValue:      &projectLimit,
		EnforcementMode: store.EnforcementModeHard,
	})
	sub := createSubscriptionOrFail(ctx, t, s, subs, baseSubscriptionInput(org.ID, plan.ID, store.SubscriptionStatusActive, now))
	upsertSubscriptionEntitlementOrFail(ctx, t, s, subs,
		baseOverrideInput(org.ID, sub.ID, "projects", store.EntitlementSourceSubscriptionOverride, 10, now))
	seedQuotaUsage(t, db, "qu_limits_entitled_projects", org.ID, "projects", 8)

	reader, err := store.NewLimitsReader(s, nil)
	if err != nil {
		t.Fatalf("NewLimitsReader: %v", err)
	}
	got, err := reader.ListEffectiveLimits(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListEffectiveLimits: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1; got = %+v", len(got), got)
	}
	limit := got[0]
	if limit.Resource != store.QuotaResourceProjects || limit.LimitValue != 10 || limit.UsedValue != 8 || limit.Scope != store.QuotaScopeSubscriptionOverride {
		t.Fatalf("entitlement-backed limit = %+v, want projects 8/10 subscription_override", limit)
	}
	if limit.ResetPeriodStart == nil || !limit.ResetPeriodStart.Equal(now.Add(-time.Hour)) {
		t.Errorf("ResetPeriodStart = %v, want current subscription start", limit.ResetPeriodStart)
	}
	if limit.ResetPeriodEnd == nil || !limit.ResetPeriodEnd.Equal(now.Add(time.Hour)) {
		t.Errorf("ResetPeriodEnd = %v, want current subscription end", limit.ResetPeriodEnd)
	}
	if len(limit.WarningThresholds) != 3 || limit.WarningThresholds[0] != 80 || limit.WarningThresholds[2] != 100 {
		t.Errorf("WarningThresholds = %v, want [80 90 100]", limit.WarningThresholds)
	}
}

// TestNewLimitsReaderRejectsNilStore proves a misconfigured reader fails at
// construction rather than on its first request.
func TestNewLimitsReaderRejectsNilStore(t *testing.T) {
	t.Parallel()

	if _, err := store.NewLimitsReader(nil, nil); err == nil {
		t.Error("NewLimitsReader(nil, nil) returned no error; want a nil-store error")
	}
}
