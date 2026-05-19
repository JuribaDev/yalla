package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestAdminOveragePolicyServicePrecedenceEffectiveTimeAndAudit(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	actorOrg := seedOrg(t, db, f, "AdminOveragePolicyActor")
	targetOrg := seedOrg(t, db, f, "AdminOveragePolicyTarget")
	ctx := context.Background()
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminOveragePolicyServiceForTest(t, s)
	plans := store.NewPricingPlanRepository()
	plan := seededPlan(ctx, t, s, plans, "business")
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	auditCtx := store.AdminOveragePolicyAuditContext{
		ActorOrgID:    actorOrg.ID,
		ActorID:       "usr_admin_overage_policy",
		ActorKind:     "user",
		RequestID:     "req_admin_overage_policy",
		CorrelationID: "corr_admin_overage_policy",
		Reason:        "pricing policy change",
	}

	global, err := svc.UpsertOveragePolicy(ctx, store.UpsertOveragePolicyInput{
		Scope:          store.OveragePolicyScopeGlobal,
		EntitlementKey: "http_bandwidth_total",
		Mode:           store.OveragePolicyModeWarn,
		EffectiveAt:    now.Add(-time.Hour),
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertOveragePolicy global: %v", err)
	}
	planPolicy, err := svc.UpsertOveragePolicy(ctx, store.UpsertOveragePolicyInput{
		Scope:          store.OveragePolicyScopePlan,
		PlanID:         plan.ID,
		EntitlementKey: "http_bandwidth_total",
		Mode:           store.OveragePolicyModeAllow,
		EffectiveAt:    now.Add(-time.Minute),
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertOveragePolicy plan: %v", err)
	}
	orgPolicy, err := svc.UpsertOveragePolicy(ctx, store.UpsertOveragePolicyInput{
		Scope:          store.OveragePolicyScopeOrganization,
		OrganizationID: targetOrg.ID,
		EntitlementKey: "http_bandwidth_total",
		Mode:           store.OveragePolicyModeRequireAdminReview,
		EffectiveAt:    now.Add(time.Hour),
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertOveragePolicy org future: %v", err)
	}

	repo := store.NewOveragePolicyRepository()
	var resolved store.OveragePolicy
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		resolved, err = repo.ResolveRuntime(ctx, q, targetOrg.ID, plan.ID, "http_bandwidth_total", now)
		return err
	}); err != nil {
		t.Fatalf("ResolveRuntime before org effective_at: %v", err)
	}
	if resolved.ID != planPolicy.ID || resolved.Mode != store.OveragePolicyModeAllow {
		t.Fatalf("resolved policy before org effective_at = %+v, want plan allow %+v", resolved, planPolicy)
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		resolved, err = repo.ResolveRuntime(ctx, q, targetOrg.ID, plan.ID, "http_bandwidth_total", now.Add(2*time.Hour))
		return err
	}); err != nil {
		t.Fatalf("ResolveRuntime after org effective_at: %v", err)
	}
	if resolved.ID != orgPolicy.ID || resolved.Mode != store.OveragePolicyModeRequireAdminReview {
		t.Fatalf("resolved policy after org effective_at = %+v, want org review %+v", resolved, orgPolicy)
	}

	if _, err := svc.UpsertOveragePolicy(ctx, store.UpsertOveragePolicyInput{
		Scope:          store.OveragePolicyScopeGlobal,
		EntitlementKey: "http_bandwidth_total",
		Mode:           store.OveragePolicyModeBlock,
		EffectiveAt:    now.Add(-24 * time.Hour),
	}, auditCtx); err == nil {
		t.Fatal("retroactive restrictive block policy error = nil, want validation")
	}

	var events []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		events, err = store.NewAuditRepository().ListByOrganization(ctx, q, actorOrg.ID, 10)
		return err
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	foundPolicies := 0
	for _, event := range events {
		if event.Action != "admin.overage_policy.upsert" {
			continue
		}
		foundPolicies++
		if event.RequestID != auditCtx.RequestID || event.CorrelationID != auditCtx.CorrelationID {
			t.Fatalf("audit event missing request identity: %+v", event)
		}
		if event.Metadata["entitlement_key"] != "http_bandwidth_total" {
			t.Fatalf("audit event missing entitlement key: %+v", event)
		}
	}
	if foundPolicies != 3 {
		t.Fatalf("overage policy audit events = %d, want 3; events=%+v; global=%+v", foundPolicies, events, global)
	}
}

func newAdminOveragePolicyServiceForTest(t *testing.T, s *store.Store) *store.AdminOveragePolicyService {
	t.Helper()
	svc, err := store.NewAdminOveragePolicyService(s, store.NewOrganizationRepository(), store.NewPricingPlanRepository(), store.NewOveragePolicyRepository(), store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewAdminOveragePolicyService: %v", err)
	}
	return svc
}
