package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestAdminEntitlementServiceLifecycleAuditAndRuntimeResolution(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "AdminEntitlement")
	ctx := context.Background()
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminPlanServiceForTest(t, s)
	auditCtx := store.AdminPlanAuditContext{
		ActorOrgID:    org.ID,
		ActorID:       "usr_admin_entitlement",
		ActorKind:     "usr",
		RequestID:     "req_admin_entitlement",
		CorrelationID: "corr_admin_entitlement",
	}

	limit := int64(42)
	ent, err := svc.UpsertPlanEntitlement(ctx, "plan_business_monthly_v1", store.UpsertPlanEntitlementInput{
		EntitlementKey:  "projects",
		LimitValue:      &limit,
		EnforcementMode: store.EnforcementModeHard,
		Metadata:        []byte(`{"unit":"project","warning_threshold":80,"upgrade_hint":"Upgrade to Enterprise","overage_behavior":"block"}`),
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertPlanEntitlement: %v", err)
	}
	if ent.PlanID != "plan_business_monthly_v1" || ent.EntitlementKey != "projects" || ent.LimitValue == nil || *ent.LimitValue != 42 {
		t.Fatalf("entitlement = %+v, want updated plan projects limit", ent)
	}

	now := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)
	sub := createSubscriptionOrFail(ctx, t, s, store.NewSubscriptionRepository(), baseSubscriptionInput(org.ID, "plan_business_monthly_v1", store.SubscriptionStatusActive, now))
	if sub.PlanID != "plan_business_monthly_v1" {
		t.Fatalf("subscription = %+v", sub)
	}
	var resolved []store.EffectiveEntitlement
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		resolved, readErr = store.NewSubscriptionRepository().ResolveEntitlements(ctx, q, org.ID, now)
		return readErr
	}); err != nil {
		t.Fatalf("ResolveEntitlements: %v", err)
	}
	projects, ok := entitlementByKey(resolved, "projects")
	if !ok || projects.LimitValue == nil || *projects.LimitValue != 42 || projects.EnforcementMode != store.EnforcementModeHard {
		t.Fatalf("resolved projects = %+v, want updated hard limit 42", projects)
	}

	renamed, err := svc.RenamePlanEntitlement(ctx, "plan_business_monthly_v1", "projects", "service_projects", "impact_admin_entitlement_rename", auditCtx)
	if err != nil {
		t.Fatalf("RenamePlanEntitlement: %v", err)
	}
	if renamed.EntitlementKey != "service_projects" || renamed.LimitValue == nil || *renamed.LimitValue != 42 {
		t.Fatalf("renamed = %+v, want service_projects carrying previous value", renamed)
	}

	if err := svc.DeletePlanEntitlement(ctx, "plan_business_monthly_v1", "service_projects", "impact_admin_entitlement_delete", auditCtx); err != nil {
		t.Fatalf("DeletePlanEntitlement: %v", err)
	}
	ents := listEntitlementsOrFail(ctx, t, s, store.NewPricingPlanRepository(), "plan_business_monthly_v1")
	for _, got := range ents {
		if got.EntitlementKey == "service_projects" {
			t.Fatalf("deleted entitlement still present: %+v", got)
		}
	}

	var events []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		events, readErr = store.NewAuditRepository().ListByOrganization(ctx, q, org.ID, 10)
		return readErr
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("audit events = %d, want 3: %+v", len(events), events)
	}
	wantActions := map[string]bool{
		"admin.plan.entitlement.upsert": false,
		"admin.plan.entitlement.rename": false,
		"admin.plan.entitlement.delete": false,
	}
	for _, event := range events {
		if _, ok := wantActions[event.Action]; ok {
			wantActions[event.Action] = true
		}
		if event.RequestID != auditCtx.RequestID || event.CorrelationID != auditCtx.CorrelationID {
			t.Fatalf("audit event missing request identity: %+v", event)
		}
		if event.ResourceKind != "plan_entitlement" || event.Decision != store.AuditDecisionAllowed {
			t.Fatalf("audit event = %+v, want allowed plan_entitlement event", event)
		}
	}
	for action, seen := range wantActions {
		if !seen {
			t.Fatalf("missing audit action %s in %+v", action, events)
		}
	}
}

func TestAdminEntitlementServiceRequiresImpactValidationForUnsafeChanges(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "AdminEntitlementImpact")
	ctx := context.Background()
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminPlanServiceForTest(t, s)
	auditCtx := store.AdminPlanAuditContext{
		ActorOrgID:    org.ID,
		ActorID:       "usr_admin_entitlement_impact",
		ActorKind:     "usr",
		RequestID:     "req_admin_entitlement_impact",
		CorrelationID: "corr_admin_entitlement_impact",
	}

	if _, err := svc.RenamePlanEntitlement(ctx, "plan_business_monthly_v1", "projects", "service_projects", "", auditCtx); err == nil {
		t.Fatal("RenamePlanEntitlement without impact validation error = nil, want conflict")
	}
	if err := svc.DeletePlanEntitlement(ctx, "plan_business_monthly_v1", "projects", "", auditCtx); err == nil {
		t.Fatal("DeletePlanEntitlement without impact validation error = nil, want conflict")
	}
}

func TestAdminEntitlementMetadataIsStableJSON(t *testing.T) {
	t.Parallel()

	meta := []byte(`{"unit":"gb","warning_threshold":90,"upgrade_hint":"Use a larger plan","overage_behavior":"warn"}`)
	var got map[string]any
	if err := json.Unmarshal(meta, &got); err != nil {
		t.Fatalf("metadata should be JSON: %v", err)
	}
}
