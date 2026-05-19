package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

func TestAdminSubscriptionServiceSetSubscriptionLifecycleAndAudit(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	actorOrg := seedOrg(t, db, f, "AdminSubscriptionActor")
	targetOrg := seedOrg(t, db, f, "AdminSubscriptionTarget")
	ctx := context.Background()
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminSubscriptionServiceForTest(t, s)
	plan := seededPlan(ctx, t, s, store.NewPricingPlanRepository(), "business")
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	auditCtx := store.AdminPlanAuditContext{
		ActorOrgID:    actorOrg.ID,
		ActorID:       "usr_admin_subscription",
		ActorKind:     "user",
		RequestID:     "req_admin_subscription",
		CorrelationID: "corr_admin_subscription",
	}

	trial, err := svc.SetSubscription(ctx, targetOrg.ID, baseSubscriptionInput(targetOrg.ID, plan.ID, store.SubscriptionStatusTrialing, now), auditCtx)
	if err != nil {
		t.Fatalf("SetSubscription trialing: %v", err)
	}
	if trial.Status != store.SubscriptionStatusTrialing || trial.TrialEndsAt == nil {
		t.Fatalf("trial subscription = %+v", trial)
	}

	activeInput := baseSubscriptionInput(targetOrg.ID, plan.ID, store.SubscriptionStatusActive, now)
	activeInput.Provider = "stripe"
	customerID := "cus_123"
	activeInput.ProviderCustomerID = &customerID
	active, err := svc.SetSubscription(ctx, targetOrg.ID, activeInput, auditCtx)
	if err != nil {
		t.Fatalf("SetSubscription active: %v", err)
	}
	if active.ID != trial.ID || active.Status != store.SubscriptionStatusActive || active.Provider != "stripe" {
		t.Fatalf("active subscription = %+v, want same row updated to active stripe", active)
	}

	pastDueInput := baseSubscriptionInput(targetOrg.ID, plan.ID, store.SubscriptionStatusPastDue, now)
	pastDueInput.CancelAtPeriodEnd = true
	pastDue, err := svc.SetSubscription(ctx, targetOrg.ID, pastDueInput, auditCtx)
	if err != nil {
		t.Fatalf("SetSubscription past_due: %v", err)
	}
	if pastDue.ID != trial.ID || pastDue.Status != store.SubscriptionStatusPastDue || !pastDue.CancelAtPeriodEnd {
		t.Fatalf("past_due subscription = %+v", pastDue)
	}

	canceled, err := svc.SetSubscription(ctx, targetOrg.ID, baseSubscriptionInput(targetOrg.ID, plan.ID, store.SubscriptionStatusCanceled, now), auditCtx)
	if err != nil {
		t.Fatalf("SetSubscription canceled: %v", err)
	}
	if canceled.ID != trial.ID || canceled.Status != store.SubscriptionStatusCanceled || canceled.CanceledAt == nil {
		t.Fatalf("canceled subscription = %+v", canceled)
	}

	reactivated, err := svc.SetSubscription(ctx, targetOrg.ID, baseSubscriptionInput(targetOrg.ID, plan.ID, store.SubscriptionStatusActive, now), auditCtx)
	if err != nil {
		t.Fatalf("SetSubscription reactivated: %v", err)
	}
	if reactivated.ID == canceled.ID || reactivated.Status != store.SubscriptionStatusActive {
		t.Fatalf("reactivated subscription = %+v, want new active row", reactivated)
	}

	var events []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		events, err = store.NewAuditRepository().ListByOrganization(ctx, q, actorOrg.ID, 10)
		return err
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("audit events = %d, want 5: %+v", len(events), events)
	}
	for _, event := range events {
		if event.Action != "admin.subscription.set" || event.ResourceKind != "subscription" || event.Decision != store.AuditDecisionAllowed {
			t.Fatalf("audit event = %+v, want allowed subscription set", event)
		}
		if event.RequestID != auditCtx.RequestID || event.CorrelationID != auditCtx.CorrelationID || event.ActorID != auditCtx.ActorID {
			t.Fatalf("audit event missing request identity: %+v", event)
		}
	}
}

func TestAdminSubscriptionServiceUpsertsOverrideAndAudits(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	actorOrg := seedOrg(t, db, f, "AdminSubscriptionOverrideActor")
	targetOrg := seedOrg(t, db, f, "AdminSubscriptionOverrideTarget")
	ctx := context.Background()
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminSubscriptionServiceForTest(t, s)
	plan := seededPlan(ctx, t, s, store.NewPricingPlanRepository(), "business")
	now := time.Date(2026, 5, 19, 11, 0, 0, 0, time.UTC)
	auditCtx := store.AdminPlanAuditContext{
		ActorOrgID:    actorOrg.ID,
		ActorID:       "usr_admin_subscription_override",
		ActorKind:     "user",
		RequestID:     "req_admin_subscription_override",
		CorrelationID: "corr_admin_subscription_override",
	}
	sub, err := svc.SetSubscription(ctx, targetOrg.ID, baseSubscriptionInput(targetOrg.ID, plan.ID, store.SubscriptionStatusActive, now), auditCtx)
	if err != nil {
		t.Fatalf("SetSubscription active: %v", err)
	}
	limit := int64(25)
	ent, err := svc.UpsertSubscriptionEntitlement(ctx, targetOrg.ID, store.UpsertSubscriptionEntitlementInput{
		SubscriptionID:  sub.ID,
		Source:          store.EntitlementSourceSubscriptionOverride,
		EntitlementKey:  "projects",
		LimitValue:      &limit,
		EnforcementMode: store.EnforcementModeHard,
		Reason:          "Authorization: Bearer should_not_persist",
		EffectiveFrom:   now.Add(-time.Minute),
		Metadata:        []byte(`{"api_token":"should_not_persist"}`),
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertSubscriptionEntitlement: %v", err)
	}
	if ent.SubscriptionID == nil || *ent.SubscriptionID != sub.ID || ent.Reason != "Authorization: "+output.Sentinel {
		t.Fatalf("entitlement = %+v, want subscription-scoped redacted override", ent)
	}

	var events []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		events, err = store.NewAuditRepository().ListByOrganization(ctx, q, actorOrg.ID, 10)
		return err
	}); err != nil {
		t.Fatalf("ListByOrganization: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("audit events = %d, want set + override: %+v", len(events), events)
	}
	foundOverride := false
	for _, event := range events {
		if event.Action == "admin.subscription.entitlement.upsert" {
			foundOverride = true
			if event.ResourceKind != "subscription_entitlement" || event.Metadata["entitlement_key"] != "projects" {
				t.Fatalf("override audit event = %+v", event)
			}
		}
	}
	if !foundOverride {
		t.Fatalf("events missing override audit: %+v", events)
	}
}

func TestAdminSubscriptionServiceValidationAndNotFound(t *testing.T) {
	t.Parallel()

	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminSubscriptionServiceForTest(t, s)
	auditCtx := store.AdminPlanAuditContext{
		ActorOrgID:    "org_missing",
		ActorID:       "usr_missing",
		ActorKind:     "user",
		RequestID:     "req_admin_subscription_missing",
		CorrelationID: "corr_admin_subscription_missing",
	}
	if _, err := svc.SetSubscription(ctx, "org_target", store.CreateSubscriptionInput{}, auditCtx); yerr.From(err).Code != yerr.CodeValidation {
		t.Fatalf("zero input err = %v, want validation", err)
	}

	f := testutil.NewFactory(t)
	actorOrg := seedOrg(t, db, f, "AdminSubscriptionMissingActor")
	auditCtx.ActorOrgID = actorOrg.ID
	if _, err := svc.SetSubscription(ctx, "org_missing", store.CreateSubscriptionInput{
		PlanID:             "plan_missing",
		Status:             store.SubscriptionStatusActive,
		CurrentPeriodStart: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		CurrentPeriodEnd:   time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	}, auditCtx); yerr.From(err).Code != yerr.CodeNotFound {
		t.Fatalf("missing target err = %v, want not found", err)
	}
}

func newAdminSubscriptionServiceForTest(t *testing.T, s *store.Store) *store.AdminSubscriptionService {
	t.Helper()
	svc, err := store.NewAdminSubscriptionService(s, store.NewOrganizationRepository(), store.NewPricingPlanRepository(), store.NewSubscriptionRepository(), store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewAdminSubscriptionService: %v", err)
	}
	return svc
}
