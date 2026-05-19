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

func createSubscriptionOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.SubscriptionRepository, in store.CreateSubscriptionInput) store.Subscription {
	t.Helper()
	var sub store.Subscription
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		sub, err = repo.Create(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("Create subscription: %v", err)
	}
	return sub
}

func upsertSubscriptionEntitlementOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.SubscriptionRepository, in store.UpsertSubscriptionEntitlementInput) store.SubscriptionEntitlement {
	t.Helper()
	var ent store.SubscriptionEntitlement
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		ent, err = repo.UpsertEntitlement(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("Upsert subscription entitlement: %v", err)
	}
	return ent
}

func seededPlan(ctx context.Context, t *testing.T, s *store.Store, repo *store.PricingPlanRepository, slug string) store.Plan {
	t.Helper()
	var plan store.Plan
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		plan, err = repo.GetBySlugVersion(ctx, q, slug, store.BillingPeriodMonthly, 1)
		return err
	}); err != nil {
		t.Fatalf("GetBySlugVersion(%q): %v", slug, err)
	}
	return plan
}

func entitlementByKey(ents []store.EffectiveEntitlement, key string) (store.EffectiveEntitlement, bool) {
	for _, ent := range ents {
		if ent.EntitlementKey == key {
			return ent, true
		}
	}
	return store.EffectiveEntitlement{}, false
}

func baseSubscriptionInput(orgID, planID string, status store.SubscriptionStatus, now time.Time) store.CreateSubscriptionInput {
	in := store.CreateSubscriptionInput{
		OrganizationID:     orgID,
		PlanID:             planID,
		Status:             status,
		CurrentPeriodStart: now.Add(-time.Hour),
		CurrentPeriodEnd:   now.Add(time.Hour),
		Provider:           "manual",
	}
	if status == store.SubscriptionStatusTrialing {
		trialEnds := now.Add(30 * time.Minute)
		in.TrialEndsAt = &trialEnds
	}
	if status == store.SubscriptionStatusCanceled {
		canceledAt := now.Add(-10 * time.Minute)
		in.CanceledAt = &canceledAt
	}
	return in
}

func baseOverrideInput(orgID, subID, key string, source store.EntitlementOverrideSource, limit int64, now time.Time) store.UpsertSubscriptionEntitlementInput {
	in := store.UpsertSubscriptionEntitlementInput{
		OrganizationID:  orgID,
		SubscriptionID:  subID,
		Source:          source,
		EntitlementKey:  key,
		LimitValue:      &limit,
		EnforcementMode: store.EnforcementModeHard,
		Reason:          "operator approved override",
		ActorID:         "usr_operator",
		ActorKind:       "user",
		RequestID:       "req_subscription_test",
		CorrelationID:   "corr_subscription_test",
		EffectiveFrom:   now.Add(-time.Minute),
		EffectiveUntil:  nil,
		Metadata:        []byte(`{"ticket":"T-123"}`),
	}
	if source == store.EntitlementSourceEmergencyAdmin {
		in.SubscriptionID = ""
	}
	return in
}

func TestSubscriptionRepositoryResolveEntitlementsPrecedence(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	pricing := store.NewPricingPlanRepository()
	repo := store.NewSubscriptionRepository()
	ctx := context.Background()
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)

	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "billing")
	plan := seededPlan(ctx, t, s, pricing, "starter")
	seatsLimit := int64(2)
	upsertEntitlementOrFail(ctx, t, s, pricing, store.UpsertPlanEntitlementInput{
		PlanID:          plan.ID,
		EntitlementKey:  "seats",
		LimitValue:      &seatsLimit,
		EnforcementMode: store.EnforcementModeHard,
	})

	sub := createSubscriptionOrFail(ctx, t, s, repo, baseSubscriptionInput(org.ID, plan.ID, store.SubscriptionStatusActive, now))

	expiredUntil := now.Add(-time.Second)
	expired := baseOverrideInput(org.ID, sub.ID, "projects", store.EntitlementSourceSubscriptionOverride, 50, now.Add(-2*time.Minute))
	expired.EffectiveUntil = &expiredUntil
	upsertSubscriptionEntitlementOrFail(ctx, t, s, repo, expired)
	upsertSubscriptionEntitlementOrFail(ctx, t, s, repo,
		baseOverrideInput(org.ID, sub.ID, "projects", store.EntitlementSourceSubscriptionOverride, 5, now))
	upsertSubscriptionEntitlementOrFail(ctx, t, s, repo,
		baseOverrideInput(org.ID, "", "projects", store.EntitlementSourceEmergencyAdmin, 99, now))
	upsertSubscriptionEntitlementOrFail(ctx, t, s, repo,
		baseOverrideInput(org.ID, "", "priority_support", store.EntitlementSourceEmergencyAdmin, 1, now))

	var got []store.EffectiveEntitlement
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		got, err = repo.ResolveEntitlements(ctx, q, org.ID, now)
		return err
	}); err != nil {
		t.Fatalf("ResolveEntitlements: %v", err)
	}

	projects, ok := entitlementByKey(got, "projects")
	if !ok {
		t.Fatalf("resolved entitlements %+v missing projects", got)
	}
	if projects.Source != store.EntitlementSourceEmergencyAdmin || projects.LimitValue == nil || *projects.LimitValue != 99 || projects.OverrideID == "" {
		t.Fatalf("projects entitlement = %+v, want emergency override limit 99", projects)
	}
	seats, ok := entitlementByKey(got, "seats")
	if !ok || seats.Source != store.EntitlementSourcePlan || seats.LimitValue == nil || *seats.LimitValue != 2 || seats.OverrideID != "" {
		t.Fatalf("seats entitlement = %+v, want plan default limit 2", seats)
	}
	support, ok := entitlementByKey(got, "priority_support")
	if !ok || support.Source != store.EntitlementSourceEmergencyAdmin {
		t.Fatalf("priority_support entitlement = %+v, want emergency-only entitlement", support)
	}
}

func TestSubscriptionRepositoryResolveEntitlementsByStatus(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	pricing := store.NewPricingPlanRepository()
	repo := store.NewSubscriptionRepository()
	ctx := context.Background()
	now := time.Date(2026, 5, 19, 11, 0, 0, 0, time.UTC)
	plan := seededPlan(ctx, t, s, pricing, "pro")
	f := testutil.NewFactory(t)

	cases := []struct {
		status  store.SubscriptionStatus
		wantAny bool
	}{
		{store.SubscriptionStatusTrialing, true},
		{store.SubscriptionStatusActive, true},
		{store.SubscriptionStatusPastDue, true},
		{store.SubscriptionStatusCanceled, false},
	}
	for _, tc := range cases {
		t.Run(string(tc.status), func(t *testing.T) {
			org := seedOrg(t, db, f, string(tc.status))
			createSubscriptionOrFail(ctx, t, s, repo, baseSubscriptionInput(org.ID, plan.ID, tc.status, now))
			var got []store.EffectiveEntitlement
			if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
				var err error
				got, err = repo.ResolveEntitlements(ctx, q, org.ID, now)
				return err
			}); err != nil {
				t.Fatalf("ResolveEntitlements(%s): %v", tc.status, err)
			}
			if (len(got) > 0) != tc.wantAny {
				t.Fatalf("ResolveEntitlements(%s) returned %d rows, want any=%v", tc.status, len(got), tc.wantAny)
			}
		})
	}
}

func TestSubscriptionRepositoryTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	pricing := store.NewPricingPlanRepository()
	repo := store.NewSubscriptionRepository()
	ctx := context.Background()
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	plan := seededPlan(ctx, t, s, pricing, "business")
	f := testutil.NewFactory(t)
	orgA := seedOrg(t, db, f, "tenant-a")
	orgB := seedOrg(t, db, f, "tenant-b")
	subA := createSubscriptionOrFail(ctx, t, s, repo, baseSubscriptionInput(orgA.ID, plan.ID, store.SubscriptionStatusActive, now))
	createSubscriptionOrFail(ctx, t, s, repo, baseSubscriptionInput(orgB.ID, plan.ID, store.SubscriptionStatusActive, now))
	upsertSubscriptionEntitlementOrFail(ctx, t, s, repo,
		baseOverrideInput(orgA.ID, subA.ID, "projects", store.EntitlementSourceSubscriptionOverride, 77, now))

	var gotB []store.EffectiveEntitlement
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		gotB, err = repo.ResolveEntitlements(ctx, q, orgB.ID, now)
		return err
	}); err != nil {
		t.Fatalf("ResolveEntitlements(orgB): %v", err)
	}
	projects, ok := entitlementByKey(gotB, "projects")
	if !ok {
		t.Fatalf("orgB entitlements %+v missing plan projects", gotB)
	}
	if projects.LimitValue == nil || *projects.LimitValue == 77 || projects.Source != store.EntitlementSourcePlan {
		t.Fatalf("orgB projects entitlement = %+v, want own plan default without orgA override", projects)
	}
}

func TestSubscriptionRepositoryValidationAndRedaction(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	pricing := store.NewPricingPlanRepository()
	repo := store.NewSubscriptionRepository()
	ctx := context.Background()
	now := time.Date(2026, 5, 19, 13, 0, 0, 0, time.UTC)
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "redaction")
	plan := seededPlan(ctx, t, s, pricing, "enterprise")
	createSubscriptionOrFail(ctx, t, s, repo, baseSubscriptionInput(org.ID, plan.ID, store.SubscriptionStatusActive, now))

	ent := upsertSubscriptionEntitlementOrFail(ctx, t, s, repo, store.UpsertSubscriptionEntitlementInput{
		OrganizationID:  org.ID,
		Source:          store.EntitlementSourceEmergencyAdmin,
		EntitlementKey:  "projects",
		LimitValue:      int64Ptr(10),
		EnforcementMode: store.EnforcementModeHard,
		Reason:          "Authorization: Bearer should_not_persist",
		ActorID:         "usr_test",
		ActorKind:       "user",
		RequestID:       "req_test",
		CorrelationID:   "corr_test",
		EffectiveFrom:   now,
	})
	if ent.Reason == "Authorization: Bearer should_not_persist" || ent.Reason != "Authorization: "+output.Sentinel {
		t.Fatalf("reason redaction = %q, want bearer redacted", ent.Reason)
	}

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.UpsertEntitlement(ctx, tx, store.UpsertSubscriptionEntitlementInput{})
		return err
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
		t.Fatalf("zero override err code = %s, want %s (err=%v)", ye.Code, yerr.CodeValidation, err)
	}
}

func int64Ptr(v int64) *int64 { return &v }
