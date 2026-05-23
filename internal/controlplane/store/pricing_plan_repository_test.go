package store_test

import (
	"context"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func createPlanOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.PricingPlanRepository, in store.CreatePlanInput) store.Plan {
	t.Helper()
	var plan store.Plan
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		plan, err = repo.Create(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("Create(%+v): %v", in, err)
	}
	return plan
}

func upsertEntitlementOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.PricingPlanRepository, in store.UpsertPlanEntitlementInput) store.PlanEntitlement {
	t.Helper()
	var ent store.PlanEntitlement
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		ent, err = repo.UpsertEntitlement(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("UpsertEntitlement(%+v): %v", in, err)
	}
	return ent
}

func getPlanOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.PricingPlanRepository, id string) store.Plan {
	t.Helper()
	var plan store.Plan
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		plan, err = repo.Get(ctx, q, id)
		return err
	}); err != nil {
		t.Fatalf("Get(%q): %v", id, err)
	}
	return plan
}

func listEntitlementsOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.PricingPlanRepository, planID string) []store.PlanEntitlement {
	t.Helper()
	var ents []store.PlanEntitlement
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		ents, err = repo.ListEntitlements(ctx, q, planID)
		return err
	}); err != nil {
		t.Fatalf("ListEntitlements(%q): %v", planID, err)
	}
	return ents
}

func TestPricingPlanRepositoryCreateUpdateArchiveAndVersioning(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPricingPlanRepository()
	ctx := context.Background()

	plan := createPlanOrFail(ctx, t, s, repo, store.CreatePlanInput{
		Slug:          "growth",
		Name:          "Growth",
		Status:        store.PlanStatusActive,
		BillingPeriod: store.BillingPeriodAnnual,
		DisplayOrder:  15,
		Version:       1,
	})
	if plan.ID == "" || plan.Version != 1 || plan.Status != store.PlanStatusActive || plan.ArchivedAt != nil {
		t.Fatalf("created plan = %+v, want active version 1 with id and no archive stamp", plan)
	}

	limit := int64(10)
	ent := upsertEntitlementOrFail(ctx, t, s, repo, store.UpsertPlanEntitlementInput{
		PlanID:          plan.ID,
		EntitlementKey:  "projects",
		LimitValue:      &limit,
		EnforcementMode: store.EnforcementModeHard,
	})
	if ent.ID == "" || ent.PlanID != plan.ID || ent.LimitValue == nil || *ent.LimitValue != 10 {
		t.Fatalf("upserted entitlement = %+v, want plan-bound hard projects limit", ent)
	}

	var next store.Plan
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		next, err = repo.Update(ctx, tx, plan.ID, store.UpdatePlanInput{
			Name:         "Growth Plus",
			Status:       store.PlanStatusActive,
			DisplayOrder: 16,
		})
		return err
	}); err != nil {
		t.Fatalf("Update(%q): %v", plan.ID, err)
	}
	if next.ID == plan.ID || next.Slug != plan.Slug || next.Version != 2 || next.Name != "Growth Plus" {
		t.Fatalf("updated plan = %+v, want new version 2 for same slug", next)
	}

	old := getPlanOrFail(ctx, t, s, repo, plan.ID)
	if old.Status != store.PlanStatusArchived || old.ArchivedAt == nil {
		t.Fatalf("old plan after update = %+v, want archived with archived_at", old)
	}
	cloned := listEntitlementsOrFail(ctx, t, s, repo, next.ID)
	if len(cloned) != 1 || cloned[0].EntitlementKey != "projects" || cloned[0].LimitValue == nil || *cloned[0].LimitValue != 10 {
		t.Fatalf("cloned entitlements = %+v, want projects limit cloned to new plan version", cloned)
	}

	var archived store.Plan
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		archived, err = repo.Archive(ctx, tx, next.ID)
		return err
	}); err != nil {
		t.Fatalf("Archive(%q): %v", next.ID, err)
	}
	if archived.Status != store.PlanStatusArchived || archived.ArchivedAt == nil {
		t.Fatalf("Archive returned %+v, want archived", archived)
	}
}

func TestPricingPlanRepositoryListActiveUsesStableOrder(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPricingPlanRepository()
	ctx := context.Background()

	var plans []store.Plan
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		plans, err = repo.ListActive(ctx, q)
		return err
	}); err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if len(plans) < 4 {
		t.Fatalf("ListActive returned %d plans, want at least seeded four", len(plans))
	}
	got := []string{plans[0].Slug, plans[1].Slug, plans[2].Slug, plans[3].Slug}
	want := []string{"starter", "pro", "business", "enterprise"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("first seeded active slugs = %v, want %v", got, want)
		}
	}
}

func TestPricingPlanRepositoryUniquenessAndNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewPricingPlanRepository()
	ctx := context.Background()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Create(ctx, tx, store.CreatePlanInput{
			Slug:          "starter",
			Name:          "Starter Duplicate",
			Status:        store.PlanStatusActive,
			BillingPeriod: store.BillingPeriodMonthly,
			DisplayOrder:  12,
			Version:       2,
		})
		return err
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("duplicate active starter err code = %s, want %s (err=%v)", ye.Code, yerr.CodeConflict, err)
	}

	createPlanOrFail(ctx, t, s, repo, store.CreatePlanInput{
		Slug:          "starter",
		Name:          "Starter Annual",
		Status:        store.PlanStatusActive,
		BillingPeriod: store.BillingPeriodAnnual,
		DisplayOrder:  13,
		Version:       1,
	})

	err = s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, "plan_missing")
		return err
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("missing Get err code = %s, want %s (err=%v)", ye.Code, yerr.CodeNotFound, err)
	}

	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Update(ctx, tx, "plan_missing", store.UpdatePlanInput{
			Name:         "Missing",
			Status:       store.PlanStatusActive,
			DisplayOrder: 1,
		})
		return err
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("missing Update err code = %s, want %s (err=%v)", ye.Code, yerr.CodeNotFound, err)
	}
}
