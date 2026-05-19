package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

func appendUsageEventOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.UsageEventRepository, in store.AppendUsageEventInput) store.UsageEvent {
	t.Helper()
	var event store.UsageEvent
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		event, err = repo.Append(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("Append(%+v): %v", in, err)
	}
	return event
}

func countUsageEventsByOrg(ctx context.Context, t *testing.T, db *testutil.DB, orgID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM usage_events WHERE organization_id = $1`, orgID).Scan(&count); err != nil {
		t.Fatalf("count usage_events: %v", err)
	}
	return count
}

func TestUsageEventRepositoryAppendIdempotentRedactedAndPeriodAssigned(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")
	project := seedProject(t, db, f, org, "App")
	env := seedEnvironment(t, db, f, project, "Prod")
	svc := seedService(t, db, f, env, "Web")

	plan := createPlanOrFail(ctx, t, s, store.NewPricingPlanRepository(), store.CreatePlanInput{
		Slug:          "metered",
		Name:          "Metered",
		Status:        store.PlanStatusActive,
		BillingPeriod: store.BillingPeriodMonthly,
		DisplayOrder:  50,
		Version:       1,
	})
	periodStart := time.Date(2026, 5, 5, 8, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 5, 8, 0, 0, 0, time.UTC)
	createSubscriptionOrFail(ctx, t, s, store.NewSubscriptionRepository(), store.CreateSubscriptionInput{
		OrganizationID:     org.ID,
		PlanID:             plan.ID,
		Status:             store.SubscriptionStatusActive,
		CurrentPeriodStart: periodStart,
		CurrentPeriodEnd:   periodEnd,
		Provider:           "manual",
	})

	repo := store.NewUsageEventRepository()
	in := store.AppendUsageEventInput{
		OrganizationID: org.ID,
		ProjectID:      project.ID,
		EnvironmentID:  env.ID,
		ServiceID:      svc.ID,
		Resource:       store.QuotaResourceServices,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       42.5,
		Unit:           "request",
		Source:         "traefik",
		IdempotencyKey: "traefik:svc-window-1",
		OccurredAt:     time.Date(2026, 5, 19, 12, 34, 0, 0, time.UTC),
		Metadata: map[string]string{
			"upstream_request": "Authorization: Bearer yk_live_secret_token",
			"api_key":          "yk_live_secret_token",
			"route":            "/healthz?token=yk_live_secret_token",
		},
	}

	first := appendUsageEventOrFail(ctx, t, s, repo, in)
	second := appendUsageEventOrFail(ctx, t, s, repo, in)

	if first.ID == "" {
		t.Fatal("Append returned empty id")
	}
	if second.ID != first.ID {
		t.Fatalf("idempotent Append returned id %q, want existing id %q", second.ID, first.ID)
	}
	if got := countUsageEventsByOrg(ctx, t, db, org.ID); got != 1 {
		t.Fatalf("usage_events count = %d, want 1 for duplicate idempotency key", got)
	}
	if first.PeriodStart == nil || !first.PeriodStart.Equal(periodStart) {
		t.Fatalf("PeriodStart = %v, want subscription period start %v", first.PeriodStart, periodStart)
	}
	if first.PeriodEnd == nil || !first.PeriodEnd.Equal(periodEnd) {
		t.Fatalf("PeriodEnd = %v, want subscription period end %v", first.PeriodEnd, periodEnd)
	}
	if first.Metadata["upstream_request"] != "Authorization: "+output.Sentinel {
		t.Fatalf("upstream_request metadata = %q, want redacted bearer value", first.Metadata["upstream_request"])
	}
	if first.Metadata["api_key"] != output.Sentinel {
		t.Fatalf("api_key metadata = %q, want sentinel for secret-shaped key", first.Metadata["api_key"])
	}
	if strings.Contains(first.Metadata["route"], "yk_live_secret_token") {
		t.Fatalf("route metadata leaked token: %q", first.Metadata["route"])
	}
}

func TestUsageEventRepositoryAppendAdjustmentAllowsNegativeQuantity(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")
	repo := store.NewUsageEventRepository()

	event := appendUsageEventOrFail(ctx, t, s, repo, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceMonthlyDeployments,
		EventType:      store.UsageEventTypeAdjusted,
		Quantity:       -3,
		Unit:           "deployment",
		Source:         "reconciliation",
		IdempotencyKey: "adjustment:deployments:1",
		OccurredAt:     time.Date(2026, 5, 19, 1, 2, 3, 0, time.UTC),
		Metadata:       map[string]string{"reason": "late duplicate window"},
	})

	if event.EventType != store.UsageEventTypeAdjusted {
		t.Fatalf("EventType = %q, want adjusted", event.EventType)
	}
	if event.Quantity != -3 {
		t.Fatalf("Quantity = %v, want -3", event.Quantity)
	}
	if event.PeriodStart == nil || event.PeriodEnd == nil {
		t.Fatal("calendar fallback period was not assigned")
	}
	if !event.PeriodStart.Equal(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("fallback PeriodStart = %v, want calendar month start", event.PeriodStart)
	}
}

func TestUsageEventRepositoryAppendValidationAndTenantScope(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	orgA := seedOrg(t, db, f, "Acme")
	orgB := seedOrg(t, db, f, "Beta")
	projB := seedProject(t, db, f, orgB, "Other")

	repo := store.NewUsageEventRepository()
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Append(ctx, tx, store.AppendUsageEventInput{
			OrganizationID: orgA.ID,
			ProjectID:      projB.ID,
			Resource:       store.QuotaResourceServices,
			EventType:      store.UsageEventTypeConsumed,
			Quantity:       1,
			Unit:           "request",
			Source:         "traefik",
			IdempotencyKey: "cross-tenant-project",
			OccurredAt:     time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC),
		})
		return err
	})
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant project error = %v (%T), want %s", err, err, yerr.CodeNotFound)
	}
	if got := countUsageEventsByOrg(ctx, t, db, orgA.ID); got != 0 {
		t.Fatalf("orgA usage_events after failed scoped append = %d, want 0", got)
	}

	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Append(ctx, tx, store.AppendUsageEventInput{
			OrganizationID: orgA.ID,
			Resource:       store.QuotaResourceServices,
			EventType:      store.UsageEventTypeConsumed,
			Quantity:       -1,
			Unit:           "request",
			Source:         "traefik",
			IdempotencyKey: "negative-consumed",
			OccurredAt:     time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC),
		})
		return err
	})
	ye = nil
	if !errors.As(err, &ye) || ye.Code != yerr.CodeValidation {
		t.Fatalf("negative consumed error = %v (%T), want %s", err, err, yerr.CodeValidation)
	}
}

func TestUsageEventsRejectUpdateAtDatabaseLevel(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")
	repo := store.NewUsageEventRepository()

	event := appendUsageEventOrFail(ctx, t, s, repo, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       1,
		Unit:           "request",
		Source:         "test",
		IdempotencyKey: "append-only",
		OccurredAt:     time.Date(2026, 5, 19, 0, 0, 0, 0, time.UTC),
	})

	if _, err := db.Exec(ctx, `UPDATE usage_events SET quantity = 2 WHERE id = $1`, event.ID); err == nil {
		t.Fatal("UPDATE usage_events succeeded, want append-only trigger rejection")
	}
}
