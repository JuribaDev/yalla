package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func aggregateUsageCountersOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.UsageCounterRepository, in store.AggregateUsageCountersInput) store.UsageCounterAggregationResult {
	t.Helper()
	var result store.UsageCounterAggregationResult
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		result, err = repo.AggregateUsageEvents(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("AggregateUsageEvents(%+v): %v", in, err)
	}
	return result
}

func countUsageCounters(ctx context.Context, t *testing.T, db *testutil.DB, orgID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM usage_counters WHERE organization_id = $1`, orgID).Scan(&count); err != nil {
		t.Fatalf("count usage_counters: %v", err)
	}
	return count
}

func countUsageCounterAdjustments(ctx context.Context, t *testing.T, db *testutil.DB, orgID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM usage_counter_adjustments WHERE organization_id = $1`, orgID).Scan(&count); err != nil {
		t.Fatalf("count usage_counter_adjustments: %v", err)
	}
	return count
}

func TestUsageCounterRepositoryAggregateUsageEventsReplayIsIdempotent(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")
	events := store.NewUsageEventRepository()
	counters := store.NewUsageCounterRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       10,
		Unit:           "request",
		Source:         "traefik",
		IdempotencyKey: "request-window-1",
		OccurredAt:     periodStart.Add(2 * time.Hour),
	})
	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		EventType:      store.UsageEventTypeAdjusted,
		Quantity:       -2.5,
		Unit:           "request",
		Source:         "traefik",
		IdempotencyKey: "request-adjustment-1",
		OccurredAt:     periodStart.Add(3 * time.Hour),
	})

	in := store.AggregateUsageCountersInput{
		OrganizationID:     org.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodStart.Add(24 * time.Hour),
		AggregationVersion: 1,
	}
	first := aggregateUsageCountersOrFail(ctx, t, s, counters, in)
	second := aggregateUsageCountersOrFail(ctx, t, s, counters, in)

	if got := countUsageCounters(ctx, t, db, org.ID); got != 1 {
		t.Fatalf("usage_counters count after replay = %d, want 1", got)
	}
	if len(first.Counters) != 1 || len(second.Counters) != 1 {
		t.Fatalf("aggregate counters lengths first=%d second=%d, want 1 each", len(first.Counters), len(second.Counters))
	}
	if first.Counters[0].ID != second.Counters[0].ID {
		t.Fatalf("replay created counter %q, want existing %q", second.Counters[0].ID, first.Counters[0].ID)
	}
	if first.Counters[0].Key != string(store.QuotaResourceServices) {
		t.Fatalf("counter key = %q, want %q", first.Counters[0].Key, store.QuotaResourceServices)
	}
	if first.Counters[0].Quantity != 7.5 {
		t.Fatalf("counter quantity = %v, want 7.5", first.Counters[0].Quantity)
	}
	if first.Counters[0].Source != "traefik" || first.Counters[0].Unit != "request" {
		t.Fatalf("counter source/unit = %q/%q, want traefik/request", first.Counters[0].Source, first.Counters[0].Unit)
	}
	if first.Counters[0].AggregationVersion != 1 {
		t.Fatalf("counter aggregation_version = %d, want 1", first.Counters[0].AggregationVersion)
	}
	if first.Counters[0].LastAggregatedAt.IsZero() {
		t.Fatal("counter last_aggregated_at was not set")
	}
}

func TestUsageCounterRepositoryLateEventsCreateClosedPeriodAdjustments(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")
	events := store.NewUsageEventRepository()
	counters := store.NewUsageCounterRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceMonthlyDeployments,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       4,
		Unit:           "deployment",
		Source:         "worker",
		IdempotencyKey: "deployments-initial",
		OccurredAt:     periodStart.Add(2 * time.Hour),
	})
	initial := aggregateUsageCountersOrFail(ctx, t, s, counters, store.AggregateUsageCountersInput{
		OrganizationID:     org.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodStart.Add(24 * time.Hour),
		AggregationVersion: 1,
	})
	if len(initial.Adjustments) != 0 {
		t.Fatalf("initial open-period aggregation adjustments = %d, want 0", len(initial.Adjustments))
	}

	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceMonthlyDeployments,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       3,
		Unit:           "deployment",
		Source:         "worker",
		IdempotencyKey: "deployments-late",
		OccurredAt:     periodStart.Add(48 * time.Hour),
	})
	late := aggregateUsageCountersOrFail(ctx, t, s, counters, store.AggregateUsageCountersInput{
		OrganizationID:     org.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodEnd.Add(time.Hour),
		AggregationVersion: 2,
	})
	replay := aggregateUsageCountersOrFail(ctx, t, s, counters, store.AggregateUsageCountersInput{
		OrganizationID:     org.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodEnd.Add(2 * time.Hour),
		AggregationVersion: 2,
	})

	if got := countUsageCounters(ctx, t, db, org.ID); got != 1 {
		t.Fatalf("usage_counters count = %d, want 1 frozen counter", got)
	}
	if got := countUsageCounterAdjustments(ctx, t, db, org.ID); got != 1 {
		t.Fatalf("usage_counter_adjustments count = %d, want 1 late-event adjustment", got)
	}
	if len(late.Adjustments) != 1 {
		t.Fatalf("late aggregation adjustments = %d, want 1", len(late.Adjustments))
	}
	if late.Adjustments[0].DeltaQuantity != 3 {
		t.Fatalf("late adjustment delta = %v, want 3", late.Adjustments[0].DeltaQuantity)
	}
	if len(replay.Adjustments) != 0 {
		t.Fatalf("closed-period replay adjustments = %d, want 0 duplicate adjustments", len(replay.Adjustments))
	}
	if late.Counters[0].Quantity != 4 {
		t.Fatalf("closed counter quantity = %v, want frozen quantity 4", late.Counters[0].Quantity)
	}
	if late.Counters[0].ClosedAt == nil || late.Counters[0].ClosedAt.Before(periodEnd) {
		t.Fatalf("closed counter ClosedAt = %v, want timestamp at or after %v", late.Counters[0].ClosedAt, periodEnd)
	}
}

func TestUsageCounterRepositoryAggregateValidationAndTenantScope(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	counters := store.NewUsageCounterRepository()

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := counters.AggregateUsageEvents(ctx, tx, store.AggregateUsageCountersInput{
			OrganizationID:     "",
			PeriodStart:        time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			PeriodEnd:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			AggregatedAt:       time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC),
			AggregationVersion: 1,
		})
		return err
	})
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != yerr.CodeValidation {
		t.Fatalf("blank org aggregate error = %v (%T), want %s", err, err, yerr.CodeValidation)
	}

	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := counters.AggregateUsageEvents(ctx, tx, store.AggregateUsageCountersInput{
			OrganizationID:     "org_missing",
			PeriodStart:        time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			PeriodEnd:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			AggregatedAt:       time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC),
			AggregationVersion: 1,
		})
		return err
	})
	ye = nil
	if !errors.As(err, &ye) || ye.Code != yerr.CodeNotFound {
		t.Fatalf("missing org aggregate error = %v (%T), want %s", err, err, yerr.CodeNotFound)
	}
}

func TestUsageCounterRepositoryAppliesOveragePolicyModes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		mode     string
		decision string
	}{
		{mode: "allow", decision: "allowed"},
		{mode: "warn", decision: "warned"},
		{mode: "block", decision: "blocked"},
		{mode: "require_admin_review", decision: "admin_review_required"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.mode, func(t *testing.T) {
			t.Parallel()
			db := testutil.RequireMigratedDB(t)
			s := newStore(t, db)
			ctx := context.Background()
			f := testutil.NewFactory(t)
			org := seedOrg(t, db, f, "overage-"+tc.mode)
			pricing := store.NewPricingPlanRepository()
			subs := store.NewSubscriptionRepository()
			events := store.NewUsageEventRepository()
			counters := store.NewUsageCounterRepository()
			periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
			periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
			plan := seededPlan(ctx, t, s, pricing, "pro")
			upsertEntitlementOrFail(ctx, t, s, pricing, store.UpsertPlanEntitlementInput{
				PlanID:          plan.ID,
				EntitlementKey:  string(store.QuotaResourceHTTPRequests),
				LimitValue:      int64Ptr(10),
				EnforcementMode: store.EnforcementModeMetered,
				Metadata:        []byte(`{"unit":"request","overage_behavior":"` + tc.mode + `"}`),
			})
			createSubscriptionOrFail(ctx, t, s, subs, store.CreateSubscriptionInput{
				OrganizationID:     org.ID,
				PlanID:             plan.ID,
				Status:             store.SubscriptionStatusActive,
				CurrentPeriodStart: periodStart,
				CurrentPeriodEnd:   periodEnd,
				Provider:           "manual",
			})
			appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
				OrganizationID: org.ID,
				Resource:       store.QuotaResourceHTTPRequests,
				EventType:      store.UsageEventTypeConsumed,
				Quantity:       14,
				Unit:           "request",
				Source:         "traefik",
				IdempotencyKey: "overage-" + tc.mode,
				OccurredAt:     periodStart.Add(time.Hour),
			})

			result := aggregateUsageCountersOrFail(ctx, t, s, counters, store.AggregateUsageCountersInput{
				OrganizationID:     org.ID,
				PeriodStart:        periodStart,
				PeriodEnd:          periodEnd,
				AggregatedAt:       periodEnd.Add(time.Hour),
				AggregationVersion: 1,
				RequestID:          "req_overage_" + tc.mode,
				CorrelationID:      "corr_overage_" + tc.mode,
			})
			if len(result.Counters) != 1 {
				t.Fatalf("counters = %d, want 1", len(result.Counters))
			}
			counter := result.Counters[0]
			if counter.EntitlementKey == nil || *counter.EntitlementKey != string(store.QuotaResourceHTTPRequests) {
				t.Fatalf("entitlement_key = %v, want http_requests", counter.EntitlementKey)
			}
			if counter.OveragePolicyMode == nil || *counter.OveragePolicyMode != tc.mode {
				t.Fatalf("overage_policy_mode = %v, want %s", counter.OveragePolicyMode, tc.mode)
			}
			if counter.OverageDecision == nil || *counter.OverageDecision != tc.decision {
				t.Fatalf("overage_decision = %v, want %s", counter.OverageDecision, tc.decision)
			}
			if counter.IncludedQuantity == nil || *counter.IncludedQuantity != 10 {
				t.Fatalf("included_quantity = %v, want 10", counter.IncludedQuantity)
			}
			if counter.OverageQuantity == nil || *counter.OverageQuantity != 4 {
				t.Fatalf("overage_quantity = %v, want 4", counter.OverageQuantity)
			}

			var auditCount int
			err := db.QueryRow(ctx,
				`SELECT count(*)
				   FROM audit_events
				  WHERE organization_id = $1
				    AND action = 'usage.overage.evaluate'
				    AND resource_id = $2
				    AND request_id = $3
				    AND correlation_id = $4
				    AND metadata->>'overage_policy_mode' = $5
				    AND metadata->>'overage_decision' = $6`,
				org.ID, counter.ID, "req_overage_"+tc.mode, "corr_overage_"+tc.mode, tc.mode, tc.decision,
			).Scan(&auditCount)
			if err != nil {
				t.Fatalf("count overage audit events: %v", err)
			}
			if auditCount != 1 {
				t.Fatalf("overage audit events = %d, want 1", auditCount)
			}
		})
	}
}

func TestUsageCounterRepositoryAggregateRollsBackOnPartialFailure(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")
	events := store.NewUsageEventRepository()
	counters := store.NewUsageCounterRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       1,
		Unit:           "request",
		Source:         "traefik",
		IdempotencyKey: "rollback-window",
		OccurredAt:     periodStart.Add(time.Hour),
	})

	sentinel := errors.New("fail after aggregation")
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		if _, err := counters.AggregateUsageEvents(ctx, tx, store.AggregateUsageCountersInput{
			OrganizationID:     org.ID,
			PeriodStart:        periodStart,
			PeriodEnd:          periodEnd,
			AggregatedAt:       periodStart.Add(2 * time.Hour),
			AggregationVersion: 1,
		}); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Write error = %v, want sentinel", err)
	}
	if got := countUsageCounters(ctx, t, db, org.ID); got != 0 {
		t.Fatalf("usage_counters after rolled-back aggregation = %d, want 0", got)
	}
}

func TestUsageCounterRepositoryConcurrentAggregatorsCreateOneCounter(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "Acme")
	events := store.NewUsageEventRepository()
	counters := store.NewUsageCounterRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceServices,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       5,
		Unit:           "request",
		Source:         "traefik",
		IdempotencyKey: "concurrent-window",
		OccurredAt:     periodStart.Add(time.Hour),
	})

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
				_, err := counters.AggregateUsageEvents(ctx, tx, store.AggregateUsageCountersInput{
					OrganizationID:     org.ID,
					PeriodStart:        periodStart,
					PeriodEnd:          periodEnd,
					AggregatedAt:       periodStart.Add(2 * time.Hour),
					AggregationVersion: 1,
				})
				return err
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent AggregateUsageEvents returned %v", err)
		}
	}
	if got := countUsageCounters(ctx, t, db, org.ID); got != 1 {
		t.Fatalf("usage_counters after concurrent aggregators = %d, want 1", got)
	}
	var quantity float64
	if err := db.QueryRow(ctx, `SELECT quantity FROM usage_counters WHERE organization_id = $1`, org.ID).Scan(&quantity); err != nil {
		t.Fatalf("read counter quantity: %v", err)
	}
	if quantity != 5 {
		t.Fatalf("counter quantity = %v, want 5", quantity)
	}
}
