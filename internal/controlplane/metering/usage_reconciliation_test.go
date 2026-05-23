package metering_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/metering"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestUsageReconcilerReplayRepairsCountersIdempotently(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	ctx := context.Background()
	seed := seedMeteringHierarchy(t, db, testutil.NewFactory(t))
	events := store.NewUsageEventRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	appendUsageEventForReconcile(t, ctx, s, events, seed, store.QuotaResourceHTTPRequests, 10, "request", "traefik", "req-window-a", periodStart, periodStart.Add(time.Hour))
	appendUsageEventForReconcile(t, ctx, s, events, seed, store.QuotaResourceHTTPRequests, 5, "request", "traefik", "req-window-b", periodStart.Add(time.Hour), periodStart.Add(2*time.Hour))

	reconciler, err := metering.NewUsageReconciler(s)
	if err != nil {
		t.Fatalf("NewUsageReconciler: %v", err)
	}
	input := metering.ReconcileUsageInput{
		OrganizationID:     seed.OrganizationID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodStart.Add(3 * time.Hour),
		AggregationVersion: 1,
		ExpectedMetrics: []metering.ExpectedUsageMetric{{
			Key:    string(store.QuotaResourceHTTPRequests),
			Unit:   "request",
			Source: "traefik",
		}},
		RequestID:     "req_usage_reconcile",
		CorrelationID: "corr_usage_reconcile",
	}
	first, err := reconciler.Reconcile(ctx, input)
	if err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if len(first.Counters) != 1 || first.Counters[0].Quantity != 15 {
		t.Fatalf("first counters = %+v, want one repaired quantity 15", first.Counters)
	}
	if len(first.Adjustments) != 0 || len(first.Findings) != 0 || len(first.Issues) != 0 {
		t.Fatalf("first result adjustments/findings/issues = %d/%d/%d, want clean replay", len(first.Adjustments), len(first.Findings), len(first.Issues))
	}

	if _, err := db.Exec(ctx,
		`UPDATE usage_counters
		    SET quantity = 7,
		        aggregation_version = 99,
		        last_aggregated_at = $2
		  WHERE organization_id = $1`,
		seed.OrganizationID, periodStart.Add(4*time.Hour)); err != nil {
		t.Fatalf("corrupt usage counter: %v", err)
	}
	second, err := reconciler.Reconcile(ctx, input)
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	third, err := reconciler.Reconcile(ctx, input)
	if err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	if len(second.Counters) != 1 || second.Counters[0].Quantity != 15 {
		t.Fatalf("second counters = %+v, want repaired quantity 15", second.Counters)
	}
	if len(third.Counters) != 1 || third.Counters[0].ID != second.Counters[0].ID || third.Counters[0].Quantity != 15 {
		t.Fatalf("third counters = %+v, want idempotent replay of %q", third.Counters, second.Counters[0].ID)
	}
	if got := countUsageCounterAdjustmentsForReconcile(t, db, seed.OrganizationID); got != 0 {
		t.Fatalf("usage_counter_adjustments = %d, want 0 for open-period repair", got)
	}
}

func TestUsageReconcilerDetectsMetricGapsAndQuarantinedSamples(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	ctx := context.Background()
	seed := seedMeteringHierarchy(t, db, testutil.NewFactory(t))
	events := store.NewUsageEventRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 5, 1, 4, 0, 0, 0, time.UTC)

	appendUsageEventForReconcile(t, ctx, s, events, seed, store.QuotaResourceHTTPRequests, 1, "request", "traefik", "gap-window-a", periodStart, periodStart.Add(time.Hour))
	appendUsageEventForReconcile(t, ctx, s, events, seed, store.QuotaResourceHTTPRequests, 1, "request", "traefik", "gap-window-b", periodStart.Add(3*time.Hour), periodEnd)

	reconciler, err := metering.NewUsageReconciler(s)
	if err != nil {
		t.Fatalf("NewUsageReconciler: %v", err)
	}
	result, err := reconciler.Reconcile(ctx, metering.ReconcileUsageInput{
		OrganizationID:     seed.OrganizationID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodEnd.Add(time.Hour),
		AggregationVersion: 1,
		ExpectedMetrics: []metering.ExpectedUsageMetric{{
			Key:    string(store.QuotaResourceHTTPRequests),
			Unit:   "request",
			Source: "traefik",
		}},
		QuarantinedSamples: []metering.QuarantinedUsageSample{{
			Key:       string(store.QuotaResourceHTTPRequests),
			Unit:      "request",
			Source:    "traefik",
			Reason:    "missing_attribution",
			WindowEnd: periodStart.Add(2 * time.Hour),
		}},
		RequestID:     "req_usage_gap",
		CorrelationID: "corr_usage_gap",
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(result.Issues) != 2 {
		t.Fatalf("issues = %+v, want metric_gap and quarantined_sample", result.Issues)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %+v, want one finding per low-confidence issue", result.Findings)
	}
	assertDriftFindingCountForReconcile(t, db, seed.OrganizationID, 2)
}

func TestUsageReconcilerDetectsDuplicateWindowsAndCounterResets(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	ctx := context.Background()
	seed := seedMeteringHierarchy(t, db, testutil.NewFactory(t))
	events := store.NewUsageEventRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	appendUsageEventWithMetadataForReconcile(t, ctx, s, events, seed, store.QuotaResourceHTTPRequests, 10, "request", "traefik", "overlap-window-a", periodStart, periodStart.Add(2*time.Hour), map[string]string{
		"counter_start": "100",
		"counter_end":   "110",
	})
	appendUsageEventWithMetadataForReconcile(t, ctx, s, events, seed, store.QuotaResourceHTTPRequests, 8, "request", "traefik", "overlap-window-b", periodStart.Add(time.Hour), periodStart.Add(3*time.Hour), map[string]string{
		"counter_start": "110",
		"counter_end":   "90",
	})

	reconciler, err := metering.NewUsageReconciler(s)
	if err != nil {
		t.Fatalf("NewUsageReconciler: %v", err)
	}
	result, err := reconciler.Reconcile(ctx, metering.ReconcileUsageInput{
		OrganizationID:     seed.OrganizationID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodStart.Add(4 * time.Hour),
		AggregationVersion: 1,
		ExpectedMetrics: []metering.ExpectedUsageMetric{{
			Key:    string(store.QuotaResourceHTTPRequests),
			Unit:   "request",
			Source: "traefik",
		}},
		RequestID:     "req_usage_overlap_reset",
		CorrelationID: "corr_usage_overlap_reset",
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(result.Issues) != 2 {
		t.Fatalf("issues = %+v, want duplicate_aggregation and counter_reset", result.Issues)
	}
	types := map[string]bool{}
	for _, issue := range result.Issues {
		types[issue.Type] = true
	}
	if !types["duplicate_aggregation"] || !types["counter_reset"] {
		t.Fatalf("issue types = %+v, want duplicate_aggregation and counter_reset", types)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %+v, want one finding per issue", result.Findings)
	}
}

func TestUsageReconcilerClosedPeriodReplayCreatesOneLateAdjustment(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	ctx := context.Background()
	seed := seedMeteringHierarchy(t, db, testutil.NewFactory(t))
	events := store.NewUsageEventRepository()
	reconciler, err := metering.NewUsageReconciler(s)
	if err != nil {
		t.Fatalf("NewUsageReconciler: %v", err)
	}
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	appendUsageEventForReconcile(t, ctx, s, events, seed, store.QuotaResourceDeployments, 4, "deployment", "worker", "closed-initial", periodStart, periodStart.Add(time.Hour))
	input := metering.ReconcileUsageInput{
		OrganizationID:     seed.OrganizationID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodEnd.Add(time.Hour),
		AggregationVersion: 1,
		RequestID:          "req_usage_closed",
		CorrelationID:      "corr_usage_closed",
	}
	initial, err := reconciler.Reconcile(ctx, input)
	if err != nil {
		t.Fatalf("initial Reconcile: %v", err)
	}
	if len(initial.Adjustments) != 0 {
		t.Fatalf("initial adjustments = %+v, want none", initial.Adjustments)
	}

	appendUsageEventForReconcile(t, ctx, s, events, seed, store.QuotaResourceDeployments, 3, "deployment", "worker", "closed-late", periodStart.Add(24*time.Hour), periodStart.Add(25*time.Hour))
	late, err := reconciler.Reconcile(ctx, input)
	if err != nil {
		t.Fatalf("late Reconcile: %v", err)
	}
	replay, err := reconciler.Reconcile(ctx, input)
	if err != nil {
		t.Fatalf("replay Reconcile: %v", err)
	}
	if len(late.Adjustments) != 1 || late.Adjustments[0].DeltaQuantity != 3 {
		t.Fatalf("late adjustments = %+v, want one delta 3", late.Adjustments)
	}
	if len(replay.Adjustments) != 0 {
		t.Fatalf("replay adjustments = %+v, want no duplicate adjustment", replay.Adjustments)
	}
	if got := countUsageCounterAdjustmentsForReconcile(t, db, seed.OrganizationID); got != 1 {
		t.Fatalf("usage_counter_adjustments = %d, want 1", got)
	}
}

func TestUsageReconcilerValidationAndTenantScope(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	ctx := context.Background()
	reconciler, err := metering.NewUsageReconciler(s)
	if err != nil {
		t.Fatalf("NewUsageReconciler: %v", err)
	}

	_, err = reconciler.Reconcile(ctx, metering.ReconcileUsageInput{})
	assertYallaCode(t, err, yerr.CodeValidation)

	_, err = reconciler.Reconcile(ctx, metering.ReconcileUsageInput{
		OrganizationID:     "org_missing",
		PeriodStart:        time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		AggregatedAt:       time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC),
		AggregationVersion: 1,
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
}

func appendUsageEventForReconcile(t *testing.T, ctx context.Context, s *store.Store, repo *store.UsageEventRepository, seed meteringSeed, resource store.QuotaResource, quantity float64, unit, source, idempotencyKey string, windowStart, windowEnd time.Time) {
	t.Helper()
	appendUsageEventWithMetadataForReconcile(t, ctx, s, repo, seed, resource, quantity, unit, source, idempotencyKey, windowStart, windowEnd, nil)
}

func appendUsageEventWithMetadataForReconcile(t *testing.T, ctx context.Context, s *store.Store, repo *store.UsageEventRepository, seed meteringSeed, resource store.QuotaResource, quantity float64, unit, source, idempotencyKey string, windowStart, windowEnd time.Time, extra map[string]string) {
	t.Helper()
	metadata := map[string]string{
		"window_start": windowStart.UTC().Format(time.RFC3339Nano),
		"window_end":   windowEnd.UTC().Format(time.RFC3339Nano),
	}
	for key, value := range extra {
		metadata[key] = value
	}
	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Append(ctx, tx, store.AppendUsageEventInput{
			OrganizationID: seed.OrganizationID,
			ProjectID:      seed.ProjectID,
			EnvironmentID:  seed.EnvironmentID,
			ServiceID:      seed.ServiceID,
			Resource:       resource,
			EventType:      store.UsageEventTypeConsumed,
			Quantity:       quantity,
			Unit:           unit,
			Source:         source,
			IdempotencyKey: idempotencyKey,
			RequestID:      "req_" + idempotencyKey,
			Metadata:       metadata,
			OccurredAt:     windowEnd.Add(-time.Nanosecond),
		})
		return err
	})
	if err != nil {
		t.Fatalf("append usage event %s: %v", idempotencyKey, err)
	}
}

func countUsageCounterAdjustmentsForReconcile(t *testing.T, db *testutil.DB, orgID string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM usage_counter_adjustments WHERE organization_id = $1`, orgID).Scan(&count); err != nil {
		t.Fatalf("count usage_counter_adjustments: %v", err)
	}
	return count
}

func assertDriftFindingCountForReconcile(t *testing.T, db *testutil.DB, orgID string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM drift_findings WHERE organization_id = $1`, orgID).Scan(&got); err != nil {
		t.Fatalf("count drift_findings: %v", err)
	}
	if got != want {
		t.Fatalf("drift_findings for %s = %d, want %d", orgID, got, want)
	}
}
