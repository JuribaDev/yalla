package store_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	"github.com/JuribaDev/yalla/internal/output"
)

func prepareBillingExportOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.BillingExportRepository, in store.PrepareBillingExportInput) store.BillingExport {
	t.Helper()
	var export store.BillingExport
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		export, err = repo.Prepare(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("Prepare billing export: %v", err)
	}
	return export
}

func markBillingExportSucceededOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.BillingExportRepository, in store.MarkBillingExportSucceededInput) store.BillingExport {
	t.Helper()
	var export store.BillingExport
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		export, err = repo.MarkSucceeded(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("MarkSucceeded billing export: %v", err)
	}
	return export
}

func markBillingExportFailedOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.BillingExportRepository, in store.MarkBillingExportFailedInput) store.BillingExport {
	t.Helper()
	var export store.BillingExport
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		export, err = repo.MarkFailed(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("MarkFailed billing export: %v", err)
	}
	return export
}

func TestBillingExportRepositoryPrepareSnapshotsCountersAndMarksSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "billing-export")
	pricing := store.NewPricingPlanRepository()
	subs := store.NewSubscriptionRepository()
	events := store.NewUsageEventRepository()
	counters := store.NewUsageCounterRepository()
	exports := store.NewBillingExportRepository()
	now := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	plan := seededPlan(ctx, t, s, pricing, "pro")
	sub := createSubscriptionOrFail(ctx, t, s, subs, store.CreateSubscriptionInput{
		OrganizationID:     org.ID,
		PlanID:             plan.ID,
		Status:             store.SubscriptionStatusActive,
		CurrentPeriodStart: periodStart,
		CurrentPeriodEnd:   periodEnd,
		Provider:           "stripe_main",
	})

	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceHTTPRequests,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       42,
		Unit:           "request",
		Source:         "traefik",
		IdempotencyKey: "billing-export-requests",
		OccurredAt:     periodStart.Add(time.Hour),
	})
	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceBuildMinutes,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       7.5,
		Unit:           "minute",
		Source:         "yalla_jobs",
		IdempotencyKey: "billing-export-build",
		OccurredAt:     periodStart.Add(2 * time.Hour),
	})
	aggregateUsageCountersOrFail(ctx, t, s, counters, store.AggregateUsageCountersInput{
		OrganizationID:     org.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodEnd.Add(time.Hour),
		AggregationVersion: 1,
	})

	prepared := prepareBillingExportOrFail(ctx, t, s, exports, store.PrepareBillingExportInput{
		OrganizationID: org.ID,
		SubscriptionID: sub.ID,
		Provider:       sub.Provider,
		PeriodStart:    periodStart,
		PeriodEnd:      periodEnd,
		RequestedAt:    now,
	})
	if prepared.Status != store.BillingExportStatusPending {
		t.Fatalf("prepared status = %q, want pending", prepared.Status)
	}
	if prepared.OrganizationID != org.ID || prepared.SubscriptionID != sub.ID || prepared.Provider != "stripe_main" {
		t.Fatalf("prepared scope = %+v, want org/sub/provider", prepared)
	}
	if len(prepared.Items) != 2 {
		t.Fatalf("prepared items = %d, want 2: %+v", len(prepared.Items), prepared.Items)
	}
	if prepared.Items[0].Key != string(store.QuotaResourceBuildMinutes) || prepared.Items[0].Quantity != 7.5 {
		t.Fatalf("first item = %+v, want build_minutes 7.5", prepared.Items[0])
	}
	if prepared.Items[1].Key != string(store.QuotaResourceHTTPRequests) || prepared.Items[1].Quantity != 42 {
		t.Fatalf("second item = %+v, want http_requests 42", prepared.Items[1])
	}

	succeeded := markBillingExportSucceededOrFail(ctx, t, s, exports, store.MarkBillingExportSucceededInput{
		OrganizationID:     org.ID,
		ExportID:           prepared.ID,
		ProviderResponseID: "in_123456789",
		ExportedAt:         now.Add(time.Minute),
	})
	if succeeded.Status != store.BillingExportStatusSucceeded {
		t.Fatalf("succeeded status = %q, want succeeded", succeeded.Status)
	}
	if succeeded.ProviderResponseID == nil || *succeeded.ProviderResponseID != "in_123456789" {
		t.Fatalf("provider response id = %v, want in_123456789", succeeded.ProviderResponseID)
	}
	if succeeded.ExportedAt == nil || !succeeded.ExportedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("exported_at = %v, want %v", succeeded.ExportedAt, now.Add(time.Minute))
	}
}

func TestBillingExportRepositoryPrepareIsIdempotentForDuplicateGroup(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "billing-export-duplicate")
	pricing := store.NewPricingPlanRepository()
	subs := store.NewSubscriptionRepository()
	exports := store.NewBillingExportRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	plan := seededPlan(ctx, t, s, pricing, "starter")
	sub := createSubscriptionOrFail(ctx, t, s, subs, store.CreateSubscriptionInput{
		OrganizationID:     org.ID,
		PlanID:             plan.ID,
		Status:             store.SubscriptionStatusActive,
		CurrentPeriodStart: periodStart,
		CurrentPeriodEnd:   periodEnd,
		Provider:           "manual",
	})
	in := store.PrepareBillingExportInput{
		OrganizationID: org.ID,
		SubscriptionID: sub.ID,
		Provider:       "manual",
		PeriodStart:    periodStart,
		PeriodEnd:      periodEnd,
		RequestedAt:    time.Date(2026, 5, 19, 11, 0, 0, 0, time.UTC),
	}

	first := prepareBillingExportOrFail(ctx, t, s, exports, in)
	second := prepareBillingExportOrFail(ctx, t, s, exports, in)
	if first.ID != second.ID {
		t.Fatalf("duplicate prepare created export %q, want existing %q", second.ID, first.ID)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM billing_exports WHERE organization_id = $1`, org.ID).Scan(&count); err != nil {
		t.Fatalf("count billing_exports: %v", err)
	}
	if count != 1 {
		t.Fatalf("billing_exports count = %d, want 1", count)
	}
}

func TestBillingExportRepositoryFailureBackoffAndRedactedLogValue(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "billing-export-failed")
	pricing := store.NewPricingPlanRepository()
	subs := store.NewSubscriptionRepository()
	exports := store.NewBillingExportRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	secret := "sk_live_secret_billing_export"
	plan := seededPlan(ctx, t, s, pricing, "business")
	sub := createSubscriptionOrFail(ctx, t, s, subs, store.CreateSubscriptionInput{
		OrganizationID:     org.ID,
		PlanID:             plan.ID,
		Status:             store.SubscriptionStatusPastDue,
		CurrentPeriodStart: periodStart,
		CurrentPeriodEnd:   periodEnd,
		Provider:           "stripe_main",
	})
	prepared := prepareBillingExportOrFail(ctx, t, s, exports, store.PrepareBillingExportInput{
		OrganizationID: org.ID,
		SubscriptionID: sub.ID,
		Provider:       sub.Provider,
		PeriodStart:    periodStart,
		PeriodEnd:      periodEnd,
		RequestedAt:    now,
	})

	failed := markBillingExportFailedOrFail(ctx, t, s, exports, store.MarkBillingExportFailedInput{
		OrganizationID: org.ID,
		ExportID:       prepared.ID,
		FailedAt:       now.Add(time.Minute),
		RetryAfter:     15 * time.Minute,
		ErrorSummary:   "stripe rejected Authorization: Bearer " + secret,
	})
	if failed.Status != store.BillingExportStatusFailed {
		t.Fatalf("failed status = %q, want failed", failed.Status)
	}
	if failed.AttemptCount != 1 {
		t.Fatalf("attempt_count = %d, want 1", failed.AttemptCount)
	}
	wantNext := now.Add(16 * time.Minute)
	if failed.NextAttemptAt == nil || !failed.NextAttemptAt.Equal(wantNext) {
		t.Fatalf("next_attempt_at = %v, want %v", failed.NextAttemptAt, wantNext)
	}
	if failed.LastErrorSummary == nil || strings.Contains(*failed.LastErrorSummary, secret) || !strings.Contains(*failed.LastErrorSummary, output.Sentinel) {
		t.Fatalf("last_error_summary = %q, want redacted sentinel and no secret", stringPtrValue(failed.LastErrorSummary))
	}

	rendered := slog.Any("export", failed).Value.String()
	if strings.Contains(rendered, secret) {
		t.Fatalf("LogValue leaked provider secret: %q", rendered)
	}
	if !strings.Contains(rendered, output.Sentinel) {
		t.Fatalf("LogValue = %q, want redaction sentinel", rendered)
	}
}

func stringPtrValue(v *string) string {
	if v == nil {
		return "<nil>"
	}
	return *v
}
