package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func closeInvoiceSnapshotOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.InvoiceSnapshotRepository, in store.CloseInvoiceSnapshotInput) store.InvoiceSnapshot {
	t.Helper()
	var snapshot store.InvoiceSnapshot
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		snapshot, err = repo.Close(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("Close invoice snapshot: %v", err)
	}
	return snapshot
}

func reopenInvoiceSnapshotOrFail(ctx context.Context, t *testing.T, s *store.Store, repo *store.InvoiceSnapshotRepository, in store.ReopenInvoiceSnapshotInput) store.InvoiceSnapshot {
	t.Helper()
	var snapshot store.InvoiceSnapshot
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		snapshot, err = repo.ReopenForCorrection(ctx, tx, in)
		return err
	}); err != nil {
		t.Fatalf("Reopen invoice snapshot: %v", err)
	}
	return snapshot
}

func TestInvoiceSnapshotRepositoryCloseFreezesCountersAndExportSnapshot(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "invoice-close")
	pricing := store.NewPricingPlanRepository()
	subs := store.NewSubscriptionRepository()
	events := store.NewUsageEventRepository()
	counters := store.NewUsageCounterRepository()
	invoices := store.NewInvoiceSnapshotRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	closedAt := periodEnd.Add(2 * time.Hour)
	plan := seededPlan(ctx, t, s, pricing, "invoice-pro")
	upsertEntitlementOrFail(ctx, t, s, pricing, store.UpsertPlanEntitlementInput{
		PlanID:          plan.ID,
		EntitlementKey:  string(store.QuotaResourceHTTPRequests),
		LimitValue:      int64Ptr(20),
		EnforcementMode: store.EnforcementModeMetered,
		Metadata:        []byte(`{"unit":"request","overage_behavior":"allow"}`),
	})
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
		Quantity:       25,
		Unit:           "request",
		Source:         "traefik",
		IdempotencyKey: "invoice-close-initial",
		OccurredAt:     periodStart.Add(time.Hour),
	})
	aggregateUsageCountersOrFail(ctx, t, s, counters, store.AggregateUsageCountersInput{
		OrganizationID:     org.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       closedAt.Add(-time.Hour),
		AggregationVersion: 1,
		RequestID:          "req_invoice_close_1",
		CorrelationID:      "corr_invoice_close_1",
	})
	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceHTTPRequests,
		EventType:      store.UsageEventTypeAdjusted,
		Quantity:       3,
		Unit:           "request",
		Source:         "traefik",
		IdempotencyKey: "invoice-close-late-adjustment",
		OccurredAt:     periodStart.Add(2 * time.Hour),
	})
	aggregateUsageCountersOrFail(ctx, t, s, counters, store.AggregateUsageCountersInput{
		OrganizationID:     org.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       closedAt,
		AggregationVersion: 2,
		RequestID:          "req_invoice_close_2",
		CorrelationID:      "corr_invoice_close_2",
	})

	snapshot := closeInvoiceSnapshotOrFail(ctx, t, s, invoices, store.CloseInvoiceSnapshotInput{
		OrganizationID:     org.ID,
		SubscriptionID:     sub.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		ClosedAt:           closedAt,
		AggregationVersion: 2,
		RequestID:          "req_invoice_close_final",
		CorrelationID:      "corr_invoice_close_final",
	})
	if snapshot.Status != store.InvoiceSnapshotStatusClosed {
		t.Fatalf("snapshot status = %q, want closed", snapshot.Status)
	}
	if snapshot.CloseVersion != 1 {
		t.Fatalf("close_version = %d, want 1", snapshot.CloseVersion)
	}
	if snapshot.PlanID != plan.ID || snapshot.PlanVersion != plan.Version || snapshot.PlanSlug != plan.Slug {
		t.Fatalf("plan snapshot = %+v, want accepted plan id/version/slug", snapshot)
	}
	if snapshot.EntitlementRevision == "" {
		t.Fatalf("entitlement_revision is blank")
	}
	if snapshot.BillingExportID == nil || snapshot.ExportStatus != store.InvoiceSnapshotExportStatusPending {
		t.Fatalf("export = id %v status %q, want pending export", snapshot.BillingExportID, snapshot.ExportStatus)
	}
	if snapshot.UsageEventChecksum == "" || snapshot.AdjustmentChecksum == "" {
		t.Fatalf("checksums = usage %q adjustment %q, want reproducibility checksums", snapshot.UsageEventChecksum, snapshot.AdjustmentChecksum)
	}
	if len(snapshot.Items) != 1 {
		t.Fatalf("items = %d, want 1: %+v", len(snapshot.Items), snapshot.Items)
	}
	item := snapshot.Items[0]
	if item.CounterQuantity != 25 || item.AdjustmentQuantity != 3 || item.FinalQuantity != 28 {
		t.Fatalf("item quantities = counter %v adjustment %v final %v, want 25/3/28", item.CounterQuantity, item.AdjustmentQuantity, item.FinalQuantity)
	}
	if item.EntitlementKey == nil || *item.EntitlementKey != string(store.QuotaResourceHTTPRequests) {
		t.Fatalf("item entitlement_key = %v, want http_requests", item.EntitlementKey)
	}

	readBack, err := invoices.Get(ctx, db, org.ID, snapshot.ID)
	if err != nil {
		t.Fatalf("Get invoice snapshot: %v", err)
	}
	if readBack.ID != snapshot.ID || len(readBack.Items) != 1 {
		t.Fatalf("readback = %+v, want same snapshot with items", readBack)
	}
}

func TestInvoiceSnapshotRepositoryClosedPeriodLateUsageCreatesAdjustmentOnly(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "invoice-closed-adjustment")
	pricing := store.NewPricingPlanRepository()
	subs := store.NewSubscriptionRepository()
	events := store.NewUsageEventRepository()
	counters := store.NewUsageCounterRepository()
	invoices := store.NewInvoiceSnapshotRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	plan := seededPlan(ctx, t, s, pricing, "invoice-closed")
	sub := createSubscriptionOrFail(ctx, t, s, subs, store.CreateSubscriptionInput{
		OrganizationID:     org.ID,
		PlanID:             plan.ID,
		Status:             store.SubscriptionStatusActive,
		CurrentPeriodStart: periodStart,
		CurrentPeriodEnd:   periodEnd,
		Provider:           "manual",
	})
	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceBuildMinutes,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       4,
		Unit:           "minute",
		Source:         "yalla_jobs",
		IdempotencyKey: "invoice-closed-initial",
		OccurredAt:     periodStart.Add(time.Hour),
	})
	aggregateUsageCountersOrFail(ctx, t, s, counters, store.AggregateUsageCountersInput{
		OrganizationID:     org.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodEnd.Add(time.Hour),
		AggregationVersion: 1,
	})
	closeInvoiceSnapshotOrFail(ctx, t, s, invoices, store.CloseInvoiceSnapshotInput{
		OrganizationID:     org.ID,
		SubscriptionID:     sub.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		ClosedAt:           periodEnd.Add(2 * time.Hour),
		AggregationVersion: 1,
		RequestID:          "req_invoice_closed_1",
		CorrelationID:      "corr_invoice_closed_1",
	})

	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceBuildMinutes,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       2,
		Unit:           "minute",
		Source:         "yalla_jobs",
		IdempotencyKey: "invoice-closed-late",
		OccurredAt:     periodStart.Add(2 * time.Hour),
	})
	result := aggregateUsageCountersOrFail(ctx, t, s, counters, store.AggregateUsageCountersInput{
		OrganizationID:     org.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodEnd.Add(3 * time.Hour),
		AggregationVersion: 2,
	})
	if len(result.Adjustments) != 1 || result.Adjustments[0].DeltaQuantity != 2 {
		t.Fatalf("late adjustments = %+v, want one delta 2", result.Adjustments)
	}
	if result.Counters[0].Quantity != 4 {
		t.Fatalf("closed counter quantity = %v, want frozen 4", result.Counters[0].Quantity)
	}
}

func TestInvoiceSnapshotRepositoryReopenForCorrectionAuditsAndAllowsNewCloseVersion(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "invoice-reopen")
	pricing := store.NewPricingPlanRepository()
	subs := store.NewSubscriptionRepository()
	events := store.NewUsageEventRepository()
	counters := store.NewUsageCounterRepository()
	invoices := store.NewInvoiceSnapshotRepository()
	audits := store.NewAuditRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	secret := "sk_live_invoice_reopen_secret"
	plan := seededPlan(ctx, t, s, pricing, "invoice-reopen")
	sub := createSubscriptionOrFail(ctx, t, s, subs, store.CreateSubscriptionInput{
		OrganizationID:     org.ID,
		PlanID:             plan.ID,
		Status:             store.SubscriptionStatusActive,
		CurrentPeriodStart: periodStart,
		CurrentPeriodEnd:   periodEnd,
		Provider:           "manual",
	})
	appendUsageEventOrFail(ctx, t, s, events, store.AppendUsageEventInput{
		OrganizationID: org.ID,
		Resource:       store.QuotaResourceDeployments,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       1,
		Unit:           "deployment",
		Source:         "yalla_events",
		IdempotencyKey: "invoice-reopen-initial",
		OccurredAt:     periodStart.Add(time.Hour),
	})
	aggregateUsageCountersOrFail(ctx, t, s, counters, store.AggregateUsageCountersInput{
		OrganizationID:     org.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		AggregatedAt:       periodEnd.Add(time.Hour),
		AggregationVersion: 1,
	})
	first := closeInvoiceSnapshotOrFail(ctx, t, s, invoices, store.CloseInvoiceSnapshotInput{
		OrganizationID:     org.ID,
		SubscriptionID:     sub.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		ClosedAt:           periodEnd.Add(2 * time.Hour),
		AggregationVersion: 1,
		RequestID:          "req_invoice_reopen_1",
		CorrelationID:      "corr_invoice_reopen_1",
	})
	reopened := reopenInvoiceSnapshotOrFail(ctx, t, s, invoices, store.ReopenInvoiceSnapshotInput{
		OrganizationID: org.ID,
		SnapshotID:     first.ID,
		ActorID:        "user_admin",
		ActorKind:      "user",
		Reason:         "correction requested after provider note " + secret,
		ReopenedAt:     periodEnd.Add(3 * time.Hour),
		RequestID:      "req_invoice_reopen_2",
		CorrelationID:  "corr_invoice_reopen_2",
	})
	if reopened.Status != store.InvoiceSnapshotStatusReopened {
		t.Fatalf("reopened status = %q, want reopened", reopened.Status)
	}

	eventsRead, err := audits.ListByOrganization(ctx, db, org.ID, 20)
	if err != nil {
		t.Fatalf("List audit events: %v", err)
	}
	var found bool
	for _, event := range eventsRead {
		if event.Action == "billing.invoice_snapshot.reopen" && event.ResourceID == first.ID {
			found = true
			if strings.Contains(event.Reason, secret) || strings.Contains(event.Metadata["reason"], secret) {
				t.Fatalf("audit leaked secret in event: %+v", event)
			}
		}
	}
	if !found {
		t.Fatalf("missing reopen audit event in %+v", eventsRead)
	}

	second := closeInvoiceSnapshotOrFail(ctx, t, s, invoices, store.CloseInvoiceSnapshotInput{
		OrganizationID:     org.ID,
		SubscriptionID:     sub.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		ClosedAt:           periodEnd.Add(4 * time.Hour),
		AggregationVersion: 2,
		RequestID:          "req_invoice_reopen_3",
		CorrelationID:      "corr_invoice_reopen_3",
	})
	if second.CloseVersion != 2 {
		t.Fatalf("second close_version = %d, want 2", second.CloseVersion)
	}
}

func TestInvoiceSnapshotRepositoryValidationAndTenantScopedNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	ctx := context.Background()
	f := testutil.NewFactory(t)
	org := seedOrg(t, db, f, "invoice-validation")
	otherOrg := seedOrg(t, db, f, "invoice-validation-other")
	pricing := store.NewPricingPlanRepository()
	subs := store.NewSubscriptionRepository()
	invoices := store.NewInvoiceSnapshotRepository()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	plan := seededPlan(ctx, t, s, pricing, "invoice-validation")
	sub := createSubscriptionOrFail(ctx, t, s, subs, store.CreateSubscriptionInput{
		OrganizationID:     org.ID,
		PlanID:             plan.ID,
		Status:             store.SubscriptionStatusActive,
		CurrentPeriodStart: periodStart,
		CurrentPeriodEnd:   periodEnd,
		Provider:           "manual",
	})

	err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, closeErr := invoices.Close(ctx, tx, store.CloseInvoiceSnapshotInput{
			OrganizationID:     org.ID,
			SubscriptionID:     sub.ID,
			PeriodStart:        periodStart,
			PeriodEnd:          periodStart,
			ClosedAt:           periodEnd,
			AggregationVersion: 1,
			RequestID:          "req_invoice_invalid",
			CorrelationID:      "corr_invoice_invalid",
		})
		return closeErr
	})
	if got := yerr.From(err).Code; got != yerr.CodeValidation {
		t.Fatalf("invalid close code = %s, want E_VALIDATION (err %v)", got, err)
	}

	snapshot := closeInvoiceSnapshotOrFail(ctx, t, s, invoices, store.CloseInvoiceSnapshotInput{
		OrganizationID:     org.ID,
		SubscriptionID:     sub.ID,
		PeriodStart:        periodStart,
		PeriodEnd:          periodEnd,
		ClosedAt:           periodEnd.Add(time.Hour),
		AggregationVersion: 1,
		RequestID:          "req_invoice_valid",
		CorrelationID:      "corr_invoice_valid",
	})
	if _, err := invoices.Get(ctx, db, otherOrg.ID, snapshot.ID); yerr.From(err).Code != yerr.CodeNotFound {
		t.Fatalf("cross-tenant Get err = %v, want E_NOT_FOUND", err)
	}
}
