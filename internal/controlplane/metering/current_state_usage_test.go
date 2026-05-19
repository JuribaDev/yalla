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

func TestCurrentStateUsageEmitterWritesActiveServicesIdempotentlyAndAggregates(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewCurrentStateUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewCurrentStateUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedCurrentStateSample{
		Name:           "active_services",
		Value:          1,
		Unit:           "service",
		WindowStart:    start,
		WindowEnd:      start.Add(time.Hour),
		OrganizationID: seed.OrganizationID,
		ProjectID:      seed.ProjectID,
		EnvironmentID:  seed.EnvironmentID,
		ServiceID:      seed.ServiceID,
		Metadata:       map[string]string{"api_key": "yalla_sk_live_should_not_leak", "service_status": "active"},
	}

	first, err := emitter.Emit(ctx, metering.CurrentStateUsageInput{
		Samples:   []metering.AttributedCurrentStateSample{sample},
		RequestID: "req_active_services",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.CurrentStateUsageInput{
		Samples:   []metering.AttributedCurrentStateSample{sample},
		RequestID: "req_active_services",
	})
	if err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if len(first.Events) != 1 || len(second.Events) != 1 {
		t.Fatalf("events len first/second = %d/%d, want 1/1", len(first.Events), len(second.Events))
	}
	event := first.Events[0]
	if event.ID != second.Events[0].ID {
		t.Fatalf("duplicate window wrote a new event id %q, want existing %q", second.Events[0].ID, event.ID)
	}
	if event.Resource != store.QuotaResourceActiveServices || event.Unit != "service" || event.Source != metering.CurrentStateUsageSource || event.Quantity != 1 {
		t.Fatalf("usage event = %+v, want active_services service yalla_current_state quantity=1", event)
	}
	if event.OrganizationID != seed.OrganizationID || event.ProjectID != seed.ProjectID || event.EnvironmentID != seed.EnvironmentID || event.ServiceID != seed.ServiceID {
		t.Fatalf("usage event scope = %+v, want full attributed service scope", event)
	}
	if event.Metadata["api_key"] != "[REDACTED]" {
		t.Fatalf("api_key metadata = %q, want redacted", event.Metadata["api_key"])
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 1)

	counterRepo := store.NewUsageCounterRepository()
	var counters []store.UsageCounter
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		result, aggErr := counterRepo.AggregateUsageEvents(ctx, tx, store.AggregateUsageCountersInput{
			OrganizationID:     seed.OrganizationID,
			PeriodStart:        time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			PeriodEnd:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			AggregatedAt:       start.Add(2 * time.Hour),
			AggregationVersion: 1,
		})
		counters = result.Counters
		return aggErr
	}); err != nil {
		t.Fatalf("AggregateUsageEvents: %v", err)
	}
	if len(counters) != 1 || counters[0].Key != "active_services" || counters[0].Unit != "service" || counters[0].Quantity != 1 {
		t.Fatalf("counters = %+v, want one active_services counter quantity=1", counters)
	}
}

func TestCurrentStateUsageEmitterSkipsMissingActiveServicesData(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewCurrentStateUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewCurrentStateUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	result, err := emitter.Emit(ctx, metering.CurrentStateUsageInput{
		Samples: []metering.AttributedCurrentStateSample{
			{Name: "unknown_current_state", Value: 1, Unit: "service", WindowStart: start, WindowEnd: start.Add(time.Hour), OrganizationID: seed.OrganizationID, ProjectID: seed.ProjectID, EnvironmentID: seed.EnvironmentID, ServiceID: seed.ServiceID},
			{Name: "active_services", Value: 1, Unit: "service", WindowStart: start, WindowEnd: start.Add(time.Hour), OrganizationID: seed.OrganizationID},
		},
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("events = %+v, want none for unsupported/incomplete samples", result.Events)
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 0)
}

func TestCurrentStateUsageEmitterKeepsActiveServicesTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedMeteringHierarchy(t, db, f)
	bravo := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewCurrentStateUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewCurrentStateUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	_, err = emitter.Emit(ctx, metering.CurrentStateUsageInput{
		Samples: []metering.AttributedCurrentStateSample{{
			Name:           "active_services",
			Value:          1,
			Unit:           "service",
			WindowStart:    start,
			WindowEnd:      start.Add(time.Hour),
			OrganizationID: alpha.OrganizationID,
			ProjectID:      bravo.ProjectID,
			EnvironmentID:  bravo.EnvironmentID,
			ServiceID:      bravo.ServiceID,
		}},
		RequestID: "req_cross_tenant_active_services",
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}

func TestBuildActiveServiceSampleCollectsOnlyActiveServiceRows(t *testing.T) {
	t.Parallel()

	windowStart := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(time.Hour)
	active := store.Service{
		ID:             "svc_active_current_state",
		OrganizationID: "org_current_state",
		ProjectID:      "proj_current_state",
		EnvironmentID:  "env_current_state",
		Status:         store.ServiceStatusActive,
		Version:        7,
	}

	sample, ok, err := metering.BuildActiveServiceSample(active, windowStart, windowEnd)
	if err != nil {
		t.Fatalf("BuildActiveServiceSample(active): %v", err)
	}
	if !ok {
		t.Fatal("BuildActiveServiceSample(active) ok=false, want active service sample")
	}
	if sample.Name != "active_services" || sample.Value != 1 || sample.Unit != "service" || sample.ServiceID != active.ID {
		t.Fatalf("sample = %+v, want active_services quantity=1 for service", sample)
	}
	if sample.Metadata["service_status"] != "active" || sample.Metadata["service_version"] != "7" {
		t.Fatalf("sample metadata = %+v, want active status/version", sample.Metadata)
	}

	deleted := active
	deleted.ID = "svc_deleted_current_state"
	deleted.Status = store.ServiceStatusDeleted
	sample, ok, err = metering.BuildActiveServiceSample(deleted, windowStart, windowEnd)
	if err != nil {
		t.Fatalf("BuildActiveServiceSample(deleted): %v", err)
	}
	if ok {
		t.Fatalf("BuildActiveServiceSample(deleted) = %+v, true; want skipped", sample)
	}
}
