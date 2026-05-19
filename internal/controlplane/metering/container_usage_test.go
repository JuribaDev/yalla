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

func TestContainerUsageEmitterWritesCPUMillicoreSecondsIdempotentlyAndAggregates(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewContainerUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewContainerUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedContainerSample{
		ContainerMetricSample: metering.ContainerMetricSample{
			Name:              "container_cpu_millicore_seconds",
			ContainerID:       "ctr-web-1",
			Value:             1250,
			Unit:              "millicore_second",
			WindowStart:       start,
			WindowEnd:         start.Add(time.Minute),
			Source:            "cadvisor",
			QueryVersion:      "cadvisor-v1",
			RawSampleChecksum: "cpuabcdef123456",
			Labels:            map[string]string{"authorization": "Bearer should-not-leak"},
		},
		OrganizationID: seed.OrganizationID,
		ProjectID:      seed.ProjectID,
		EnvironmentID:  seed.EnvironmentID,
		ServiceID:      seed.ServiceID,
		Metadata:       map[string]string{"api_key": "must-redact", "node": "worker-1"},
	}

	first, err := emitter.Emit(ctx, metering.ContainerUsageInput{
		Samples:   []metering.AttributedContainerSample{sample},
		RequestID: "req_container_cpu",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.ContainerUsageInput{
		Samples:   []metering.AttributedContainerSample{sample},
		RequestID: "req_container_cpu",
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
	if event.Resource != store.QuotaResourceContainerCPUMillicoreSeconds || event.Unit != "millicore_second" || event.Source != metering.ContainerUsageSource || event.Quantity != 1250 {
		t.Fatalf("usage event = %+v, want container_cpu_millicore_seconds millicore_second dokploy_or_cadvisor quantity=1250", event)
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
			AggregatedAt:       start.Add(2 * time.Minute),
			AggregationVersion: 1,
		})
		counters = result.Counters
		return aggErr
	}); err != nil {
		t.Fatalf("AggregateUsageEvents: %v", err)
	}
	if len(counters) != 1 || counters[0].Key != "container_cpu_millicore_seconds" || counters[0].Unit != "millicore_second" || counters[0].Quantity != 1250 {
		t.Fatalf("counters = %+v, want one container_cpu_millicore_seconds counter quantity=1250", counters)
	}
}

func TestContainerUsageEmitterSkipsMissingData(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewContainerUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewContainerUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	result, err := emitter.Emit(ctx, metering.ContainerUsageInput{
		Samples: []metering.AttributedContainerSample{
			{
				ContainerMetricSample: metering.ContainerMetricSample{Name: "container_memory_mb_hours", Value: 4, Unit: "mb_hour", WindowStart: start, WindowEnd: start.Add(time.Minute)},
				OrganizationID:        seed.OrganizationID,
				ProjectID:             seed.ProjectID,
				EnvironmentID:         seed.EnvironmentID,
				ServiceID:             seed.ServiceID,
			},
			{
				ContainerMetricSample: metering.ContainerMetricSample{Name: "container_cpu_millicore_seconds", Value: 1, Unit: "millicore_second", WindowStart: start, WindowEnd: start.Add(time.Minute)},
				OrganizationID:        seed.OrganizationID,
			},
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

func TestContainerUsageEmitterKeepsCPUMillicoreSecondsTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedMeteringHierarchy(t, db, f)
	bravo := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewContainerUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewContainerUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	_, err = emitter.Emit(ctx, metering.ContainerUsageInput{
		Samples: []metering.AttributedContainerSample{{
			ContainerMetricSample: metering.ContainerMetricSample{
				Name:              "container_cpu_millicore_seconds",
				ContainerID:       "ctr-cross-tenant",
				Value:             99,
				Unit:              "millicore_second",
				WindowStart:       start,
				WindowEnd:         start.Add(time.Minute),
				RawSampleChecksum: "cross-tenant-container-cpu",
			},
			OrganizationID: alpha.OrganizationID,
			ProjectID:      bravo.ProjectID,
			EnvironmentID:  bravo.EnvironmentID,
			ServiceID:      bravo.ServiceID,
		}},
		RequestID: "req_cross_tenant_container_cpu",
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}
