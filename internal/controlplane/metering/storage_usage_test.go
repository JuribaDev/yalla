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

func TestStorageUsageEmitterWritesGBMonthIdempotentlyAndAggregates(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewStorageUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewStorageUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedStorageSample{
		StorageMetricSample: metering.StorageMetricSample{
			Name:              "storage_gb_month",
			VolumeID:          "vol-primary",
			Value:             12.75,
			Unit:              "gb_month",
			WindowStart:       start,
			WindowEnd:         start.Add(time.Hour),
			Source:            "node-volume-scanner",
			QueryVersion:      "volume-scanner-v1",
			RawSampleChecksum: "storageabcdef123456",
			Labels:            map[string]string{"cookie": "session=should-not-leak"},
		},
		OrganizationID: seed.OrganizationID,
		ProjectID:      seed.ProjectID,
		EnvironmentID:  seed.EnvironmentID,
		ServiceID:      seed.ServiceID,
		Metadata:       map[string]string{"database_url": "postgres://secret", "mount": "/data"},
	}

	first, err := emitter.Emit(ctx, metering.StorageUsageInput{
		Samples:   []metering.AttributedStorageSample{sample},
		RequestID: "req_storage_gb_month",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.StorageUsageInput{
		Samples:   []metering.AttributedStorageSample{sample},
		RequestID: "req_storage_gb_month",
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
	if event.Resource != store.QuotaResourceStorageGBMonth || event.Unit != "gb_month" || event.Source != metering.StorageUsageSource || event.Quantity != 12.75 {
		t.Fatalf("usage event = %+v, want storage_gb_month gb_month volume_scanner quantity=12.75", event)
	}
	if event.OrganizationID != seed.OrganizationID || event.ProjectID != seed.ProjectID || event.EnvironmentID != seed.EnvironmentID || event.ServiceID != seed.ServiceID {
		t.Fatalf("usage event scope = %+v, want full attributed service scope", event)
	}
	if event.Metadata["database_url"] != "[REDACTED]" {
		t.Fatalf("database_url metadata = %q, want redacted", event.Metadata["database_url"])
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
	if len(counters) != 1 || counters[0].Key != "storage_gb_month" || counters[0].Unit != "gb_month" || counters[0].Quantity != 12.75 {
		t.Fatalf("counters = %+v, want one storage_gb_month counter quantity=12.75", counters)
	}
}

func TestStorageUsageEmitterSkipsMissingData(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewStorageUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewStorageUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	result, err := emitter.Emit(ctx, metering.StorageUsageInput{
		Samples: []metering.AttributedStorageSample{
			{
				StorageMetricSample: metering.StorageMetricSample{Name: "storage_unknown", Value: 4, Unit: "gb_month", WindowStart: start, WindowEnd: start.Add(time.Hour)},
				OrganizationID:      seed.OrganizationID,
				ProjectID:           seed.ProjectID,
				EnvironmentID:       seed.EnvironmentID,
				ServiceID:           seed.ServiceID,
			},
			{
				StorageMetricSample: metering.StorageMetricSample{Name: "storage_gb_month", Value: 1, Unit: "gb_month", WindowStart: start, WindowEnd: start.Add(time.Hour)},
				OrganizationID:      seed.OrganizationID,
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

func TestStorageUsageEmitterKeepsGBMonthTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedMeteringHierarchy(t, db, f)
	bravo := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewStorageUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewStorageUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	_, err = emitter.Emit(ctx, metering.StorageUsageInput{
		Samples: []metering.AttributedStorageSample{{
			StorageMetricSample: metering.StorageMetricSample{
				Name:              "storage_gb_month",
				VolumeID:          "vol-cross-tenant",
				Value:             99,
				Unit:              "gb_month",
				WindowStart:       start,
				WindowEnd:         start.Add(time.Hour),
				RawSampleChecksum: "cross-tenant-storage-gb-month",
			},
			OrganizationID: alpha.OrganizationID,
			ProjectID:      bravo.ProjectID,
			EnvironmentID:  bravo.EnvironmentID,
			ServiceID:      bravo.ServiceID,
		}},
		RequestID: "req_cross_tenant_storage",
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}

func TestBuildStorageGBMonthSampleProratesCreateDeleteMidPeriod(t *testing.T) {
	t.Parallel()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	createdAt := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	deletedAt := time.Date(2026, 5, 20, 18, 0, 0, 0, time.UTC)

	sample, ok, err := metering.BuildStorageGBMonthSample(metering.StorageGBMonthSampleInput{
		OrganizationID: "org_storage_proration",
		ProjectID:      "proj_storage_proration",
		EnvironmentID:  "env_storage_proration",
		ServiceID:      "svc_storage_proration",
		VolumeID:       "vol_prorated",
		SizeBytes:      10 * 1024 * 1024 * 1024,
		WindowStart:    periodStart,
		WindowEnd:      periodEnd,
		PeriodStart:    periodStart,
		PeriodEnd:      periodEnd,
		CreatedAt:      createdAt,
		DeletedAt:      &deletedAt,
		Source:         "volume_scanner",
	})
	if err != nil {
		t.Fatalf("BuildStorageGBMonthSample: %v", err)
	}
	if !ok {
		t.Fatal("BuildStorageGBMonthSample ok=false, want billable historical usage")
	}
	want := 10 * deletedAt.Sub(createdAt).Hours() / periodEnd.Sub(periodStart).Hours()
	if sample.Name != "storage_gb_month" || sample.Unit != "gb_month" || sample.WindowStart != createdAt || sample.WindowEnd != deletedAt {
		t.Fatalf("sample window/identity = %+v, want storage_gb_month clipped to resource lifetime", sample)
	}
	if diff := sample.Value - want; diff < -0.0000001 || diff > 0.0000001 {
		t.Fatalf("sample.Value = %.12f, want %.12f", sample.Value, want)
	}
	if sample.Metadata["resource_lifecycle"] != "deleted_during_period" {
		t.Fatalf("resource_lifecycle metadata = %q, want deleted_during_period", sample.Metadata["resource_lifecycle"])
	}
}

func TestStorageUsageEmitterWritesAdjustmentEvents(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewStorageUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewStorageUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	result, err := emitter.Emit(ctx, metering.StorageUsageInput{
		Samples: []metering.AttributedStorageSample{{
			StorageMetricSample: metering.StorageMetricSample{
				Name:              "storage_gb_month",
				VolumeID:          "vol-correction",
				Value:             -1.25,
				Unit:              "gb_month",
				WindowStart:       start,
				WindowEnd:         start.Add(time.Hour),
				RawSampleChecksum: "storage-correction-1",
			},
			OrganizationID: seed.OrganizationID,
			ProjectID:      seed.ProjectID,
			EnvironmentID:  seed.EnvironmentID,
			ServiceID:      seed.ServiceID,
			EventType:      store.UsageEventTypeAdjusted,
			Metadata:       map[string]string{"reason": "volume_rescan_correction"},
		}},
		RequestID: "req_storage_adjustment",
	})
	if err != nil {
		t.Fatalf("Emit adjustment: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("events = %+v, want one adjustment", result.Events)
	}
	if result.Events[0].EventType != store.UsageEventTypeAdjusted || result.Events[0].Quantity != -1.25 {
		t.Fatalf("event = %+v, want adjusted quantity -1.25", result.Events[0])
	}
}
