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

func TestBackupUsageEmitterWritesStorageGBMonthIdempotentlyAndAggregates(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewBackupUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewBackupUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedBackupSample{
		BackupMetricSample: metering.BackupMetricSample{
			Name:              "backup_storage_gb_month",
			BackupID:          "backup-nightly-20260519",
			Value:             8.5,
			Unit:              "gb_month",
			WindowStart:       start,
			WindowEnd:         start.Add(time.Hour),
			Source:            "backup-metadata-v1",
			QueryVersion:      "backup-metadata-query-v1",
			RawSampleChecksum: "backupstorageabcdef123456",
			Labels:            map[string]string{"cookie": "session=should-not-leak"},
		},
		OrganizationID: seed.OrganizationID,
		ProjectID:      seed.ProjectID,
		EnvironmentID:  seed.EnvironmentID,
		ServiceID:      seed.ServiceID,
		Metadata:       map[string]string{"api_key": "yalla_secret", "backup_name": "nightly"},
	}

	first, err := emitter.Emit(ctx, metering.BackupUsageInput{
		Samples:   []metering.AttributedBackupSample{sample},
		RequestID: "req_backup_storage_gb_month",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.BackupUsageInput{
		Samples:   []metering.AttributedBackupSample{sample},
		RequestID: "req_backup_storage_gb_month",
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
	if event.Resource != store.QuotaResourceBackupStorageGBMonth || event.Unit != "gb_month" || event.Source != metering.BackupUsageSource || event.Quantity != 8.5 {
		t.Fatalf("usage event = %+v, want backup_storage_gb_month gb_month backup_metadata quantity=8.5", event)
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
	if len(counters) != 1 || counters[0].Key != "backup_storage_gb_month" || counters[0].Unit != "gb_month" || counters[0].Quantity != 8.5 {
		t.Fatalf("counters = %+v, want one backup_storage_gb_month counter quantity=8.5", counters)
	}
}

func TestBackupUsageEmitterSkipsMissingData(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewBackupUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewBackupUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	result, err := emitter.Emit(ctx, metering.BackupUsageInput{
		Samples: []metering.AttributedBackupSample{
			{
				BackupMetricSample: metering.BackupMetricSample{Name: "backup_unknown", Value: 4, Unit: "gb_month", WindowStart: start, WindowEnd: start.Add(time.Hour)},
				OrganizationID:     seed.OrganizationID,
				ProjectID:          seed.ProjectID,
				EnvironmentID:      seed.EnvironmentID,
				ServiceID:          seed.ServiceID,
			},
			{
				BackupMetricSample: metering.BackupMetricSample{Name: "backup_storage_gb_month", Value: 1, Unit: "gb_month", WindowStart: start, WindowEnd: start.Add(time.Hour)},
				OrganizationID:     seed.OrganizationID,
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

func TestBackupUsageEmitterKeepsStorageGBMonthTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedMeteringHierarchy(t, db, f)
	bravo := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewBackupUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewBackupUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	_, err = emitter.Emit(ctx, metering.BackupUsageInput{
		Samples: []metering.AttributedBackupSample{{
			BackupMetricSample: metering.BackupMetricSample{
				Name:              "backup_storage_gb_month",
				BackupID:          "backup-cross-tenant",
				Value:             99,
				Unit:              "gb_month",
				WindowStart:       start,
				WindowEnd:         start.Add(time.Hour),
				RawSampleChecksum: "cross-tenant-backup-storage-gb-month",
			},
			OrganizationID: alpha.OrganizationID,
			ProjectID:      bravo.ProjectID,
			EnvironmentID:  bravo.EnvironmentID,
			ServiceID:      bravo.ServiceID,
		}},
		RequestID: "req_cross_tenant_backup_storage",
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}

func TestBuildBackupStorageGBMonthSampleTracksRetentionAndSkipsFailures(t *testing.T) {
	t.Parallel()
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	createdAt := time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC)
	expiresAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)

	sample, ok, err := metering.BuildBackupStorageGBMonthSample(metering.BackupStorageGBMonthSampleInput{
		OrganizationID: "org_backup_retention",
		ProjectID:      "proj_backup_retention",
		EnvironmentID:  "env_backup_retention",
		ServiceID:      "svc_backup_retention",
		BackupID:       "backup_retained",
		SizeBytes:      20 * 1024 * 1024 * 1024,
		Status:         metering.BackupArtifactSucceeded,
		WindowStart:    periodStart,
		WindowEnd:      periodEnd,
		PeriodStart:    periodStart,
		PeriodEnd:      periodEnd,
		CreatedAt:      createdAt,
		ExpiresAt:      &expiresAt,
		Source:         "backup_metadata",
	})
	if err != nil {
		t.Fatalf("BuildBackupStorageGBMonthSample: %v", err)
	}
	if !ok {
		t.Fatal("BuildBackupStorageGBMonthSample ok=false, want retained backup usage")
	}
	want := 20 * expiresAt.Sub(createdAt).Hours() / periodEnd.Sub(periodStart).Hours()
	if sample.Name != "backup_storage_gb_month" || sample.Unit != "gb_month" || sample.WindowStart != createdAt || sample.WindowEnd != expiresAt {
		t.Fatalf("sample window/identity = %+v, want backup_storage_gb_month clipped to retention lifetime", sample)
	}
	if diff := sample.Value - want; diff < -0.0000001 || diff > 0.0000001 {
		t.Fatalf("sample.Value = %.12f, want %.12f", sample.Value, want)
	}
	if sample.Metadata["retention_expires_at"] != expiresAt.Format(time.RFC3339Nano) || sample.Metadata["backup_status"] != "succeeded" {
		t.Fatalf("metadata = %+v, want retention expiry and succeeded status", sample.Metadata)
	}

	failed, ok, err := metering.BuildBackupStorageGBMonthSample(metering.BackupStorageGBMonthSampleInput{
		OrganizationID: "org_backup_retention",
		ProjectID:      "proj_backup_retention",
		EnvironmentID:  "env_backup_retention",
		ServiceID:      "svc_backup_retention",
		BackupID:       "backup_failed",
		SizeBytes:      20 * 1024 * 1024 * 1024,
		Status:         metering.BackupArtifactFailed,
		WindowStart:    periodStart,
		WindowEnd:      periodEnd,
		PeriodStart:    periodStart,
		PeriodEnd:      periodEnd,
		CreatedAt:      createdAt,
		Source:         "backup_metadata",
	})
	if err != nil {
		t.Fatalf("failed BuildBackupStorageGBMonthSample: %v", err)
	}
	if ok || failed.Value != 0 {
		t.Fatalf("failed backup sample = %+v ok=%v, want skipped without billable usage", failed, ok)
	}
}

func TestBackupUsageEmitterWritesAdjustmentEvents(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewBackupUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewBackupUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	result, err := emitter.Emit(ctx, metering.BackupUsageInput{
		Samples: []metering.AttributedBackupSample{{
			BackupMetricSample: metering.BackupMetricSample{
				Name:              "backup_storage_gb_month",
				BackupID:          "backup-correction",
				Value:             -0.75,
				Unit:              "gb_month",
				WindowStart:       start,
				WindowEnd:         start.Add(time.Hour),
				RawSampleChecksum: "backup-correction-1",
			},
			OrganizationID: seed.OrganizationID,
			ProjectID:      seed.ProjectID,
			EnvironmentID:  seed.EnvironmentID,
			ServiceID:      seed.ServiceID,
			EventType:      store.UsageEventTypeAdjusted,
			Metadata:       map[string]string{"reason": "backup_inventory_correction"},
		}},
		RequestID: "req_backup_adjustment",
	})
	if err != nil {
		t.Fatalf("Emit adjustment: %v", err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("events = %+v, want one adjustment", result.Events)
	}
	if result.Events[0].EventType != store.UsageEventTypeAdjusted || result.Events[0].Quantity != -0.75 {
		t.Fatalf("event = %+v, want adjusted quantity -0.75", result.Events[0])
	}
}
