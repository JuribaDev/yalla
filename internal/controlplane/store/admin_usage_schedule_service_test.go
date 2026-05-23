package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestAdminUsageAggregationScheduleServiceVersionDisableAndRuntimeReload(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	actorOrg := seedOrg(t, db, f, "AdminUsageScheduleActor")
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminUsageScheduleServiceForTest(t, s)
	auditCtx := store.AdminUsageAggregationScheduleAuditContext{
		ActorOrgID:    actorOrg.ID,
		ActorID:       "usr_admin_usage_schedule",
		ActorKind:     "user",
		RequestID:     "req_admin_usage_schedule_store",
		CorrelationID: "corr_admin_usage_schedule_store",
		Reason:        "publish usage aggregation schedule",
	}

	schedule, err := svc.UpsertUsageAggregationSchedule(ctx, "http_requests_hourly", store.UpsertUsageAggregationScheduleInput{
		Source:                     "traefik",
		MetricKey:                  "http_requests_total",
		AggregationIntervalSeconds: 3600,
		ReplayLookbackSeconds:      86400,
		CloseDelaySeconds:          7200,
		LateEventMode:              store.LateEventModeAdjust,
		Enabled:                    true,
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertUsageAggregationSchedule create: %v", err)
	}
	if schedule.Version != 1 || !schedule.Enabled || schedule.AggregationIntervalSeconds != 3600 {
		t.Fatalf("created schedule = %+v", schedule)
	}

	updated, err := svc.UpsertUsageAggregationSchedule(ctx, "http_requests_hourly", store.UpsertUsageAggregationScheduleInput{
		Source:                     "traefik",
		MetricKey:                  "http_requests_total",
		AggregationIntervalSeconds: 1800,
		ReplayLookbackSeconds:      172800,
		CloseDelaySeconds:          3600,
		LateEventMode:              store.LateEventModeQuarantine,
		Enabled:                    true,
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertUsageAggregationSchedule update: %v", err)
	}
	if updated.Version != 2 || updated.AggregationIntervalSeconds != 1800 || updated.LateEventMode != store.LateEventModeQuarantine {
		t.Fatalf("updated schedule = %+v", updated)
	}

	repo := store.NewUsageAggregationScheduleRepository()
	var runtimeSchedules []store.UsageAggregationSchedule
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		runtimeSchedules, err = repo.ListRuntimeEnabled(ctx, q, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("ListRuntimeEnabled: %v", err)
	}
	if len(runtimeSchedules) != 1 || runtimeSchedules[0].Version != 2 || runtimeSchedules[0].ScheduleKey != "http_requests_hourly" {
		t.Fatalf("runtime schedules = %+v", runtimeSchedules)
	}

	disabled, err := svc.DisableUsageAggregationSchedule(ctx, "http_requests_hourly", auditCtx)
	if err != nil {
		t.Fatalf("DisableUsageAggregationSchedule: %v", err)
	}
	if disabled.Enabled {
		t.Fatalf("disabled schedule remains enabled: %+v", disabled)
	}
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		runtimeSchedules, err = repo.ListRuntimeEnabled(ctx, q, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("ListRuntimeEnabled after disable: %v", err)
	}
	if len(runtimeSchedules) != 0 {
		t.Fatalf("disabled schedule remained in runtime list: %+v", runtimeSchedules)
	}

	var eventCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id = $1 AND action LIKE 'admin.usage_aggregation_schedule.%'`, actorOrg.ID).Scan(&eventCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if eventCount != 3 {
		t.Fatalf("audit event count = %d, want 3", eventCount)
	}
}

func TestUsageAggregationScheduleRepositoryValidationAndNotFound(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStoreForAdminPlanTest(t, db)
	repo := store.NewUsageAggregationScheduleRepository()

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Upsert(ctx, tx, "bad-key", store.UpsertUsageAggregationScheduleInput{
			Source:                     "traefik",
			MetricKey:                  "http_requests_total",
			AggregationIntervalSeconds: 3600,
			LateEventMode:              store.LateEventModeAdjust,
			Enabled:                    true,
		})
		return err
	}); err == nil {
		t.Fatal("invalid schedule key was accepted")
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, "missing_schedule")
		return err
	}); err == nil {
		t.Fatal("missing schedule returned nil error")
	}
}

func newAdminUsageScheduleServiceForTest(t *testing.T, s *store.Store) *store.AdminUsageAggregationScheduleService {
	t.Helper()
	svc, err := store.NewAdminUsageAggregationScheduleService(s, store.NewOrganizationRepository(), store.NewUsageAggregationScheduleRepository(), store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewAdminUsageAggregationScheduleService: %v", err)
	}
	return svc
}
