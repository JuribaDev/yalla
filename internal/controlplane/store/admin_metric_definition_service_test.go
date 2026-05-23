package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
)

func TestAdminMetricDefinitionServiceCreateVersionDisableAndRuntimeReload(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	f := testutil.NewFactory(t)
	actorOrg := seedOrg(t, db, f, "AdminMetricDefinitionActor")
	s := newStoreForAdminPlanTest(t, db)
	svc := newAdminMetricDefinitionServiceForTest(t, s)
	auditCtx := store.AdminMetricDefinitionAuditContext{
		ActorOrgID:    actorOrg.ID,
		ActorID:       "usr_admin_metric_definition",
		ActorKind:     "user",
		RequestID:     "req_admin_metric_definition_store",
		CorrelationID: "corr_admin_metric_definition_store",
		Reason:        "publish tracked metric definition",
	}

	def, err := svc.UpsertMetricDefinition(ctx, "http_rps_peak_1m", store.UpsertMetricDefinitionInput{
		Unit:                     "request_per_second",
		Source:                   "traefik",
		AggregationFunction:      store.MetricAggregationMax,
		AggregationWindowSeconds: 60,
		BillingGrade:             true,
		RetentionDays:            400,
		EnforcementLink:          "http_rps_peak_1m",
		Enabled:                  true,
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertMetricDefinition create: %v", err)
	}
	if def.Version != 1 || !def.Enabled || !def.BillingGrade {
		t.Fatalf("created definition = %+v", def)
	}

	if _, err := svc.UpsertMetricDefinition(ctx, "http_rps_peak_1m", store.UpsertMetricDefinitionInput{
		Unit:                     "request",
		Source:                   "traefik",
		AggregationFunction:      store.MetricAggregationMax,
		AggregationWindowSeconds: 60,
		BillingGrade:             true,
		RetentionDays:            400,
		EnforcementLink:          "http_rps_peak_1m",
		Enabled:                  true,
	}, auditCtx); err == nil {
		t.Fatal("unsafe billing-grade unit change without AllowNewVersion succeeded")
	}

	versioned, err := svc.UpsertMetricDefinition(ctx, "http_rps_peak_1m", store.UpsertMetricDefinitionInput{
		Unit:                     "request",
		Source:                   "traefik",
		AggregationFunction:      store.MetricAggregationMax,
		AggregationWindowSeconds: 60,
		BillingGrade:             true,
		RetentionDays:            400,
		EnforcementLink:          "http_rps_peak_1m",
		Enabled:                  true,
		AllowNewVersion:          true,
	}, auditCtx)
	if err != nil {
		t.Fatalf("UpsertMetricDefinition versioned: %v", err)
	}
	if versioned.Version != 2 || versioned.Unit != "request" {
		t.Fatalf("versioned definition = %+v", versioned)
	}

	repo := store.NewMetricDefinitionRepository()
	var runtimeDefs []store.MetricDefinition
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		runtimeDefs, err = repo.ListRuntimePublished(ctx, q, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("ListRuntimePublished: %v", err)
	}
	if len(runtimeDefs) != 1 || runtimeDefs[0].Version != 2 || runtimeDefs[0].Key != "http_rps_peak_1m" {
		t.Fatalf("runtime definitions = %+v", runtimeDefs)
	}

	disabled, err := svc.DisableMetricDefinition(ctx, "http_rps_peak_1m", auditCtx)
	if err != nil {
		t.Fatalf("DisableMetricDefinition: %v", err)
	}
	if disabled.Enabled {
		t.Fatalf("disabled definition remains enabled: %+v", disabled)
	}
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		runtimeDefs, err = repo.ListRuntimePublished(ctx, q, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("ListRuntimePublished after disable: %v", err)
	}
	if len(runtimeDefs) != 0 {
		t.Fatalf("disabled definition remained in runtime list: %+v", runtimeDefs)
	}

	var eventCount int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id = $1 AND action LIKE 'admin.metric_definition.%'`, actorOrg.ID).Scan(&eventCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if eventCount != 3 {
		t.Fatalf("audit event count = %d, want 3", eventCount)
	}
}

func TestMetricDefinitionRepositoryValidationAndNotFound(t *testing.T) {
	ctx := context.Background()
	db := testutil.RequireMigratedDB(t)
	s := newStoreForAdminPlanTest(t, db)
	repo := store.NewMetricDefinitionRepository()

	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := repo.Upsert(ctx, tx, "bad-key", store.UpsertMetricDefinitionInput{
			Unit:                "request",
			Source:              "traefik",
			AggregationFunction: store.MetricAggregationSum,
			Enabled:             true,
		})
		return err
	}); err == nil {
		t.Fatal("invalid metric key was accepted")
	}

	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		_, err := repo.Get(ctx, q, "missing_metric")
		return err
	}); err == nil {
		t.Fatal("missing metric definition returned nil error")
	}
}

func newAdminMetricDefinitionServiceForTest(t *testing.T, s *store.Store) *store.AdminMetricDefinitionService {
	t.Helper()
	svc, err := store.NewAdminMetricDefinitionService(s, store.NewOrganizationRepository(), store.NewMetricDefinitionRepository(), store.NewAuditRepository())
	if err != nil {
		t.Fatalf("NewAdminMetricDefinitionService: %v", err)
	}
	return svc
}
