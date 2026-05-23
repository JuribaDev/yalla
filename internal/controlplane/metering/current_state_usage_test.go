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

func TestCurrentStateUsageEmitterWritesActiveDatabasesIdempotentlyAndAggregates(t *testing.T) {
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
		Name:           "active_databases",
		Value:          1,
		Unit:           "database",
		WindowStart:    start,
		WindowEnd:      start.Add(time.Hour),
		OrganizationID: seed.OrganizationID,
		ProjectID:      seed.ProjectID,
		EnvironmentID:  seed.EnvironmentID,
		ServiceID:      seed.ServiceID,
		Metadata:       map[string]string{"database_url": "postgres://secret:secret@db.internal:5432/app", "service_status": "active", "service_kind": "database"},
	}

	first, err := emitter.Emit(ctx, metering.CurrentStateUsageInput{
		Samples:   []metering.AttributedCurrentStateSample{sample},
		RequestID: "req_active_databases",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.CurrentStateUsageInput{
		Samples:   []metering.AttributedCurrentStateSample{sample},
		RequestID: "req_active_databases",
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
	if event.Resource != store.QuotaResourceActiveDatabases || event.Unit != "database" || event.Source != metering.CurrentStateUsageSource || event.Quantity != 1 {
		t.Fatalf("usage event = %+v, want active_databases database yalla_current_state quantity=1", event)
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
	if len(counters) != 1 || counters[0].Key != "active_databases" || counters[0].Unit != "database" || counters[0].Quantity != 1 {
		t.Fatalf("counters = %+v, want one active_databases counter quantity=1", counters)
	}
}

func TestCurrentStateUsageEmitterWritesActiveDomainsIdempotentlyAndAggregates(t *testing.T) {
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
		Name:           "active_domains",
		Value:          1,
		Unit:           "domain",
		WindowStart:    start,
		WindowEnd:      start.Add(time.Hour),
		OrganizationID: seed.OrganizationID,
		ProjectID:      seed.ProjectID,
		EnvironmentID:  seed.EnvironmentID,
		ServiceID:      seed.ServiceID,
		Metadata:       map[string]string{"hostname": "app.example.com", "tls_key": "yalla_sk_live_should_not_leak"},
	}

	first, err := emitter.Emit(ctx, metering.CurrentStateUsageInput{
		Samples:   []metering.AttributedCurrentStateSample{sample},
		RequestID: "req_active_domains",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.CurrentStateUsageInput{
		Samples:   []metering.AttributedCurrentStateSample{sample},
		RequestID: "req_active_domains",
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
	if event.Resource != store.QuotaResourceActiveDomains || event.Unit != "domain" || event.Source != metering.CurrentStateUsageSource || event.Quantity != 1 {
		t.Fatalf("usage event = %+v, want active_domains domain yalla_current_state quantity=1", event)
	}
	if event.OrganizationID != seed.OrganizationID || event.ProjectID != seed.ProjectID || event.EnvironmentID != seed.EnvironmentID || event.ServiceID != seed.ServiceID {
		t.Fatalf("usage event scope = %+v, want full attributed service scope", event)
	}
	if event.Metadata["tls_key"] != "[REDACTED]" {
		t.Fatalf("tls_key metadata = %q, want redacted", event.Metadata["tls_key"])
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
	if len(counters) != 1 || counters[0].Key != "active_domains" || counters[0].Unit != "domain" || counters[0].Quantity != 1 {
		t.Fatalf("counters = %+v, want one active_domains counter quantity=1", counters)
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

func TestCurrentStateUsageEmitterSkipsMissingActiveDatabasesData(t *testing.T) {
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
			{Name: "active_databases", Value: 1, Unit: "database", WindowStart: start, WindowEnd: start.Add(time.Hour), OrganizationID: seed.OrganizationID},
		},
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("events = %+v, want none for incomplete samples", result.Events)
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 0)
}

func TestCurrentStateUsageEmitterSkipsMissingActiveDomainsData(t *testing.T) {
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
			{Name: "active_domains", Value: 1, Unit: "domain", WindowStart: start, WindowEnd: start.Add(time.Hour), OrganizationID: seed.OrganizationID},
		},
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("events = %+v, want none for incomplete samples", result.Events)
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

func TestCurrentStateUsageEmitterKeepsActiveDatabasesTenantScoped(t *testing.T) {
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
			Name:           "active_databases",
			Value:          1,
			Unit:           "database",
			WindowStart:    start,
			WindowEnd:      start.Add(time.Hour),
			OrganizationID: alpha.OrganizationID,
			ProjectID:      bravo.ProjectID,
			EnvironmentID:  bravo.EnvironmentID,
			ServiceID:      bravo.ServiceID,
		}},
		RequestID: "req_cross_tenant_active_databases",
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}

func TestCurrentStateUsageEmitterKeepsActiveDomainsTenantScoped(t *testing.T) {
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
			Name:           "active_domains",
			Value:          1,
			Unit:           "domain",
			WindowStart:    start,
			WindowEnd:      start.Add(time.Hour),
			OrganizationID: alpha.OrganizationID,
			ProjectID:      bravo.ProjectID,
			EnvironmentID:  bravo.EnvironmentID,
			ServiceID:      bravo.ServiceID,
		}},
		RequestID: "req_cross_tenant_active_domains",
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

func TestBuildActiveDatabaseSampleCollectsOnlyActiveDatabaseRows(t *testing.T) {
	t.Parallel()

	windowStart := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(time.Hour)
	activeDatabase := store.Service{
		ID:             "svc_active_database_current_state",
		OrganizationID: "org_current_state",
		ProjectID:      "proj_current_state",
		EnvironmentID:  "env_current_state",
		Kind:           store.ServiceKindDatabase,
		Status:         store.ServiceStatusActive,
		Version:        7,
	}

	sample, ok, err := metering.BuildActiveDatabaseSample(activeDatabase, windowStart, windowEnd)
	if err != nil {
		t.Fatalf("BuildActiveDatabaseSample(active database): %v", err)
	}
	if !ok {
		t.Fatal("BuildActiveDatabaseSample(active database) ok=false, want active database sample")
	}
	if sample.Name != "active_databases" || sample.Value != 1 || sample.Unit != "database" || sample.ServiceID != activeDatabase.ID {
		t.Fatalf("sample = %+v, want active_databases quantity=1 for database service", sample)
	}
	if sample.Metadata["service_status"] != "active" || sample.Metadata["service_kind"] != "database" || sample.Metadata["service_version"] != "7" {
		t.Fatalf("sample metadata = %+v, want active database status/kind/version", sample.Metadata)
	}

	activeApplication := activeDatabase
	activeApplication.ID = "svc_active_application_current_state"
	activeApplication.Kind = store.ServiceKindApplication
	sample, ok, err = metering.BuildActiveDatabaseSample(activeApplication, windowStart, windowEnd)
	if err != nil {
		t.Fatalf("BuildActiveDatabaseSample(active application): %v", err)
	}
	if ok {
		t.Fatalf("BuildActiveDatabaseSample(active application) = %+v, true; want skipped", sample)
	}

	deletedDatabase := activeDatabase
	deletedDatabase.ID = "svc_deleted_database_current_state"
	deletedDatabase.Status = store.ServiceStatusDeleted
	sample, ok, err = metering.BuildActiveDatabaseSample(deletedDatabase, windowStart, windowEnd)
	if err != nil {
		t.Fatalf("BuildActiveDatabaseSample(deleted database): %v", err)
	}
	if ok {
		t.Fatalf("BuildActiveDatabaseSample(deleted database) = %+v, true; want skipped", sample)
	}
}

func TestBuildActiveDomainSampleCollectsOnlyActiveDomainRows(t *testing.T) {
	t.Parallel()

	windowStart := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(time.Hour)
	service := store.Service{
		ID:             "svc_active_domain_current_state",
		OrganizationID: "org_current_state",
		ProjectID:      "proj_current_state",
		EnvironmentID:  "env_current_state",
		Status:         store.ServiceStatusActive,
		Version:        7,
	}
	domain := store.ServiceDomain{
		ID:             "sdom_active_current_state",
		OrganizationID: service.OrganizationID,
		ServiceID:      service.ID,
		Hostname:       "app.example.com",
		Path:           "/",
		Version:        3,
	}

	sample, ok, err := metering.BuildActiveDomainSample(domain, service, windowStart, windowEnd)
	if err != nil {
		t.Fatalf("BuildActiveDomainSample(active domain): %v", err)
	}
	if !ok {
		t.Fatal("BuildActiveDomainSample(active domain) ok=false, want active domain sample")
	}
	if sample.Name != "active_domains" || sample.Value != 1 || sample.Unit != "domain" || sample.ServiceID != service.ID {
		t.Fatalf("sample = %+v, want active_domains quantity=1 for service domain", sample)
	}
	if sample.Metadata["domain_version"] != "3" || sample.Metadata["service_status"] != "active" {
		t.Fatalf("sample metadata = %+v, want active domain/service versions", sample.Metadata)
	}

	deletedService := service
	deletedService.Status = store.ServiceStatusDeleted
	sample, ok, err = metering.BuildActiveDomainSample(domain, deletedService, windowStart, windowEnd)
	if err != nil {
		t.Fatalf("BuildActiveDomainSample(deleted service): %v", err)
	}
	if ok {
		t.Fatalf("BuildActiveDomainSample(deleted service) = %+v, true; want skipped", sample)
	}

	foreignDomain := domain
	foreignDomain.ServiceID = "svc_foreign_current_state"
	sample, ok, err = metering.BuildActiveDomainSample(foreignDomain, service, windowStart, windowEnd)
	if err != nil {
		t.Fatalf("BuildActiveDomainSample(foreign service): %v", err)
	}
	if ok {
		t.Fatalf("BuildActiveDomainSample(foreign service) = %+v, true; want quarantined/skipped", sample)
	}
}
