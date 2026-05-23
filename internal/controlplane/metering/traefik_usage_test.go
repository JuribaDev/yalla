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

func TestTraefikUsageEmitterWritesHTTPRequestsUsageEventsIdempotently(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedTraefikSample{
		TraefikMetricSample: metering.TraefikMetricSample{
			Name:              "http_requests",
			Service:           "customer-yalla-" + seed.ServiceID,
			Status:            "200",
			Value:             42,
			Unit:              "request",
			WindowStart:       start,
			WindowEnd:         start.Add(time.Minute),
			QueryVersion:      "traefik-prom-v1",
			RawSampleChecksum: "abcdef123456",
			Labels:            map[string]string{"authorization": "Bearer should-not-leak"},
		},
		OrganizationID:    seed.OrganizationID,
		ProjectID:         seed.ProjectID,
		EnvironmentID:     seed.EnvironmentID,
		ServiceID:         seed.ServiceID,
		AttributionSource: metering.TraefikAttributionSourceLabel,
		Confidence:        metering.TraefikAttributionConfidenceHigh,
		Metadata:          map[string]string{"token": "must-redact", "route": "/"},
	}

	first, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_requests",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_requests",
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
	if event.Resource != store.QuotaResourceHTTPRequests || event.Unit != "request" || event.Source != metering.TraefikUsageSource || event.Quantity != 42 {
		t.Fatalf("usage event = %+v, want http_requests request traefik quantity=42", event)
	}
	if event.OrganizationID != seed.OrganizationID || event.ProjectID != seed.ProjectID || event.EnvironmentID != seed.EnvironmentID || event.ServiceID != seed.ServiceID {
		t.Fatalf("usage event scope = %+v, want full attributed service scope", event)
	}
	if event.RequestID != "req_http_requests" {
		t.Fatalf("RequestID = %q, want req_http_requests", event.RequestID)
	}
	if event.Metadata["token"] != "[REDACTED]" {
		t.Fatalf("token metadata = %q, want redacted", event.Metadata["token"])
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 1)
}

func TestTraefikUsageEmitterWritesHTTPRPSPeak1mUsageEventsIdempotently(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedTraefikSample{
		TraefikMetricSample: metering.TraefikMetricSample{
			Name:              "http_rps_peak_1m",
			Service:           "customer-yalla-" + seed.ServiceID,
			Value:             7.5,
			Unit:              "requests_per_second",
			WindowStart:       start,
			WindowEnd:         start.Add(time.Minute),
			QueryVersion:      "traefik-prom-v1",
			RawSampleChecksum: "rpspeakabcdef123456",
			Labels:            map[string]string{"authorization": "Bearer should-not-leak"},
		},
		OrganizationID:    seed.OrganizationID,
		ProjectID:         seed.ProjectID,
		EnvironmentID:     seed.EnvironmentID,
		ServiceID:         seed.ServiceID,
		AttributionSource: metering.TraefikAttributionSourceLabel,
		Confidence:        metering.TraefikAttributionConfidenceHigh,
		Metadata:          map[string]string{"token": "must-redact", "route": "/"},
	}

	first, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_rps_peak",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_rps_peak",
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
	if event.Resource != store.QuotaResourceHTTPRPSPeak1m || event.Unit != "requests_per_second" || event.Source != metering.TraefikUsageSource || event.Quantity != 7.5 {
		t.Fatalf("usage event = %+v, want http_rps_peak_1m requests_per_second traefik quantity=7.5", event)
	}
	if event.OrganizationID != seed.OrganizationID || event.ProjectID != seed.ProjectID || event.EnvironmentID != seed.EnvironmentID || event.ServiceID != seed.ServiceID {
		t.Fatalf("usage event scope = %+v, want full attributed service scope", event)
	}
	if event.Metadata["token"] != "[REDACTED]" {
		t.Fatalf("token metadata = %q, want redacted", event.Metadata["token"])
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 1)
}

func TestTraefikUsageEmitterWritesHTTP5xxCountUsageEventsIdempotently(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedTraefikSample{
		TraefikMetricSample: metering.TraefikMetricSample{
			Name:              "http_5xx_count",
			Service:           "customer-yalla-" + seed.ServiceID,
			Value:             3,
			Unit:              "response",
			WindowStart:       start,
			WindowEnd:         start.Add(time.Minute),
			QueryVersion:      "traefik-prom-v1",
			RawSampleChecksum: "fivehundredabcdef123456",
			Labels:            map[string]string{"cookie": "session=should-not-leak"},
		},
		OrganizationID:    seed.OrganizationID,
		ProjectID:         seed.ProjectID,
		EnvironmentID:     seed.EnvironmentID,
		ServiceID:         seed.ServiceID,
		AttributionSource: metering.TraefikAttributionSourceLabel,
		Confidence:        metering.TraefikAttributionConfidenceHigh,
		Metadata:          map[string]string{"api_key": "must-redact", "route": "/checkout"},
	}

	first, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_5xx_count",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_5xx_count",
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
	if event.Resource != store.QuotaResourceHTTP5xxCount || event.Unit != "response" || event.Source != metering.TraefikUsageSource || event.Quantity != 3 {
		t.Fatalf("usage event = %+v, want http_5xx_count response traefik quantity=3", event)
	}
	if event.OrganizationID != seed.OrganizationID || event.ProjectID != seed.ProjectID || event.EnvironmentID != seed.EnvironmentID || event.ServiceID != seed.ServiceID {
		t.Fatalf("usage event scope = %+v, want full attributed service scope", event)
	}
	if event.RequestID != "req_http_5xx_count" {
		t.Fatalf("RequestID = %q, want req_http_5xx_count", event.RequestID)
	}
	if event.Metadata["api_key"] != "[REDACTED]" {
		t.Fatalf("api_key metadata = %q, want redacted", event.Metadata["api_key"])
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 1)

	counters := store.NewUsageCounterRepository()
	var aggregation store.UsageCounterAggregationResult
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var aggregateErr error
		aggregation, aggregateErr = counters.AggregateUsageEvents(ctx, tx, store.AggregateUsageCountersInput{
			OrganizationID:     seed.OrganizationID,
			PeriodStart:        time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			PeriodEnd:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			AggregatedAt:       start.Add(2 * time.Minute),
			AggregationVersion: 1,
		})
		return aggregateErr
	}); err != nil {
		t.Fatalf("AggregateUsageEvents: %v", err)
	}
	if len(aggregation.Counters) != 1 {
		t.Fatalf("aggregated counters len = %d, want 1; got %+v", len(aggregation.Counters), aggregation.Counters)
	}
	counter := aggregation.Counters[0]
	if counter.Key != string(store.QuotaResourceHTTP5xxCount) || counter.Unit != "response" || counter.Source != metering.TraefikUsageSource || counter.Quantity != 3 {
		t.Fatalf("usage counter = %+v, want http_5xx_count response traefik quantity=3", counter)
	}
}

func TestTraefikUsageEmitterWritesLatencyP95MSUsageEventsIdempotently(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedTraefikSample{
		TraefikMetricSample: metering.TraefikMetricSample{
			Name:              "latency_p95_ms",
			Service:           "customer-yalla-" + seed.ServiceID,
			Value:             125,
			Unit:              "millisecond",
			WindowStart:       start,
			WindowEnd:         start.Add(time.Minute),
			QueryVersion:      "traefik-prom-v1",
			RawSampleChecksum: "latencyp95abcdef123456",
			Labels:            map[string]string{"authorization": "Bearer should-not-leak"},
		},
		OrganizationID:    seed.OrganizationID,
		ProjectID:         seed.ProjectID,
		EnvironmentID:     seed.EnvironmentID,
		ServiceID:         seed.ServiceID,
		AttributionSource: metering.TraefikAttributionSourceLabel,
		Confidence:        metering.TraefikAttributionConfidenceHigh,
		Metadata:          map[string]string{"token": "must-redact", "route": "/checkout"},
	}

	first, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_latency_p95_ms",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_latency_p95_ms",
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
	if event.Resource != store.QuotaResourceLatencyP95MS || event.Unit != "millisecond" || event.Source != metering.TraefikUsageSource || event.Quantity != 125 {
		t.Fatalf("usage event = %+v, want latency_p95_ms millisecond traefik quantity=125", event)
	}
	if event.OrganizationID != seed.OrganizationID || event.ProjectID != seed.ProjectID || event.EnvironmentID != seed.EnvironmentID || event.ServiceID != seed.ServiceID {
		t.Fatalf("usage event scope = %+v, want full attributed service scope", event)
	}
	if event.RequestID != "req_latency_p95_ms" {
		t.Fatalf("RequestID = %q, want req_latency_p95_ms", event.RequestID)
	}
	if event.Metadata["token"] != "[REDACTED]" {
		t.Fatalf("token metadata = %q, want redacted", event.Metadata["token"])
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 1)

	counters := store.NewUsageCounterRepository()
	var aggregation store.UsageCounterAggregationResult
	if err := s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var aggregateErr error
		aggregation, aggregateErr = counters.AggregateUsageEvents(ctx, tx, store.AggregateUsageCountersInput{
			OrganizationID:     seed.OrganizationID,
			PeriodStart:        time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			PeriodEnd:          time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
			AggregatedAt:       start.Add(2 * time.Minute),
			AggregationVersion: 1,
		})
		return aggregateErr
	}); err != nil {
		t.Fatalf("AggregateUsageEvents: %v", err)
	}
	if len(aggregation.Counters) != 1 {
		t.Fatalf("aggregated counters len = %d, want 1; got %+v", len(aggregation.Counters), aggregation.Counters)
	}
	counter := aggregation.Counters[0]
	if counter.Key != string(store.QuotaResourceLatencyP95MS) || counter.Unit != "millisecond" || counter.Source != metering.TraefikUsageSource || counter.Quantity != 125 {
		t.Fatalf("usage counter = %+v, want latency_p95_ms millisecond traefik quantity=125", counter)
	}
}

func TestTraefikUsageEmitterWritesHTTPResponseBytesUsageEventsIdempotently(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedTraefikSample{
		TraefikMetricSample: metering.TraefikMetricSample{
			Name:              "http_response_bytes",
			Service:           "customer-yalla-" + seed.ServiceID,
			Value:             2048,
			Unit:              "byte",
			WindowStart:       start,
			WindowEnd:         start.Add(time.Minute),
			QueryVersion:      "traefik-prom-v1",
			RawSampleChecksum: "respabcdef123456",
			Labels:            map[string]string{"cookie": "session=should-not-leak"},
		},
		OrganizationID:    seed.OrganizationID,
		ProjectID:         seed.ProjectID,
		EnvironmentID:     seed.EnvironmentID,
		ServiceID:         seed.ServiceID,
		AttributionSource: metering.TraefikAttributionSourceName,
		Confidence:        metering.TraefikAttributionConfidenceMedium,
		Metadata:          map[string]string{"api_key": "must-redact", "route": "/assets/app.js"},
	}

	first, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_response_bytes",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_response_bytes",
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
	if event.Resource != store.QuotaResourceHTTPResponseBytes || event.Unit != "byte" || event.Source != metering.TraefikUsageSource || event.Quantity != 2048 {
		t.Fatalf("usage event = %+v, want http_response_bytes byte traefik quantity=2048", event)
	}
	if event.OrganizationID != seed.OrganizationID || event.ProjectID != seed.ProjectID || event.EnvironmentID != seed.EnvironmentID || event.ServiceID != seed.ServiceID {
		t.Fatalf("usage event scope = %+v, want full attributed service scope", event)
	}
	if event.RequestID != "req_http_response_bytes" {
		t.Fatalf("RequestID = %q, want req_http_response_bytes", event.RequestID)
	}
	if event.Metadata["api_key"] != "[REDACTED]" {
		t.Fatalf("api_key metadata = %q, want redacted", event.Metadata["api_key"])
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 1)
}

func TestTraefikUsageEmitterWritesHTTPRequestBytesUsageEventsIdempotently(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedTraefikSample{
		TraefikMetricSample: metering.TraefikMetricSample{
			Name:              "http_request_bytes",
			Service:           "customer-yalla-" + seed.ServiceID,
			Value:             1536,
			Unit:              "byte",
			WindowStart:       start,
			WindowEnd:         start.Add(time.Minute),
			QueryVersion:      "traefik-prom-v1",
			RawSampleChecksum: "reqbytesabcdef123456",
			Labels:            map[string]string{"authorization": "Bearer should-not-leak"},
		},
		OrganizationID:    seed.OrganizationID,
		ProjectID:         seed.ProjectID,
		EnvironmentID:     seed.EnvironmentID,
		ServiceID:         seed.ServiceID,
		AttributionSource: metering.TraefikAttributionSourceLabel,
		Confidence:        metering.TraefikAttributionConfidenceHigh,
		Metadata:          map[string]string{"cookie": "session=must-redact", "route": "/api"},
	}

	first, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_request_bytes",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_request_bytes",
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
	if event.Resource != store.QuotaResourceHTTPRequestBytes || event.Unit != "byte" || event.Source != metering.TraefikUsageSource || event.Quantity != 1536 {
		t.Fatalf("usage event = %+v, want http_request_bytes byte traefik quantity=1536", event)
	}
	if event.OrganizationID != seed.OrganizationID || event.ProjectID != seed.ProjectID || event.EnvironmentID != seed.EnvironmentID || event.ServiceID != seed.ServiceID {
		t.Fatalf("usage event scope = %+v, want full attributed service scope", event)
	}
	if event.RequestID != "req_http_request_bytes" {
		t.Fatalf("RequestID = %q, want req_http_request_bytes", event.RequestID)
	}
	if event.Metadata["cookie"] != "[REDACTED]" {
		t.Fatalf("cookie metadata = %q, want redacted", event.Metadata["cookie"])
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 1)
}

func TestTraefikUsageEmitterWritesHTTPBandwidthTotalUsageEventsIdempotently(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	sample := metering.AttributedTraefikSample{
		TraefikMetricSample: metering.TraefikMetricSample{
			Name:              "http_bandwidth_total",
			Service:           "customer-yalla-" + seed.ServiceID,
			Value:             3584,
			Unit:              "byte",
			WindowStart:       start,
			WindowEnd:         start.Add(time.Minute),
			QueryVersion:      "traefik-prom-v1",
			RawSampleChecksum: "bandwidthabcdef123456",
			Labels:            map[string]string{"authorization": "Bearer should-not-leak"},
		},
		OrganizationID:    seed.OrganizationID,
		ProjectID:         seed.ProjectID,
		EnvironmentID:     seed.EnvironmentID,
		ServiceID:         seed.ServiceID,
		AttributionSource: metering.TraefikAttributionSourceLabel,
		Confidence:        metering.TraefikAttributionConfidenceHigh,
		Metadata:          map[string]string{"api_key": "must-redact", "route": "/download"},
	}

	first, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_bandwidth_total",
	})
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples:   []metering.AttributedTraefikSample{sample},
		RequestID: "req_http_bandwidth_total",
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
	if event.Resource != store.QuotaResourceHTTPBandwidthTotal || event.Unit != "byte" || event.Source != metering.TraefikUsageSource || event.Quantity != 3584 {
		t.Fatalf("usage event = %+v, want http_bandwidth_total byte traefik quantity=3584", event)
	}
	if event.OrganizationID != seed.OrganizationID || event.ProjectID != seed.ProjectID || event.EnvironmentID != seed.EnvironmentID || event.ServiceID != seed.ServiceID {
		t.Fatalf("usage event scope = %+v, want full attributed service scope", event)
	}
	if event.RequestID != "req_http_bandwidth_total" {
		t.Fatalf("RequestID = %q, want req_http_bandwidth_total", event.RequestID)
	}
	if event.Metadata["api_key"] != "[REDACTED]" {
		t.Fatalf("api_key metadata = %q, want redacted", event.Metadata["api_key"])
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 1)
}

func TestTraefikUsageEmitterSkipsUnsupportedOrUnsafeSamples(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	seed := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	result, err := emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples: []metering.AttributedTraefikSample{
			{
				TraefikMetricSample: metering.TraefikMetricSample{Name: "http_request_duration_seconds_bucket", Value: 4, Unit: "observation", WindowStart: start, WindowEnd: start.Add(time.Minute)},
				OrganizationID:      seed.OrganizationID,
				ProjectID:           seed.ProjectID,
				EnvironmentID:       seed.EnvironmentID,
				ServiceID:           seed.ServiceID,
			},
			{
				TraefikMetricSample: metering.TraefikMetricSample{Name: "http_requests", Value: 1, Unit: "request", WindowStart: start, WindowEnd: start.Add(time.Minute)},
				OrganizationID:      seed.OrganizationID,
			},
		},
	})
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if len(result.Events) != 0 {
		t.Fatalf("events = %+v, want none for non-billing/incomplete scope samples", result.Events)
	}
	assertUsageEventCount(t, db, seed.OrganizationID, 0)
}

func TestTraefikUsageEmitterKeepsHTTPResponseBytesTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedMeteringHierarchy(t, db, f)
	bravo := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	_, err = emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples: []metering.AttributedTraefikSample{{
			TraefikMetricSample: metering.TraefikMetricSample{
				Name:              "http_response_bytes",
				Service:           "customer-yalla-" + bravo.ServiceID,
				Value:             1024,
				Unit:              "byte",
				WindowStart:       start,
				WindowEnd:         start.Add(time.Minute),
				RawSampleChecksum: "cross-tenant-response-bytes",
			},
			OrganizationID:    alpha.OrganizationID,
			ProjectID:         bravo.ProjectID,
			EnvironmentID:     bravo.EnvironmentID,
			ServiceID:         bravo.ServiceID,
			AttributionSource: metering.TraefikAttributionSourceLabel,
			Confidence:        metering.TraefikAttributionConfidenceHigh,
		}},
		RequestID: "req_cross_tenant_response_bytes",
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}

func TestTraefikUsageEmitterKeepsHTTPRequestBytesTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedMeteringHierarchy(t, db, f)
	bravo := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	_, err = emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples: []metering.AttributedTraefikSample{{
			TraefikMetricSample: metering.TraefikMetricSample{
				Name:              "http_request_bytes",
				Service:           "customer-yalla-" + bravo.ServiceID,
				Value:             512,
				Unit:              "byte",
				WindowStart:       start,
				WindowEnd:         start.Add(time.Minute),
				RawSampleChecksum: "cross-tenant-request-bytes",
			},
			OrganizationID:    alpha.OrganizationID,
			ProjectID:         bravo.ProjectID,
			EnvironmentID:     bravo.EnvironmentID,
			ServiceID:         bravo.ServiceID,
			AttributionSource: metering.TraefikAttributionSourceLabel,
			Confidence:        metering.TraefikAttributionConfidenceHigh,
		}},
		RequestID: "req_cross_tenant_request_bytes",
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}

func TestTraefikUsageEmitterKeepsHTTPBandwidthTotalTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedMeteringHierarchy(t, db, f)
	bravo := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	_, err = emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples: []metering.AttributedTraefikSample{{
			TraefikMetricSample: metering.TraefikMetricSample{
				Name:              "http_bandwidth_total",
				Service:           "customer-yalla-" + bravo.ServiceID,
				Value:             4096,
				Unit:              "byte",
				WindowStart:       start,
				WindowEnd:         start.Add(time.Minute),
				RawSampleChecksum: "cross-tenant-bandwidth-total",
			},
			OrganizationID:    alpha.OrganizationID,
			ProjectID:         bravo.ProjectID,
			EnvironmentID:     bravo.EnvironmentID,
			ServiceID:         bravo.ServiceID,
			AttributionSource: metering.TraefikAttributionSourceLabel,
			Confidence:        metering.TraefikAttributionConfidenceHigh,
		}},
		RequestID: "req_cross_tenant_bandwidth_total",
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}

func TestTraefikUsageEmitterKeepsHTTPRPSPeak1mTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedMeteringHierarchy(t, db, f)
	bravo := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	_, err = emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples: []metering.AttributedTraefikSample{{
			TraefikMetricSample: metering.TraefikMetricSample{
				Name:              "http_rps_peak_1m",
				Service:           "customer-yalla-" + bravo.ServiceID,
				Value:             6.25,
				Unit:              "requests_per_second",
				WindowStart:       start,
				WindowEnd:         start.Add(time.Minute),
				RawSampleChecksum: "cross-tenant-rps-peak",
			},
			OrganizationID:    alpha.OrganizationID,
			ProjectID:         bravo.ProjectID,
			EnvironmentID:     bravo.EnvironmentID,
			ServiceID:         bravo.ServiceID,
			AttributionSource: metering.TraefikAttributionSourceLabel,
			Confidence:        metering.TraefikAttributionConfidenceHigh,
		}},
		RequestID: "req_cross_tenant_rps_peak",
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}

func TestTraefikUsageEmitterKeepsLatencyP95MSTenantScoped(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	ctx := context.Background()

	alpha := seedMeteringHierarchy(t, db, f)
	bravo := seedMeteringHierarchy(t, db, f)
	emitter, err := metering.NewTraefikUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewTraefikUsageEmitter: %v", err)
	}
	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	_, err = emitter.Emit(ctx, metering.TraefikUsageInput{
		Samples: []metering.AttributedTraefikSample{{
			TraefikMetricSample: metering.TraefikMetricSample{
				Name:              "latency_p95_ms",
				Service:           "customer-yalla-" + bravo.ServiceID,
				Value:             150,
				Unit:              "millisecond",
				WindowStart:       start,
				WindowEnd:         start.Add(time.Minute),
				RawSampleChecksum: "cross-tenant-latency-p95",
			},
			OrganizationID:    alpha.OrganizationID,
			ProjectID:         bravo.ProjectID,
			EnvironmentID:     bravo.EnvironmentID,
			ServiceID:         bravo.ServiceID,
			AttributionSource: metering.TraefikAttributionSourceLabel,
			Confidence:        metering.TraefikAttributionConfidenceHigh,
		}},
		RequestID: "req_cross_tenant_latency_p95",
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}
