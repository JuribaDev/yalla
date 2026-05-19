package metering_test

import (
	"context"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/metering"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
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

func TestTraefikUsageEmitterSkipsNonBillingOrUnsafeSamples(t *testing.T) {
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
				TraefikMetricSample: metering.TraefikMetricSample{Name: "http_rps_peak_1m", Value: 4, Unit: "requests_per_second", WindowStart: start, WindowEnd: start.Add(time.Minute)},
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
