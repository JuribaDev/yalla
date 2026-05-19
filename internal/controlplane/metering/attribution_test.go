package metering

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTraefikAttributorMapsKnownServiceSamples(t *testing.T) {
	t.Parallel()

	start := time.Unix(1770000000, 0).UTC()
	resolver := fakeTraefikResolver{
		byServiceID: map[string]TraefikResourceAttribution{
			"svc_valid": {
				OrganizationID: "org_alpha",
				ProjectID:      "proj_alpha",
				EnvironmentID:  "env_alpha",
				ServiceID:      "svc_valid",
				Source:         TraefikAttributionSourceLabel,
				Confidence:     TraefikAttributionConfidenceHigh,
			},
		},
	}
	attributor := NewTraefikAttributor(resolver)

	got, err := attributor.Attribute(context.Background(), TraefikAttributionInput{
		Samples: []TraefikMetricSample{{
			Name:        "http_requests",
			Service:     "traefik-generated-name",
			Value:       42,
			Unit:        "request",
			WindowStart: start,
			WindowEnd:   start.Add(time.Minute),
			Labels:      map[string]string{"yalla_service_id": "svc_valid"},
		}},
	})
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if len(got.Attributed) != 1 || len(got.Quarantined) != 0 {
		t.Fatalf("classified attributed=%d quarantined=%d, want 1/0", len(got.Attributed), len(got.Quarantined))
	}
	sample := got.Attributed[0]
	if sample.OrganizationID != "org_alpha" || sample.ProjectID != "proj_alpha" || sample.EnvironmentID != "env_alpha" || sample.ServiceID != "svc_valid" {
		t.Fatalf("resource scope = (%q,%q,%q,%q), want org/project/env/service", sample.OrganizationID, sample.ProjectID, sample.EnvironmentID, sample.ServiceID)
	}
	if sample.AttributionSource != TraefikAttributionSourceLabel || sample.Confidence != TraefikAttributionConfidenceHigh {
		t.Fatalf("attribution = (%q,%q), want label/high", sample.AttributionSource, sample.Confidence)
	}
	if sample.Metadata["traefik_service"] != "traefik-generated-name" || sample.Metadata["query_version"] != "" {
		t.Fatalf("metadata = %#v, want original service and no fabricated query version", sample.Metadata)
	}
}

func TestTraefikAttributorMapsRenamedDokployAppByEmbeddedServiceID(t *testing.T) {
	t.Parallel()

	resolver := fakeTraefikResolver{
		byServiceID: map[string]TraefikResourceAttribution{
			"svc_renamed": {
				OrganizationID: "org_alpha",
				ProjectID:      "proj_alpha",
				EnvironmentID:  "env_alpha",
				ServiceID:      "svc_renamed",
				Source:         TraefikAttributionSourceName,
				Confidence:     TraefikAttributionConfidenceMedium,
			},
		},
	}
	attributor := NewTraefikAttributor(resolver)

	got, err := attributor.Attribute(context.Background(), TraefikAttributionInput{
		Samples: []TraefikMetricSample{{
			Name:    "http_response_bytes",
			Service: "customer-renamed-yalla-svc_renamed",
			Value:   512,
			Unit:    "byte",
			Labels:  map[string]string{"appName": "customer-renamed-yalla-svc_renamed"},
		}},
	})
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if len(got.Attributed) != 1 || got.Attributed[0].ServiceID != "svc_renamed" {
		t.Fatalf("renamed app attributed = %#v, want service svc_renamed", got.Attributed)
	}
	if len(got.Quarantined) != 0 {
		t.Fatalf("renamed app quarantined = %#v, want none", got.Quarantined)
	}
}

func TestTraefikAttributorQuarantinesUnknownDeletedAndUnmanagedSamples(t *testing.T) {
	t.Parallel()

	resolver := fakeTraefikResolver{
		byServiceID: map[string]TraefikResourceAttribution{
			"svc_deleted": {
				OrganizationID: "org_alpha",
				ProjectID:      "proj_alpha",
				EnvironmentID:  "env_alpha",
				ServiceID:      "svc_deleted",
				Deleted:        true,
				Source:         TraefikAttributionSourceLabel,
				Confidence:     TraefikAttributionConfidenceHigh,
			},
		},
	}
	attributor := NewTraefikAttributor(resolver)

	got, err := attributor.Attribute(context.Background(), TraefikAttributionInput{
		Samples: []TraefikMetricSample{
			{Name: "http_requests", Service: "yalla-svc_missing", Value: 1, Unit: "request"},
			{Name: "http_requests", Service: "nginx@docker", Value: 2, Unit: "request"},
			{Name: "http_requests", Service: "anything", Value: 3, Unit: "request", Labels: map[string]string{"yalla_service_id": "svc_deleted"}},
		},
	})
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if len(got.Attributed) != 0 {
		t.Fatalf("attributed = %#v, want none", got.Attributed)
	}
	if len(got.Quarantined) != 3 {
		t.Fatalf("quarantined = %#v, want three samples", got.Quarantined)
	}
	wantReasons := map[TraefikQuarantineReason]bool{
		TraefikQuarantineMissingRef:        false,
		TraefikQuarantineUnmanagedResource: false,
		TraefikQuarantineDeletedService:    false,
	}
	for _, sample := range got.Quarantined {
		if _, ok := wantReasons[sample.Reason]; !ok {
			t.Fatalf("unexpected quarantine reason %q in %#v", sample.Reason, got.Quarantined)
		}
		wantReasons[sample.Reason] = true
		if sample.Sample.Value == 0 {
			t.Fatalf("quarantined sample lost source value: %#v", sample)
		}
	}
	for reason, seen := range wantReasons {
		if !seen {
			t.Fatalf("missing quarantine reason %q in %#v", reason, got.Quarantined)
		}
	}
}

func TestTraefikAttributorRejectsNilResolver(t *testing.T) {
	t.Parallel()

	_, err := NewTraefikAttributor(nil).Attribute(context.Background(), TraefikAttributionInput{
		Samples: []TraefikMetricSample{{Name: "http_requests", Service: "yalla-svc_valid"}},
	})
	if err == nil {
		t.Fatal("Attribute with nil resolver returned nil error")
	}
}

type fakeTraefikResolver struct {
	byServiceID map[string]TraefikResourceAttribution
}

func (f fakeTraefikResolver) ResolveTraefikService(ctx context.Context, in TraefikResolveInput) (TraefikResourceAttribution, error) {
	if in.ServiceID == "" {
		return TraefikResourceAttribution{}, ErrTraefikUnmanagedResource
	}
	attr, ok := f.byServiceID[in.ServiceID]
	if !ok {
		return TraefikResourceAttribution{}, ErrTraefikAttributionNotFound
	}
	if attr.ServiceID == "" {
		return TraefikResourceAttribution{}, errors.New("test resolver returned blank service id")
	}
	return attr, nil
}
