package metering

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeContainerResolver map[string]ContainerResourceAttribution

func (f fakeContainerResolver) ResolveContainerService(_ context.Context, in ContainerResolveInput) (ContainerResourceAttribution, error) {
	attr, ok := f[in.ServiceID]
	if !ok {
		return ContainerResourceAttribution{}, ErrContainerAttributionNotFound
	}
	return attr, nil
}

func TestContainerAttributorAttributesByServiceLabel(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	attributor := NewContainerAttributor(fakeContainerResolver{
		"svc_web": {
			OrganizationID: "org_1",
			ProjectID:      "proj_1",
			EnvironmentID:  "env_1",
			ServiceID:      "svc_web",
			Source:         ContainerAttributionSourceLabel,
			Confidence:     ContainerAttributionConfidenceHigh,
		},
	})
	result, err := attributor.Attribute(context.Background(), ContainerAttributionInput{
		Samples: []ContainerMetricSample{{
			Name:        "container_cpu_millicore_seconds",
			ContainerID: "ctr_1",
			Value:       10,
			Unit:        "millicore_second",
			WindowStart: start,
			WindowEnd:   start.Add(time.Minute),
			Labels:      map[string]string{"yalla_service_id": "svc_web", "authorization": "Bearer should-not-leak"},
		}},
	})
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if len(result.Attributed) != 1 || len(result.Quarantined) != 0 {
		t.Fatalf("result = %+v, want one attributed sample", result)
	}
	got := result.Attributed[0]
	if got.OrganizationID != "org_1" || got.ProjectID != "proj_1" || got.EnvironmentID != "env_1" || got.ServiceID != "svc_web" {
		t.Fatalf("scope = %+v, want resolved service scope", got)
	}
	if got.Metadata["attribution_source"] != string(ContainerAttributionSourceLabel) || got.Metadata["attribution_confidence"] != string(ContainerAttributionConfidenceHigh) {
		t.Fatalf("metadata = %+v, want attribution source/confidence", got.Metadata)
	}
}

func TestContainerAttributorQuarantinesUnsafeSamples(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	attributor := NewContainerAttributor(fakeContainerResolver{})
	result, err := attributor.Attribute(context.Background(), ContainerAttributionInput{
		Samples: []ContainerMetricSample{
			{
				Name:        "container_cpu_millicore_seconds",
				ContainerID: "ctr_unmanaged",
				Value:       10,
				Unit:        "millicore_second",
				WindowStart: start,
				WindowEnd:   start.Add(time.Minute),
			},
			{
				Name:        "container_cpu_millicore_seconds",
				ContainerID: "ctr_missing_ref",
				Value:       10,
				Unit:        "millicore_second",
				WindowStart: start,
				WindowEnd:   start.Add(time.Minute),
				Labels:      map[string]string{"yalla_service_id": "svc_missing"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Attribute: %v", err)
	}
	if len(result.Attributed) != 0 || len(result.Quarantined) != 2 {
		t.Fatalf("result = %+v, want two quarantined samples", result)
	}
	if result.Quarantined[0].Reason != ContainerQuarantineUnmanagedResource || result.Quarantined[1].Reason != ContainerQuarantineMissingRef {
		t.Fatalf("quarantine reasons = %+v, want unmanaged then missing_ref", result.Quarantined)
	}
}

func TestContainerAttributorPropagatesDependencyFailures(t *testing.T) {
	t.Parallel()

	attributor := NewContainerAttributor(containerResolverFunc(func(context.Context, ContainerResolveInput) (ContainerResourceAttribution, error) {
		return ContainerResourceAttribution{}, errors.New("database down")
	}))
	_, err := attributor.Attribute(context.Background(), ContainerAttributionInput{
		Samples: []ContainerMetricSample{{
			Name:   "container_cpu_millicore_seconds",
			Labels: map[string]string{"service_id": "svc_web"},
		}},
	})
	if err == nil {
		t.Fatal("Attribute error = nil, want dependency failure")
	}
}

type containerResolverFunc func(context.Context, ContainerResolveInput) (ContainerResourceAttribution, error)

func (f containerResolverFunc) ResolveContainerService(ctx context.Context, in ContainerResolveInput) (ContainerResourceAttribution, error) {
	return f(ctx, in)
}
