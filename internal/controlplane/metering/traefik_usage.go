package metering

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// TraefikUsageSource is the stable usage_events source for Traefik metrics.
const TraefikUsageSource = "traefik"

// TraefikUsageInput is one attributed Traefik collection window ready for
// billing-grade event emission.
type TraefikUsageInput struct {
	Samples   []AttributedTraefikSample
	RequestID string
}

// TraefikUsageResult reports the usage_events accepted for the input window.
type TraefikUsageResult struct {
	Events []store.UsageEvent
}

// TraefikUsageEmitter writes billing-grade Traefik samples as append-only
// usage_events. Quarantine decisions happen before this layer; samples with an
// incomplete tenant scope are skipped instead of becoming billable.
type TraefikUsageEmitter struct {
	store *store.Store
	usage *store.UsageEventRepository
}

// NewTraefikUsageEmitter builds a Traefik usage emitter over store.
func NewTraefikUsageEmitter(s *store.Store) (*TraefikUsageEmitter, error) {
	if s == nil {
		return nil, errors.New("metering: nil store")
	}
	return &TraefikUsageEmitter{store: s, usage: store.NewUsageEventRepository()}, nil
}

// Emit appends idempotent usage events for billing-grade Traefik metrics.
func (e *TraefikUsageEmitter) Emit(ctx context.Context, in TraefikUsageInput) (TraefikUsageResult, error) {
	if e == nil || e.store == nil || e.usage == nil {
		return TraefikUsageResult{}, errors.New("metering: nil TraefikUsageEmitter")
	}
	result := TraefikUsageResult{Events: []store.UsageEvent{}}
	if len(in.Samples) == 0 {
		return result, nil
	}
	err := e.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, sample := range in.Samples {
			eventInput, ok, err := buildTraefikUsageEventInput(sample, in.RequestID)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			event, appendErr := e.usage.Append(ctx, tx, eventInput)
			if appendErr != nil {
				return appendErr
			}
			result.Events = append(result.Events, event)
		}
		return nil
	})
	if err != nil {
		return TraefikUsageResult{}, err
	}
	return result, nil
}

func buildTraefikUsageEventInput(sample AttributedTraefikSample, requestID string) (store.AppendUsageEventInput, bool, error) {
	def, ok := LookupMetricDefinition(sample.Name)
	if !ok || !def.BillingGrade {
		return store.AppendUsageEventInput{}, false, nil
	}
	if sample.OrganizationID == "" || sample.ProjectID == "" || sample.EnvironmentID == "" || sample.ServiceID == "" {
		return store.AppendUsageEventInput{}, false, nil
	}
	if sample.Unit != def.Unit {
		return store.AppendUsageEventInput{}, false, apierr.InvalidInput(apierr.FieldViolation{Field: "samples.unit", Reason: "must match metric definition"})
	}
	if !sample.WindowEnd.After(sample.WindowStart) {
		return store.AppendUsageEventInput{}, false, apierr.InvalidInput(apierr.FieldViolation{Field: "samples.window_end", Reason: "must be after window_start"})
	}
	resource, ok := metricResource(def.Key)
	if !ok {
		return store.AppendUsageEventInput{}, false, nil
	}
	metadata := copyStringMap(sample.Metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadata["metric_key"] = def.Key
	metadata["window_start"] = sample.WindowStart.UTC().Format(time.RFC3339Nano)
	metadata["window_end"] = sample.WindowEnd.UTC().Format(time.RFC3339Nano)
	metadata["quantity"] = strconv.FormatFloat(sample.Value, 'f', -1, 64)
	idempotencyKey := traefikUsageIdempotencyKey(sample)
	return store.AppendUsageEventInput{
		OrganizationID: sample.OrganizationID,
		ProjectID:      sample.ProjectID,
		EnvironmentID:  sample.EnvironmentID,
		ServiceID:      sample.ServiceID,
		Resource:       resource,
		EventType:      store.UsageEventTypeConsumed,
		Quantity:       sample.Value,
		Unit:           def.Unit,
		Source:         def.Source,
		IdempotencyKey: idempotencyKey,
		RequestID:      strings.TrimSpace(requestID),
		Metadata:       metadata,
		OccurredAt:     sample.WindowEnd,
	}, true, nil
}

func metricResource(key string) (store.QuotaResource, bool) {
	switch key {
	case "http_requests":
		return store.QuotaResourceHTTPRequests, true
	case "http_response_bytes":
		return store.QuotaResourceHTTPResponseBytes, true
	default:
		return "", false
	}
}

func traefikUsageIdempotencyKey(sample AttributedTraefikSample) string {
	status := sample.Status
	if status == "" {
		status = "-"
	}
	bucket := sample.Bucket
	if bucket == "" {
		bucket = "-"
	}
	checksum := sample.RawSampleChecksum
	if checksum == "" {
		checksum = "-"
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s",
		sample.Name,
		sample.ServiceID,
		sample.WindowStart.UTC().Format(time.RFC3339Nano),
		sample.WindowEnd.UTC().Format(time.RFC3339Nano),
		status,
		bucket,
		checksum,
	)
}
