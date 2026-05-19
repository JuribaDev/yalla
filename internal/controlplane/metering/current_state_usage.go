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

// CurrentStateUsageSource is the stable usage_events source for metrics
// collected from Yalla's current source-of-truth rows.
const CurrentStateUsageSource = "yalla_current_state"

// AttributedCurrentStateSample is safe to convert into a usage event when it
// carries the complete tenant scope for the resource being counted.
type AttributedCurrentStateSample struct {
	Name              string
	Value             float64
	Unit              string
	WindowStart       time.Time
	WindowEnd         time.Time
	RawSampleChecksum string
	OrganizationID    string
	ProjectID         string
	EnvironmentID     string
	ServiceID         string
	Metadata          map[string]string
}

// CurrentStateUsageInput is one current-state collection window ready for
// usage-event emission.
type CurrentStateUsageInput struct {
	Samples   []AttributedCurrentStateSample
	RequestID string
}

// CurrentStateUsageResult reports the usage_events accepted for the input
// window.
type CurrentStateUsageResult struct {
	Events []store.UsageEvent
}

// CurrentStateUsageEmitter writes current-state metrics as append-only
// usage_events. Unsafe or unsupported samples are skipped instead of emitted.
type CurrentStateUsageEmitter struct {
	store *store.Store
	usage *store.UsageEventRepository
}

// NewCurrentStateUsageEmitter builds a current-state usage emitter over store.
func NewCurrentStateUsageEmitter(s *store.Store) (*CurrentStateUsageEmitter, error) {
	if s == nil {
		return nil, errors.New("metering: nil store")
	}
	return &CurrentStateUsageEmitter{store: s, usage: store.NewUsageEventRepository()}, nil
}

// BuildActiveServiceSample converts one service source-of-truth row into an
// active_services sample. Terminal and non-live rows are skipped because they
// should not contribute to the active-service count.
func BuildActiveServiceSample(service store.Service, windowStart, windowEnd time.Time) (AttributedCurrentStateSample, bool, error) {
	if !windowEnd.After(windowStart) {
		return AttributedCurrentStateSample{}, false, apierr.InvalidInput(apierr.FieldViolation{Field: "window_end", Reason: "must be after window_start"})
	}
	if service.Status != store.ServiceStatusActive {
		return AttributedCurrentStateSample{}, false, nil
	}
	metadata := map[string]string{
		"service_status":  service.Status.String(),
		"service_version": strconv.FormatInt(service.Version, 10),
	}
	return AttributedCurrentStateSample{
		Name:           "active_services",
		Value:          1,
		Unit:           "service",
		WindowStart:    windowStart.UTC(),
		WindowEnd:      windowEnd.UTC(),
		OrganizationID: strings.TrimSpace(service.OrganizationID),
		ProjectID:      strings.TrimSpace(service.ProjectID),
		EnvironmentID:  strings.TrimSpace(service.EnvironmentID),
		ServiceID:      strings.TrimSpace(service.ID),
		Metadata:       metadata,
	}, true, nil
}

// BuildActiveDatabaseSample converts one database service source-of-truth row
// into an active_databases sample. Non-database or non-live services are
// skipped because they should not contribute to the active-database count.
func BuildActiveDatabaseSample(service store.Service, windowStart, windowEnd time.Time) (AttributedCurrentStateSample, bool, error) {
	if !windowEnd.After(windowStart) {
		return AttributedCurrentStateSample{}, false, apierr.InvalidInput(apierr.FieldViolation{Field: "window_end", Reason: "must be after window_start"})
	}
	if service.Status != store.ServiceStatusActive || service.Kind != store.ServiceKindDatabase {
		return AttributedCurrentStateSample{}, false, nil
	}
	metadata := map[string]string{
		"service_status":  service.Status.String(),
		"service_kind":    service.Kind,
		"service_version": strconv.FormatInt(service.Version, 10),
	}
	return AttributedCurrentStateSample{
		Name:           "active_databases",
		Value:          1,
		Unit:           "database",
		WindowStart:    windowStart.UTC(),
		WindowEnd:      windowEnd.UTC(),
		OrganizationID: strings.TrimSpace(service.OrganizationID),
		ProjectID:      strings.TrimSpace(service.ProjectID),
		EnvironmentID:  strings.TrimSpace(service.EnvironmentID),
		ServiceID:      strings.TrimSpace(service.ID),
		Metadata:       metadata,
	}, true, nil
}

// Emit appends idempotent usage events for current-state metrics.
func (e *CurrentStateUsageEmitter) Emit(ctx context.Context, in CurrentStateUsageInput) (CurrentStateUsageResult, error) {
	if e == nil || e.store == nil || e.usage == nil {
		return CurrentStateUsageResult{}, errors.New("metering: nil CurrentStateUsageEmitter")
	}
	result := CurrentStateUsageResult{Events: []store.UsageEvent{}}
	if len(in.Samples) == 0 {
		return result, nil
	}
	err := e.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, sample := range in.Samples {
			eventInput, ok, err := buildCurrentStateUsageEventInput(sample, in.RequestID)
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
		return CurrentStateUsageResult{}, err
	}
	return result, nil
}

func buildCurrentStateUsageEventInput(sample AttributedCurrentStateSample, requestID string) (store.AppendUsageEventInput, bool, error) {
	def, ok := LookupMetricDefinition(sample.Name)
	if !ok {
		return store.AppendUsageEventInput{}, false, nil
	}
	resource, ok := currentStateMetricResource(def.Key)
	if !ok {
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
	metadata := copyStringMap(sample.Metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadata["metric_key"] = def.Key
	metadata["window_start"] = sample.WindowStart.UTC().Format(time.RFC3339Nano)
	metadata["window_end"] = sample.WindowEnd.UTC().Format(time.RFC3339Nano)
	metadata["quantity"] = strconv.FormatFloat(sample.Value, 'f', -1, 64)
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
		IdempotencyKey: currentStateUsageIdempotencyKey(sample),
		RequestID:      strings.TrimSpace(requestID),
		Metadata:       metadata,
		OccurredAt:     sample.WindowEnd,
	}, true, nil
}

func currentStateMetricResource(key string) (store.QuotaResource, bool) {
	switch key {
	case "active_services":
		return store.QuotaResourceActiveServices, true
	case "active_databases":
		return store.QuotaResourceActiveDatabases, true
	default:
		return "", false
	}
}

func currentStateUsageIdempotencyKey(sample AttributedCurrentStateSample) string {
	checksum := sample.RawSampleChecksum
	if checksum == "" {
		checksum = "-"
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s",
		sample.Name,
		sample.ServiceID,
		sample.WindowStart.UTC().Format(time.RFC3339Nano),
		sample.WindowEnd.UTC().Format(time.RFC3339Nano),
		checksum,
	)
}
