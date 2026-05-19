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

// ContainerUsageSource is the stable usage_events source for container
// resource metrics collected from Dokploy-compatible or cAdvisor-compatible
// sources.
const ContainerUsageSource = "dokploy_or_cadvisor"

// ContainerMetricSample is one normalized, bounded container metric window
// before billing-grade emission. Attribution happens before this emitter.
type ContainerMetricSample struct {
	Name              string
	ContainerID       string
	Value             float64
	Unit              string
	WindowStart       time.Time
	WindowEnd         time.Time
	Source            string
	QueryVersion      string
	RawSampleChecksum string
	Labels            map[string]string
}

// AttributedContainerSample is safe to convert into a usage event when it
// carries the complete tenant scope.
type AttributedContainerSample struct {
	ContainerMetricSample
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Metadata       map[string]string
}

// ContainerUsageInput is one attributed container collection window ready for
// billing-grade event emission.
type ContainerUsageInput struct {
	Samples   []AttributedContainerSample
	RequestID string
}

// ContainerUsageResult reports the usage_events accepted for the input window.
type ContainerUsageResult struct {
	Events []store.UsageEvent
}

// ContainerUsageEmitter writes billing-grade container samples as append-only
// usage_events. Unsafe or unsupported samples are skipped instead of billed.
type ContainerUsageEmitter struct {
	store *store.Store
	usage *store.UsageEventRepository
}

// NewContainerUsageEmitter builds a container usage emitter over store.
func NewContainerUsageEmitter(s *store.Store) (*ContainerUsageEmitter, error) {
	if s == nil {
		return nil, errors.New("metering: nil store")
	}
	return &ContainerUsageEmitter{store: s, usage: store.NewUsageEventRepository()}, nil
}

// Emit appends idempotent usage events for billing-grade container metrics.
func (e *ContainerUsageEmitter) Emit(ctx context.Context, in ContainerUsageInput) (ContainerUsageResult, error) {
	if e == nil || e.store == nil || e.usage == nil {
		return ContainerUsageResult{}, errors.New("metering: nil ContainerUsageEmitter")
	}
	result := ContainerUsageResult{Events: []store.UsageEvent{}}
	if len(in.Samples) == 0 {
		return result, nil
	}
	err := e.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, sample := range in.Samples {
			eventInput, ok, err := buildContainerUsageEventInput(sample, in.RequestID)
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
		return ContainerUsageResult{}, err
	}
	return result, nil
}

func buildContainerUsageEventInput(sample AttributedContainerSample, requestID string) (store.AppendUsageEventInput, bool, error) {
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
	resource, ok := containerMetricResource(def.Key)
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
	if source := strings.TrimSpace(sample.Source); source != "" {
		metadata["source_adapter"] = source
	}
	if qv := strings.TrimSpace(sample.QueryVersion); qv != "" {
		metadata["query_version"] = qv
	}
	if containerID := strings.TrimSpace(sample.ContainerID); containerID != "" {
		metadata["container_id"] = containerID
	}
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
		IdempotencyKey: containerUsageIdempotencyKey(sample),
		RequestID:      strings.TrimSpace(requestID),
		Metadata:       metadata,
		OccurredAt:     sample.WindowEnd,
	}, true, nil
}

func containerMetricResource(key string) (store.QuotaResource, bool) {
	switch key {
	case "container_cpu_millicore_seconds":
		return store.QuotaResourceContainerCPUMillicoreSeconds, true
	default:
		return "", false
	}
}

func containerUsageIdempotencyKey(sample AttributedContainerSample) string {
	containerID := sample.ContainerID
	if containerID == "" {
		containerID = "-"
	}
	checksum := sample.RawSampleChecksum
	if checksum == "" {
		checksum = "-"
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		sample.Name,
		sample.ServiceID,
		containerID,
		sample.WindowStart.UTC().Format(time.RFC3339Nano),
		sample.WindowEnd.UTC().Format(time.RFC3339Nano),
		checksum,
	)
}
