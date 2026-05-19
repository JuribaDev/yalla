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

// StorageUsageSource is the stable usage_events source for storage metrics
// collected by Yalla volume scanners.
const StorageUsageSource = "volume_scanner"

// StorageMetricSample is one normalized, bounded storage metric window before
// billing-grade emission. Attribution happens before this emitter.
type StorageMetricSample struct {
	Name              string
	VolumeID          string
	Value             float64
	Unit              string
	WindowStart       time.Time
	WindowEnd         time.Time
	Source            string
	QueryVersion      string
	RawSampleChecksum string
	Labels            map[string]string
}

// AttributedStorageSample is safe to convert into a usage event when it carries
// the complete tenant scope.
type AttributedStorageSample struct {
	StorageMetricSample
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Metadata       map[string]string
}

// StorageUsageInput is one attributed storage collection window ready for
// billing-grade event emission.
type StorageUsageInput struct {
	Samples   []AttributedStorageSample
	RequestID string
}

// StorageUsageResult reports the usage_events accepted for the input window.
type StorageUsageResult struct {
	Events []store.UsageEvent
}

// StorageUsageEmitter writes billing-grade storage samples as append-only
// usage_events. Unsafe or unsupported samples are skipped instead of billed.
type StorageUsageEmitter struct {
	store *store.Store
	usage *store.UsageEventRepository
}

// NewStorageUsageEmitter builds a storage usage emitter over store.
func NewStorageUsageEmitter(s *store.Store) (*StorageUsageEmitter, error) {
	if s == nil {
		return nil, errors.New("metering: nil store")
	}
	return &StorageUsageEmitter{store: s, usage: store.NewUsageEventRepository()}, nil
}

// Emit appends idempotent usage events for billing-grade storage metrics.
func (e *StorageUsageEmitter) Emit(ctx context.Context, in StorageUsageInput) (StorageUsageResult, error) {
	if e == nil || e.store == nil || e.usage == nil {
		return StorageUsageResult{}, errors.New("metering: nil StorageUsageEmitter")
	}
	result := StorageUsageResult{Events: []store.UsageEvent{}}
	if len(in.Samples) == 0 {
		return result, nil
	}
	err := e.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, sample := range in.Samples {
			eventInput, ok, err := buildStorageUsageEventInput(sample, in.RequestID)
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
		return StorageUsageResult{}, err
	}
	return result, nil
}

func buildStorageUsageEventInput(sample AttributedStorageSample, requestID string) (store.AppendUsageEventInput, bool, error) {
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
	resource, ok := storageMetricResource(def.Key)
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
	if volumeID := strings.TrimSpace(sample.VolumeID); volumeID != "" {
		metadata["volume_id"] = volumeID
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
		IdempotencyKey: storageUsageIdempotencyKey(sample),
		RequestID:      strings.TrimSpace(requestID),
		Metadata:       metadata,
		OccurredAt:     sample.WindowEnd,
	}, true, nil
}

func storageMetricResource(key string) (store.QuotaResource, bool) {
	switch key {
	case "storage_gb_month":
		return store.QuotaResourceStorageGBMonth, true
	default:
		return "", false
	}
}

func storageUsageIdempotencyKey(sample AttributedStorageSample) string {
	volumeID := sample.VolumeID
	if volumeID == "" {
		volumeID = "-"
	}
	checksum := sample.RawSampleChecksum
	if checksum == "" {
		checksum = "-"
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		sample.Name,
		sample.ServiceID,
		volumeID,
		sample.WindowStart.UTC().Format(time.RFC3339Nano),
		sample.WindowEnd.UTC().Format(time.RFC3339Nano),
		checksum,
	)
}
