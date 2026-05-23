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
	EventType      store.UsageEventType
	Metadata       map[string]string
}

// StorageGBMonthSampleInput describes one bounded persistent-storage sample.
// SizeBytes is converted to GB-months by prorating its overlap with the
// billing period and the resource lifetime.
type StorageGBMonthSampleInput struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	VolumeID       string
	SizeBytes      int64
	WindowStart    time.Time
	WindowEnd      time.Time
	PeriodStart    time.Time
	PeriodEnd      time.Time
	CreatedAt      time.Time
	DeletedAt      *time.Time
	Source         string
	QueryVersion   string
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
	eventType := sample.EventType
	if eventType == "" {
		eventType = store.UsageEventTypeConsumed
	}
	metadata["event_type"] = string(eventType)
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
		EventType:      eventType,
		Quantity:       sample.Value,
		Unit:           def.Unit,
		Source:         def.Source,
		IdempotencyKey: storageUsageIdempotencyKey(sample),
		RequestID:      strings.TrimSpace(requestID),
		Metadata:       metadata,
		OccurredAt:     sample.WindowEnd,
	}, true, nil
}

// BuildStorageGBMonthSample converts a point-in-time storage-size observation
// into a billing-period prorated GB-month sample. It returns ok=false when the
// window has no overlap with the resource's lifetime in the target period.
func BuildStorageGBMonthSample(in StorageGBMonthSampleInput) (AttributedStorageSample, bool, error) {
	start, end, ok, err := meteringWindowOverlap(in.WindowStart, in.WindowEnd, in.PeriodStart, in.PeriodEnd, in.CreatedAt, in.DeletedAt)
	if err != nil || !ok {
		return AttributedStorageSample{}, false, err
	}
	if in.SizeBytes < 0 {
		return AttributedStorageSample{}, false, apierr.InvalidInput(apierr.FieldViolation{Field: "size_bytes", Reason: "must be non-negative"})
	}
	quantity := bytesToGBMonth(in.SizeBytes, start, end, in.PeriodStart, in.PeriodEnd)
	metadata := copyStringMap(in.Metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadata["period_start"] = in.PeriodStart.UTC().Format(time.RFC3339Nano)
	metadata["period_end"] = in.PeriodEnd.UTC().Format(time.RFC3339Nano)
	metadata["size_bytes"] = strconv.FormatInt(in.SizeBytes, 10)
	metadata["resource_lifecycle"] = "active"
	if in.DeletedAt != nil && in.DeletedAt.After(in.PeriodStart) && in.DeletedAt.Before(in.PeriodEnd) {
		metadata["resource_lifecycle"] = "deleted_during_period"
		metadata["deleted_at"] = in.DeletedAt.UTC().Format(time.RFC3339Nano)
	}
	source := strings.TrimSpace(in.Source)
	if source == "" {
		source = StorageUsageSource
	}
	return AttributedStorageSample{
		StorageMetricSample: StorageMetricSample{
			Name:         "storage_gb_month",
			VolumeID:     strings.TrimSpace(in.VolumeID),
			Value:        quantity,
			Unit:         "gb_month",
			WindowStart:  start,
			WindowEnd:    end,
			Source:       source,
			QueryVersion: strings.TrimSpace(in.QueryVersion),
		},
		OrganizationID: strings.TrimSpace(in.OrganizationID),
		ProjectID:      strings.TrimSpace(in.ProjectID),
		EnvironmentID:  strings.TrimSpace(in.EnvironmentID),
		ServiceID:      strings.TrimSpace(in.ServiceID),
		Metadata:       metadata,
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
	eventType := sample.EventType
	if eventType == "" {
		eventType = store.UsageEventTypeConsumed
	}
	key := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		sample.Name,
		sample.ServiceID,
		volumeID,
		sample.WindowStart.UTC().Format(time.RFC3339Nano),
		sample.WindowEnd.UTC().Format(time.RFC3339Nano),
		checksum,
	)
	if eventType == store.UsageEventTypeAdjusted {
		return "adjusted:" + key
	}
	return key
}

func meteringWindowOverlap(windowStart, windowEnd, periodStart, periodEnd, createdAt time.Time, endedAt *time.Time) (time.Time, time.Time, bool, error) {
	windowStart = windowStart.UTC()
	windowEnd = windowEnd.UTC()
	periodStart = periodStart.UTC()
	periodEnd = periodEnd.UTC()
	createdAt = createdAt.UTC()
	var violations []apierr.FieldViolation
	if windowStart.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "window_start", Reason: "is required"})
	}
	if windowEnd.IsZero() || !windowEnd.After(windowStart) {
		violations = append(violations, apierr.FieldViolation{Field: "window_end", Reason: "must be after window_start"})
	}
	if periodStart.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "period_start", Reason: "is required"})
	}
	if periodEnd.IsZero() || !periodEnd.After(periodStart) {
		violations = append(violations, apierr.FieldViolation{Field: "period_end", Reason: "must be after period_start"})
	}
	if createdAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "created_at", Reason: "is required"})
	}
	if len(violations) > 0 {
		return time.Time{}, time.Time{}, false, apierr.InvalidInput(violations...)
	}
	start := maxTime(maxTime(windowStart, periodStart), createdAt)
	end := minTime(windowEnd, periodEnd)
	if endedAt != nil {
		ended := endedAt.UTC()
		end = minTime(end, ended)
	}
	if !end.After(start) {
		return time.Time{}, time.Time{}, false, nil
	}
	return start, end, true, nil
}

func bytesToGBMonth(sizeBytes int64, start, end, periodStart, periodEnd time.Time) float64 {
	const bytesPerGiB = 1024 * 1024 * 1024
	gb := float64(sizeBytes) / float64(bytesPerGiB)
	return gb * end.Sub(start).Hours() / periodEnd.Sub(periodStart).Hours()
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
