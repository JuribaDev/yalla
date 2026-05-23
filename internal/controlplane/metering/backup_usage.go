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

// BackupUsageSource is the stable usage_events source for backup artefact
// storage metrics derived from backup metadata.
const BackupUsageSource = "backup_metadata"

// BackupMetricSample is one normalized, bounded backup metric window before
// billing-grade emission. Attribution happens before this emitter.
type BackupMetricSample struct {
	Name              string
	BackupID          string
	Value             float64
	Unit              string
	WindowStart       time.Time
	WindowEnd         time.Time
	Source            string
	QueryVersion      string
	RawSampleChecksum string
	Labels            map[string]string
}

// AttributedBackupSample is safe to convert into a usage event when it carries
// the complete tenant scope.
type AttributedBackupSample struct {
	BackupMetricSample
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	EventType      store.UsageEventType
	Metadata       map[string]string
}

// BackupArtifactStatus is the normalized status used by backup metadata
// metering before a sample becomes billing-grade usage.
type BackupArtifactStatus string

const (
	// BackupArtifactSucceeded marks a backup artefact that exists and should
	// contribute retained storage usage while it overlaps the billing period.
	BackupArtifactSucceeded BackupArtifactStatus = "succeeded"
	// BackupArtifactFailed marks a failed backup attempt that produced no
	// billable retained artefact.
	BackupArtifactFailed BackupArtifactStatus = "failed"
)

// BackupStorageGBMonthSampleInput describes one backup artefact retained over
// a billing window. Failed artefacts are not billable and return ok=false.
type BackupStorageGBMonthSampleInput struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	BackupID       string
	SizeBytes      int64
	Status         BackupArtifactStatus
	WindowStart    time.Time
	WindowEnd      time.Time
	PeriodStart    time.Time
	PeriodEnd      time.Time
	CreatedAt      time.Time
	ExpiresAt      *time.Time
	Source         string
	QueryVersion   string
	Metadata       map[string]string
}

// BackupUsageInput is one attributed backup collection window ready for
// billing-grade event emission.
type BackupUsageInput struct {
	Samples   []AttributedBackupSample
	RequestID string
}

// BackupUsageResult reports the usage_events accepted for the input window.
type BackupUsageResult struct {
	Events []store.UsageEvent
}

// BackupUsageEmitter writes billing-grade backup samples as append-only
// usage_events. Unsafe or unsupported samples are skipped instead of billed.
type BackupUsageEmitter struct {
	store *store.Store
	usage *store.UsageEventRepository
}

// NewBackupUsageEmitter builds a backup usage emitter over store.
func NewBackupUsageEmitter(s *store.Store) (*BackupUsageEmitter, error) {
	if s == nil {
		return nil, errors.New("metering: nil store")
	}
	return &BackupUsageEmitter{store: s, usage: store.NewUsageEventRepository()}, nil
}

// Emit appends idempotent usage events for billing-grade backup metrics.
func (e *BackupUsageEmitter) Emit(ctx context.Context, in BackupUsageInput) (BackupUsageResult, error) {
	if e == nil || e.store == nil || e.usage == nil {
		return BackupUsageResult{}, errors.New("metering: nil BackupUsageEmitter")
	}
	result := BackupUsageResult{Events: []store.UsageEvent{}}
	if len(in.Samples) == 0 {
		return result, nil
	}
	err := e.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		for _, sample := range in.Samples {
			eventInput, ok, err := buildBackupUsageEventInput(sample, in.RequestID)
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
		return BackupUsageResult{}, err
	}
	return result, nil
}

func buildBackupUsageEventInput(sample AttributedBackupSample, requestID string) (store.AppendUsageEventInput, bool, error) {
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
	resource, ok := backupMetricResource(def.Key)
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
	if backupID := strings.TrimSpace(sample.BackupID); backupID != "" {
		metadata["backup_id"] = backupID
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
		IdempotencyKey: backupUsageIdempotencyKey(sample),
		RequestID:      strings.TrimSpace(requestID),
		Metadata:       metadata,
		OccurredAt:     sample.WindowEnd,
	}, true, nil
}

// BuildBackupStorageGBMonthSample converts backup metadata into a prorated
// GB-month sample, clipped by retention expiry and the billing period.
func BuildBackupStorageGBMonthSample(in BackupStorageGBMonthSampleInput) (AttributedBackupSample, bool, error) {
	if in.Status == BackupArtifactFailed {
		return AttributedBackupSample{}, false, nil
	}
	if in.Status != "" && in.Status != BackupArtifactSucceeded {
		return AttributedBackupSample{}, false, apierr.InvalidInput(apierr.FieldViolation{Field: "status", Reason: "must be succeeded or failed"})
	}
	start, end, ok, err := meteringWindowOverlap(in.WindowStart, in.WindowEnd, in.PeriodStart, in.PeriodEnd, in.CreatedAt, in.ExpiresAt)
	if err != nil || !ok {
		return AttributedBackupSample{}, false, err
	}
	if in.SizeBytes < 0 {
		return AttributedBackupSample{}, false, apierr.InvalidInput(apierr.FieldViolation{Field: "size_bytes", Reason: "must be non-negative"})
	}
	quantity := bytesToGBMonth(in.SizeBytes, start, end, in.PeriodStart, in.PeriodEnd)
	metadata := copyStringMap(in.Metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadata["period_start"] = in.PeriodStart.UTC().Format(time.RFC3339Nano)
	metadata["period_end"] = in.PeriodEnd.UTC().Format(time.RFC3339Nano)
	metadata["size_bytes"] = strconv.FormatInt(in.SizeBytes, 10)
	metadata["backup_status"] = string(BackupArtifactSucceeded)
	if in.ExpiresAt != nil {
		metadata["retention_expires_at"] = in.ExpiresAt.UTC().Format(time.RFC3339Nano)
		metadata["retention_hours"] = strconv.FormatFloat(in.ExpiresAt.Sub(in.CreatedAt).Hours(), 'f', -1, 64)
	}
	source := strings.TrimSpace(in.Source)
	if source == "" {
		source = BackupUsageSource
	}
	return AttributedBackupSample{
		BackupMetricSample: BackupMetricSample{
			Name:         "backup_storage_gb_month",
			BackupID:     strings.TrimSpace(in.BackupID),
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

func backupMetricResource(key string) (store.QuotaResource, bool) {
	switch key {
	case "backup_storage_gb_month":
		return store.QuotaResourceBackupStorageGBMonth, true
	default:
		return "", false
	}
}

func backupUsageIdempotencyKey(sample AttributedBackupSample) string {
	backupID := sample.BackupID
	if backupID == "" {
		backupID = "-"
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
		backupID,
		sample.WindowStart.UTC().Format(time.RFC3339Nano),
		sample.WindowEnd.UTC().Format(time.RFC3339Nano),
		checksum,
	)
	if eventType == store.UsageEventTypeAdjusted {
		return "adjusted:" + key
	}
	return key
}
