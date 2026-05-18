package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// JobEventType is the closed-set kind of a provisioning_job_events row. The
// values mirror provisioning_jobs.status so the lifecycle timeline can be
// reconstructed by replaying events in occurred_at order.
type JobEventType string

const (
	// JobEventTypeQueued records a job entering the queued lifecycle state.
	JobEventTypeQueued JobEventType = "queued"
	// JobEventTypeRunning records a worker claiming the job for execution.
	JobEventTypeRunning JobEventType = "running"
	// JobEventTypeRetrying records a transient failure scheduled for retry.
	JobEventTypeRetrying JobEventType = "retrying"
	// JobEventTypeSucceeded records the terminal successful lifecycle state.
	JobEventTypeSucceeded JobEventType = "succeeded"
	// JobEventTypeFailed records a terminal permanent failure.
	JobEventTypeFailed JobEventType = "failed"
	// JobEventTypeCancelled records the terminal cancelled lifecycle state.
	JobEventTypeCancelled JobEventType = "cancelled"
	// JobEventTypeDeadLetter records a terminal exhausted-retry lifecycle state.
	JobEventTypeDeadLetter JobEventType = "dead_letter"
)

func (t JobEventType) String() string { return string(t) }

func (s JobStatus) jobEventType() JobEventType {
	switch s {
	case JobStatusQueued:
		return JobEventTypeQueued
	case JobStatusRunning:
		return JobEventTypeRunning
	case JobStatusRetrying:
		return JobEventTypeRetrying
	case JobStatusSucceeded:
		return JobEventTypeSucceeded
	case JobStatusFailed:
		return JobEventTypeFailed
	case JobStatusCancelled:
		return JobEventTypeCancelled
	case JobStatusDeadLetter:
		return JobEventTypeDeadLetter
	default:
		return ""
	}
}

const jobEventListMaxRows = 500

// JobEvent is one immutable lifecycle event for a provisioning job. Message
// and Metadata are redacted before persistence by the transition path.
type JobEvent struct {
	ID             string
	OrganizationID string
	JobID          string
	EventType      JobEventType
	Message        string
	Metadata       map[string]string
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures a JobEvent safe.
func (e JobEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("job_id", e.JobID),
		slog.String("event_type", e.EventType.String()),
		slog.String("request_id", e.RequestID),
		slog.String("correlation_id", e.CorrelationID),
	)
}

const jobEventColumns = `id, organization_id, job_id, event_type,
	message, metadata, request_id, correlation_id, occurred_at, created_at`

// JobEventRepository is the persistence surface for provisioning_job_events.
// Rows are append-only and tenant-scoped by (organization_id, job_id).
type JobEventRepository struct{}

// NewJobEventRepository returns a JobEventRepository.
func NewJobEventRepository() *JobEventRepository { return &JobEventRepository{} }

// Append persists e as a new provisioning_job_events row inside tx.
func (r *JobEventRepository) Append(ctx context.Context, tx *Tx, e JobEvent) (JobEvent, error) {
	if tx == nil {
		return JobEvent{}, apierr.Internal(errors.New("store: JobEventRepository.Append called with a nil transaction"))
	}
	if e.EventType == "" {
		return JobEvent{}, apierr.Internal(errors.New("store: JobEventRepository.Append called with a blank event type"))
	}
	if e.ID == "" {
		id, err := newJobEventID()
		if err != nil {
			return JobEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalJobEventMetadata(e.Metadata)
	if err != nil {
		return JobEvent{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO provisioning_job_events
		   (id, organization_id, job_id, event_type,
		    message, metadata, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4,
		         $5, $6, $7, $8, COALESCE($9, now()))
		 RETURNING `+jobEventColumns,
		e.ID, e.OrganizationID, e.JobID, e.EventType.String(),
		e.Message, metadata, e.RequestID, e.CorrelationID, nullableOccurredAt(e.OccurredAt))
	created, err := scanJobEvent(row)
	if err != nil {
		return JobEvent{}, mapWriteError(err, "a provisioning job event with this id already exists")
	}
	return created, nil
}

// ListByJob returns every event owned by (organizationID, jobID), oldest first.
func (r *JobEventRepository) ListByJob(ctx context.Context, q Querier, organizationID, jobID string) ([]JobEvent, error) {
	rows, err := q.Query(ctx,
		`SELECT `+jobEventColumns+`
		   FROM provisioning_job_events
		  WHERE organization_id = $1 AND job_id = $2
		  ORDER BY occurred_at ASC, id ASC
		  LIMIT $3`,
		organizationID, jobID, jobEventListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]JobEvent, 0)
	for rows.Next() {
		e, scanErr := scanJobEvent(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// GetByID returns one provisioning_job_events row by tenant-scoped id.
func (r *JobEventRepository) GetByID(ctx context.Context, q Querier, organizationID, eventID string) (JobEvent, error) {
	row := q.QueryRow(ctx,
		`SELECT `+jobEventColumns+`
		   FROM provisioning_job_events
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, eventID)
	e, err := scanJobEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return JobEvent{}, apierr.NotFound("provisioning_job_event", eventID)
	}
	if err != nil {
		return JobEvent{}, apierr.StoreUnavailable(err)
	}
	return e, nil
}

func scanJobEvent(row scanRow) (JobEvent, error) {
	var (
		e            JobEvent
		eventTypeStr string
		metadataRaw  []byte
	)
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.JobID,
		&eventTypeStr,
		&e.Message,
		&metadataRaw,
		&e.RequestID,
		&e.CorrelationID,
		&e.OccurredAt,
		&e.CreatedAt,
	); err != nil {
		return JobEvent{}, err
	}
	e.EventType = JobEventType(eventTypeStr)
	metadata, err := unmarshalJobEventMetadata(metadataRaw)
	if err != nil {
		return JobEvent{}, err
	}
	e.Metadata = metadata
	return e, nil
}

func marshalJobEventMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling provisioning job event metadata: %w", err)
	}
	return b, nil
}

func unmarshalJobEventMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("store: unmarshalling provisioning job event metadata: %w", err)
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

func newJobEventID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("store: generating provisioning job event id entropy: %w", err)
	}
	return "jobev_" + hex.EncodeToString(buf[:]), nil
}
