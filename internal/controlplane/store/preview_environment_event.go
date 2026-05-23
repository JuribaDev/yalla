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

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// PreviewEnvironmentEventType is the closed-set kind of a
// preview_environment_events row. Values mirror preview_environments.status so
// replaying the timeline reconstructs accepted lifecycle transitions.
type PreviewEnvironmentEventType string

const (
	// PreviewEnvironmentEventTypePending records a preview entering pending.
	PreviewEnvironmentEventTypePending PreviewEnvironmentEventType = "pending"
	// PreviewEnvironmentEventTypeProvisioning records a preview entering provisioning.
	PreviewEnvironmentEventTypeProvisioning PreviewEnvironmentEventType = "provisioning"
	// PreviewEnvironmentEventTypeReady records a preview entering ready.
	PreviewEnvironmentEventTypeReady PreviewEnvironmentEventType = "ready"
	// PreviewEnvironmentEventTypeDeleting records a preview entering deleting.
	PreviewEnvironmentEventTypeDeleting PreviewEnvironmentEventType = "deleting"
	// PreviewEnvironmentEventTypeDeleted records a preview entering deleted.
	PreviewEnvironmentEventTypeDeleted PreviewEnvironmentEventType = "deleted"
	// PreviewEnvironmentEventTypeFailed records a preview entering failed.
	PreviewEnvironmentEventTypeFailed PreviewEnvironmentEventType = "failed"
)

func (t PreviewEnvironmentEventType) String() string { return string(t) }

const previewEnvironmentEventListMaxRows = 500

// PreviewEnvironmentEvent is one immutable lifecycle event for a preview
// environment. Message and Metadata are redacted before persistence by the
// transition path.
type PreviewEnvironmentEvent struct {
	ID             string
	OrganizationID string
	PreviewID      string
	EventType      PreviewEnvironmentEventType
	Message        string
	Metadata       map[string]string
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures a PreviewEnvironmentEvent
// safe.
func (e PreviewEnvironmentEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("preview_id", e.PreviewID),
		slog.String("event_type", e.EventType.String()),
		slog.String("request_id", e.RequestID),
		slog.String("correlation_id", e.CorrelationID),
	)
}

const previewEnvironmentEventColumns = `id, organization_id, preview_id, event_type,
	message, metadata, request_id, correlation_id, occurred_at, created_at`

// PreviewEnvironmentEventRepository is the persistence surface for
// preview_environment_events. Rows are append-only and tenant-scoped by
// (organization_id, preview_id).
type PreviewEnvironmentEventRepository struct{}

// NewPreviewEnvironmentEventRepository returns a
// PreviewEnvironmentEventRepository.
func NewPreviewEnvironmentEventRepository() *PreviewEnvironmentEventRepository {
	return &PreviewEnvironmentEventRepository{}
}

// Append persists e as a new preview_environment_events row inside tx.
func (r *PreviewEnvironmentEventRepository) Append(ctx context.Context, tx *Tx, e PreviewEnvironmentEvent) (PreviewEnvironmentEvent, error) {
	if tx == nil {
		return PreviewEnvironmentEvent{}, apierr.Internal(errors.New("store: PreviewEnvironmentEventRepository.Append called with a nil transaction"))
	}
	if e.EventType == "" {
		return PreviewEnvironmentEvent{}, apierr.Internal(errors.New("store: PreviewEnvironmentEventRepository.Append called with a blank event type"))
	}
	if e.ID == "" {
		id, err := newPreviewEnvironmentEventID()
		if err != nil {
			return PreviewEnvironmentEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalPreviewEnvironmentEventMetadata(e.Metadata)
	if err != nil {
		return PreviewEnvironmentEvent{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO preview_environment_events
		   (id, organization_id, preview_id, event_type,
		    message, metadata, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4,
		         $5, $6, $7, $8, COALESCE($9, now()))
		 RETURNING `+previewEnvironmentEventColumns,
		e.ID, e.OrganizationID, e.PreviewID, e.EventType.String(),
		e.Message, metadata, e.RequestID, e.CorrelationID, nullableOccurredAt(e.OccurredAt))
	created, err := scanPreviewEnvironmentEvent(row)
	if err != nil {
		return PreviewEnvironmentEvent{}, mapWriteError(err, "a preview environment event with this id already exists")
	}
	return created, nil
}

// ListByPreviewEnvironment returns every event owned by
// (organizationID, previewID), oldest first.
func (r *PreviewEnvironmentEventRepository) ListByPreviewEnvironment(ctx context.Context, q Querier, organizationID, previewID string) ([]PreviewEnvironmentEvent, error) {
	rows, err := q.Query(ctx,
		`SELECT `+previewEnvironmentEventColumns+`
		   FROM preview_environment_events
		  WHERE organization_id = $1 AND preview_id = $2
		  ORDER BY occurred_at ASC, id ASC
		  LIMIT $3`,
		organizationID, previewID, previewEnvironmentEventListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]PreviewEnvironmentEvent, 0)
	for rows.Next() {
		e, scanErr := scanPreviewEnvironmentEvent(rows)
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

// GetByID returns one preview_environment_events row by tenant-scoped id.
func (r *PreviewEnvironmentEventRepository) GetByID(ctx context.Context, q Querier, organizationID, eventID string) (PreviewEnvironmentEvent, error) {
	row := q.QueryRow(ctx,
		`SELECT `+previewEnvironmentEventColumns+`
		   FROM preview_environment_events
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, eventID)
	e, err := scanPreviewEnvironmentEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return PreviewEnvironmentEvent{}, apierr.NotFound("preview_environment_event", eventID)
	}
	if err != nil {
		return PreviewEnvironmentEvent{}, apierr.StoreUnavailable(err)
	}
	return e, nil
}

func scanPreviewEnvironmentEvent(row scanRow) (PreviewEnvironmentEvent, error) {
	var (
		e            PreviewEnvironmentEvent
		eventTypeStr string
		metadataRaw  []byte
	)
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.PreviewID,
		&eventTypeStr,
		&e.Message,
		&metadataRaw,
		&e.RequestID,
		&e.CorrelationID,
		&e.OccurredAt,
		&e.CreatedAt,
	); err != nil {
		return PreviewEnvironmentEvent{}, err
	}
	e.EventType = PreviewEnvironmentEventType(eventTypeStr)
	metadata, err := unmarshalPreviewEnvironmentEventMetadata(metadataRaw)
	if err != nil {
		return PreviewEnvironmentEvent{}, err
	}
	e.Metadata = metadata
	return e, nil
}

func marshalPreviewEnvironmentEventMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling preview environment event metadata: %w", err)
	}
	return b, nil
}

func unmarshalPreviewEnvironmentEventMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshalling preview environment event metadata: %w", err)
	}
	if out == nil {
		return map[string]string{}, nil
	}
	return out, nil
}

func newPreviewEnvironmentEventID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("store: generating preview environment event id: %w", err)
	}
	return "pevt_" + hex.EncodeToString(raw[:]), nil
}
