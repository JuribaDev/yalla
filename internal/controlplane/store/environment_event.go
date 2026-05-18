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

// EnvironmentEventType is the closed-set kind of an environment_events row.
// Values mirror environments.status so replaying the timeline reconstructs
// accepted lifecycle transitions.
type EnvironmentEventType string

const (
	// EnvironmentEventTypePending records an environment entering pending.
	EnvironmentEventTypePending EnvironmentEventType = "pending"
	// EnvironmentEventTypeActive records an environment entering active.
	EnvironmentEventTypeActive EnvironmentEventType = "active"
	// EnvironmentEventTypeSuspended records an environment entering suspended.
	EnvironmentEventTypeSuspended EnvironmentEventType = "suspended"
	// EnvironmentEventTypeDeleting records an environment entering deleting.
	EnvironmentEventTypeDeleting EnvironmentEventType = "deleting"
	// EnvironmentEventTypeDeleted records an environment entering deleted.
	EnvironmentEventTypeDeleted EnvironmentEventType = "deleted"
)

func (t EnvironmentEventType) String() string { return string(t) }

const environmentEventListMaxRows = 500

// EnvironmentEvent is one immutable lifecycle event for an environment.
// Message and Metadata are redacted before persistence by the transition path.
type EnvironmentEvent struct {
	ID             string
	OrganizationID string
	EnvironmentID  string
	EventType      EnvironmentEventType
	Message        string
	Metadata       map[string]string
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures an EnvironmentEvent safe.
func (e EnvironmentEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("environment_id", e.EnvironmentID),
		slog.String("event_type", e.EventType.String()),
		slog.String("request_id", e.RequestID),
		slog.String("correlation_id", e.CorrelationID),
	)
}

const environmentEventColumns = `id, organization_id, environment_id, event_type,
	message, metadata, request_id, correlation_id, occurred_at, created_at`

// EnvironmentEventRepository is the persistence surface for
// environment_events. Rows are append-only and tenant-scoped by
// (organization_id, environment_id).
type EnvironmentEventRepository struct{}

// NewEnvironmentEventRepository returns an EnvironmentEventRepository.
func NewEnvironmentEventRepository() *EnvironmentEventRepository {
	return &EnvironmentEventRepository{}
}

// Append persists e as a new environment_events row inside tx.
func (r *EnvironmentEventRepository) Append(ctx context.Context, tx *Tx, e EnvironmentEvent) (EnvironmentEvent, error) {
	if tx == nil {
		return EnvironmentEvent{}, apierr.Internal(errors.New("store: EnvironmentEventRepository.Append called with a nil transaction"))
	}
	if e.EventType == "" {
		return EnvironmentEvent{}, apierr.Internal(errors.New("store: EnvironmentEventRepository.Append called with a blank event type"))
	}
	if e.ID == "" {
		id, err := newEnvironmentEventID()
		if err != nil {
			return EnvironmentEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalEnvironmentEventMetadata(e.Metadata)
	if err != nil {
		return EnvironmentEvent{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO environment_events
		   (id, organization_id, environment_id, event_type,
		    message, metadata, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4,
		         $5, $6, $7, $8, COALESCE($9, now()))
		 RETURNING `+environmentEventColumns,
		e.ID, e.OrganizationID, e.EnvironmentID, e.EventType.String(),
		e.Message, metadata, e.RequestID, e.CorrelationID, nullableOccurredAt(e.OccurredAt))
	created, err := scanEnvironmentEvent(row)
	if err != nil {
		return EnvironmentEvent{}, mapWriteError(err, "an environment event with this id already exists")
	}
	return created, nil
}

// ListByEnvironment returns every event owned by (organizationID,
// environmentID), oldest first.
func (r *EnvironmentEventRepository) ListByEnvironment(ctx context.Context, q Querier, organizationID, environmentID string) ([]EnvironmentEvent, error) {
	rows, err := q.Query(ctx,
		`SELECT `+environmentEventColumns+`
		   FROM environment_events
		  WHERE organization_id = $1 AND environment_id = $2
		  ORDER BY occurred_at ASC, id ASC
		  LIMIT $3`,
		organizationID, environmentID, environmentEventListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]EnvironmentEvent, 0)
	for rows.Next() {
		e, scanErr := scanEnvironmentEvent(rows)
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

// GetByID returns one environment_events row by tenant-scoped id.
func (r *EnvironmentEventRepository) GetByID(ctx context.Context, q Querier, organizationID, eventID string) (EnvironmentEvent, error) {
	row := q.QueryRow(ctx,
		`SELECT `+environmentEventColumns+`
		   FROM environment_events
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, eventID)
	e, err := scanEnvironmentEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnvironmentEvent{}, apierr.NotFound("environment_event", eventID)
	}
	if err != nil {
		return EnvironmentEvent{}, apierr.StoreUnavailable(err)
	}
	return e, nil
}

func scanEnvironmentEvent(row scanRow) (EnvironmentEvent, error) {
	var (
		e            EnvironmentEvent
		eventTypeStr string
		metadataRaw  []byte
	)
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.EnvironmentID,
		&eventTypeStr,
		&e.Message,
		&metadataRaw,
		&e.RequestID,
		&e.CorrelationID,
		&e.OccurredAt,
		&e.CreatedAt,
	); err != nil {
		return EnvironmentEvent{}, err
	}
	e.EventType = EnvironmentEventType(eventTypeStr)
	metadata, err := unmarshalEnvironmentEventMetadata(metadataRaw)
	if err != nil {
		return EnvironmentEvent{}, err
	}
	e.Metadata = metadata
	return e, nil
}

func marshalEnvironmentEventMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling environment event metadata: %w", err)
	}
	return b, nil
}

func unmarshalEnvironmentEventMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshalling environment event metadata: %w", err)
	}
	if out == nil {
		return map[string]string{}, nil
	}
	return out, nil
}

func newEnvironmentEventID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("store: generating environment event id: %w", err)
	}
	return "enev_" + hex.EncodeToString(raw[:]), nil
}
