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

// BreakGlassSessionEventType is the closed-set kind of a
// break_glass_session_events row. Values mirror break_glass_sessions.status so
// replaying the timeline reconstructs accepted lifecycle transitions.
type BreakGlassSessionEventType string

const (
	// BreakGlassSessionEventTypeActive records a session entering active.
	BreakGlassSessionEventTypeActive BreakGlassSessionEventType = "active"
	// BreakGlassSessionEventTypeRevoked records a session entering revoked.
	BreakGlassSessionEventTypeRevoked BreakGlassSessionEventType = "revoked"
	// BreakGlassSessionEventTypeExpired records a session entering expired.
	BreakGlassSessionEventTypeExpired BreakGlassSessionEventType = "expired"
)

func (t BreakGlassSessionEventType) String() string { return string(t) }

const breakGlassSessionEventListMaxRows = 500

// BreakGlassSessionEvent is one immutable lifecycle event for a break-glass
// session. Message and Metadata are redacted before persistence by the
// transition path.
type BreakGlassSessionEvent struct {
	ID             string
	OrganizationID string
	SessionID      string
	EventType      BreakGlassSessionEventType
	Message        string
	Metadata       map[string]string
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures a BreakGlassSessionEvent
// safe.
func (e BreakGlassSessionEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("session_id", e.SessionID),
		slog.String("event_type", e.EventType.String()),
		slog.String("request_id", e.RequestID),
		slog.String("correlation_id", e.CorrelationID),
	)
}

const breakGlassSessionEventColumns = `id, organization_id, session_id, event_type,
	message, metadata, request_id, correlation_id, occurred_at, created_at`

// BreakGlassSessionEventRepository is the persistence surface for
// break_glass_session_events. Rows are append-only and tenant-scoped by
// (organization_id, session_id).
type BreakGlassSessionEventRepository struct{}

// NewBreakGlassSessionEventRepository returns a BreakGlassSessionEventRepository.
func NewBreakGlassSessionEventRepository() *BreakGlassSessionEventRepository {
	return &BreakGlassSessionEventRepository{}
}

// Append persists e as a new break_glass_session_events row inside tx.
func (r *BreakGlassSessionEventRepository) Append(ctx context.Context, tx *Tx, e BreakGlassSessionEvent) (BreakGlassSessionEvent, error) {
	if tx == nil {
		return BreakGlassSessionEvent{}, apierr.Internal(errors.New("store: BreakGlassSessionEventRepository.Append called with a nil transaction"))
	}
	if e.EventType == "" {
		return BreakGlassSessionEvent{}, apierr.Internal(errors.New("store: BreakGlassSessionEventRepository.Append called with a blank event type"))
	}
	if e.ID == "" {
		id, err := newBreakGlassSessionEventID()
		if err != nil {
			return BreakGlassSessionEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalBreakGlassSessionEventMetadata(e.Metadata)
	if err != nil {
		return BreakGlassSessionEvent{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO break_glass_session_events
		   (id, organization_id, session_id, event_type,
		    message, metadata, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4,
		         $5, $6, $7, $8, COALESCE($9, now()))
		 RETURNING `+breakGlassSessionEventColumns,
		e.ID, e.OrganizationID, e.SessionID, e.EventType.String(),
		e.Message, metadata, e.RequestID, e.CorrelationID, nullableOccurredAt(e.OccurredAt))
	created, err := scanBreakGlassSessionEvent(row)
	if err != nil {
		return BreakGlassSessionEvent{}, mapWriteError(err, "a break-glass session event with this id already exists")
	}
	return created, nil
}

// ListBySession returns every event owned by (organizationID, sessionID),
// oldest first.
func (r *BreakGlassSessionEventRepository) ListBySession(ctx context.Context, q Querier, organizationID, sessionID string) ([]BreakGlassSessionEvent, error) {
	rows, err := q.Query(ctx,
		`SELECT `+breakGlassSessionEventColumns+`
		   FROM break_glass_session_events
		  WHERE organization_id = $1 AND session_id = $2
		  ORDER BY occurred_at ASC, id ASC
		  LIMIT $3`,
		organizationID, sessionID, breakGlassSessionEventListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]BreakGlassSessionEvent, 0)
	for rows.Next() {
		e, scanErr := scanBreakGlassSessionEvent(rows)
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

// GetByID returns one break_glass_session_events row by tenant-scoped id.
func (r *BreakGlassSessionEventRepository) GetByID(ctx context.Context, q Querier, organizationID, eventID string) (BreakGlassSessionEvent, error) {
	row := q.QueryRow(ctx,
		`SELECT `+breakGlassSessionEventColumns+`
		   FROM break_glass_session_events
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, eventID)
	e, err := scanBreakGlassSessionEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return BreakGlassSessionEvent{}, apierr.NotFound("break_glass_session_event", eventID)
	}
	if err != nil {
		return BreakGlassSessionEvent{}, apierr.StoreUnavailable(err)
	}
	return e, nil
}

func scanBreakGlassSessionEvent(row scanRow) (BreakGlassSessionEvent, error) {
	var (
		e            BreakGlassSessionEvent
		eventTypeStr string
		metadataRaw  []byte
	)
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.SessionID,
		&eventTypeStr,
		&e.Message,
		&metadataRaw,
		&e.RequestID,
		&e.CorrelationID,
		&e.OccurredAt,
		&e.CreatedAt,
	); err != nil {
		return BreakGlassSessionEvent{}, err
	}
	e.EventType = BreakGlassSessionEventType(eventTypeStr)
	metadata, err := unmarshalBreakGlassSessionEventMetadata(metadataRaw)
	if err != nil {
		return BreakGlassSessionEvent{}, err
	}
	e.Metadata = metadata
	e.OccurredAt = e.OccurredAt.UTC()
	e.CreatedAt = e.CreatedAt.UTC()
	return e, nil
}

func marshalBreakGlassSessionEventMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling break-glass session event metadata: %w", err)
	}
	return b, nil
}

func unmarshalBreakGlassSessionEventMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshalling break-glass session event metadata: %w", err)
	}
	if out == nil {
		return map[string]string{}, nil
	}
	return out, nil
}

func newBreakGlassSessionEventID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("store: generating break-glass session event id: %w", err)
	}
	return "bgsevt_" + hex.EncodeToString(raw[:]), nil
}
