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

// APIKeyEventType is the closed-set kind of an api_key_events row. Values
// mirror api_keys.status so replaying the timeline reconstructs accepted
// lifecycle transitions.
type APIKeyEventType string

const (
	// APIKeyEventTypeActive records a key entering active.
	APIKeyEventTypeActive APIKeyEventType = "active"
	// APIKeyEventTypeRevoked records a key entering revoked.
	APIKeyEventTypeRevoked APIKeyEventType = "revoked"
	// APIKeyEventTypeExpired records a key entering expired.
	APIKeyEventTypeExpired APIKeyEventType = "expired"
)

func (t APIKeyEventType) String() string { return string(t) }

const apiKeyEventListMaxRows = 500

// APIKeyEvent is one immutable lifecycle event for an API key. Message and
// Metadata are redacted before persistence by the transition path.
type APIKeyEvent struct {
	ID             string
	OrganizationID string
	KeyID          string
	EventType      APIKeyEventType
	Message        string
	Metadata       map[string]string
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures an APIKeyEvent safe.
func (e APIKeyEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("key_id", e.KeyID),
		slog.String("event_type", e.EventType.String()),
		slog.String("request_id", e.RequestID),
		slog.String("correlation_id", e.CorrelationID),
	)
}

const apiKeyEventColumns = `id, organization_id, key_id, event_type,
	message, metadata, request_id, correlation_id, occurred_at, created_at`

// APIKeyEventRepository is the persistence surface for api_key_events. Rows
// are append-only and tenant-scoped by (organization_id, key_id).
type APIKeyEventRepository struct{}

// NewAPIKeyEventRepository returns an APIKeyEventRepository.
func NewAPIKeyEventRepository() *APIKeyEventRepository { return &APIKeyEventRepository{} }

// Append persists e as a new api_key_events row inside tx.
func (r *APIKeyEventRepository) Append(ctx context.Context, tx *Tx, e APIKeyEvent) (APIKeyEvent, error) {
	if tx == nil {
		return APIKeyEvent{}, apierr.Internal(errors.New("store: APIKeyEventRepository.Append called with a nil transaction"))
	}
	if e.EventType == "" {
		return APIKeyEvent{}, apierr.Internal(errors.New("store: APIKeyEventRepository.Append called with a blank event type"))
	}
	if e.ID == "" {
		id, err := newAPIKeyEventID()
		if err != nil {
			return APIKeyEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalAPIKeyEventMetadata(e.Metadata)
	if err != nil {
		return APIKeyEvent{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO api_key_events
		   (id, organization_id, key_id, event_type,
		    message, metadata, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4,
		         $5, $6, $7, $8, COALESCE($9, now()))
		 RETURNING `+apiKeyEventColumns,
		e.ID, e.OrganizationID, e.KeyID, e.EventType.String(),
		e.Message, metadata, e.RequestID, e.CorrelationID, nullableOccurredAt(e.OccurredAt))
	created, err := scanAPIKeyEvent(row)
	if err != nil {
		return APIKeyEvent{}, mapWriteError(err, "an api key event with this id already exists")
	}
	return created, nil
}

// ListByAPIKey returns every event owned by (organizationID, keyID), oldest first.
func (r *APIKeyEventRepository) ListByAPIKey(ctx context.Context, q Querier, organizationID, keyID string) ([]APIKeyEvent, error) {
	rows, err := q.Query(ctx,
		`SELECT `+apiKeyEventColumns+`
		   FROM api_key_events
		  WHERE organization_id = $1 AND key_id = $2
		  ORDER BY occurred_at ASC, id ASC
		  LIMIT $3`,
		organizationID, keyID, apiKeyEventListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]APIKeyEvent, 0)
	for rows.Next() {
		e, scanErr := scanAPIKeyEvent(rows)
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

// GetByID returns one api_key_events row by tenant-scoped id.
func (r *APIKeyEventRepository) GetByID(ctx context.Context, q Querier, organizationID, eventID string) (APIKeyEvent, error) {
	row := q.QueryRow(ctx,
		`SELECT `+apiKeyEventColumns+`
		   FROM api_key_events
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, eventID)
	e, err := scanAPIKeyEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKeyEvent{}, apierr.NotFound("api_key_event", eventID)
	}
	if err != nil {
		return APIKeyEvent{}, apierr.StoreUnavailable(err)
	}
	return e, nil
}

func scanAPIKeyEvent(row scanRow) (APIKeyEvent, error) {
	var (
		e            APIKeyEvent
		eventTypeStr string
		metadataRaw  []byte
	)
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.KeyID,
		&eventTypeStr,
		&e.Message,
		&metadataRaw,
		&e.RequestID,
		&e.CorrelationID,
		&e.OccurredAt,
		&e.CreatedAt,
	); err != nil {
		return APIKeyEvent{}, err
	}
	e.EventType = APIKeyEventType(eventTypeStr)
	metadata, err := unmarshalAPIKeyEventMetadata(metadataRaw)
	if err != nil {
		return APIKeyEvent{}, err
	}
	e.Metadata = metadata
	return e, nil
}

func marshalAPIKeyEventMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling api key event metadata: %w", err)
	}
	return b, nil
}

func unmarshalAPIKeyEventMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshalling api key event metadata: %w", err)
	}
	if out == nil {
		return map[string]string{}, nil
	}
	return out, nil
}

func newAPIKeyEventID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("store: generating api key event id: %w", err)
	}
	return "akevt_" + hex.EncodeToString(raw[:]), nil
}
