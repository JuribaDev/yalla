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

// QuotaReservationEventType is the closed-set kind of a
// quota_reservation_events row. Values mirror quota_reservations.status so the
// timeline reconstructs accepted lifecycle transitions.
type QuotaReservationEventType string

const (
	// QuotaReservationEventTypeActive records a reservation entering active.
	QuotaReservationEventTypeActive QuotaReservationEventType = "active"
	// QuotaReservationEventTypeCommitted records a reservation being committed.
	QuotaReservationEventTypeCommitted QuotaReservationEventType = "committed"
	// QuotaReservationEventTypeReleased records a reservation being released.
	QuotaReservationEventTypeReleased QuotaReservationEventType = "released"
	// QuotaReservationEventTypeExpired records a reservation expiring.
	QuotaReservationEventTypeExpired QuotaReservationEventType = "expired"
)

func (t QuotaReservationEventType) String() string { return string(t) }

const quotaReservationEventListMaxRows = 500

// QuotaReservationEvent is one immutable lifecycle event for a quota
// reservation. Message and Metadata are redacted before persistence by the
// transition path.
type QuotaReservationEvent struct {
	ID             string
	OrganizationID string
	ReservationID  string
	EventType      QuotaReservationEventType
	Message        string
	Metadata       map[string]string
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures a QuotaReservationEvent
// safe.
func (e QuotaReservationEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("reservation_id", e.ReservationID),
		slog.String("event_type", e.EventType.String()),
		slog.String("request_id", e.RequestID),
		slog.String("correlation_id", e.CorrelationID),
	)
}

const quotaReservationEventColumns = `id, organization_id, reservation_id, event_type,
	message, metadata, request_id, correlation_id, occurred_at, created_at`

// QuotaReservationEventRepository is the persistence surface for
// quota_reservation_events. Rows are append-only and tenant-scoped by
// (organization_id, reservation_id).
type QuotaReservationEventRepository struct{}

// NewQuotaReservationEventRepository returns a QuotaReservationEventRepository.
func NewQuotaReservationEventRepository() *QuotaReservationEventRepository {
	return &QuotaReservationEventRepository{}
}

// Append persists e as a new quota_reservation_events row inside tx.
func (r *QuotaReservationEventRepository) Append(ctx context.Context, tx *Tx, e QuotaReservationEvent) (QuotaReservationEvent, error) {
	if tx == nil {
		return QuotaReservationEvent{}, apierr.Internal(errors.New("store: QuotaReservationEventRepository.Append called with a nil transaction"))
	}
	if e.EventType == "" {
		return QuotaReservationEvent{}, apierr.Internal(errors.New("store: QuotaReservationEventRepository.Append called with a blank event type"))
	}
	if e.ID == "" {
		id, err := newQuotaReservationEventID()
		if err != nil {
			return QuotaReservationEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalQuotaReservationEventMetadata(e.Metadata)
	if err != nil {
		return QuotaReservationEvent{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO quota_reservation_events
		   (id, organization_id, reservation_id, event_type,
		    message, metadata, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4,
		         $5, $6, $7, $8, COALESCE($9, now()))
		 RETURNING `+quotaReservationEventColumns,
		e.ID, e.OrganizationID, e.ReservationID, e.EventType.String(),
		e.Message, metadata, e.RequestID, e.CorrelationID, nullableOccurredAt(e.OccurredAt))
	created, err := scanQuotaReservationEvent(row)
	if err != nil {
		return QuotaReservationEvent{}, mapWriteError(err, "a quota reservation event with this id already exists")
	}
	return created, nil
}

// ListByReservation returns every event owned by
// (organizationID, reservationID), oldest first.
func (r *QuotaReservationEventRepository) ListByReservation(ctx context.Context, q Querier, organizationID, reservationID string) ([]QuotaReservationEvent, error) {
	rows, err := q.Query(ctx,
		`SELECT `+quotaReservationEventColumns+`
		   FROM quota_reservation_events
		  WHERE organization_id = $1 AND reservation_id = $2
		  ORDER BY occurred_at ASC, id ASC
		  LIMIT $3`,
		organizationID, reservationID, quotaReservationEventListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]QuotaReservationEvent, 0)
	for rows.Next() {
		e, scanErr := scanQuotaReservationEvent(rows)
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

// GetByID returns one quota_reservation_events row by tenant-scoped id.
func (r *QuotaReservationEventRepository) GetByID(ctx context.Context, q Querier, organizationID, eventID string) (QuotaReservationEvent, error) {
	row := q.QueryRow(ctx,
		`SELECT `+quotaReservationEventColumns+`
		   FROM quota_reservation_events
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, eventID)
	e, err := scanQuotaReservationEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return QuotaReservationEvent{}, apierr.NotFound("quota_reservation_event", eventID)
	}
	if err != nil {
		return QuotaReservationEvent{}, apierr.StoreUnavailable(err)
	}
	return e, nil
}

func scanQuotaReservationEvent(row scanRow) (QuotaReservationEvent, error) {
	var (
		e            QuotaReservationEvent
		eventTypeStr string
		metadataRaw  []byte
	)
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.ReservationID,
		&eventTypeStr,
		&e.Message,
		&metadataRaw,
		&e.RequestID,
		&e.CorrelationID,
		&e.OccurredAt,
		&e.CreatedAt,
	); err != nil {
		return QuotaReservationEvent{}, err
	}
	e.EventType = QuotaReservationEventType(eventTypeStr)
	metadata, err := unmarshalQuotaReservationEventMetadata(metadataRaw)
	if err != nil {
		return QuotaReservationEvent{}, err
	}
	e.Metadata = metadata
	return e, nil
}

func marshalQuotaReservationEventMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling quota reservation event metadata: %w", err)
	}
	return b, nil
}

func unmarshalQuotaReservationEventMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshalling quota reservation event metadata: %w", err)
	}
	if out == nil {
		return map[string]string{}, nil
	}
	return out, nil
}

func newQuotaReservationEventID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("store: generating quota reservation event id: %w", err)
	}
	return "qrev_" + hex.EncodeToString(raw[:]), nil
}
