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

// ServiceEventType is the closed-set kind of a service_events row. Values
// mirror services.status so replaying the timeline reconstructs accepted
// lifecycle transitions.
type ServiceEventType string

const (
	// ServiceEventTypePending records a service entering pending.
	ServiceEventTypePending ServiceEventType = "pending"
	// ServiceEventTypeActive records a service entering active.
	ServiceEventTypeActive ServiceEventType = "active"
	// ServiceEventTypeSuspended records a service entering suspended.
	ServiceEventTypeSuspended ServiceEventType = "suspended"
	// ServiceEventTypeDeleting records a service entering deleting.
	ServiceEventTypeDeleting ServiceEventType = "deleting"
	// ServiceEventTypeDeleted records a service entering deleted.
	ServiceEventTypeDeleted ServiceEventType = "deleted"
)

func (t ServiceEventType) String() string { return string(t) }

const serviceEventListMaxRows = 500

// ServiceEvent is one immutable lifecycle event for a service. Message and
// Metadata are redacted before persistence by the transition path.
type ServiceEvent struct {
	ID             string
	OrganizationID string
	ServiceID      string
	EventType      ServiceEventType
	Message        string
	Metadata       map[string]string
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures a ServiceEvent safe.
func (e ServiceEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("service_id", e.ServiceID),
		slog.String("event_type", e.EventType.String()),
		slog.String("request_id", e.RequestID),
		slog.String("correlation_id", e.CorrelationID),
	)
}

const serviceEventColumns = `id, organization_id, service_id, event_type,
	message, metadata, request_id, correlation_id, occurred_at, created_at`

// ServiceEventRepository is the persistence surface for service_events. Rows
// are append-only and tenant-scoped by (organization_id, service_id).
type ServiceEventRepository struct{}

// NewServiceEventRepository returns a ServiceEventRepository.
func NewServiceEventRepository() *ServiceEventRepository { return &ServiceEventRepository{} }

// Append persists e as a new service_events row inside tx.
func (r *ServiceEventRepository) Append(ctx context.Context, tx *Tx, e ServiceEvent) (ServiceEvent, error) {
	if tx == nil {
		return ServiceEvent{}, apierr.Internal(errors.New("store: ServiceEventRepository.Append called with a nil transaction"))
	}
	if e.EventType == "" {
		return ServiceEvent{}, apierr.Internal(errors.New("store: ServiceEventRepository.Append called with a blank event type"))
	}
	if e.ID == "" {
		id, err := newServiceEventID()
		if err != nil {
			return ServiceEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalServiceEventMetadata(e.Metadata)
	if err != nil {
		return ServiceEvent{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO service_events
		   (id, organization_id, service_id, event_type,
		    message, metadata, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4,
		         $5, $6, $7, $8, COALESCE($9, now()))
		 RETURNING `+serviceEventColumns,
		e.ID, e.OrganizationID, e.ServiceID, e.EventType.String(),
		e.Message, metadata, e.RequestID, e.CorrelationID, nullableOccurredAt(e.OccurredAt))
	created, err := scanServiceEvent(row)
	if err != nil {
		return ServiceEvent{}, mapWriteError(err, "a service event with this id already exists")
	}
	return created, nil
}

// ListByService returns every event owned by (organizationID, serviceID),
// oldest first.
func (r *ServiceEventRepository) ListByService(ctx context.Context, q Querier, organizationID, serviceID string) ([]ServiceEvent, error) {
	rows, err := q.Query(ctx,
		`SELECT `+serviceEventColumns+`
		   FROM service_events
		  WHERE organization_id = $1 AND service_id = $2
		  ORDER BY occurred_at ASC, id ASC
		  LIMIT $3`,
		organizationID, serviceID, serviceEventListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]ServiceEvent, 0)
	for rows.Next() {
		e, scanErr := scanServiceEvent(rows)
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

// GetByID returns one service_events row by tenant-scoped id.
func (r *ServiceEventRepository) GetByID(ctx context.Context, q Querier, organizationID, eventID string) (ServiceEvent, error) {
	row := q.QueryRow(ctx,
		`SELECT `+serviceEventColumns+`
		   FROM service_events
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, eventID)
	e, err := scanServiceEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceEvent{}, apierr.NotFound("service_event", eventID)
	}
	if err != nil {
		return ServiceEvent{}, apierr.StoreUnavailable(err)
	}
	return e, nil
}

func scanServiceEvent(row scanRow) (ServiceEvent, error) {
	var (
		e            ServiceEvent
		eventTypeStr string
		metadataRaw  []byte
	)
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.ServiceID,
		&eventTypeStr,
		&e.Message,
		&metadataRaw,
		&e.RequestID,
		&e.CorrelationID,
		&e.OccurredAt,
		&e.CreatedAt,
	); err != nil {
		return ServiceEvent{}, err
	}
	e.EventType = ServiceEventType(eventTypeStr)
	metadata, err := unmarshalServiceEventMetadata(metadataRaw)
	if err != nil {
		return ServiceEvent{}, err
	}
	e.Metadata = metadata
	return e, nil
}

func marshalServiceEventMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling service event metadata: %w", err)
	}
	return b, nil
}

func unmarshalServiceEventMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshalling service event metadata: %w", err)
	}
	if out == nil {
		return map[string]string{}, nil
	}
	return out, nil
}

func newServiceEventID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("store: generating service event id: %w", err)
	}
	return "sevt_" + hex.EncodeToString(raw[:]), nil
}
