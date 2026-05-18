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

// DriftFindingEventType is the closed-set kind of a drift_finding_events row.
// Values mirror drift_findings.status so replaying the timeline reconstructs
// accepted lifecycle transitions.
type DriftFindingEventType string

const (
	// DriftFindingEventTypeOpen records a finding entering open.
	DriftFindingEventTypeOpen DriftFindingEventType = "open"
	// DriftFindingEventTypeResolved records a finding entering resolved.
	DriftFindingEventTypeResolved DriftFindingEventType = "resolved"
)

func (t DriftFindingEventType) String() string { return string(t) }

const driftFindingEventListMaxRows = 500

// DriftFindingEvent is one immutable lifecycle event for a drift finding.
// Message and Metadata are redacted before persistence by the transition path.
type DriftFindingEvent struct {
	ID             string
	OrganizationID string
	FindingID      string
	EventType      DriftFindingEventType
	Message        string
	Metadata       map[string]string
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures a DriftFindingEvent safe.
func (e DriftFindingEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("finding_id", e.FindingID),
		slog.String("event_type", e.EventType.String()),
		slog.String("request_id", e.RequestID),
		slog.String("correlation_id", e.CorrelationID),
	)
}

const driftFindingEventColumns = `id, organization_id, finding_id, event_type,
	message, metadata, request_id, correlation_id, occurred_at, created_at`

// DriftFindingEventRepository is the persistence surface for
// drift_finding_events. Rows are append-only and tenant-scoped by
// (organization_id, finding_id).
type DriftFindingEventRepository struct{}

// NewDriftFindingEventRepository returns a DriftFindingEventRepository.
func NewDriftFindingEventRepository() *DriftFindingEventRepository {
	return &DriftFindingEventRepository{}
}

// Append persists e as a new drift_finding_events row inside tx.
func (r *DriftFindingEventRepository) Append(ctx context.Context, tx *Tx, e DriftFindingEvent) (DriftFindingEvent, error) {
	if tx == nil {
		return DriftFindingEvent{}, apierr.Internal(errors.New("store: DriftFindingEventRepository.Append called with a nil transaction"))
	}
	if e.EventType == "" {
		return DriftFindingEvent{}, apierr.Internal(errors.New("store: DriftFindingEventRepository.Append called with a blank event type"))
	}
	if e.ID == "" {
		id, err := newDriftFindingEventID()
		if err != nil {
			return DriftFindingEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalDriftFindingEventMetadata(e.Metadata)
	if err != nil {
		return DriftFindingEvent{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO drift_finding_events
		   (id, organization_id, finding_id, event_type,
		    message, metadata, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4,
		         $5, $6, $7, $8, COALESCE($9, now()))
		 RETURNING `+driftFindingEventColumns,
		e.ID, e.OrganizationID, e.FindingID, e.EventType.String(),
		e.Message, metadata, e.RequestID, e.CorrelationID, nullableOccurredAt(e.OccurredAt))
	created, err := scanDriftFindingEvent(row)
	if err != nil {
		return DriftFindingEvent{}, mapWriteError(err, "a drift finding event with this id already exists")
	}
	return created, nil
}

// ListByFinding returns every event owned by (organizationID, findingID),
// oldest first.
func (r *DriftFindingEventRepository) ListByFinding(ctx context.Context, q Querier, organizationID, findingID string) ([]DriftFindingEvent, error) {
	rows, err := q.Query(ctx,
		`SELECT `+driftFindingEventColumns+`
		   FROM drift_finding_events
		  WHERE organization_id = $1 AND finding_id = $2
		  ORDER BY occurred_at ASC, id ASC
		  LIMIT $3`,
		organizationID, findingID, driftFindingEventListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]DriftFindingEvent, 0)
	for rows.Next() {
		e, scanErr := scanDriftFindingEvent(rows)
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

// GetByID returns one drift_finding_events row by tenant-scoped id.
func (r *DriftFindingEventRepository) GetByID(ctx context.Context, q Querier, organizationID, eventID string) (DriftFindingEvent, error) {
	row := q.QueryRow(ctx,
		`SELECT `+driftFindingEventColumns+`
		   FROM drift_finding_events
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, eventID)
	e, err := scanDriftFindingEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return DriftFindingEvent{}, apierr.NotFound("drift_finding_event", eventID)
	}
	if err != nil {
		return DriftFindingEvent{}, apierr.StoreUnavailable(err)
	}
	return e, nil
}

func scanDriftFindingEvent(row scanRow) (DriftFindingEvent, error) {
	var (
		e            DriftFindingEvent
		eventTypeStr string
		metadataRaw  []byte
	)
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.FindingID,
		&eventTypeStr,
		&e.Message,
		&metadataRaw,
		&e.RequestID,
		&e.CorrelationID,
		&e.OccurredAt,
		&e.CreatedAt,
	); err != nil {
		return DriftFindingEvent{}, err
	}
	e.EventType = DriftFindingEventType(eventTypeStr)
	metadata, err := unmarshalDriftFindingEventMetadata(metadataRaw)
	if err != nil {
		return DriftFindingEvent{}, err
	}
	e.Metadata = metadata
	e.OccurredAt = e.OccurredAt.UTC()
	e.CreatedAt = e.CreatedAt.UTC()
	return e, nil
}

func marshalDriftFindingEventMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling drift finding event metadata: %w", err)
	}
	return b, nil
}

func unmarshalDriftFindingEventMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshalling drift finding event metadata: %w", err)
	}
	if out == nil {
		return map[string]string{}, nil
	}
	return out, nil
}

func newDriftFindingEventID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("store: generating drift finding event id: %w", err)
	}
	return "drfevt_" + hex.EncodeToString(raw[:]), nil
}
