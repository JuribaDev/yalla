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

// ProjectEventType is the closed-set kind of a project_events row. Values
// mirror projects.status so replaying the timeline reconstructs accepted
// lifecycle transitions.
type ProjectEventType string

const (
	// ProjectEventTypePending records a project entering pending.
	ProjectEventTypePending ProjectEventType = "pending"
	// ProjectEventTypeActive records a project entering active.
	ProjectEventTypeActive ProjectEventType = "active"
	// ProjectEventTypeSuspended records a project entering suspended.
	ProjectEventTypeSuspended ProjectEventType = "suspended"
	// ProjectEventTypeDeleting records a project entering deleting.
	ProjectEventTypeDeleting ProjectEventType = "deleting"
	// ProjectEventTypeDeleted records a project entering deleted.
	ProjectEventTypeDeleted ProjectEventType = "deleted"
)

func (t ProjectEventType) String() string { return string(t) }

const projectEventListMaxRows = 500

// ProjectEvent is one immutable lifecycle event for a project. Message and
// Metadata are redacted before persistence by the transition path.
type ProjectEvent struct {
	ID             string
	OrganizationID string
	ProjectID      string
	EventType      ProjectEventType
	Message        string
	Metadata       map[string]string
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures a ProjectEvent safe.
func (e ProjectEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("project_id", e.ProjectID),
		slog.String("event_type", e.EventType.String()),
		slog.String("request_id", e.RequestID),
		slog.String("correlation_id", e.CorrelationID),
	)
}

const projectEventColumns = `id, organization_id, project_id, event_type,
	message, metadata, request_id, correlation_id, occurred_at, created_at`

// ProjectEventRepository is the persistence surface for project_events. Rows
// are append-only and tenant-scoped by (organization_id, project_id).
type ProjectEventRepository struct{}

// NewProjectEventRepository returns a ProjectEventRepository.
func NewProjectEventRepository() *ProjectEventRepository { return &ProjectEventRepository{} }

// Append persists e as a new project_events row inside tx.
func (r *ProjectEventRepository) Append(ctx context.Context, tx *Tx, e ProjectEvent) (ProjectEvent, error) {
	if tx == nil {
		return ProjectEvent{}, apierr.Internal(errors.New("store: ProjectEventRepository.Append called with a nil transaction"))
	}
	if e.EventType == "" {
		return ProjectEvent{}, apierr.Internal(errors.New("store: ProjectEventRepository.Append called with a blank event type"))
	}
	if e.ID == "" {
		id, err := newProjectEventID()
		if err != nil {
			return ProjectEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalProjectEventMetadata(e.Metadata)
	if err != nil {
		return ProjectEvent{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO project_events
		   (id, organization_id, project_id, event_type,
		    message, metadata, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4,
		         $5, $6, $7, $8, COALESCE($9, now()))
		 RETURNING `+projectEventColumns,
		e.ID, e.OrganizationID, e.ProjectID, e.EventType.String(),
		e.Message, metadata, e.RequestID, e.CorrelationID, nullableOccurredAt(e.OccurredAt))
	created, err := scanProjectEvent(row)
	if err != nil {
		return ProjectEvent{}, mapWriteError(err, "a project event with this id already exists")
	}
	return created, nil
}

// ListByProject returns every event owned by (organizationID, projectID),
// oldest first.
func (r *ProjectEventRepository) ListByProject(ctx context.Context, q Querier, organizationID, projectID string) ([]ProjectEvent, error) {
	rows, err := q.Query(ctx,
		`SELECT `+projectEventColumns+`
		   FROM project_events
		  WHERE organization_id = $1 AND project_id = $2
		  ORDER BY occurred_at ASC, id ASC
		  LIMIT $3`,
		organizationID, projectID, projectEventListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]ProjectEvent, 0)
	for rows.Next() {
		e, scanErr := scanProjectEvent(rows)
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

// GetByID returns one project_events row by tenant-scoped id.
func (r *ProjectEventRepository) GetByID(ctx context.Context, q Querier, organizationID, eventID string) (ProjectEvent, error) {
	row := q.QueryRow(ctx,
		`SELECT `+projectEventColumns+`
		   FROM project_events
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, eventID)
	e, err := scanProjectEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProjectEvent{}, apierr.NotFound("project_event", eventID)
	}
	if err != nil {
		return ProjectEvent{}, apierr.StoreUnavailable(err)
	}
	return e, nil
}

func scanProjectEvent(row scanRow) (ProjectEvent, error) {
	var (
		e            ProjectEvent
		eventTypeStr string
		metadataRaw  []byte
	)
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.ProjectID,
		&eventTypeStr,
		&e.Message,
		&metadataRaw,
		&e.RequestID,
		&e.CorrelationID,
		&e.OccurredAt,
		&e.CreatedAt,
	); err != nil {
		return ProjectEvent{}, err
	}
	e.EventType = ProjectEventType(eventTypeStr)
	metadata, err := unmarshalProjectEventMetadata(metadataRaw)
	if err != nil {
		return ProjectEvent{}, err
	}
	e.Metadata = metadata
	return e, nil
}

func marshalProjectEventMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling project event metadata: %w", err)
	}
	return b, nil
}

func unmarshalProjectEventMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var out map[string]string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshalling project event metadata: %w", err)
	}
	if out == nil {
		return map[string]string{}, nil
	}
	return out, nil
}

func newProjectEventID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("store: generating project event id: %w", err)
	}
	return "pevt_" + hex.EncodeToString(raw[:]), nil
}
