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

// DeploymentEventType is the closed-set kind of a deployment_events row. The
// first six values mirror the deployments.status taxonomy so a deployment's
// status timeline can be reconstructed by replaying the event log; 'progress'
// is a non-terminal worker progress beat for long-running deploys that does
// not change the deployment's status, and 'log' is a redacted worker log line.
// The string values match the deployment_events.event_type CHECK constraint
// verbatim and are public compatibility contract for the timeline endpoint.
type DeploymentEventType string

const (
	// DeploymentEventTypeQueued records a deployment entering the queued
	// lifecycle state. It is the first event a worker emits when it claims
	// the provisioning job.
	DeploymentEventTypeQueued DeploymentEventType = "queued"
	// DeploymentEventTypeRunning records a deployment entering the running
	// lifecycle state. The worker emits it once the Dokploy mutation has
	// been accepted upstream.
	DeploymentEventTypeRunning DeploymentEventType = "running"
	// DeploymentEventTypeSucceeded records a deployment converging to the
	// terminal succeeded state.
	DeploymentEventTypeSucceeded DeploymentEventType = "succeeded"
	// DeploymentEventTypeFailed records a deployment converging to the
	// terminal failed state. The message column carries the redacted
	// failure summary the worker observed.
	DeploymentEventTypeFailed DeploymentEventType = "failed"
	// DeploymentEventTypeCancelled records a deployment converging to the
	// terminal cancelled state.
	DeploymentEventTypeCancelled DeploymentEventType = "cancelled"
	// DeploymentEventTypeRolledBack records a deployment converging to the
	// terminal rolled-back state.
	DeploymentEventTypeRolledBack DeploymentEventType = "rolled_back"
	// DeploymentEventTypeProgress records a non-terminal worker progress
	// beat (e.g. "pulled image", "started container", "waiting for
	// healthcheck") that does not change the deployment's status. The
	// message column carries the redacted progress text.
	DeploymentEventTypeProgress DeploymentEventType = "progress"
	// DeploymentEventTypeLog records a redacted worker log line attached to
	// the deployment timeline. The message column carries the redacted log
	// text. Unlike 'progress', a log event is not expected to correlate
	// with a status transition.
	DeploymentEventTypeLog DeploymentEventType = "log"
)

// String returns the type's stable string value, matching the database
// CHECK constraint verbatim.
func (t DeploymentEventType) String() string { return string(t) }

// deploymentEventListMaxRows caps how many deployment_events rows a single
// ListByDeployment call returns, so an unbounded query can never be issued by
// accident; an HTTP layer that wants pagination later will add an explicit
// offset or cursor parameter rather than relax this ceiling.
const deploymentEventListMaxRows = 500

// DeploymentEvent is the source-of-truth representation of a row in the
// deployment_events table — one immutable record on the timeline of a single
// deployment. The DeploymentEvent struct is the persistence-layer shape;
// building an event from a worker observation (and redacting its message and
// metadata) is the job of the worker layer.
//
// The struct carries no credential material — message and metadata are
// redacted by the worker before they reach this layer, and no other field
// stores tokens, API keys, cookies, or rendered environment variable values.
type DeploymentEvent struct {
	ID             string
	OrganizationID string
	DeploymentID   string
	EventType      DeploymentEventType
	Message        string
	Metadata       map[string]string
	RequestID      string
	CorrelationID  string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures a DeploymentEvent safe.
// Message and metadata are redacted by the writer before this layer, but
// LogValue omits them at the slog boundary too so a panic stack trace that
// happens to include an event payload cannot inadvertently widen the redaction
// surface. The structural identifiers and event type are non-secret and are
// safe to log.
func (e DeploymentEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", e.ID),
		slog.String("organization_id", e.OrganizationID),
		slog.String("deployment_id", e.DeploymentID),
		slog.String("event_type", e.EventType.String()),
		slog.String("request_id", e.RequestID),
		slog.String("correlation_id", e.CorrelationID),
	)
}

// deploymentEventColumns is the SELECT projection used by every read in this
// repository. Keeping it as a single string keeps the column list in lockstep
// with scanDeploymentEvent.
const deploymentEventColumns = `id, organization_id, deployment_id, event_type,
	message, metadata, request_id, correlation_id, occurred_at, created_at`

// DeploymentEventRepository is the persistence half of the deployment_events
// surface. Every read and every write is tenant-scoped: the organization_id
// leg of the predicate is non-optional, so a missing or cross-tenant id
// matches no rows — never another tenant's deployment events. The repository
// is stateless; the constructor exists so call sites depend on a value rather
// than a bare struct literal.
//
// There is no per-row Update or Delete here: deployment_events is append-only
// by design — the database BEFORE UPDATE trigger rejects every update and
// the store package exposes no row-level delete of its own. Row removal is
// reachable only through ON DELETE CASCADE when the parent deployment (and
// in turn the organization) is deleted.
type DeploymentEventRepository struct{}

// NewDeploymentEventRepository returns a DeploymentEventRepository.
func NewDeploymentEventRepository() *DeploymentEventRepository {
	return &DeploymentEventRepository{}
}

// Append persists e as a new deployment_events row inside tx and returns the
// committed row (including the database-owned created_at, occurred_at, and
// id when blank). It requires a *Tx — not a bare Querier — so an event can
// be written in the same transaction as the deployment lifecycle mutation it
// records, and so the event write commits or rolls back atomically with that
// mutation. A blank ID is minted here with the depev_ prefix. A blank
// EventType is rejected as a programming error at the application boundary
// (the closed set is small and the database CHECK is the authoritative
// belt-and-braces).
//
// The schema enforces the tenant invariant — the composite foreign key
// (organization_id, deployment_id) references deployments
// (organization_id, id) so an event can never sit under a foreign tenant's
// deployment — and the event_type CHECK rejects an unknown type as a
// deterministic apierr.Conflict through mapWriteError; the raw constraint
// name never leaks into the user-facing message.
func (r *DeploymentEventRepository) Append(ctx context.Context, tx *Tx, e DeploymentEvent) (DeploymentEvent, error) {
	if tx == nil {
		return DeploymentEvent{}, apierr.Internal(errors.New("store: DeploymentEventRepository.Append called with a nil transaction"))
	}
	if e.EventType == "" {
		return DeploymentEvent{}, apierr.Internal(errors.New("store: DeploymentEventRepository.Append called with a blank event type"))
	}
	if e.ID == "" {
		id, err := newDeploymentEventID()
		if err != nil {
			return DeploymentEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalDeploymentEventMetadata(e.Metadata)
	if err != nil {
		return DeploymentEvent{}, apierr.Internal(err)
	}
	occurredAt := nullableOccurredAt(e.OccurredAt)
	row := tx.QueryRow(ctx,
		`INSERT INTO deployment_events
		   (id, organization_id, deployment_id, event_type,
		    message, metadata, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4,
		         $5, $6, $7, $8, COALESCE($9, now()))
		 RETURNING `+deploymentEventColumns,
		e.ID, e.OrganizationID, e.DeploymentID, e.EventType.String(),
		e.Message, metadata, e.RequestID, e.CorrelationID, occurredAt)
	created, err := scanDeploymentEvent(row)
	if err != nil {
		return DeploymentEvent{}, mapWriteError(err, "a deployment event with this id already exists")
	}
	return created, nil
}

// ListByDeployment returns every event owned by (organizationID,
// deploymentID), in chronological order (occurred_at ASC, id ASC as a
// tiebreaker), so the timeline endpoint renders the deployment unfolding
// forward in time. The read is tenant-scoped at the SQL predicate, so a
// cross-tenant tuple matches no rows. The query is bounded by
// deploymentEventListMaxRows; a future pagination story will add an explicit
// cursor.
//
// This method does NOT verify the deployment exists; callers that need to
// distinguish "deployment missing" from "deployment has no events" must
// Get the deployment first.
func (r *DeploymentEventRepository) ListByDeployment(ctx context.Context, q Querier, organizationID, deploymentID string) ([]DeploymentEvent, error) {
	rows, err := q.Query(ctx,
		`SELECT `+deploymentEventColumns+`
		   FROM deployment_events
		  WHERE organization_id = $1 AND deployment_id = $2
		  ORDER BY occurred_at ASC, id ASC
		  LIMIT $3`,
		organizationID, deploymentID, deploymentEventListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]DeploymentEvent, 0)
	for rows.Next() {
		e, scanErr := scanDeploymentEvent(rows)
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

// GetByID returns the single deployment_events row identified by
// (organizationID, eventID), tenant-scoped at the SQL predicate. The
// composite predicate is non-optional: a missing or cross-tenant
// organizationID matches no row even when an event with the same id exists
// in another tenant — the response is never an oracle that reveals another
// organization's event ids. A row that does not exist surfaces as the same
// typed apierr.NotFound, never as a 500 leaking the cause; the not-found
// payload names only the event id the caller already supplied.
func (r *DeploymentEventRepository) GetByID(ctx context.Context, q Querier, organizationID, eventID string) (DeploymentEvent, error) {
	row := q.QueryRow(ctx,
		`SELECT `+deploymentEventColumns+`
		   FROM deployment_events
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, eventID)
	e, err := scanDeploymentEvent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeploymentEvent{}, apierr.NotFound("deployment_event", eventID)
	}
	if err != nil {
		return DeploymentEvent{}, apierr.StoreUnavailable(err)
	}
	return e, nil
}

// nullableOccurredAt returns nil for the zero time so the INSERT lets the
// database stamp occurred_at with now(); a non-zero caller-supplied time is
// preserved verbatim so a worker that batches events or reconciles after a
// restart can persist the original wallclock the event was observed at.
func nullableOccurredAt(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// scanDeploymentEvent scans one deployment_events row in
// deploymentEventColumns order.
func scanDeploymentEvent(row scanRow) (DeploymentEvent, error) {
	var (
		e            DeploymentEvent
		eventTypeStr string
		metadataRaw  []byte
	)
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.DeploymentID,
		&eventTypeStr,
		&e.Message,
		&metadataRaw,
		&e.RequestID,
		&e.CorrelationID,
		&e.OccurredAt,
		&e.CreatedAt,
	); err != nil {
		return DeploymentEvent{}, err
	}
	e.EventType = DeploymentEventType(eventTypeStr)
	metadata, err := unmarshalDeploymentEventMetadata(metadataRaw)
	if err != nil {
		return DeploymentEvent{}, err
	}
	e.Metadata = metadata
	return e, nil
}

// marshalDeploymentEventMetadata renders event metadata for the jsonb column.
// A nil or empty map becomes the empty JSON object so the column never stores
// SQL NULL, keeping reads total. json.Marshal sorts map keys, so the stored
// document is deterministic.
func marshalDeploymentEventMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling deployment event metadata: %w", err)
	}
	return b, nil
}

// unmarshalDeploymentEventMetadata parses the jsonb metadata column back into
// a map. An empty or empty-object document yields a nil map so callers do not
// have to distinguish "no metadata" from "empty metadata".
func unmarshalDeploymentEventMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("store: unmarshalling deployment event metadata: %w", err)
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

// newDeploymentEventID mints an opaque, non-guessable id for a deployment_events
// row. Deployment events are an internal accounting trail rather than a
// customer-facing addressable resource (the customer addresses the timeline
// through its parent deployment id, not through individual event ids), so —
// like audit_events and quota_reservations — they carry their own prefixed
// id rather than a domain.Kind id.
func newDeploymentEventID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("store: generating deployment event id entropy: %w", err)
	}
	return "depev_" + hex.EncodeToString(buf[:]), nil
}
