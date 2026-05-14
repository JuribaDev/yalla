package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// AuditDecision is the verdict an audit record captures. An authorization
// decision is recorded whether it allowed or denied the action, so the audit
// log is the source of truth for both "what was done" and "what was refused".
type AuditDecision string

const (
	// AuditDecisionAllowed marks a recorded decision that permitted the action.
	AuditDecisionAllowed AuditDecision = "allowed"
	// AuditDecisionDenied marks a recorded decision that refused the action.
	AuditDecisionDenied AuditDecision = "denied"
)

// Valid reports whether d is one of the two recognised verdicts. It mirrors the
// audit_events.decision CHECK constraint.
func (d AuditDecision) Valid() bool {
	return d == AuditDecisionAllowed || d == AuditDecisionDenied
}

// String returns the decision's stable string value.
func (d AuditDecision) String() string { return string(d) }

// auditEventListMaxLimit caps how many audit rows a single ListByOrganization
// call returns, so an unbounded query can never be issued by accident. A
// non-positive or larger requested limit is clamped to this value.
const auditEventListMaxLimit = 200

// AuditEvent is the source-of-truth representation of a row in the audit_events
// table — one immutable record of a security-relevant authorization decision.
// It is the persistence-layer shape; building an AuditEvent from a policy
// decision, a principal, and request context (and redacting its metadata) is
// the job of internal/controlplane/audit.
//
// Actor fields are empty for a denied decision that never resolved a principal
// (an unauthenticated request is still audited). Metadata is expected to be
// already redacted by the time it reaches this layer; no field ever carries a
// token, API key, cookie, or rendered environment variable value.
type AuditEvent struct {
	ID             string
	OrganizationID string
	ActorID        string
	ActorKind      string
	Action         string
	ResourceKind   string
	ResourceID     string
	Decision       AuditDecision
	Reason         string
	RequestID      string
	CorrelationID  string
	IPAddress      string
	UserAgent      string
	Metadata       map[string]string
	OccurredAt     time.Time
	CreatedAt      time.Time
}

// AuditRepository is the persistence layer for Yalla's immutable audit log. It
// follows the same transaction pattern as ProjectRepository — mutations require
// a *Tx, reads accept a Querier, every query is tenant scoped — with one
// deliberate addition: it exposes only an append and tenant-scoped reads. There
// is no update or delete method, so application code structurally cannot alter
// or remove an audit record. The audit_events table additionally rejects every
// UPDATE at the database level, so immutability holds even against a direct SQL
// console.
//
// The repository is stateless; the constructor exists so call sites depend on a
// value rather than a bare struct literal.
type AuditRepository struct{}

// NewAuditRepository returns an AuditRepository.
func NewAuditRepository() *AuditRepository { return &AuditRepository{} }

// auditEventColumns is the column list returned by every audit query, in the
// order scanAuditEvent expects.
const auditEventColumns = `id, organization_id, actor_id, actor_kind, action, ` +
	`resource_kind, resource_id, decision, reason, request_id, correlation_id, ` +
	`ip_address, user_agent, metadata, occurred_at, created_at`

// Append writes a new audit record inside tx and returns the persisted row,
// including the database-assigned timestamps. It requires a *Tx — not a bare
// Querier — so an audit record can be written in the same transaction as the
// mutation it records, and so the audit write commits or rolls back atomically
// with that mutation. A blank ID is minted here. The decision must be a valid
// verdict; an invalid one is a programming error and is reported as Internal
// rather than reaching the database.
func (r *AuditRepository) Append(ctx context.Context, tx *Tx, e AuditEvent) (AuditEvent, error) {
	if tx == nil {
		return AuditEvent{}, apierr.Internal(errors.New("store: AuditRepository.Append called with a nil transaction"))
	}
	if !e.Decision.Valid() {
		return AuditEvent{}, apierr.Internal(fmt.Errorf("store: AuditRepository.Append called with an invalid decision %q", e.Decision))
	}
	if e.ID == "" {
		id, err := newAuditID()
		if err != nil {
			return AuditEvent{}, apierr.Internal(err)
		}
		e.ID = id
	}
	metadata, err := marshalAuditMetadata(e.Metadata)
	if err != nil {
		return AuditEvent{}, apierr.Internal(err)
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO audit_events
		   (id, organization_id, actor_id, actor_kind, action, resource_kind,
		    resource_id, decision, reason, request_id, correlation_id,
		    ip_address, user_agent, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 RETURNING `+auditEventColumns,
		e.ID, e.OrganizationID, e.ActorID, e.ActorKind, e.Action, e.ResourceKind,
		e.ResourceID, string(e.Decision), e.Reason, e.RequestID, e.CorrelationID,
		e.IPAddress, e.UserAgent, metadata)
	created, err := scanAuditEvent(row)
	if err != nil {
		return AuditEvent{}, mapWriteError(err, "an audit event with this id already exists")
	}
	return created, nil
}

// ListByOrganization returns the most recent audit events for organizationID,
// newest first, capped at limit (clamped to a sane maximum, and to that maximum
// when limit is non-positive). The query is tenant scoped by organization_id,
// so an organization id from another tenant simply matches no rows — the audit
// log of one organization can never be read through another's id. It accepts a
// Querier so it works against a read-only transaction or an open write
// transaction.
func (r *AuditRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > auditEventListMaxLimit {
		limit = auditEventListMaxLimit
	}
	rows, err := q.Query(ctx,
		`SELECT `+auditEventColumns+`
		   FROM audit_events
		  WHERE organization_id = $1
		  ORDER BY occurred_at DESC, id DESC
		  LIMIT $2`,
		organizationID, limit)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		e, scanErr := scanAuditEvent(rows)
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

// scanAuditEvent scans one audit row in auditEventColumns order. pgx.Rows
// satisfies pgx.Row, so the same scanner serves both the single-row Append
// RETURNING and the ListByOrganization loop.
func scanAuditEvent(row pgx.Row) (AuditEvent, error) {
	var (
		e        AuditEvent
		decision string
		metadata []byte
	)
	if err := row.Scan(
		&e.ID, &e.OrganizationID, &e.ActorID, &e.ActorKind, &e.Action,
		&e.ResourceKind, &e.ResourceID, &decision, &e.Reason, &e.RequestID,
		&e.CorrelationID, &e.IPAddress, &e.UserAgent, &metadata,
		&e.OccurredAt, &e.CreatedAt,
	); err != nil {
		return AuditEvent{}, err
	}
	e.Decision = AuditDecision(decision)
	parsed, err := unmarshalAuditMetadata(metadata)
	if err != nil {
		return AuditEvent{}, err
	}
	e.Metadata = parsed
	return e, nil
}

// marshalAuditMetadata renders audit metadata for the jsonb column. A nil or
// empty map becomes the empty JSON object so the column never stores SQL NULL,
// keeping reads total. json.Marshal sorts map keys, so the stored document is
// deterministic.
func marshalAuditMetadata(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling audit metadata: %w", err)
	}
	return b, nil
}

// unmarshalAuditMetadata parses the jsonb metadata column back into a map. An
// empty or empty-object document yields a nil map so callers do not have to
// distinguish "no metadata" from "empty metadata".
func unmarshalAuditMetadata(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("store: unmarshalling audit metadata: %w", err)
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}

// newAuditID mints an opaque, non-guessable id for an audit_events row. Audit
// records are an internal accounting trail rather than customer-facing domain
// resources, so — like the quota accounting rows — they carry their own
// prefixed id rather than a domain.Kind id.
func newAuditID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("store: generating audit id entropy: %w", err)
	}
	return "aud_" + hex.EncodeToString(buf[:]), nil
}
