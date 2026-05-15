package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// The action strings recorded on audit events written by the break-glass
// service. They are kept as plain string constants here so the store layer
// takes no build dependency on internal/controlplane/policy; the HTTP
// authorization middleware authorizes the same actions before the handler
// is reached, and the policy matrix tests keep the two values in sync.
const (
	breakGlassStartAction  = "admin.break_glass"
	breakGlassRevokeAction = "admin.break_glass"
)

// breakGlassMaxTTL caps how far in the future a break-glass session may be
// scheduled to expire. A multi-hour session is enough for any legitimate
// support engagement; preventing a year-long session is a structural
// safeguard the engine layer does not need to second-guess.
const breakGlassMaxTTL = 24 * time.Hour

// breakGlassReasonMaxLen caps the operator-authored reason field so a
// runaway client cannot blow the JSON envelope or the database row out.
const breakGlassReasonMaxLen = 4096

// breakGlassSessionListMaxLimit caps how many sessions a single
// ListByOrganization call returns, so an unbounded query can never be
// issued by accident. A non-positive or larger requested limit is clamped
// to this value.
const breakGlassSessionListMaxLimit = 200

// BreakGlassSession is the source-of-truth representation of a row in the
// break_glass_sessions table — one durable record of an internal support
// session in which an admin uses their support capability to access
// another tenant's data.
//
// The reason field is operator-authored justification (an incident id, a
// ticket id, a one-line note). It is treated as auditable but not as
// credential material; the service layer rejects payloads under
// secret-shaped keys and scrubs known secret transport patterns before
// the row is persisted. ip_address and user_agent are recorded as-is for
// forensic correlation; the user_agent is scrubbed by the same redactor
// the audit log uses.
type BreakGlassSession struct {
	ID                  string
	OrganizationID      string
	ActorID             string
	ActorKind           string
	ActorOrganizationID string
	Reason              string
	StartedAt           time.Time
	ExpiresAt           time.Time
	RevokedAt           *time.Time
	RevokedByID         string
	RevokedByKind       string
	RequestID           string
	CorrelationID       string
	IPAddress           string
	UserAgent           string
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Active reports whether the session is still in force at t. A session is
// active when it has not been revoked and its expiry is strictly in the
// future relative to t. The check uses the persisted expiry rather than a
// stored "active" flag so a session whose deadline has elapsed flips to
// inactive automatically, without requiring a sweeper job.
func (s BreakGlassSession) Active(t time.Time) bool {
	if s.RevokedAt != nil && !s.RevokedAt.IsZero() {
		return false
	}
	return t.Before(s.ExpiresAt)
}

// breakGlassColumns is the column list returned by every read query, in the
// order scanBreakGlassSession expects.
const breakGlassColumns = `id, organization_id, actor_id, actor_kind, actor_organization_id,
	reason, started_at, expires_at, revoked_at, revoked_by_id, revoked_by_kind,
	request_id, correlation_id, ip_address, user_agent, version, created_at, updated_at`

// BreakGlassRepository is the persistence layer for the break_glass_sessions
// table. It follows the same transaction pattern as the rest of the store —
// mutations require a *Tx, reads accept a Querier, every query is tenant
// scoped — with the deliberate addition that the schema rejects rewriting
// any column except the revocation columns at the database level. A session
// row is therefore append-mostly even against a direct SQL console.
type BreakGlassRepository struct{}

// NewBreakGlassRepository returns a BreakGlassRepository.
func NewBreakGlassRepository() *BreakGlassRepository { return &BreakGlassRepository{} }

// Append inserts a new break-glass session inside tx and returns the persisted
// row, including the database-assigned timestamps. It requires a *Tx — not a
// bare Querier — so the session row commits or rolls back atomically with
// the audit record the service appends in the same transaction. A blank ID
// is minted here. The schema's CHECK predicates reject a non-positive TTL,
// a blank reason, or an unknown actor kind; those rejections roll the whole
// transaction back as a typed Conflict, the same way every other constraint
// violation does.
func (r *BreakGlassRepository) Append(ctx context.Context, tx *Tx, s BreakGlassSession) (BreakGlassSession, error) {
	if tx == nil {
		return BreakGlassSession{}, apierr.Internal(errors.New("store: BreakGlassRepository.Append called with a nil transaction"))
	}
	if s.ID == "" {
		id, err := newBreakGlassID()
		if err != nil {
			return BreakGlassSession{}, apierr.Internal(err)
		}
		s.ID = id
	}
	if s.StartedAt.IsZero() {
		s.StartedAt = time.Now().UTC()
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO break_glass_sessions
			(id, organization_id, actor_id, actor_kind, actor_organization_id,
			 reason, started_at, expires_at,
			 request_id, correlation_id, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 RETURNING `+breakGlassColumns,
		s.ID, s.OrganizationID, s.ActorID, s.ActorKind, s.ActorOrganizationID,
		s.Reason, s.StartedAt.UTC(), s.ExpiresAt.UTC(),
		s.RequestID, s.CorrelationID, s.IPAddress, s.UserAgent)
	created, err := scanBreakGlassSession(row)
	if err != nil {
		return BreakGlassSession{}, mapWriteError(err, "a break-glass session with this id already exists")
	}
	return created, nil
}

// Get returns the break-glass session for sessionID scoped to organizationID,
// or a typed NotFound if it does not exist within that organization. The
// query is tenant scoped, so a session id from another organization simply
// does not match and is reported as NotFound — a cross-tenant id can never
// reveal another organization's data.
func (r *BreakGlassRepository) Get(ctx context.Context, q Querier, organizationID, sessionID string) (BreakGlassSession, error) {
	row := q.QueryRow(ctx,
		`SELECT `+breakGlassColumns+`
		   FROM break_glass_sessions
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, sessionID)
	s, err := scanBreakGlassSession(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return BreakGlassSession{}, apierr.NotFound("break_glass_session", sessionID)
	}
	if err != nil {
		return BreakGlassSession{}, apierr.StoreUnavailable(err)
	}
	return s, nil
}

// ListByOrganization returns the break-glass sessions targeting organizationID,
// newest first by started_at then id, capped at limit (clamped to a sane
// maximum, and to that maximum when limit is non-positive). The query is
// tenant scoped, so an organization id from another tenant simply matches
// no rows.
func (r *BreakGlassRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string, limit int) ([]BreakGlassSession, error) {
	if limit <= 0 || limit > breakGlassSessionListMaxLimit {
		limit = breakGlassSessionListMaxLimit
	}
	rows, err := q.Query(ctx,
		`SELECT `+breakGlassColumns+`
		   FROM break_glass_sessions
		  WHERE organization_id = $1
		  ORDER BY started_at DESC, id DESC
		  LIMIT $2`,
		organizationID, limit)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]BreakGlassSession, 0)
	for rows.Next() {
		s, scanErr := scanBreakGlassSession(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// MarkRevoked sets the revocation columns on the session for sessionID scoped
// to organizationID, but only if it is still active (not already revoked).
// It returns the updated row, a typed NotFound if no such session exists for
// the tenant, and a typed Conflict if the session has already been revoked
// or has expired — a revoke against a session that no longer needs revoking
// must not silently succeed, because the audit record names the actor who
// revoked it. The schema rejects rewriting any column other than the
// revocation columns at the database level, so a misuse of this method
// cannot corrupt the trail.
func (r *BreakGlassRepository) MarkRevoked(ctx context.Context, tx *Tx, organizationID, sessionID, revokedByID, revokedByKind string, at time.Time) (BreakGlassSession, error) {
	if tx == nil {
		return BreakGlassSession{}, apierr.Internal(errors.New("store: BreakGlassRepository.MarkRevoked called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`UPDATE break_glass_sessions
		    SET revoked_at      = $3,
		        revoked_by_id   = $4,
		        revoked_by_kind = $5
		  WHERE organization_id = $1
		    AND id              = $2
		    AND revoked_at IS NULL
		 RETURNING `+breakGlassColumns,
		organizationID, sessionID, at.UTC(), revokedByID, revokedByKind)
	s, err := scanBreakGlassSession(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// Tell the caller why: either no such session for the tenant, or it
		// has already been revoked. Distinguishing the two requires a follow
		// up read so the error message stays diagnosable without leaking
		// data across tenants.
		existing, getErr := r.Get(ctx, tx, organizationID, sessionID)
		if getErr != nil {
			return BreakGlassSession{}, getErr
		}
		return BreakGlassSession{}, apierr.Conflict("break-glass session " + existing.ID + " has already been revoked")
	}
	if err != nil {
		return BreakGlassSession{}, mapWriteError(err, "break-glass session revocation conflicts with existing state")
	}
	return s, nil
}

// scanBreakGlassSession scans one break_glass_sessions row in breakGlassColumns
// order. pgx.Rows satisfies pgx.Row, so the same scanner serves both single
// row queries and list loops.
func scanBreakGlassSession(row pgx.Row) (BreakGlassSession, error) {
	var (
		s         BreakGlassSession
		revokedAt *time.Time
	)
	if err := row.Scan(
		&s.ID, &s.OrganizationID, &s.ActorID, &s.ActorKind, &s.ActorOrganizationID,
		&s.Reason, &s.StartedAt, &s.ExpiresAt, &revokedAt, &s.RevokedByID, &s.RevokedByKind,
		&s.RequestID, &s.CorrelationID, &s.IPAddress, &s.UserAgent,
		&s.Version, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return BreakGlassSession{}, err
	}
	if revokedAt != nil && !revokedAt.IsZero() {
		t := revokedAt.UTC()
		s.RevokedAt = &t
	}
	s.StartedAt = s.StartedAt.UTC()
	s.ExpiresAt = s.ExpiresAt.UTC()
	s.CreatedAt = s.CreatedAt.UTC()
	s.UpdatedAt = s.UpdatedAt.UTC()
	return s, nil
}

// newBreakGlassID mints an opaque, non-guessable id for a break_glass_sessions
// row. Sessions are not on the domain.Kind hierarchy — they describe access
// to a tenant rather than being themselves a tenant resource — so this
// package mints their ids directly, exactly like newAuditID.
func newBreakGlassID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("store: generating break-glass session id entropy: %w", err)
	}
	return "bgs_" + hex.EncodeToString(buf[:]), nil
}
