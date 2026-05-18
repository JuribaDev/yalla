package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// breakGlassElevatedAccessKey is the audit-metadata key the service stamps
// on every break-glass session record. Any audit row carrying this key with
// value "true" represents an elevated-access mutation; analytics, alerting,
// and dashboards branch on it. The value is a literal string so the JSON
// projection is stable and easy to grep.
const (
	breakGlassElevatedAccessKey   = "elevated_access"
	breakGlassElevatedAccessValue = "true"
)

// StartBreakGlassInput is the input to BreakGlassService.StartSession.
//
// OrganizationID is the target tenant — the organization the support
// principal needs to reach into. ActorID/ActorKind/ActorOrgID describe the
// authenticated principal performing the elevated access (typically a
// support user in Yalla's home org). Reason is the operator-authored
// justification (incident id, ticket reference). TTL is how long the
// session may stay active relative to NowFn(); a zero or negative TTL is a
// validation failure and a TTL greater than breakGlassMaxTTL is capped.
// The Request/Correlation/IP/UserAgent fields ride along on the durable
// row and the audit event for forensic correlation.
type StartBreakGlassInput struct {
	OrganizationID string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	Reason         string
	TTL            time.Duration
	RequestID      string
	CorrelationID  string
	IPAddress      string
	UserAgent      string
}

// RevokeBreakGlassInput is the input to BreakGlassService.Revoke.
type RevokeBreakGlassInput struct {
	OrganizationID string
	SessionID      string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
	IPAddress      string
	UserAgent      string
}

// BreakGlassService is the unit-of-work orchestrator for the break-glass
// surface. StartSession and Revoke each compose — in a fixed order, inside
// one transaction — a tenant-scoped existence check on the target
// organization, the session-row mutation, and the immutable audit event
// stamped with elevated_access=true. Because every step shares the *Tx
// opened by Store.Write, a failure in any of them rolls the others back: a
// session row without its audit trail, or an audit record for a session
// that never persisted, are both impossible.
//
// The service intentionally does NOT mint API keys, rotate keys, or perform
// any other credential-bearing mutation. Break-glass is access-only: the
// session records that the support principal reached into the target
// tenant, the policy engine continues to deny anything the principal's
// role does not authorize, and a separate test asserts the support role
// cannot reach keys.manage even with an active session.
type BreakGlassService struct {
	store    *Store
	orgs     *OrganizationRepository
	sessions *BreakGlassRepository
	audit    AuditAppender
	redactor *output.Redactor
	nowFn    func() time.Time
}

// NewBreakGlassService wires a BreakGlassService from its dependencies. It
// returns a typed error if any dependency is nil, so a misconfigured service
// fails at construction rather than on its first request. nowFn is plumbed
// in so unit tests can pin time; production callers should leave it nil to
// use time.Now in UTC.
func NewBreakGlassService(s *Store, orgs *OrganizationRepository, sessions *BreakGlassRepository, audit AuditAppender, nowFn func() time.Time) (*BreakGlassService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case orgs == nil:
		return nil, errors.New("store: nil organization repository")
	case sessions == nil:
		return nil, errors.New("store: nil break-glass repository")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	return &BreakGlassService{
		store:    s,
		orgs:     orgs,
		sessions: sessions,
		audit:    audit,
		redactor: output.NewRedactor(),
		nowFn:    nowFn,
	}, nil
}

// StartSession validates in, then runs the start-break-glass unit of work
// inside one transaction: verify the target organization exists, insert the
// session row, append the audit event with elevated_access=true. Validation
// runs before the transaction is opened, so an invalid request never
// touches the database. An organization that does not exist is the typed
// NotFound the existence check produces.
func (svc *BreakGlassService) StartSession(ctx context.Context, in StartBreakGlassInput) (BreakGlassSession, error) {
	now := svc.now()
	session, err := svc.buildSessionToCreate(in, now)
	if err != nil {
		return BreakGlassSession{}, err
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return BreakGlassSession{}, apierr.Internal(errors.New("store: BreakGlassService.StartSession requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         breakGlassStartAction,
		ResourceKind:   string(domain.KindOrganization),
		ResourceID:     session.OrganizationID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for admin.break_glass (start)",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		IPAddress:      strings.TrimSpace(in.IPAddress),
		UserAgent:      svc.redactor.Redact(strings.TrimSpace(in.UserAgent)),
		Metadata: map[string]string{
			breakGlassElevatedAccessKey: breakGlassElevatedAccessValue,
			"target_organization_id":    session.OrganizationID,
			"expires_at":                session.ExpiresAt.Format(time.RFC3339Nano),
			"ttl_seconds":               itoa(int(session.ExpiresAt.Sub(session.StartedAt) / time.Second)),
		},
	}

	var persisted BreakGlassSession
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, getErr := svc.orgs.Get(ctx, tx, session.OrganizationID); getErr != nil {
			return getErr
		}
		row, insErr := svc.sessions.Append(ctx, tx, session)
		if insErr != nil {
			return insErr
		}
		// Stamp the audit event with the persisted session id so reviewers
		// can join audit_events to break_glass_sessions trivially.
		event.Metadata["break_glass_session_id"] = row.ID
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		persisted = row
		return nil
	})
	if txErr != nil {
		return BreakGlassSession{}, txErr
	}
	return persisted, nil
}

// Revoke ends an active session early. It runs in one transaction: verify
// the target organization exists, mark the session revoked, append the
// audit event with elevated_access=true. A session that is already
// revoked or that has elapsed is reported as a typed Conflict; a session
// that does not exist for the tenant is a typed NotFound.
func (svc *BreakGlassService) Revoke(ctx context.Context, in RevokeBreakGlassInput) (BreakGlassSession, error) {
	organizationID := strings.TrimSpace(in.OrganizationID)
	sessionID := strings.TrimSpace(in.SessionID)
	if organizationID == "" {
		return BreakGlassSession{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	if sessionID == "" {
		return BreakGlassSession{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "session_id",
			Reason: "must not be blank",
		})
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return BreakGlassSession{}, apierr.Internal(errors.New("store: BreakGlassService.Revoke requires an actor organization for the audit record"))
	}

	now := svc.now()
	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         breakGlassRevokeAction,
		ResourceKind:   string(domain.KindOrganization),
		ResourceID:     organizationID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for admin.break_glass (revoke)",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		IPAddress:      strings.TrimSpace(in.IPAddress),
		UserAgent:      svc.redactor.Redact(strings.TrimSpace(in.UserAgent)),
		Metadata: map[string]string{
			breakGlassElevatedAccessKey: breakGlassElevatedAccessValue,
			"target_organization_id":    organizationID,
			"break_glass_session_id":    sessionID,
			"action_kind":               "revoke",
		},
	}

	var revoked BreakGlassSession
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, getErr := svc.orgs.Get(ctx, tx, organizationID); getErr != nil {
			return getErr
		}
		row, _, revErr := svc.sessions.Transition(ctx, tx, BreakGlassSessionTransition{
			OrganizationID: organizationID,
			SessionID:      sessionID,
			NextStatus:     BreakGlassSessionStatusRevoked,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			Reason:         "revoke",
			Now:            now,
		})
		if revErr != nil {
			if ye := yerr.From(revErr); ye.Code == yerr.CodeInvalidStateTransition {
				return apierr.Conflict("break-glass session " + sessionID + " has already been revoked")
			}
			return revErr
		}
		if _, audErr := svc.audit.Append(ctx, tx, event); audErr != nil {
			return audErr
		}
		revoked = row
		return nil
	})
	if txErr != nil {
		return BreakGlassSession{}, txErr
	}
	return revoked, nil
}

// now returns the current time through the injected clock, defaulting to
// time.Now in UTC when nowFn is nil.
func (svc *BreakGlassService) now() time.Time {
	t := svc.nowFn()
	return t.UTC()
}

// buildSessionToCreate validates in against the start-session contract and
// returns the BreakGlassSession to insert. Validation is split out so the
// rules are unit testable without a database, and so an invalid request is
// rejected before a transaction is ever opened. On failure it returns a
// typed apierr.InvalidInput carrying stable field paths — never the
// submitted reason — so the rejection can name the offending field
// without leaking input.
func (svc *BreakGlassService) buildSessionToCreate(in StartBreakGlassInput, now time.Time) (BreakGlassSession, error) {
	var violations []apierr.FieldViolation

	organizationID := strings.TrimSpace(in.OrganizationID)
	if organizationID == "" {
		violations = append(violations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must not be blank",
		})
	}
	actorID := strings.TrimSpace(in.ActorID)
	if actorID == "" {
		violations = append(violations, apierr.FieldViolation{
			Field:  "actor_id",
			Reason: "must not be blank",
		})
	}
	actorKind := strings.TrimSpace(in.ActorKind)
	switch actorKind {
	case string(domain.KindUser), string(domain.KindServiceAccount):
		// allowed
	default:
		violations = append(violations, apierr.FieldViolation{
			Field:  "actor_kind",
			Reason: "must be one of usr, sa",
		})
	}

	reason := strings.TrimSpace(in.Reason)
	switch {
	case reason == "":
		violations = append(violations, apierr.FieldViolation{
			Field:  "reason",
			Reason: "must not be blank",
		})
	case len(reason) > breakGlassReasonMaxLen:
		violations = append(violations, apierr.FieldViolation{
			Field:  "reason",
			Reason: "must be at most 4096 characters",
		})
	}

	ttl := in.TTL
	switch {
	case ttl <= 0:
		violations = append(violations, apierr.FieldViolation{
			Field:  "ttl",
			Reason: "must be a positive duration",
		})
	case ttl > breakGlassMaxTTL:
		ttl = breakGlassMaxTTL
	}

	if len(violations) > 0 {
		return BreakGlassSession{}, apierr.InvalidInput(violations...)
	}

	// Scrub known secret transport patterns from the reason before it lands
	// on disk. The audit log already redacts values under secret-shaped
	// keys; here the *value* itself is the reason, so we apply the
	// redactor without renaming the field. Operator-authored reasons
	// should not contain credential material; the scrub is a structural
	// backstop, not a sanctioning of leaking secrets into justifications.
	reason = svc.redactor.Redact(reason)

	started := now.UTC()
	return BreakGlassSession{
		OrganizationID:      organizationID,
		ActorID:             actorID,
		ActorKind:           actorKind,
		ActorOrganizationID: strings.TrimSpace(in.ActorOrgID),
		Reason:              reason,
		Status:              BreakGlassSessionStatusActive,
		StartedAt:           started,
		ExpiresAt:           started.Add(ttl),
		RequestID:           strings.TrimSpace(in.RequestID),
		CorrelationID:       strings.TrimSpace(in.CorrelationID),
		IPAddress:           strings.TrimSpace(in.IPAddress),
		UserAgent:           svc.redactor.Redact(strings.TrimSpace(in.UserAgent)),
	}, nil
}

// ListSessions returns the break-glass sessions targeting organizationID,
// newest first, capped at the repository's documented maximum. The query
// opens its own read-only transaction through Store.Read so each call gets
// a consistent snapshot.
func (svc *BreakGlassService) ListSessions(ctx context.Context, organizationID string, limit int) ([]BreakGlassSession, error) {
	var out []BreakGlassSession
	if err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		sessions, err := svc.sessions.ListByOrganization(ctx, q, organizationID, limit)
		if err != nil {
			return err
		}
		out = sessions
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// GetSession returns one break-glass session by id scoped to organizationID,
// or a typed NotFound if it does not exist within the tenant. The query
// opens its own read-only transaction.
func (svc *BreakGlassService) GetSession(ctx context.Context, organizationID, sessionID string) (BreakGlassSession, error) {
	var out BreakGlassSession
	if err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		s, err := svc.sessions.Get(ctx, q, organizationID, sessionID)
		if err != nil {
			return err
		}
		out = s
		return nil
	}); err != nil {
		return BreakGlassSession{}, err
	}
	return out, nil
}
