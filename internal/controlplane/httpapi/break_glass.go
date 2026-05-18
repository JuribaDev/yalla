package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// errNoBreakGlassController is returned when a /v1/organizations/{org_id}/
// break-glass endpoint is reached without a controller wired into
// NewHandler. Like errNoLimitsReader it can only happen through a wiring
// error — a programming mistake, not a client error — so the handler
// reports it as a typed internal failure rather than silently failing.
var errNoBreakGlassController = errors.New("httpapi: no break-glass controller configured")

// breakGlassListDefaultLimit is the page size GET
// /v1/organizations/{org_id}/break-glass returns when the caller does not
// supply ?limit=.
const breakGlassListDefaultLimit = 50

// breakGlassListMaxLimit is the hard ceiling the handler accepts on
// ?limit=. It mirrors store.breakGlassSessionListMaxLimit so an agent
// learns the contract from the rejection rather than discovering the
// repository clamps silently.
const breakGlassListMaxLimit = 200

// breakGlassMinTTLSeconds is the smallest TTL (in seconds) the handler
// accepts on POST. A non-positive ttl is a stable 400.
const breakGlassMinTTLSeconds = 1

// BreakGlassController is the narrow port the break-glass HTTP surface
// depends on. *store.BreakGlassService satisfies it in production; tests
// supply a fake. Keeping the dependency an interface keeps the handlers
// unit-testable without a real database, mirroring the LimitsReader /
// LimitsUpdater pattern used by every other store-backed surface.
//
// The store contract is that every mutation appends an immutable audit
// event stamped with elevated_access=true inside the same transaction as
// the session-row write, so a successful response always names a session
// whose audit trail also persisted. A missing target organization is a
// typed NotFound; a session id not found within the named organization is
// also a typed NotFound, never another tenant's row.
type BreakGlassController interface {
	StartSession(ctx context.Context, in store.StartBreakGlassInput) (store.BreakGlassSession, error)
	Revoke(ctx context.Context, in store.RevokeBreakGlassInput) (store.BreakGlassSession, error)
	ListSessions(ctx context.Context, organizationID string, limit int) ([]store.BreakGlassSession, error)
	GetSession(ctx context.Context, organizationID, sessionID string) (store.BreakGlassSession, error)
}

// startBreakGlassRequest is the decoded POST
// /v1/organizations/{org_id}/break-glass body. Reason is the
// operator-authored justification (incident id, ticket id); the store
// service scrubs known secret transport patterns before persistence. TTL
// is expressed in whole seconds — JSON-native ergonomics, no string
// parsing — and must be a positive integer.
type startBreakGlassRequest struct {
	Reason     string `json:"reason"`
	TTLSeconds *int   `json:"ttl_seconds"`
}

// startAdminBreakGlassRequest is the decoded POST /v1/admin/break-glass
// body. organization_id may repeat the query-scoped target for typed
// clients, but the query parameter is the authorization-visible cross-tenant
// selector.
type startAdminBreakGlassRequest struct {
	OrganizationID string `json:"organization_id,omitempty"`
	Reason         string `json:"reason"`
	TTLSeconds     *int   `json:"ttl_seconds"`
}

// startBreakGlassPayload is the data block of the POST
// /v1/organizations/{org_id}/break-glass success envelope. It returns the
// persisted session row in the stable wire shape. The fields are
// non-secret identifiers and timestamps; the reason has already been
// scrubbed.
type startBreakGlassPayload struct {
	Session breakGlassSessionResource `json:"session"`
}

type listBreakGlassPayload struct {
	Sessions []breakGlassSessionResource `json:"sessions"`
}

type getBreakGlassPayload struct {
	Session breakGlassSessionResource `json:"session"`
}

type revokeBreakGlassPayload struct {
	Session breakGlassSessionResource `json:"session"`
}

// breakGlassSessionResource is the stable wire shape for one persisted
// break-glass session row. Active is computed against the current clock
// at projection time so the caller does not need to recompute it. The
// optional revoked_at is rendered as nil (JSON null) when the session is
// still active, mirroring how audit_events project nullable actor blocks.
type breakGlassSessionResource struct {
	ID                  string     `json:"id"`
	OrganizationID      string     `json:"organization_id"`
	ActorID             string     `json:"actor_id"`
	ActorKind           string     `json:"actor_kind"`
	ActorOrganizationID string     `json:"actor_organization_id"`
	Reason              string     `json:"reason"`
	Status              string     `json:"status"`
	StartedAt           time.Time  `json:"started_at"`
	ExpiresAt           time.Time  `json:"expires_at"`
	RevokedAt           *time.Time `json:"revoked_at"`
	RevokedByID         string     `json:"revoked_by_id"`
	RevokedByKind       string     `json:"revoked_by_kind"`
	Active              bool       `json:"active"`
	ElevatedAccess      bool       `json:"elevated_access"`
	RequestID           string     `json:"request_id"`
	CorrelationID       string     `json:"correlation_id"`
	Version             int64      `json:"version"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

func breakGlassSessionResourceOf(s store.BreakGlassSession, at time.Time) breakGlassSessionResource {
	return breakGlassSessionResource{
		ID:                  s.ID,
		OrganizationID:      s.OrganizationID,
		ActorID:             s.ActorID,
		ActorKind:           s.ActorKind,
		ActorOrganizationID: s.ActorOrganizationID,
		Reason:              s.Reason,
		Status:              s.Status.String(),
		StartedAt:           s.StartedAt,
		ExpiresAt:           s.ExpiresAt,
		RevokedAt:           s.RevokedAt,
		RevokedByID:         s.RevokedByID,
		RevokedByKind:       s.RevokedByKind,
		Active:              s.Active(at),
		ElevatedAccess:      true,
		RequestID:           s.RequestID,
		CorrelationID:       s.CorrelationID,
		Version:             s.Version,
		CreatedAt:           s.CreatedAt,
		UpdatedAt:           s.UpdatedAt,
	}
}

// startBreakGlassHandler builds the POST /v1/organizations/{org_id}/break-glass
// handler. It decodes the body, delegates to the store-layer unit of work
// (verify the target organization, insert the session, append the audit
// event), and renders the persisted row.
//
// RequireAuth gates the route on action admin.break_glass before the
// handler runs — authorized through organizationIDResolver against the
// organization the path names. admin.break_glass is a CapSupport action,
// so only a principal holding the support capability can start a
// session; an owner or admin of another tenant cannot. A
// support-principal start against a tenant other than its own is
// ReasonAllowedBySupport — the deliberate cross-tenant exception that
// makes break-glass useful — and is itself audited with
// elevated_access=true by the store-layer unit of work.
//
// Validation rejects a missing reason and a non-positive ttl_seconds
// with stable field paths before any database work runs. Body decoding
// uses validate.DecodeJSON so an oversized or malformed body is a typed
// 400 that never echoes the input.
func startBreakGlassHandler(ctl BreakGlassController, nowFn func() time.Time) http.HandlerFunc {
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if ctl == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoBreakGlassController))
			return
		}

		var req startBreakGlassRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		ttl, err := parseBreakGlassTTL(req.TTLSeconds)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())

		session, err := ctl.StartSession(r.Context(), store.StartBreakGlassInput{
			OrganizationID: r.PathValue("org_id"),
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			Reason:         req.Reason,
			TTL:            ttl,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
			IPAddress:      clientIP(r),
			UserAgent:      r.UserAgent(),
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), startBreakGlassPayload{
			Session: breakGlassSessionResourceOf(session, nowFn()),
		})
	}
}

func startAdminBreakGlassHandler(ctl BreakGlassController, nowFn func() time.Time) http.HandlerFunc {
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if ctl == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoBreakGlassController))
			return
		}

		var req startAdminBreakGlassRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		organizationID, err := parseAdminBreakGlassTarget(r, p.OrganizationID, req.OrganizationID)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		ttl, err := parseBreakGlassTTL(req.TTLSeconds)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		session, err := ctl.StartSession(r.Context(), store.StartBreakGlassInput{
			OrganizationID: organizationID,
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			Reason:         req.Reason,
			TTL:            ttl,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
			IPAddress:      clientIP(r),
			UserAgent:      r.UserAgent(),
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), startBreakGlassPayload{
			Session: breakGlassSessionResourceOf(session, nowFn()),
		})
	}
}

// listBreakGlassHandler builds the GET /v1/organizations/{org_id}/break-glass
// handler. It reads the most recent break-glass sessions targeting the
// organization named by the path parameter, newest first, capped at
// ?limit= (default 50, max 200).
//
// RequireAuth gates the route on action admin.break_glass before the
// handler runs.
func listBreakGlassHandler(ctl BreakGlassController, nowFn func() time.Time) http.HandlerFunc {
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if ctl == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoBreakGlassController))
			return
		}

		limit, err := parseBreakGlassLimit(r.URL.Query().Get("limit"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		sessions, err := ctl.ListSessions(r.Context(), r.PathValue("org_id"), limit)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		now := nowFn()
		payload := listBreakGlassPayload{
			Sessions: make([]breakGlassSessionResource, 0, len(sessions)),
		}
		for _, s := range sessions {
			payload.Sessions = append(payload.Sessions, breakGlassSessionResourceOf(s, now))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}

// getBreakGlassHandler builds the GET
// /v1/organizations/{org_id}/break-glass/{session_id} handler. It returns
// the named session if it exists within the named organization, or a
// typed NotFound otherwise. Tenant scoping is enforced both at the
// policy boundary (organizationIDResolver) and at the persistence layer
// (the repository query is filtered by organization_id).
func getBreakGlassHandler(ctl BreakGlassController, nowFn func() time.Time) http.HandlerFunc {
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if ctl == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoBreakGlassController))
			return
		}

		session, err := ctl.GetSession(r.Context(), r.PathValue("org_id"), r.PathValue("session_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusOK, requestID(r), getBreakGlassPayload{
			Session: breakGlassSessionResourceOf(session, nowFn()),
		})
	}
}

// revokeBreakGlassHandler builds the DELETE
// /v1/organizations/{org_id}/break-glass/{session_id} handler. It ends an
// active session early; the store-layer unit of work marks the row
// revoked and appends another audit event stamped with
// elevated_access=true inside the same transaction. A session that is
// already revoked or that has elapsed is a typed Conflict.
func revokeBreakGlassHandler(ctl BreakGlassController, nowFn func() time.Time) http.HandlerFunc {
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if ctl == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoBreakGlassController))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		session, err := ctl.Revoke(r.Context(), store.RevokeBreakGlassInput{
			OrganizationID: r.PathValue("org_id"),
			SessionID:      r.PathValue("session_id"),
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
			IPAddress:      clientIP(r),
			UserAgent:      r.UserAgent(),
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusOK, requestID(r), revokeBreakGlassPayload{
			Session: breakGlassSessionResourceOf(session, nowFn()),
		})
	}
}

// revokeAdminBreakGlassHandler builds the DELETE
// /v1/admin/break-glass/{session_id} handler. It mirrors the admin start
// route's query-scoped target selection: organization_id is read from the
// query string for cross-tenant support actions and defaults to the
// authenticated principal's home organization. RequireAuth authorizes
// admin.break_glass against that same target before this handler runs.
func revokeAdminBreakGlassHandler(ctl BreakGlassController, nowFn func() time.Time) http.HandlerFunc {
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if ctl == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoBreakGlassController))
			return
		}

		organizationID, err := parseAdminBreakGlassTarget(r, p.OrganizationID, "")
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		session, err := ctl.Revoke(r.Context(), store.RevokeBreakGlassInput{
			OrganizationID: organizationID,
			SessionID:      r.PathValue("session_id"),
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
			IPAddress:      clientIP(r),
			UserAgent:      r.UserAgent(),
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusOK, requestID(r), revokeBreakGlassPayload{
			Session: breakGlassSessionResourceOf(session, nowFn()),
		})
	}
}

// parseBreakGlassLimit resolves the effective page size from the optional
// ?limit= query parameter, mirroring parseAuditEventLimit. An absent
// parameter resolves to the handler default; a malformed, non-positive,
// or larger-than-ceiling value is rejected as a stable 400 before any
// database work runs.
func parseBreakGlassLimit(raw string) (int, error) {
	if raw == "" {
		return breakGlassListDefaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "limit",
			Reason: "must be a positive integer",
		})
	}
	if n < 1 || n > breakGlassListMaxLimit {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "limit",
			Reason: "must be between 1 and " + strconv.Itoa(breakGlassListMaxLimit),
		})
	}
	return n, nil
}

func parseBreakGlassTTL(raw *int) (time.Duration, error) {
	if raw == nil {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "ttl_seconds",
			Reason: "must be supplied",
		})
	}
	if *raw < breakGlassMinTTLSeconds {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "ttl_seconds",
			Reason: "must be a positive number of seconds",
		})
	}
	// A TTL above the documented ceiling is clamped server-side by the
	// store; reject anything more than a year up front so the validation
	// error is stable for obviously bogus payloads.
	if *raw > 365*24*60*60 {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "ttl_seconds",
			Reason: "must be at most 1 year",
		})
	}
	return time.Duration(*raw) * time.Second, nil
}

func parseAdminBreakGlassTarget(r *http.Request, defaultOrganizationID, bodyOrganizationID string) (string, error) {
	queryOrganizationID := r.URL.Query().Get("organization_id")
	orgID := queryOrganizationID
	if orgID == "" {
		orgID = defaultOrganizationID
	}
	if bodyOrganizationID != "" {
		if queryOrganizationID != "" && bodyOrganizationID != queryOrganizationID {
			return "", apierr.InvalidInput(apierr.FieldViolation{Field: "organization_id", Reason: "must match query organization_id"})
		}
		if queryOrganizationID == "" && bodyOrganizationID != defaultOrganizationID {
			return "", apierr.InvalidInput(apierr.FieldViolation{Field: "organization_id", Reason: "must be supplied as a query parameter for cross-tenant break-glass"})
		}
		orgID = bodyOrganizationID
	}
	if err := validateOrganizationIDField("organization_id", orgID); err != nil {
		return "", err
	}
	return orgID, nil
}

func adminBreakGlassResolver(r *http.Request) policy.Resource {
	scope := policy.Scope{
		OrganizationID: r.URL.Query().Get("organization_id"),
	}
	if scope.OrganizationID == "" {
		if p, ok := policy.PrincipalFromContext(r.Context()); ok {
			scope.OrganizationID = p.OrganizationID
		}
	}
	return policy.Resource{Kind: domain.KindOrganization, Scope: scope}
}

// clientIP returns the immediate transport peer's IP. We deliberately do
// not honour X-Forwarded-For or X-Real-IP: in a control-plane that sits
// behind a reverse proxy the trusted IP is set up by deployment, not by
// each handler. The audit row records what the server saw at the
// transport layer; an operator-visible trusted-proxy story can replace
// this later without changing the audit shape.
func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.RemoteAddr
}
