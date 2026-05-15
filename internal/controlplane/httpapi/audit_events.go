package httpapi

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// errNoAuditEventReader is returned when GET
// /v1/organizations/{org_id}/audit-events is reached without an audit
// reader wired into NewHandler. Like errNoUsageReader it can only happen
// through a wiring error — a programming mistake, not a client error — so
// the handler reports it as a typed internal failure rather than serving
// an empty or misleading list.
var errNoAuditEventReader = errors.New("httpapi: no audit event reader configured")

// auditEventListDefaultLimit is the page size GET
// /v1/organizations/{org_id}/audit-events returns when the caller does
// not supply ?limit=. It is deliberately lower than the repository's
// hard ceiling (auditEventListMaxLimit, 200) so a typical agent fetch
// stays small while the explicit ?limit= escape hatch remains available
// for an operator paging the full window.
const auditEventListDefaultLimit = 50

// auditEventListMaxLimit mirrors store.auditEventListMaxLimit and is the
// hard ceiling the handler accepts on ?limit=. A larger value is
// rejected as a stable 400 before any database work runs, so an agent
// learns the contract from the error rather than discovering the
// repository clamps silently.
const auditEventListMaxLimit = 200

// AuditEventReader is the narrow persistence port GET
// /v1/organizations/{org_id}/audit-events depends on.
// *store.AuditEventReader satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler
// unit-testable without a real database, the same way UsageReader and
// LimitsReader do for their endpoints.
//
// The read is tenant scoped at the persistence layer: the repository
// filters by organization_id, so a cross-tenant {org_id} simply matches
// no rows and yields an empty list, never another organization's audit
// trail. The organizationIDResolver this route uses authorizes the call
// against the {org_id} path parameter before the handler runs, so a
// cross-tenant id is rejected as a 403 long before this port is reached
// (with the support principal's deliberate cross-tenant read exception
// preserved by the policy engine for read actions).
//
// The store contract is that every value reaching this port is already
// redacted: the audit.Auditor scrubs metadata, IP address, and user
// agent before AuditRepository.Append persists the row, so projecting
// them onto the wire cannot leak a secret.
type AuditEventReader interface {
	ListByOrganization(ctx context.Context, organizationID string, limit int) ([]store.AuditEvent, error)
}

// listAuditEventsPayload is the data block of the GET
// /v1/organizations/{org_id}/audit-events success envelope: the most
// recent audit events for the organization named by the {org_id} path
// parameter, newest first, capped at the effective limit. Events is
// always a non-nil slice so agents can iterate it without a nil check;
// an organization with no audit history yields [].
type listAuditEventsPayload struct {
	Events []auditEvent `json:"events"`
}

// auditEvent is one entry in a listAuditEventsPayload: a single immutable
// authorization decision recorded by the control plane. Every field is
// already redacted at the persistence boundary, so this projection is
// safe to render verbatim.
//
// Actor and Resource are nested objects rather than coupled scalars: an
// unauthenticated denied request has no resolved principal, which
// projects as Actor = nil (a single null on the wire) instead of three
// coupled null-or-empty scalar fields; similarly, a request that names
// no specific resource (an organization-root action) projects as
// Resource = nil. This mirrors the limit/null convention the usage
// endpoint uses, and lets a future field on either object land as a
// forward-compatible addition.
type auditEvent struct {
	ID            string            `json:"id"`
	OccurredAt    time.Time         `json:"occurred_at"`
	Action        string            `json:"action"`
	Decision      string            `json:"decision"`
	Reason        string            `json:"reason"`
	Actor         *auditActor       `json:"actor"`
	Resource      *auditResource    `json:"resource"`
	RequestID     string            `json:"request_id"`
	CorrelationID string            `json:"correlation_id"`
	IPAddress     string            `json:"ip_address"`
	UserAgent     string            `json:"user_agent"`
	Metadata      map[string]string `json:"metadata"`
}

// auditActor is the principal that triggered the recorded decision. Both
// fields are stable, non-secret identifiers: ID is an opaque principal id
// (a user id, an API-key id, or an internal service account id) and Kind
// names which of those it is. An unauthenticated request has no resolved
// principal and projects as a null auditActor on the wire.
type auditActor struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// auditResource is the resource the recorded action named, if any. Both
// fields are stable, non-secret identifiers: ID is the resource's opaque
// id within its tenant and Kind names the resource type
// (organization/project/environment/service/...). An action that names
// no specific resource (an organization-root or self action) projects as
// a null auditResource on the wire.
type auditResource struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// auditEventOf projects a store.AuditEvent into the stable wire shape.
// The wire field names are the stable contract; the persistence shape can
// evolve without changing the response. Metadata keys are sorted into a
// fresh map so the JSON document is byte-deterministic for the same row
// even though Go's map iteration order is randomised.
func auditEventOf(e store.AuditEvent) auditEvent {
	out := auditEvent{
		ID:            e.ID,
		OccurredAt:    e.OccurredAt,
		Action:        e.Action,
		Decision:      string(e.Decision),
		Reason:        e.Reason,
		RequestID:     e.RequestID,
		CorrelationID: e.CorrelationID,
		IPAddress:     e.IPAddress,
		UserAgent:     e.UserAgent,
		Metadata:      sortedMetadata(e.Metadata),
	}
	if e.ActorID != "" || e.ActorKind != "" {
		out.Actor = &auditActor{ID: e.ActorID, Kind: e.ActorKind}
	}
	if e.ResourceID != "" || e.ResourceKind != "" {
		out.Resource = &auditResource{ID: e.ResourceID, Kind: e.ResourceKind}
	}
	return out
}

// sortedMetadata returns a fresh copy of m with keys traversed in sorted
// order. encoding/json already sorts map keys on marshal, so the wire
// document is deterministic without this helper; the copy exists so the
// projection does not alias the persistence layer's map, and so a future
// per-key projection rule has a single chokepoint.
func sortedMetadata(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(m))
	for _, k := range keys {
		out[k] = m[k]
	}
	return out
}

// parseAuditEventLimit resolves the effective page size from the
// optional ?limit= query parameter. An absent parameter resolves to the
// handler default; a malformed, non-positive, or larger-than-ceiling
// value is rejected as a stable 400 E_INVALID_INPUT before any database
// work runs. The error path never echoes the submitted string — only the
// classification and the accepted range — so a typo can never become a
// reflection-style content channel.
func parseAuditEventLimit(raw string) (int, error) {
	if raw == "" {
		return auditEventListDefaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "limit",
			Reason: "must be a positive integer",
		})
	}
	if n < 1 || n > auditEventListMaxLimit {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "limit",
			Reason: "must be between 1 and " + strconv.Itoa(auditEventListMaxLimit),
		})
	}
	return n, nil
}

// listAuditEventsHandler builds the GET
// /v1/organizations/{org_id}/audit-events handler. It reads the most
// recent audit events for the organization named by the {org_id} path
// parameter from the source-of-truth database through the
// AuditEventReader port, and renders them in a stable yalla.output.v1
// envelope.
//
// RequireAuth gates the route on action audit.read before the handler
// runs — authorized through organizationIDResolver against the
// organization the path names — and attaches the resolved principal, so
// a request that reaches the handler has already cleared the tenant
// boundary: a cross-tenant {org_id} was rejected as a 403 by the policy
// engine, never reaching this code. A request that arrives here with no
// principal is therefore a wiring error and is reported as a typed
// internal error rather than reading for a zero principal. A reader-store
// outage surfaces as its own typed 5xx, and an {org_id} with no audit
// rows is a deterministic empty list — the audit read has no
// "not found" path of its own, mirroring every list endpoint.
//
// The endpoint accepts an optional ?limit= query parameter in the range
// [1, 200]; an absent value defaults to 50.
func listAuditEventsHandler(reader AuditEventReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAuditEventReader))
			return
		}

		limit, err := parseAuditEventLimit(r.URL.Query().Get("limit"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		events, err := reader.ListByOrganization(r.Context(), r.PathValue("org_id"), limit)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		payload := listAuditEventsPayload{
			Events: make([]auditEvent, 0, len(events)),
		}
		for _, e := range events {
			payload.Events = append(payload.Events, auditEventOf(e))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}
