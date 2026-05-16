package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// errNoServiceLogReader is returned when GET
// /v1/services/{service_id}/logs is reached without a
// ServiceLogReader wired into NewHandler. Like errNoServiceReader it
// can only happen through a wiring error — a programming mistake,
// not a client error — so the handler reports it as a typed internal
// failure rather than serving a misleading empty list (which would
// invite an agent to believe the service exists with no logs when in
// fact no log fetcher is configured).
var errNoServiceLogReader = errors.New("httpapi: no service log reader configured")

const (
	// serviceLogsDefaultLimit is the page size GET
	// /v1/services/{service_id}/logs returns when the caller omits
	// the ?limit= query parameter. 100 is large enough to make the
	// endpoint useful for diagnosis without the caller having to
	// page, and small enough that a request that forgets to clamp
	// can not waste a transaction reading thousands of lines.
	serviceLogsDefaultLimit = 100
	// serviceLogsMaxLimit is the hard ceiling for ?limit=. A request
	// asking for more is rejected as a typed 400 E_INVALID_INPUT
	// before any database work runs.
	serviceLogsMaxLimit = 1000
)

// ServiceLogReader is the narrow persistence port GET
// /v1/services/{service_id}/logs depends on. *store.ServiceLogReader
// satisfies it in production; tests supply a fake. Keeping the
// dependency an interface keeps the handler unit-testable without a
// real database — the concrete adapter performs the tenant-scoped
// service existence check inside a short-lived read-only transaction
// (so a cross-tenant or unknown service_id surfaces as a typed
// apierr.NotFound before any log fetcher runs) and projects the
// resulting line set onto the stable wire shape this handler
// returns.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action logs.read against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the reader has
// already cleared the policy boundary. The store layer still
// re-validates the tenant scope at the SQL leg — defense-in-depth
// against a grant change that landed between the HTTP authorize and
// the read.
type ServiceLogReader interface {
	ListLogs(ctx context.Context, in store.ListServiceLogsInput) (store.ServiceLogs, error)
}

// serviceLogLine is the wire-shape of one entry in the log list. It
// is the projection of store.ServiceLogLine onto stable JSON tag
// names; an agent reading the payload can branch on Stream
// (closed set: "stdout", "stderr", "system") without escape-
// decoding it. Message is the literal byte content of the log line
// as the worker emitted it; the placeholder reader never produces
// content from secret-bearing tables, and the eventual Dokploy
// adapter (BE-0301+) is responsible for rendering-environment
// redaction at its layer.
type serviceLogLine struct {
	OccurredAt string `json:"occurred_at"`
	Stream     string `json:"stream"`
	Message    string `json:"message"`
}

// listServiceLogsPayload is the data block of the GET
// /v1/services/{service_id}/logs success envelope: the service id
// the lines belong to (echoed back so an agent can distinguish a
// multi-resource batch in a future log-stream endpoint even though
// today's GET addresses exactly one service) and the lines
// themselves in occurrence order (oldest first). The placeholder
// always returns an empty Lines slice — never nil, so the wire
// shape is "lines": [] rather than "lines": null, which is what
// every list payload in the API surface returns to keep agents
// from special-casing the absent-vs-empty distinction.
type listServiceLogsPayload struct {
	ServiceID string           `json:"service_id"`
	Lines     []serviceLogLine `json:"lines"`
}

// parseServiceLogsLimit resolves the effective page size from the
// optional ?limit= query parameter. An absent parameter resolves to
// the handler default; a malformed, non-positive, or larger-than-
// ceiling value is rejected as a stable 400 E_INVALID_INPUT before
// any database work runs. The error path never echoes the submitted
// string — only the classification and the accepted range — so a
// typo can never become a reflection-style content channel. Mirrors
// parseAuditEventLimit (BE-0103) for the audit-events endpoint.
func parseServiceLogsLimit(raw string) (int, error) {
	if raw == "" {
		return serviceLogsDefaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "limit",
			Reason: "must be a positive integer",
		})
	}
	if n < 1 || n > serviceLogsMaxLimit {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "limit",
			Reason: "must be between 1 and " + strconv.Itoa(serviceLogsMaxLimit),
		})
	}
	return n, nil
}

// listServiceLogsHandler builds the GET /v1/services/{service_id}/logs
// handler. It reads the log lines for the service named by the
// {service_id} path parameter through the ServiceLogReader port and
// renders them in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action logs.read before the handler
// runs — authorized through serviceIDResolver against the (principal
// home organization, {service_id}) resource the path names — and
// attaches the resolved principal to the context. logs.read is a
// CapRead action, so the gate admits the principal's organization-wide
// read roles (owner, admin, developer, viewer, ci). The support
// principal's cross-tenant read exception does NOT apply through this
// endpoint because the resolver pins the resource scope to the
// principal's home organization, not the path service's tenant —
// support cross-tenant log reads remain available through endpoints
// whose path carries an explicit {org_id}. The path carries no parent
// project_id or environment_id, so the policy engine cannot pin those
// legs of the resource scope at authorization time — project-,
// environment-, and service-scoped grants are denied at the boundary
// by the engine's covers() rule (a grant with a pinned ProjectID
// cannot cover a resource with no ProjectID); principals whose only
// access is a scoped grant must use a parent-scoped route to address
// a service by its (project, environment, service) tuple.
//
// The handler reads from the principal's home organization id only —
// it never trusts a caller-supplied organization id — so the tenant
// boundary is structural at the persistence layer too: a cross-tenant
// service_id reaches the store with the principal's home organization
// id and is rejected as a typed NotFound by the tenant-scoped
// existence check. A request that arrives with no principal is a
// wiring error reported as a typed internal error; a reader-store
// outage surfaces as its own typed 5xx; an unknown or cross-tenant
// service_id is a typed 404, never disguised as an empty success.
//
// The endpoint accepts an optional ?limit= query parameter in the
// range [1, 1000]; an absent value defaults to 100. A malformed,
// non-positive, or larger-than-ceiling value is rejected as a stable
// 400 E_INVALID_INPUT before any database work runs.
//
// The response carries no credential material: the placeholder
// reader never produces content from secret-bearing tables, and the
// eventual Dokploy adapter is responsible for rendering-environment
// redaction at its layer. The empty Lines slice marshals as
// "lines": [], never "lines": null, so an agent does not need to
// special-case the absent-vs-empty distinction.
func listServiceLogsHandler(reader ServiceLogReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceLogReader))
			return
		}

		limit, err := parseServiceLogsLimit(r.URL.Query().Get("limit"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		logs, err := reader.ListLogs(r.Context(), store.ListServiceLogsInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			Limit:          limit,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		payload := listServiceLogsPayload{
			ServiceID: logs.ServiceID,
			Lines:     make([]serviceLogLine, 0, len(logs.Lines)),
		}
		for _, line := range logs.Lines {
			payload.Lines = append(payload.Lines, serviceLogLine{
				OccurredAt: line.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
				Stream:     line.Stream,
				Message:    line.Message,
			})
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}
