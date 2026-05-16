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

// errNoServiceMetricsReader is returned when GET
// /v1/services/{service_id}/metrics is reached without a
// ServiceMetricsReader wired into NewHandler. Like errNoServiceLogReader
// it can only happen through a wiring error — a programming mistake,
// not a client error — so the handler reports it as a typed internal
// failure rather than serving a misleading empty list (which would
// invite an agent to believe the service exists with no samples when
// in fact no metrics source is configured).
var errNoServiceMetricsReader = errors.New("httpapi: no service metrics reader configured")

const (
	// serviceMetricsDefaultLimit is the page size GET
	// /v1/services/{service_id}/metrics returns when the caller omits
	// the ?limit= query parameter. 100 is large enough to make the
	// endpoint useful for diagnosis without the caller having to
	// page, and small enough that a request that forgets to clamp
	// can not waste a transaction reading thousands of samples.
	serviceMetricsDefaultLimit = 100
	// serviceMetricsMaxLimit is the hard ceiling for ?limit=. A
	// request asking for more is rejected as a typed 400
	// E_INVALID_INPUT before any database work runs.
	serviceMetricsMaxLimit = 1000
)

// ServiceMetricsReader is the narrow persistence port GET
// /v1/services/{service_id}/metrics depends on.
// *store.ServiceMetricsReader satisfies it in production; tests
// supply a fake. Keeping the dependency an interface keeps the
// handler unit-testable without a real database — the concrete
// adapter performs the tenant-scoped service existence check inside
// a short-lived read-only transaction (so a cross-tenant or unknown
// service_id surfaces as a typed apierr.NotFound before any metrics
// fetcher runs) and projects the resulting sample set onto the
// stable wire shape this handler returns.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action metrics.read against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the reader has
// already cleared the policy boundary. The store layer still
// re-validates the tenant scope at the SQL leg — defense-in-depth
// against a grant change that landed between the HTTP authorize and
// the read.
type ServiceMetricsReader interface {
	ListMetrics(ctx context.Context, in store.ListServiceMetricsInput) (store.ServiceMetrics, error)
}

// serviceMetricSample is the wire-shape of one entry in the metric
// sample list. It is the projection of store.ServiceMetricSample onto
// stable JSON tag names; an agent reading the payload can branch on
// Name and Unit without escape-decoding them. Value is the numeric
// sample as the source adapter emitted it; the placeholder reader
// never produces content from secret-bearing tables, and the
// eventual Traefik/Dokploy adapter is responsible for label
// attribution at its layer.
type serviceMetricSample struct {
	Name       string  `json:"name"`
	OccurredAt string  `json:"occurred_at"`
	Value      float64 `json:"value"`
	Unit       string  `json:"unit"`
}

// listServiceMetricsPayload is the data block of the GET
// /v1/services/{service_id}/metrics success envelope: the service
// id the samples belong to (echoed back so an agent can distinguish
// a multi-resource batch in a future metrics-stream endpoint even
// though today's GET addresses exactly one service) and the samples
// themselves in occurrence order (oldest first). The placeholder
// always returns an empty Samples slice — never nil, so the wire
// shape is "samples": [] rather than "samples": null, which is what
// every list payload in the API surface returns to keep agents from
// special-casing the absent-vs-empty distinction.
type listServiceMetricsPayload struct {
	ServiceID string                `json:"service_id"`
	Samples   []serviceMetricSample `json:"samples"`
}

// parseServiceMetricsLimit resolves the effective page size from the
// optional ?limit= query parameter. An absent parameter resolves to
// the handler default; a malformed, non-positive, or larger-than-
// ceiling value is rejected as a stable 400 E_INVALID_INPUT before
// any database work runs. The error path never echoes the submitted
// string — only the classification and the accepted range — so a
// typo can never become a reflection-style content channel. Mirrors
// parseServiceLogsLimit (BE-0229) for the service-logs endpoint.
func parseServiceMetricsLimit(raw string) (int, error) {
	if raw == "" {
		return serviceMetricsDefaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "limit",
			Reason: "must be a positive integer",
		})
	}
	if n < 1 || n > serviceMetricsMaxLimit {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "limit",
			Reason: "must be between 1 and " + strconv.Itoa(serviceMetricsMaxLimit),
		})
	}
	return n, nil
}

// listServiceMetricsHandler builds the GET /v1/services/{service_id}/metrics
// handler. It reads the metric samples for the service named by the
// {service_id} path parameter through the ServiceMetricsReader port
// and renders them in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action metrics.read before the
// handler runs — authorized through serviceIDResolver against the
// (principal home organization, {service_id}) resource the path
// names — and attaches the resolved principal to the context.
// metrics.read is a CapRead action, so the gate admits the
// principal's organization-wide read roles (owner, admin, developer,
// viewer, ci). The support principal's cross-tenant read exception
// does NOT apply through this endpoint because the resolver pins the
// resource scope to the principal's home organization, not the path
// service's tenant — support cross-tenant metrics reads remain
// available through endpoints whose path carries an explicit
// {org_id}. The path carries no parent project_id or environment_id,
// so the policy engine cannot pin those legs of the resource scope
// at authorization time — project-, environment-, and service-scoped
// grants are denied at the boundary by the engine's covers() rule (a
// grant with a pinned ProjectID cannot cover a resource with no
// ProjectID); principals whose only access is a scoped grant must
// use a parent-scoped route to address a service by its (project,
// environment, service) tuple.
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
// eventual Traefik/Dokploy metrics adapter is responsible for label
// attribution at its layer. The empty Samples slice marshals as
// "samples": [], never "samples": null, so an agent does not need
// to special-case the absent-vs-empty distinction.
func listServiceMetricsHandler(reader ServiceMetricsReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceMetricsReader))
			return
		}

		limit, err := parseServiceMetricsLimit(r.URL.Query().Get("limit"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		metrics, err := reader.ListMetrics(r.Context(), store.ListServiceMetricsInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			Limit:          limit,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		payload := listServiceMetricsPayload{
			ServiceID: metrics.ServiceID,
			Samples:   make([]serviceMetricSample, 0, len(metrics.Samples)),
		}
		for _, sample := range metrics.Samples {
			payload.Samples = append(payload.Samples, serviceMetricSample{
				Name:       sample.Name,
				OccurredAt: sample.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
				Value:      sample.Value,
				Unit:       sample.Unit,
			})
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}
