package httpapi

import (
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
)

// GET /v1/services/{service_id}/rendered (BE-0196) returns the
// rendered desired-state PREVIEW of one service — the deterministic
// projection of how the source-of-truth row reaches the worker
// (Dokploy resource name, type, structural identity labels) — so an
// agent can verify what the control plane will hand to provisioning
// before any mutation runs.
//
// The endpoint is pure: it reads exactly one services row through the
// shared ServiceReader port (the same port GET /v1/services/{service_id}
// is built on) and renders the deterministic projection on the wire.
// The renderer is the IDENTITY layer — the Dokploy resource name and
// the structural attribution labels — because those are the bits of
// the rendered spec the current source-of-truth schema fully owns and
// the worker reads back unmodified. The merged environment-variable
// set, build settings, resource limits, and requested domains live in
// their own per-level tables (service-level variables / build / domains
// are scheduled into later stories and have no migration yet), so the
// public projection deliberately carries no values for them today; a
// future story extends the projection's `rendered` block with those
// fields once their source-of-truth columns exist. Forward-compatibility
// is structural: every field documented on this payload is stable, and
// only new fields are added later.
//
// Authorization is uniform with GET /v1/services/{service_id}: action
// service.read at the (principal home organization, {service_id})
// resource the path names. serviceIDResolver pins NO ProjectID leg, so
// project-, environment-, and service-scoped grants are denied at the
// policy boundary by the engine's covers() rule — principals whose
// only access is a scoped grant must use a parent-scoped route. The
// resource organization id comes from the principal's home org, never
// the caller, so a cross-tenant service_id is rejected as a
// deterministic 404 by the tenant-scoped GetByID query at the
// persistence layer.
//
// The response carries no credential material: the services row
// itself stores none, and the rendered projection contains only
// structural identifiers and the deterministic Dokploy resource name
// derived from the row's display_name and id. Service-scoped
// variables (rendered values verbatim) live behind their own
// /variables endpoints where the per-route redaction policy applies;
// rendered values never appear in THIS endpoint's payload.

// renderedLabel is one structural attribution label on the rendered
// service. Labels carry only Yalla-canonical identifiers — the
// organization, project, environment, and service ids the worker
// stamps onto the Dokploy resource so a Yalla owner can be recovered
// from the provisioned object. Labels carry no human content from the
// row (no slug, no display name) and no credential material.
type renderedLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// renderedService is the deterministic identity projection of a
// service's rendered Dokploy spec. Name is the canonical Docker-safe
// resource name domain.DokployName builds from the row's display_name
// and id; Type is the Dokploy service taxonomy mapped from the row's
// kind; Labels are the structural attribution labels the worker would
// stamp onto the provisioned resource. The variable, resource, build,
// and domain blocks of the full rendered spec are intentionally
// absent from this projection today — their source-of-truth tables
// are scheduled into later stories — and will be added forward-
// compatibly when they land.
type renderedService struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Labels []renderedLabel `json:"labels"`
}

// renderedServicePayload is the data block of the GET
// /v1/services/{service_id}/rendered success envelope. Service is the
// same wire shape every services endpoint returns (so an agent can
// correlate the rendered preview with the underlying row by id and
// version), and Rendered is the deterministic identity projection of
// what provisioning would build.
type renderedServicePayload struct {
	Service  environmentService `json:"service"`
	Rendered renderedService    `json:"rendered"`
}

// renderedServiceType maps a Yalla services.kind value to the Dokploy
// service taxonomy. The kind column is enforced by the store layer to
// be one of "application", "database", "compose"; the projection
// passes it through verbatim to keep the rendered preview in lockstep
// with dokploy.ServiceType. An unknown kind would surface as an
// internal contract violation at the persistence layer (rejected by
// the orchestrator before any insert), so a row that reaches this
// code path always carries a valid kind — the switch is exhaustive
// over the closed taxonomy and any addition there must be reflected
// here in lockstep.
func renderedServiceType(kind string) dokploy.ServiceType {
	switch kind {
	case "application":
		return dokploy.ServiceApplication
	case "database":
		return dokploy.ServiceDatabase
	case "compose":
		return dokploy.ServiceCompose
	default:
		return dokploy.ServiceType(kind)
	}
}

// renderServiceLabels builds the deterministic identity-attribution
// labels for one service. The keys are the stable yalla.* prefix the
// worker stamps onto every provisioned Dokploy object; the values are
// the canonical hierarchy ids. Order is deterministic
// (organization → project → environment → service) so the JSON wire
// shape is stable across calls.
func renderServiceLabels(orgID, projectID, envID, svcID string) []renderedLabel {
	return []renderedLabel{
		{Key: "yalla.organization_id", Value: orgID},
		{Key: "yalla.project_id", Value: projectID},
		{Key: "yalla.environment_id", Value: envID},
		{Key: "yalla.service_id", Value: svcID},
	}
}

// getServiceRenderedHandler builds the GET
// /v1/services/{service_id}/rendered handler. It reads the service
// named by the {service_id} path parameter through the shared
// ServiceReader port and renders the deterministic identity
// projection in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action service.read before the
// handler runs — authorized through serviceIDResolver against the
// (principal home organization, service_id) resource — and attaches
// the resolved principal to the context. service.read is a CapRead
// action, so the gate admits the principal's organization-wide read
// roles (owner, admin, developer, viewer, ci). The support
// principal's cross-tenant read exception does NOT apply here because
// the resolver pins the resource scope to the principal's home
// organization, not the path service's tenant.
//
// The handler reads from the principal's home organization id only —
// it never trusts a caller-supplied organization id — so the tenant
// boundary is structural at the persistence layer too: a cross-tenant
// service_id reaches the store with the principal's home organization
// id and is rejected as a typed NotFound by the tenant-scoped GetByID
// query. A request that arrives with no principal is a wiring error
// reported as a typed internal error rather than reading for a zero
// principal; a reader-store outage surfaces as its own typed 5xx; an
// unknown or cross-tenant service_id is a typed 404, never disguised
// as an empty success.
//
// The rendered projection is deterministic and pure: the Dokploy
// resource name is domain.DokployName(svc.DisplayName, svc.ID) and
// the labels are the canonical hierarchy ids. DokployName always
// succeeds for a valid service id (it falls back to the resource kind
// when the label has no usable alphanumeric content), so the
// computation has no client-failure mode — a returned error is a
// defensive contract assertion and surfaces as a typed internal error.
func getServiceRenderedHandler(reader ServiceReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceReader))
			return
		}
		svc, err := reader.GetService(r.Context(), p.OrganizationID, r.PathValue("service_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		name, err := domain.DokployName(svc.DisplayName, domain.ID(svc.ID))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), renderedServicePayload{
			Service: environmentServiceOf(svc),
			Rendered: renderedService{
				Name:   name,
				Type:   string(renderedServiceType(svc.Kind)),
				Labels: renderServiceLabels(svc.OrganizationID, svc.ProjectID, svc.EnvironmentID, svc.ID),
			},
		})
	}
}
