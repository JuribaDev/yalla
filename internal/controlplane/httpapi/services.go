package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// errNoServiceReader is returned when GET /v1/services/{service_id} is
// reached without a ServiceReader wired into NewHandler. Like
// errNoEnvironmentReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it
// as a typed internal failure rather than serving a misleading
// not-found.
var errNoServiceReader = errors.New("httpapi: no service reader configured")

// ServiceReader is the narrow persistence port GET
// /v1/services/{service_id} depends on. *store.ServiceReader satisfies
// it in production; tests supply a fake. Keeping the dependency an
// interface keeps the handler unit-testable without a real database,
// the same way EnvironmentReader keeps the bare-id environment lookup
// testable.
//
// The read is tenant-scoped at the persistence layer: the adapter
// composes ServiceRepository.GetByID under (organization_id,
// service_id) inside a short-lived read-only transaction, so a
// cross-tenant or unknown service_id surfaces as a typed
// apierr.NotFound — never another tenant's row, never a 500. The
// route uses serviceIDResolver which authorizes the call against the
// (principal home org, path service_id) resource before the handler
// runs; the support principal's deliberate cross-tenant read
// exception does NOT apply through this endpoint because the resource
// scope is pinned to the principal's home organization, not the path
// service's tenant. Project-, environment-, and service-scoped grants
// whose pinned ProjectID is unknown to the resolver — the bare path
// carries only the service_id — are denied at the policy boundary by
// the engine's covers() rule (a grant scope that pins ProjectID
// cannot cover a resource scope that does not); principals whose only
// access is a scoped grant must use a parent-scoped route to address
// a service by its (project, environment, service) tuple.
type ServiceReader interface {
	GetService(ctx context.Context, organizationID, serviceID string) (store.Service, error)
}

// getServicePayload is the data block of the GET
// /v1/services/{service_id} success envelope: the service in the same
// stable wire shape GET /v1/environments/{environment_id}/services
// returns. It carries no credential material — the services table
// itself stores no secrets; service-scoped variables and other
// secret-bearing resources live behind their own endpoints (later
// stories) where the redaction policy applies.
type getServicePayload struct {
	Service environmentService `json:"service"`
}

// serviceIDResolver builds the policy resource for routes that
// address a service by its bare top-level id. The resource scope pins
// the principal's home organization id and the {service_id} PATH
// parameter — and CRUCIALLY pins NO ProjectID leg, because the bare
// top-level path carries no parent project_id (the same load-bearing
// distinction environmentIDResolver carries against
// projectIDResolver). Every scoped grant in the engine pins a
// ProjectID, and the engine's covers() rule is one-way (a grant scope
// that pins ProjectID cannot cover a resource scope that does not),
// so ALL project-, environment-, and service-scoped grants are denied
// at the boundary by ReasonDeniedOutOfScope — even a service-scoped
// Admin grant naming THIS service's id, because the grant scope pins
// a ProjectID the resource scope does not. Principals whose only
// access is a scoped grant must use a parent-scoped route to address
// a service by its (project, environment, service) tuple; this route
// is reserved for org-wide read roles (owner, admin, developer,
// viewer, ci) and org-wide grants.
func serviceIDResolver(r *http.Request) policy.Resource {
	scope := policy.Scope{ServiceID: r.PathValue("service_id")}
	if p, ok := policy.PrincipalFromContext(r.Context()); ok {
		scope.OrganizationID = p.OrganizationID
	}
	return policy.Resource{
		Kind:  domain.KindService,
		Scope: scope,
	}
}

// getServiceHandler builds the GET /v1/services/{service_id} handler.
// It reads the service named by the {service_id} path parameter from
// the source-of-truth database through the ServiceReader port and
// renders it in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action service.read before the
// handler runs — authorized through serviceIDResolver against the
// (principal home organization, service_id) resource — and attaches
// the resolved principal to the context. service.read is a CapRead
// action, so the gate admits the principal's organization-wide read
// roles (owner, admin, developer, viewer, ci). The support
// principal's cross-tenant read exception does NOT apply here because
// the resolver pins the resource scope to the principal's own home
// organization, not the path service's tenant.
//
// The handler reads from the principal's home organization id only —
// it never trusts a caller-supplied organization id — so the tenant
// boundary is structural at the persistence layer too: a cross-tenant
// service_id reaches the store with the principal's home
// organization id and is rejected as a typed NotFound by the
// tenant-scoped GetByID query. A request that arrives with no
// principal is a wiring error reported as a typed internal error
// rather than reading for a zero principal; a reader-store outage
// surfaces as its own typed 5xx; an unknown or cross-tenant
// service_id is a typed 404, never disguised as an empty success.
func getServiceHandler(reader ServiceReader) http.HandlerFunc {
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
		apienvelope.WriteData(w, http.StatusOK, requestID(r), getServicePayload{
			Service: environmentServiceOf(svc),
		})
	}
}
