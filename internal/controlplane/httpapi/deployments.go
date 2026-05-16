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

// errNoDeploymentGetter is returned when GET
// /v1/deployments/{deployment_id} is reached without a DeploymentGetter
// wired into NewHandler. Like errNoDeploymentLister it can only happen
// through a wiring error — a programming mistake, not a client error —
// so the handler reports it as a typed internal failure rather than
// serving a misleading not-found or a 200 with no payload.
var errNoDeploymentGetter = errors.New("httpapi: no deployment getter configured")

// DeploymentGetter is the narrow persistence port GET
// /v1/deployments/{deployment_id} depends on. *store.DeploymentReader
// satisfies it in production; tests supply a fake. Keeping the
// dependency an interface keeps the handler unit-testable without a
// real database — the concrete adapter (a tenant-scoped row lookup
// inside a short-lived read transaction) lives in the store layer.
//
// The read is tenant scoped at the persistence layer: the adapter Gets
// the deployment under (organization_id, deployment_id) so a
// cross-tenant or unknown deployment_id surfaces as a typed
// apierr.NotFound — never an oracle that reveals another tenant's
// deployment ids. The route uses deploymentIDResolver which authorizes
// the call against the (principal home org, path deployment_id)
// resource before the handler runs; the support principal's
// deliberate cross-tenant read exception does NOT apply through this
// resolver because the resource scope is pinned to the principal's
// own home organization, not the path deployment's tenant. Project-,
// environment-, and service-scoped grants are denied at the boundary
// by the engine's covers() rule (a grant scope that pins ProjectID
// cannot cover a resource scope that does not); principals whose only
// access is a scoped grant must use a parent-scoped route family to
// address a deployment by its (project, environment, service,
// deployment) tuple.
type DeploymentGetter interface {
	GetServiceDeployment(ctx context.Context, organizationID, deploymentID string) (store.Deployment, error)
}

// deploymentIDResolver authorizes the bare /v1/deployments/{deployment_id}
// route against a (principal home organization) Deployment resource.
// The OrganizationID leg is pinned to the principal's home org —
// never to a caller-supplied path or body value — so a cross-tenant
// deployment_id reaches the persistence layer with the attacker's own
// org id and is rejected as a deterministic 404 by the tenant-scoped
// repository query. The policy.Scope hierarchy stops at ServiceID:
// the deployment_id itself is NOT a Scope leg, so the resource scope
// carries no ProjectID, EnvironmentID, ServiceID, or deployment-id
// leg at all. That posture matches the engine's covers() rule for
// scoped grants: every project-, environment-, and service-scoped
// grant pins a leg the resource leaves empty, so the engine denies
// such grants at the boundary via ReasonDeniedOutOfScope — even when
// the grant happens to name the deployment's actual parent project /
// environment / service (which the path does not carry, and so the
// engine cannot inspect). Principals whose only access is a scoped
// grant must use a parent-scoped route to address a deployment;
// organization-wide roles and org-level grants pass through.
func deploymentIDResolver(r *http.Request) policy.Resource {
	scope := policy.Scope{}
	if p, ok := policy.PrincipalFromContext(r.Context()); ok {
		scope.OrganizationID = p.OrganizationID
	}
	return policy.Resource{
		Kind:  domain.KindDeployment,
		Scope: scope,
	}
}

// getServiceDeploymentPayload is the data block of the GET
// /v1/deployments/{deployment_id} success envelope: a single
// deployment, projected onto the same stable wire shape the
// service-scoped list endpoint returns. The wire shape is reused
// verbatim from the list endpoint so an agent that listed deployments
// for a service does not have to re-parse a different shape to
// address one of them by id.
type getServiceDeploymentPayload struct {
	Deployment serviceDeployment `json:"deployment"`
}

// getServiceDeploymentHandler builds the GET
// /v1/deployments/{deployment_id} handler. It reads the deployment
// named by the {deployment_id} path parameter from the
// source-of-truth database through the DeploymentGetter port and
// renders it in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action deployment.read before the
// handler runs — authorized through deploymentIDResolver against the
// (principal home organization, deployment_id) resource — and
// attaches the resolved principal, so a request that reaches the
// handler has already cleared the tenant boundary against the
// principal's home organization combined with the path id.
// deployment.read is a CapRead action, so the gate admits the
// principal's organization-wide read roles (owner, admin, developer,
// viewer, ci); the support principal's cross-tenant read exception
// does NOT apply here because deploymentIDResolver pins the resource
// scope to the principal's own home organization, not the path
// deployment's tenant. Project-, environment-, and service-scoped
// grants are denied at the policy boundary by the engine's covers()
// rule (a grant with a pinned ProjectID cannot cover a resource with
// no ProjectID); principals whose only access is a scoped grant must
// use a parent-scoped route to address a deployment.
//
// A request that arrives here with no principal is a wiring error and
// is reported as a typed internal error rather than reading for a zero
// principal. A reader-store outage surfaces as its own typed 5xx; a
// cross-tenant or unknown deployment_id reaches the persistence layer
// with the principal's home organization id and is rejected as a
// deterministic 404 by the reader's tenant-scoped existence check —
// never disguised as a 200 with another tenant's data.
func getServiceDeploymentHandler(getter DeploymentGetter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if getter == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoDeploymentGetter))
			return
		}
		// OrganizationID is taken from the principal's home org (never
		// the caller — there is no organization id on the read path),
		// so a cross-tenant deployment_id still hits the tenant-scoped
		// repository query and surfaces as a 404 at the persistence
		// boundary.
		deployment, err := getter.GetServiceDeployment(r.Context(), p.OrganizationID, r.PathValue("deployment_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), getServiceDeploymentPayload{
			Deployment: serviceDeploymentOf(deployment),
		})
	}
}
