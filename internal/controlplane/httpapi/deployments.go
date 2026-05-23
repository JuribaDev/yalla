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
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
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

// errNoDeploymentCanceler is returned when POST
// /v1/deployments/{deployment_id}/cancel is reached without a
// DeploymentCanceler wired into NewHandler. Like errNoDeploymentGetter
// it can only happen through a wiring error — a programming mistake,
// not a client error — so the handler reports it as a typed internal
// failure rather than serving a misleading 2xx with no side effect.
var errNoDeploymentCanceler = errors.New("httpapi: no deployment canceler configured")

// DeploymentCanceler is the narrow persistence port POST
// /v1/deployments/{deployment_id}/cancel depends on.
// *store.DeploymentService satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database — the concrete orchestrator (the
// tenant-scoped existence check, the in-tx authorize, the atomic
// non-terminal -> 'cancelled' transition with optional optimistic-
// concurrency precondition, and the audit append, all in one
// transaction) lives in the store layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action deployment.cancel against the
// (principal home organization) Deployment resource through
// deploymentIDResolver, so a request that reaches the canceler has
// already cleared the policy boundary. The store layer still
// re-authorizes inside the same *Tx as the cancel write — defense-in-
// depth against a grant change that landed between the HTTP authorize
// and the desired-state write.
type DeploymentCanceler interface {
	Cancel(ctx context.Context, in store.CancelDeploymentInput) (store.Deployment, error)
}

// cancelServiceDeploymentPayload is the data block of the POST
// /v1/deployments/{deployment_id}/cancel success envelope: the
// deployment with its lifecycle status transitioned to 'cancelled' and
// its finished_at stamp set, in the same stable wire shape every other
// deployment endpoint returns. It carries no credential material — the
// deployments table itself stores no secrets, the source reference is
// the customer-supplied value the worker mirrors verbatim into Dokploy,
// and the worker-written error_message on a failed deployment is run
// through the output redactor before persistence so tokens, API keys,
// and rendered environment variable values can never reach the column.
type cancelServiceDeploymentPayload struct {
	Deployment serviceDeployment `json:"deployment"`
}

// cancelServiceDeploymentHandler builds the POST
// /v1/deployments/{deployment_id}/cancel handler. It transitions the
// deployment named by the {deployment_id} path parameter from a non-
// terminal status ('queued' or 'running') to the terminal 'cancelled'
// status in the source-of-truth database through the DeploymentCanceler
// port, then renders the persisted row in a stable yalla.output.v1
// envelope. The cancellation is durable: the database UPDATE and the
// immutable audit record committed in one transaction are the record of
// the customer intent, and the worker observes the cancelled status to
// stop any in-flight Dokploy provisioning in a later worker story.
//
// RequireAuth gates the route on action deployment.cancel before the
// handler runs — authorized through deploymentIDResolver against the
// (principal home organization) Deployment resource — and attaches
// the resolved principal, so a request that reaches the handler has
// already cleared the policy boundary. deployment.cancel is a
// CapDeploy action, so the gate admits the principal's organization-
// wide deploy roles (owner, admin, developer, ci) and denies viewer
// (CapRead only), denies support (CapRead+CapSupport — support is a
// deliberate cross-tenant READ exception, never a deploy one). The
// path carries only the {deployment_id} and the policy.Scope hierarchy
// stops at ServiceID, so the resource scope carries no ProjectID,
// EnvironmentID, or ServiceID leg — project-, environment-, and
// service-scoped grants are denied at the boundary by the engine's
// covers() rule (a grant scope that pins a leg the resource leaves
// empty cannot cover); principals whose only access is a scoped grant
// must use a parent-scoped route family to address a deployment.
//
// The handler never trusts a caller-supplied organization id: the
// store call is built from principal.OrganizationID and
// r.PathValue("deployment_id"), so a cross-tenant deployment_id
// reaches the tenant-scoped repository query with the principal's home
// organization id and is reported as a deterministic NotFound by the
// persistence layer, never another tenant's row. A request that
// arrives with no principal is a wiring error reported as a typed
// internal error; an If-Match parse failure, a stale If-Match version,
// a not-found {deployment_id}, a deployment already in a terminal
// state, and a datastore outage each surface as their own typed
// status, never disguised as one another. On success, the handler
// mirrors the row's authoritative version into the ETag response
// header so the caller can echo it back as the next If-Match
// precondition without re-reading the row.
func cancelServiceDeploymentHandler(canceler DeploymentCanceler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if canceler == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoDeploymentCanceler))
			return
		}

		ifMatchVersion, ifMatchErr := parseIfMatchVersion(r)
		if ifMatchErr != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(ifMatchErr))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		deployment, err := canceler.Cancel(r.Context(), store.CancelDeploymentInput{
			OrganizationID: p.OrganizationID,
			DeploymentID:   r.PathValue("deployment_id"),
			IfMatchVersion: ifMatchVersion,
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		writeOrganizationETag(w, deployment.Version)
		apienvelope.WriteData(w, http.StatusOK, requestID(r), cancelServiceDeploymentPayload{
			Deployment: serviceDeploymentOf(deployment),
		})
	}
}
