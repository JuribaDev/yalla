package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// errNoServiceStarter is returned when POST
// /v1/services/{service_id}/start is reached without a ServiceStarter
// wired into NewHandler. It can only happen through a wiring error —
// a programming mistake, not a client error — so the handler reports
// it as a typed internal failure rather than serving a misleading
// 2xx with no side effect.
var errNoServiceStarter = errors.New("httpapi: no service starter configured")

// ServiceStarter is the narrow persistence port POST
// /v1/services/{service_id}/start depends on. *store.ServiceService
// satisfies it in production; tests supply a fake. Keeping the
// dependency an interface keeps the handler unit-testable without a
// real database — the concrete orchestrator (the parent-service
// existence check, the not-scheduled-for-deletion check, the in-tx
// authorize, the provisioning-job enqueue, and the audit append, all
// in one transaction) lives in the store layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action service.start against the (principal
// home organization, {service_id}) resource the path names through
// serviceIDResolver, so a request that reaches the starter has
// already cleared the policy boundary. The store layer still
// re-authorizes inside the same *Tx as the audit append —
// defense-in-depth against a grant change that landed between the
// HTTP authorize and the job-enqueue write.
type ServiceStarter interface {
	Start(ctx context.Context, in store.StartServiceInput) (store.Service, error)
}

// startServicePayload is the data block of the POST
// /v1/services/{service_id}/start success envelope: the service whose
// start was just enqueued, in the same stable wire shape the other
// service endpoints return. The service's desired state has not
// changed — start is a worker-driven operation against the
// already-persisted service row — so the projected row is the
// current row exactly as it sits in the source-of-truth database. It
// carries no credential material: the services table itself stores
// no secrets, and service-scoped variables live behind their own
// endpoints where the redaction policy applies.
type startServicePayload struct {
	Service environmentService `json:"service"`
}

// startServiceHandler builds the POST /v1/services/{service_id}/start
// handler. It records the customer's start intent through the
// ServiceStarter port — which enqueues the durable provisioning job
// that mirrors the start into Dokploy and appends the immutable audit
// record in one transaction — then renders the service row in a
// stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action service.start through
// serviceIDResolver before the handler runs and attaches the resolved
// principal, so a request that reaches the handler with no principal
// is a wiring error reported as a typed internal error.
// service.start is a CapDeploy action evaluated against the (principal
// home organization, {service_id}) resource, so the gate admits the
// principal's organization-wide deploy roles (owner, admin,
// developer, ci) and denies viewer (CapRead only), denies support
// (CapRead+CapSupport — support is a deliberate cross-tenant READ
// exception, never a deploy one). The path carries no parent
// project_id or environment_id, so the policy engine cannot pin
// those legs of the resource scope at authorization time —
// project-, environment-, and service-scoped grants are denied at
// the boundary by the engine's covers() rule (a grant scope that
// pins ProjectID cannot cover a resource scope that does not);
// principals whose only access is a scoped grant must use a
// parent-scoped route to address a service by its (project,
// environment, service) tuple.
//
// The handler resolves the organization id from the authenticated
// principal's home organization and the service id from the
// {service_id} PATH parameter — never from the request body — so the
// tenant boundary is structural here: there is no caller input that
// could point the write at another tenant. A cross-tenant service_id
// reaches the persistence layer with the principal's home
// organization id and is rejected as a deterministic 404 by the
// store-layer's tenant-scoped service existence check (the same
// property GET /v1/services/{service_id} inherits), never disguised
// as a 200 or a 403 that would confirm the foreign service's
// existence. A service that is already scheduled for deletion is a
// deterministic 409 — a start cannot land on a service whose teardown
// is queued. The principal and the request correlation identifiers
// are passed to the starter so the audit record names the actor.
//
// The request body is empty: start is a fire-and-forget signal that
// targets the entire service and carries no caller-supplied
// parameters — no source, no idempotency key, no ref. Requests with
// a non-empty body are accepted to keep the path simple; the worker
// derives all needed context from the persisted service row.
func startServiceHandler(starter ServiceStarter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if starter == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceStarter))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		// OrganizationID is taken from the principal's home org (never
		// the caller — the request body carries no fields at all), so
		// a cross-tenant service_id still hits the tenant-scoped
		// repository query and surfaces as a 404 at the persistence
		// boundary.
		service, err := starter.Start(r.Context(), store.StartServiceInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
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

		apienvelope.WriteData(w, http.StatusAccepted, requestID(r), startServicePayload{
			Service: environmentServiceOf(service),
		})
	}
}
