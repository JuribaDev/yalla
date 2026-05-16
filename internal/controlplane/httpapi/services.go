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
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// errNoServiceReader is returned when GET /v1/services/{service_id} is
// reached without a ServiceReader wired into NewHandler. Like
// errNoEnvironmentReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it
// as a typed internal failure rather than serving a misleading
// not-found.
var errNoServiceReader = errors.New("httpapi: no service reader configured")

// errNoServiceUpdater is returned when PATCH /v1/services/{service_id}
// is reached without a ServiceUpdater wired into NewHandler. Like
// errNoServiceReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it
// as a typed internal failure rather than silently failing to persist
// the mutation.
var errNoServiceUpdater = errors.New("httpapi: no service updater configured")

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

// ServiceUpdater is the narrow persistence port PATCH
// /v1/services/{service_id} depends on. *store.ServiceService
// satisfies it in production; tests supply a fake. The concrete
// orchestrator (the desired-state UPDATE and the immutable audit
// record committed in one transaction) lives in the store layer, so
// the handler stays unit-testable without a real database — the same
// shape EnvironmentUpdater carries for the environment surface.
type ServiceUpdater interface {
	Update(ctx context.Context, in store.UpdateServiceInput) (store.Service, error)
}

// updateServiceRequest is the decoded PATCH /v1/services/{service_id}
// request body. Both fields are optional pointers: a nil pointer means
// the caller did not include the field and it is left unchanged, which
// is what makes the endpoint a partial update. The store layer
// validates every supplied field before any database work and rejects
// a patch that names no field at all — a mutation that changes
// nothing is a client error, not a silent success. Neither field
// carries credential material.
//
// The request body intentionally exposes no organization_id,
// project_id, environment_id, or service_id field: the organization is
// derived from the authenticated principal's home organization and the
// service_id comes from the path, never from the body, so a caller
// cannot point the mutation at another tenant's service even if the
// strict decoder were bypassed. The parent project_id and
// environment_id are not mutable through this endpoint: a service
// belongs to exactly one (project, environment) for its lifetime, and
// reparenting is a deliberate operation that would belong to a
// separate endpoint behind a different action constant. Kind is closed
// Dokploy taxonomy and cannot be changed once provisioning has been
// told what to build.
type updateServiceRequest struct {
	Slug        *string `json:"slug"`
	DisplayName *string `json:"display_name"`
}

// updateServicePayload is the data block of the PATCH
// /v1/services/{service_id} success envelope: the service after the
// update, in the same stable wire shape the other service endpoints
// return. It carries no credential material — the services table
// itself stores no secrets; service-scoped variables and other secrets
// live behind their own endpoints where the redaction policy applies.
type updateServicePayload struct {
	Service environmentService `json:"service"`
}

// updateServiceHandler builds the PATCH /v1/services/{service_id}
// handler. It decodes and delegates: the request body is strictly
// decoded (oversized, malformed, or unknown-field bodies become a
// typed 400 that never echoes the input), the If-Match header is
// parsed as an optional optimistic-concurrency precondition, and then
// the update-service unit of work — validate, read the current row,
// apply the patch, write the row back, append the audit record, all
// in one transaction — runs in the store layer through the
// ServiceUpdater port.
//
// RequireAuth gates the route on action service.update before the
// handler runs — authorized through serviceIDResolver against the
// (principal home organization, {service_id}) resource the path
// names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the policy boundary.
// service.update is a CapWrite action, so the gate admits the
// principal's organization-wide write roles (owner, admin, developer,
// ci) and denies viewer, denies support (a support principal is
// CapRead-only and cannot mutate even within its home tenant). The
// path carries no parent project_id or environment_id, so the policy
// engine cannot pin those legs of the resource scope at authorization
// time — project-, environment-, and service-scoped grants are denied
// at the boundary by the engine's covers() rule (a grant with a
// pinned ProjectID cannot cover a resource with no ProjectID);
// principals whose only access is a scoped grant must use a
// parent-scoped route to address a service by its (project,
// environment, service) tuple.
//
// The handler never trusts a caller-supplied organization id: the
// store call is built from principal.OrganizationID and
// r.PathValue("service_id"), so a cross-tenant service_id reaches the
// tenant-scoped repository query with the principal's home
// organization id and is reported as a deterministic NotFound by the
// persistence layer, never another tenant's row. A request that
// arrives with no principal is a wiring error reported as a typed
// internal error; a validation failure, a slug conflict, a not-found
// {service_id}, a stale If-Match version, and a datastore outage each
// surface as their own typed status, never disguised as one another.
// On success, the handler mirrors the row's authoritative version
// into the ETag response header so the caller can echo it back as the
// next If-Match precondition without re-reading the row.
func updateServiceHandler(updater ServiceUpdater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if updater == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceUpdater))
			return
		}

		ifMatchVersion, ifMatchErr := parseIfMatchVersion(r)
		if ifMatchErr != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(ifMatchErr))
			return
		}

		var req updateServiceRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		service, err := updater.Update(r.Context(), store.UpdateServiceInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
			Slug:           req.Slug,
			DisplayName:    req.DisplayName,
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

		writeOrganizationETag(w, service.Version)
		apienvelope.WriteData(w, http.StatusOK, requestID(r), updateServicePayload{
			Service: environmentServiceOf(service),
		})
	}
}
