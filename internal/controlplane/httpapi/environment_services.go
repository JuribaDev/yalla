package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// errNoEnvironmentServiceReader is returned when GET
// /v1/environments/{environment_id}/services is reached without an
// environment service reader wired into NewHandler. It can only happen
// through a wiring error — a programming mistake, not a client error
// — so the handler reports it as a typed internal failure rather than
// serving an empty or misleading list.
var errNoEnvironmentServiceReader = errors.New("httpapi: no environment service reader configured")

// errNoEnvironmentServiceCreator is returned when POST
// /v1/environments/{environment_id}/services is reached without an
// EnvironmentServiceCreator wired into NewHandler. Like
// errNoEnvironmentServiceReader it can only happen through a wiring
// error and is reported as a typed internal failure rather than a
// misleading 2xx with no side effect.
var errNoEnvironmentServiceCreator = errors.New("httpapi: no environment service creator configured")

// EnvironmentServiceReader is the narrow persistence port GET
// /v1/environments/{environment_id}/services depends on.
// *store.ServiceReader satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database, the same way EnvironmentVariableReader
// keeps the environment-variables surface testable.
//
// The read is tenant scoped at the persistence layer: the adapter Gets
// the environment under (organization_id, environment_id) before
// listing its services, so a cross-tenant or unknown environment_id
// surfaces as a typed apierr.NotFound — never as an empty list, which
// would invite an agent to believe the environment exists with no
// services. The route uses environmentIDResolver which authorizes the
// call against the (principal home org, path environment_id) resource
// before the handler runs, so a project- or environment-scoped grant
// for a SIBLING is rejected at the boundary; scoped grants whose
// pinned ProjectID is unknown to the resolver — the bare path carries
// only the environment_id — are denied by the engine; principals
// whose only access is a scoped grant must use a parent-scoped route
// to address an environment by its (project, environment) tuple.
type EnvironmentServiceReader interface {
	ListEnvironmentServices(ctx context.Context, organizationID, environmentID string) ([]store.Service, error)
}

// listEnvironmentServicesPayload is the data block of the GET
// /v1/environments/{environment_id}/services success envelope: every
// service the environment owns, in deterministic (slug, id) order.
// Services is always a non-nil slice so agents can iterate it without
// a nil check; a live environment with no configured services yields
// [].
type listEnvironmentServicesPayload struct {
	Services []environmentService `json:"services"`
}

// environmentService is one entry in a listEnvironmentServicesPayload.
//
// The wire shape carries no credential material — the services table
// stores only structural identifiers, a slug, a display name, the
// kind taxonomy ("application", "database", "compose"), an
// optimistic-concurrency version, and lifecycle timestamps. Service-
// scoped variables and other secret-bearing resources live behind
// their own endpoints (later stories) where the redaction policy
// applies. CreatedAt and UpdatedAt are RFC 3339 timestamps with the
// same semantics as every other dated resource the API surfaces;
// Version is the database-owned optimistic-concurrency counter
// callers use as an If-Match precondition on PATCH and DELETE.
// DeletionScheduledAt is the soft-delete marker added by migration
// 0020 (mirroring projectEnvironment.deletion_scheduled_at from
// migration 0016): omitted entirely on a live service and rendered as
// an RFC 3339 timestamp on one already scheduled for teardown by
// DELETE /v1/services/{service_id}.
type environmentService struct {
	ID                  string    `json:"id"`
	OrganizationID      string    `json:"organization_id"`
	ProjectID           string    `json:"project_id"`
	EnvironmentID       string    `json:"environment_id"`
	Slug                string    `json:"slug"`
	DisplayName         string    `json:"display_name"`
	Kind                string    `json:"kind"`
	Version             int64     `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	DeletionScheduledAt *string   `json:"deletion_scheduled_at,omitempty"`
}

// environmentServiceOf projects a store.Service into the stable wire
// shape. No field requires redaction at this seam — the services
// table itself carries no credential material — but the projection
// remains the single chokepoint so a future column added to
// store.Service is reviewed for its wire exposure here rather than
// leaking by default. A nil DeletionScheduledAt — a live service — is
// omitted from the wire shape entirely, matching the
// projectEnvironment.deletion_scheduled_at omitempty convention.
func environmentServiceOf(s store.Service) environmentService {
	out := environmentService{
		ID:             s.ID,
		OrganizationID: s.OrganizationID,
		ProjectID:      s.ProjectID,
		EnvironmentID:  s.EnvironmentID,
		Slug:           s.Slug,
		DisplayName:    s.DisplayName,
		Kind:           s.Kind,
		Version:        s.Version,
		CreatedAt:      s.CreatedAt,
		UpdatedAt:      s.UpdatedAt,
	}
	if s.DeletionScheduledAt != nil {
		scheduled := s.DeletionScheduledAt.UTC().Format(time.RFC3339Nano)
		out.DeletionScheduledAt = &scheduled
	}
	return out
}

// listEnvironmentServicesHandler builds the GET
// /v1/environments/{environment_id}/services handler. It reads the
// services of the environment named by the {environment_id} path
// parameter from the source-of-truth database through the
// EnvironmentServiceReader port, and renders them in a stable
// yalla.output.v1 envelope.
//
// RequireAuth gates the route on action service.read before the
// handler runs — authorized through environmentIDResolver against the
// (principal home organization, environment_id) resource — and
// attaches the resolved principal to the context. service.read is a
// CapRead action, so the gate admits the principal's organization-wide
// read roles (owner, admin, developer, viewer, ci); the support
// principal's cross-tenant read exception does NOT apply here because
// environmentIDResolver pins the resource scope to the principal's
// own home organization, not the path env's tenant. The path carries
// no parent project_id, so the policy engine cannot pin the ProjectID
// leg of the resource scope at authorization time — project-,
// environment-, and service-scoped grants are denied at the boundary
// because the engine asks whether the grant scope (which pins
// ProjectID) covers the resource scope (which does not), never the
// reverse; principals whose only access is a scoped grant must use a
// parent-scoped route to address an environment-scoped service list.
//
// The handler reads from the principal's home organization id only —
// it never trusts a caller-supplied organization id — so the tenant
// boundary is structural at the persistence layer too: a cross-tenant
// environment_id reaches the store with the principal's home
// organization id and is rejected as a typed NotFound by the
// tenant-scoped GetByID query the reader composes. A request that
// arrives here with no principal is a wiring error and is reported as
// a typed internal error rather than reading for a zero principal; a
// reader-store outage surfaces as its own typed 5xx; an unknown or
// cross-tenant environment_id is a typed 404, never disguised as an
// empty success.
func listEnvironmentServicesHandler(reader EnvironmentServiceReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentServiceReader))
			return
		}
		services, err := reader.ListEnvironmentServices(r.Context(), p.OrganizationID, r.PathValue("environment_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]environmentService, 0, len(services))
		for _, s := range services {
			out = append(out, environmentServiceOf(s))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listEnvironmentServicesPayload{Services: out})
	}
}

// EnvironmentServiceCreator is the narrow persistence port POST
// /v1/environments/{environment_id}/services depends on.
// *store.ServiceService satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database — the concrete orchestrator (the
// parent-environment existence check / in-transaction authorize /
// quota reservation / desired-state write / provisioning-job enqueue
// / audit append composition committed in one transaction) lives in
// the store layer.
//
// The HTTP boundary is the authoritative authorization gate:
// RequireAuth authorizes action service.create against the
// (principal home organization, {environment_id}) resource the path
// names through environmentIDResolver, so a request that reaches the
// creator has already cleared the policy boundary. The store layer
// still re-authorizes inside the same *Tx as the desired-state write
// — defense-in-depth against a grant change that landed between the
// HTTP authorize and the quota reservation.
type EnvironmentServiceCreator interface {
	Create(ctx context.Context, in store.CreateServiceInput) (store.Service, error)
}

// createEnvironmentServiceRequest is the decoded POST
// /v1/environments/{environment_id}/services request body. ServiceID
// is the caller-supplied canonical service id — the agent contract
// mints ids client-side so an idempotent retry is structural rather
// than header-encoded; Slug is the canonical [a-z0-9-] identifier
// the service is addressed by within its environment; DisplayName is
// its human-authored label; Kind is the Dokploy taxonomy
// ("application", "database", "compose") the database CHECK
// confines. The request body intentionally exposes no
// organization_id, project_id, or environment_id field: the
// organization is derived from the authenticated principal's home
// organization, the environment is sourced from the
// {environment_id} PATH parameter, and the new service inherits its
// parent environment's project_id — there is no caller-supplied
// parameter that could redirect the create at another tenant or
// another project. The store layer validates every field before any
// database work, so an invalid request never opens a transaction —
// and the request body never carries credential material.
type createEnvironmentServiceRequest struct {
	ServiceID   string `json:"service_id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Kind        string `json:"kind"`
}

// createEnvironmentServicePayload is the data block of the POST
// /v1/environments/{environment_id}/services success envelope: the
// service that was created, in the same stable wire shape GET
// /v1/environments/{environment_id}/services returns. It carries no
// credential material — a services row stores no secrets.
type createEnvironmentServicePayload struct {
	Service environmentService `json:"service"`
}

// createEnvironmentServiceHandler builds the POST
// /v1/environments/{environment_id}/services handler. It decodes and
// delegates: the request body is strictly decoded (oversized,
// malformed, or unknown-field bodies become a typed 400 that never
// echoes the input), then the create-service unit of work —
// re-authorize, reserve quota, write the service row, enqueue the
// provisioning job, append the audit record, all in one transaction
// — runs in the store layer through the EnvironmentServiceCreator
// port.
//
// RequireAuth gates the route on action service.create through
// environmentIDResolver before the handler runs and attaches the
// resolved principal, so a request that reaches the handler with no
// principal is a wiring error reported as a typed internal error.
// service.create is a CapWrite action evaluated against the
// (principal home organization, {environment_id}) resource, so the
// gate admits the principal's organization-wide write roles (owner,
// admin, developer, ci) and denies viewer (CapRead only), denies
// support (CapRead-only — support is a deliberate cross-tenant READ
// exception, never a write one). The path carries no parent
// project_id, so the policy engine cannot pin the ProjectID leg of
// the resource scope at authorization time — project-, environment-,
// and service-scoped grants are denied at the boundary by the
// engine's covers() rule (a grant scope that pins ProjectID cannot
// cover a resource scope that does not); principals whose only access
// is a scoped grant must use a parent-scoped route to address an
// environment by its (project, environment) tuple.
//
// The handler resolves the organization id from the authenticated
// principal's home organization and the environment id from the
// {environment_id} PATH parameter — never from the request body — so
// the tenant boundary is structural here: there is no caller input
// that could point the write at another tenant. A cross-tenant
// environment_id reaches the persistence layer with the principal's
// home organization id and is rejected as a deterministic 404 by the
// store-layer's tenant-scoped environment existence check (the same
// property GET /v1/environments/{environment_id}/services inherits),
// never disguised as a 200 or a 403 that would confirm the foreign
// environment's existence. The principal and the request correlation
// identifiers are passed to the creator so the audit record names the
// actor; a validation failure, a slug conflict, an exhausted quota,
// a denied in-tx authorize, and a datastore outage each surface as
// their own typed status, never disguised as one another.
func createEnvironmentServiceHandler(creator EnvironmentServiceCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if creator == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentServiceCreator))
			return
		}

		var req createEnvironmentServiceRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		service, err := creator.Create(r.Context(), store.CreateServiceInput{
			OrganizationID: p.OrganizationID,
			EnvironmentID:  r.PathValue("environment_id"),
			ServiceID:      req.ServiceID,
			Slug:           req.Slug,
			DisplayName:    req.DisplayName,
			Kind:           req.Kind,
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

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), createEnvironmentServicePayload{
			Service: environmentServiceOf(service),
		})
	}
}
