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

// errNoEnvironmentReader is returned when GET
// /v1/environments/{environment_id} is reached without an environment
// reader wired into NewHandler. Like errNoProjectEnvironmentReader it
// can only happen through a wiring error — a programming mistake, not a
// client error — so the handler reports it as a typed internal failure
// rather than serving a misleading not-found.
var errNoEnvironmentReader = errors.New("httpapi: no environment reader configured")

// EnvironmentReader is the narrow persistence port GET
// /v1/environments/{environment_id} depends on.
// *store.EnvironmentReader satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database, the same way ProjectEnvironmentReader
// keeps the project-environment list surface testable.
//
// The read is tenant-scoped at the persistence layer: the adapter
// composes EnvironmentRepository.GetByID under (organization_id,
// environment_id) inside a short-lived read-only transaction, so a
// cross-tenant or unknown environment_id surfaces as a typed
// apierr.NotFound — never another tenant's row, never a 500. The route
// uses environmentIDResolver which authorizes the call against the
// (principal home org, path environment_id) resource before the handler
// runs; the support principal's deliberate cross-tenant read exception
// does NOT apply through this endpoint because the resource scope is
// pinned to the principal's home organization, not the path env's
// tenant. Project- and environment-scoped grants whose pinned ProjectID
// is unknown to the resolver — the bare path carries only the env_id —
// are denied by the engine; principals whose only access is a scoped
// grant must use the parent-scoped GET
// /v1/projects/{project_id}/environments to address an environment by
// its (project, environment) tuple.
type EnvironmentReader interface {
	GetEnvironment(ctx context.Context, organizationID, environmentID string) (store.Environment, error)
}

// getEnvironmentPayload is the data block of the GET
// /v1/environments/{environment_id} success envelope: the single
// environment addressed by the {environment_id} path parameter, in the
// same stable wire shape GET /v1/projects/{project_id}/environments
// returns for each list element. It carries no credential material —
// the environments table itself stores only structural identifiers, a
// slug, a display name, an optimistic-concurrency version, and lifecycle
// timestamps; environment-scoped variables and other secrets live behind
// their own endpoints (a later story) where the redaction policy
// applies.
type getEnvironmentPayload struct {
	Environment projectEnvironment `json:"environment"`
}

// environmentIDResolver derives the policy.Resource a GET
// /v1/environments/{environment_id} request acts on from its
// {environment_id} path parameter and the authenticated principal's
// home organization id (read from the context the RequireAuth
// middleware attached before invoking the resolver). RequireAuth calls
// it after the principal is resolved and before action environment.read
// is authorized.
//
// The organization id on the resource is the principal's home
// organization id, never a caller-supplied value. A cross-tenant
// environment_id therefore reaches the store layer with the principal's
// home organization id and is reported as a deterministic NotFound by
// the tenant-scoped GetByID query — a cross-tenant id can never reveal
// another organization's environment. (A support principal performing a
// read is allowed cross-tenant by the policy engine, but the support
// principal is still bound to its own home organization on the resource
// scope here, so the persistence layer still refuses to surface another
// tenant's row through this endpoint.)
//
// The resolver pins the EnvironmentID leg of the policy scope but
// cannot pin the ProjectID leg — the bare top-level path carries no
// parent project_id. As a consequence the policy engine admits
// org-wide read roles (owner, admin, developer, viewer, ci) and
// org-wide grants but denies project-, environment-, and service-scoped
// grants by the engine's covers() rule (a grant with a pinned ProjectID
// cannot cover a resource with no ProjectID). Principals whose only
// access is a scoped grant must use the parent-scoped GET
// /v1/projects/{project_id}/environments route to address an
// environment by its (project, environment) tuple.
func environmentIDResolver(r *http.Request) policy.Resource {
	scope := policy.Scope{EnvironmentID: r.PathValue("environment_id")}
	if p, ok := policy.PrincipalFromContext(r.Context()); ok {
		scope.OrganizationID = p.OrganizationID
	}
	return policy.Resource{
		Kind:  domain.KindEnvironment,
		Scope: scope,
	}
}

// getEnvironmentHandler builds the GET /v1/environments/{environment_id}
// handler. It reads the environment named by the {environment_id} path
// parameter from the source-of-truth database through the
// EnvironmentReader port and renders it in a stable yalla.output.v1
// envelope.
//
// RequireAuth gates the route on action environment.read before the
// handler runs — authorized through environmentIDResolver against the
// (principal home organization, environment_id) resource — and attaches
// the resolved principal to the context. environment.read is a CapRead
// action, so the gate admits the principal's organization-wide read
// roles (owner, admin, developer, viewer, ci). The support principal's
// cross-tenant read exception does NOT apply here because the resolver
// pins the resource scope to the principal's own home organization,
// not the path env's tenant.
//
// The handler reads from the principal's home organization id only — it
// never trusts a caller-supplied organization id — so the tenant
// boundary is structural at the persistence layer too: a cross-tenant
// environment_id reaches the store with the principal's home
// organization id and is rejected as a typed NotFound by the
// tenant-scoped GetByID query. A request that arrives with no
// principal is a wiring error reported as a typed internal error rather
// than reading for a zero principal; a reader-store outage surfaces as
// its own typed 5xx; an unknown or cross-tenant environment_id is a
// typed 404, never disguised as an empty success.
func getEnvironmentHandler(reader EnvironmentReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentReader))
			return
		}
		env, err := reader.GetEnvironment(r.Context(), p.OrganizationID, r.PathValue("environment_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), getEnvironmentPayload{
			Environment: projectEnvironmentOf(env),
		})
	}
}
