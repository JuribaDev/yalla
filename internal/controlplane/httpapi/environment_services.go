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
)

// errNoEnvironmentServiceReader is returned when GET
// /v1/environments/{environment_id}/services is reached without an
// environment service reader wired into NewHandler. It can only happen
// through a wiring error — a programming mistake, not a client error
// — so the handler reports it as a typed internal failure rather than
// serving an empty or misleading list.
var errNoEnvironmentServiceReader = errors.New("httpapi: no environment service reader configured")

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
// callers will use as an If-Match precondition on PATCH and DELETE
// once those endpoints land.
type environmentService struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	ProjectID      string    `json:"project_id"`
	EnvironmentID  string    `json:"environment_id"`
	Slug           string    `json:"slug"`
	DisplayName    string    `json:"display_name"`
	Kind           string    `json:"kind"`
	Version        int64     `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// environmentServiceOf projects a store.Service into the stable wire
// shape. No field requires redaction at this seam — the services
// table itself carries no credential material — but the projection
// remains the single chokepoint so a future column added to
// store.Service is reviewed for its wire exposure here rather than
// leaking by default.
func environmentServiceOf(s store.Service) environmentService {
	return environmentService{
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
