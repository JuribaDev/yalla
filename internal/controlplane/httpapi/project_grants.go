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

// errNoProjectGrantReader is returned when GET
// /v1/projects/{project_id}/grants is reached without a grant reader wired
// into NewHandler. Like errNoProjectReader it can only happen through a
// wiring error — a programming mistake, not a client error — so the
// handler reports it as a typed internal failure rather than serving an
// empty or misleading list.
var errNoProjectGrantReader = errors.New("httpapi: no project grant reader configured")

// ProjectGrantReader is the narrow persistence port GET
// /v1/projects/{project_id}/grants depends on. *store.ProjectGrantReader
// satisfies it in production; tests supply a fake. Keeping the dependency
// an interface keeps the handler unit-testable without a real database,
// the same way OrganizationVariableReader keeps the variables surface
// testable.
//
// The read is tenant scoped at the persistence layer: the adapter Gets the
// project under (organization_id, project_id) before listing its grants,
// so a cross-tenant or unknown project_id surfaces as a typed
// apierr.NotFound — never as an empty list, which would invite an agent to
// believe the project exists with no grants. The route uses
// projectIDResolver which authorizes the call against the (principal home
// org, path project_id) resource before the handler runs, so a
// project-scoped grant for THAT project authorizes the read while a
// sibling-project grant is rejected at the boundary; the support
// principal's deliberate cross-tenant read exception does NOT apply here
// because the resource scope is pinned to the principal's home
// organization, not the path's tenant (see projectIDResolver).
type ProjectGrantReader interface {
	ListProjectGrants(ctx context.Context, organizationID, projectID string) ([]store.ProjectGrant, error)
}

// listProjectGrantsPayload is the data block of the GET
// /v1/projects/{project_id}/grants success envelope: every grant attached
// to the project addressed by the {project_id} path parameter, in
// deterministic (principal_id, environment_id NULLS FIRST, service_id
// NULLS FIRST, id) order. Grants is always a non-nil slice so agents can
// iterate it without a nil check; a live project with no configured grants
// yields [].
type listProjectGrantsPayload struct {
	Grants []projectGrantResource `json:"grants"`
}

// projectGrantResource is one entry in a listProjectGrantsPayload: the
// source-of-truth grant resource — its id, the id of the organization
// that owns it, the id of the project it targets, the principal it
// confers a role on, the role it confers, optional further (environment,
// service) scoping, optimistic-concurrency version, and lifecycle
// timestamps. A grant carries no credential material — the schema stores
// only structural identifiers and a role enum — so the payload is safe to
// log and audit verbatim, mirroring the projectResource posture.
//
// The principal is projected as a nested object so an agent reads one
// boolean (principal.kind == "usr") instead of branching on coupled
// scalars. EnvironmentID and ServiceID are nullable pointers so the wire
// distinguishes "project-scoped grant" (both null) from
// "environment-scoped grant" (only environment set) from
// "service-scoped grant" (both set) — the same precedence the renderer
// reads them with.
type projectGrantResource struct {
	GrantID        string                `json:"grant_id"`
	OrganizationID string                `json:"organization_id"`
	ProjectID      string                `json:"project_id"`
	Principal      projectGrantPrincipal `json:"principal"`
	Role           string                `json:"role"`
	EnvironmentID  *string               `json:"environment_id"`
	ServiceID      *string               `json:"service_id"`
	Version        int64                 `json:"version"`
	CreatedAt      string                `json:"created_at"`
	UpdatedAt      string                `json:"updated_at"`
}

// projectGrantPrincipal is the nested principal block of a
// projectGrantResource: the identity the grant confers a role on. Kind is
// closed to "usr" (a user) or "sa" (a service account) — the two
// principal kinds the policy engine resolves — so an agent can branch on
// the value as a stable enum.
type projectGrantPrincipal struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// projectGrantResourceOf projects a store.ProjectGrant onto the stable
// wire shape. Timestamps are rendered as UTC RFC 3339 strings so the
// contract is independent of the database driver's time representation
// and the response is deterministic for a given row. The store struct's
// EnvironmentID / ServiceID *string pointers are copied verbatim — a nil
// stays nil — so the (project | environment | service)-scoped distinction
// reaches the wire intact.
func projectGrantResourceOf(g store.ProjectGrant) projectGrantResource {
	resource := projectGrantResource{
		GrantID:        g.ID,
		OrganizationID: g.OrganizationID,
		ProjectID:      g.ProjectID,
		Principal: projectGrantPrincipal{
			ID:   g.PrincipalID,
			Kind: g.PrincipalKind,
		},
		Role:      g.Role,
		Version:   g.Version,
		CreatedAt: g.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt: g.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if g.EnvironmentID != nil {
		envID := *g.EnvironmentID
		resource.EnvironmentID = &envID
	}
	if g.ServiceID != nil {
		svcID := *g.ServiceID
		resource.ServiceID = &svcID
	}
	return resource
}

// listProjectGrantsHandler builds the GET
// /v1/projects/{project_id}/grants handler. It reads the grants of the
// project named by the {project_id} path parameter from the
// source-of-truth database through the ProjectGrantReader port and
// renders them in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action project.grants.read before the
// handler runs — authorized through projectIDResolver against the
// (principal home organization, {project_id}) resource the path names —
// and attaches the resolved principal, so a request that reaches the
// handler has already cleared the tenant boundary against the principal's
// home organization combined with the path id. project.grants.read is a
// CapRead action, so the gate admits the principal's organization-wide
// read roles (owner, admin, developer, viewer, ci); the support
// principal's cross-tenant read exception does NOT apply here because
// projectIDResolver pins the resource scope to the principal's own home
// organization, not the path's tenant. A scoped grant covering the
// resource (for example a project-scoped Viewer grant for THAT project)
// authorizes the read; a grant that names only a SIBLING project, an
// unrelated environment, or an unrelated service is rejected at the
// boundary because the policy engine asks whether the grant scope
// contains the resource scope, never the reverse.
//
// A request that arrives here with no principal is a wiring error and is
// reported as a typed internal error rather than reading for a zero
// principal. A reader-store outage surfaces as its own typed 5xx; a
// cross-tenant or unknown project_id reaches the persistence layer with
// the principal's home organization id and is rejected as a deterministic
// 404 by the reader's project existence check — never disguised as an
// empty success.
func listProjectGrantsHandler(reader ProjectGrantReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoProjectGrantReader))
			return
		}
		grants, err := reader.ListProjectGrants(r.Context(), p.OrganizationID, r.PathValue("project_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]projectGrantResource, 0, len(grants))
		for _, g := range grants {
			out = append(out, projectGrantResourceOf(g))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listProjectGrantsPayload{Grants: out})
	}
}
