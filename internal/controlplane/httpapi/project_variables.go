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
	"github.com/JuribaDev/yalla/internal/output"
)

// errNoProjectVariableReader is returned when GET
// /v1/projects/{project_id}/variables is reached without a variable
// reader wired into NewHandler. Like errNoProjectGrantReader it can only
// happen through a wiring error — a programming mistake, not a client
// error — so the handler reports it as a typed internal failure rather
// than serving an empty or misleading list.
var errNoProjectVariableReader = errors.New("httpapi: no project variable reader configured")

// ProjectVariableReader is the narrow persistence port GET
// /v1/projects/{project_id}/variables depends on.
// *store.ProjectVariableReader satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler
// unit-testable without a real database, the same way
// ProjectGrantReader keeps the project-grants surface testable.
//
// The read is tenant scoped at the persistence layer: the adapter Gets
// the project under (organization_id, project_id) before listing its
// variables, so a cross-tenant or unknown project_id surfaces as a
// typed apierr.NotFound — never as an empty list, which would invite
// an agent to believe the project exists with no variables. The route
// uses projectIDResolver which authorizes the call against the
// (principal home org, path project_id) resource before the handler
// runs, so a project-scoped grant for THAT project authorizes the read
// while a sibling-project grant is rejected at the boundary; the
// support principal's deliberate cross-tenant read exception does NOT
// apply here because the resource scope is pinned to the principal's
// home organization, not the path's tenant (see projectIDResolver).
type ProjectVariableReader interface {
	ListProjectVariables(ctx context.Context, organizationID, projectID string) ([]store.ProjectVariable, error)
}

// listProjectVariablesPayload is the data block of the GET
// /v1/projects/{project_id}/variables success envelope: every project-
// scoped variable the project owns, in deterministic (key, id) order.
// Variables is always a non-nil slice so agents can iterate it without a
// nil check; a live project with no configured variables yields [].
type listProjectVariablesPayload struct {
	Variables []projectVariable `json:"variables"`
}

// projectVariable is one entry in a listProjectVariablesPayload.
//
// Value is the wire-level redaction chokepoint. Secret variables ALWAYS
// project as output.Sentinel — the customer can never read a secret
// value through this endpoint by design, the same posture every
// credential-bearing resource in this API takes. Non-secret variables
// project verbatim so the customer can audit their own project-wide
// defaults.
//
// CreatedAt and UpdatedAt are RFC 3339 timestamps with the same
// semantics as every other dated resource the API surfaces; Version is
// the database-owned optimistic-concurrency counter callers use as an
// If-Match precondition on PATCH / DELETE in later stories.
type projectVariable struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	ProjectID      string    `json:"project_id"`
	Key            string    `json:"key"`
	Value          string    `json:"value"`
	IsSecret       bool      `json:"is_secret"`
	Version        int64     `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// projectVariableOf projects a store.ProjectVariable into the stable
// wire shape. Secret values are replaced with output.Sentinel here —
// the projection is the chokepoint, not the caller. A future regression
// that adds another caller of this shape cannot accidentally skip the
// redaction.
func projectVariableOf(v store.ProjectVariable) projectVariable {
	value := v.Value
	if v.IsSecret {
		value = output.Sentinel
	}
	return projectVariable{
		ID:             v.ID,
		OrganizationID: v.OrganizationID,
		ProjectID:      v.ProjectID,
		Key:            v.Key,
		Value:          value,
		IsSecret:       v.IsSecret,
		Version:        v.Version,
		CreatedAt:      v.CreatedAt,
		UpdatedAt:      v.UpdatedAt,
	}
}

// listProjectVariablesHandler builds the GET
// /v1/projects/{project_id}/variables handler. It reads the project-
// scoped variables of the project named by the {project_id} path
// parameter from the source-of-truth database through the
// ProjectVariableReader port, and renders them in a stable
// yalla.output.v1 envelope.
//
// RequireAuth gates the route on action env.read before the handler
// runs — authorized through projectIDResolver against the
// (principal home organization, {project_id}) resource the path names —
// and attaches the resolved principal, so a request that reaches the
// handler has already cleared the tenant boundary against the
// principal's home organization combined with the path id. env.read is
// a CapRead action, so the gate admits the principal's organization-
// wide read roles (owner, admin, developer, viewer, ci); the support
// principal's cross-tenant read exception does NOT apply here because
// projectIDResolver pins the resource scope to the principal's own
// home organization, not the path's tenant. A scoped grant covering
// the resource (for example a project-scoped Viewer grant for THAT
// project) authorizes the read; a grant that names only a SIBLING
// project, an unrelated environment, or an unrelated service is
// rejected at the boundary because the policy engine asks whether the
// grant scope contains the resource scope, never the reverse.
//
// A request that arrives here with no principal is a wiring error and
// is reported as a typed internal error rather than reading for a zero
// principal. A reader-store outage surfaces as its own typed 5xx; a
// cross-tenant or unknown project_id reaches the persistence layer
// with the principal's home organization id and is rejected as a
// deterministic 404 by the reader's project existence check — never
// disguised as an empty success.
func listProjectVariablesHandler(reader ProjectVariableReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoProjectVariableReader))
			return
		}
		vars, err := reader.ListProjectVariables(r.Context(), p.OrganizationID, r.PathValue("project_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]projectVariable, 0, len(vars))
		for _, v := range vars {
			out = append(out, projectVariableOf(v))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listProjectVariablesPayload{Variables: out})
	}
}
