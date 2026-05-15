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

// errNoProjectReader is returned when GET /v1/projects is reached without a
// project reader wired into NewHandler. Like errNoOrganizationReader it can
// only happen through a wiring error — a programming mistake, not a client
// error — so the handler reports it as a typed internal failure rather than
// serving an empty or misleading list.
var errNoProjectReader = errors.New("httpapi: no project reader configured")

// ProjectReader is the narrow persistence port GET /v1/projects depends on.
// *store.ProjectReader satisfies it in production; tests supply a fake.
// Keeping the dependency an interface keeps the handler unit-testable
// without a real database, the same way OrganizationReader keeps GET
// /v1/organizations testable.
//
// The read is tenant scoped at the persistence layer: the repository
// filters by organization_id, so a cross-tenant id simply matches no rows
// and the handler renders an empty list, never another organization's
// projects. The route uses a nil resolver, so the policy engine authorizes
// action project.read against the principal's home organization before the
// handler runs.
type ProjectReader interface {
	ListProjects(ctx context.Context, organizationID string) ([]store.Project, error)
}

// listProjectsPayload is the data block of the GET /v1/projects success
// envelope: every project the authenticated principal's home organization
// owns, in deterministic (slug, id) order. Every field is a non-secret
// identifier, slug, display name, version, or timestamp — the endpoint
// never returns credential material, so the payload is safe to log and
// audit verbatim. Projects is always a non-nil slice so agents can iterate
// it without a nil check.
type listProjectsPayload struct {
	Projects []projectResource `json:"projects"`
}

// projectResource is one project in a listProjectsPayload: the
// source-of-truth project resource — its id, the id of the organization
// that owns it, slug, display name, optimistic-concurrency version, and
// lifecycle timestamps — as the control plane stores it. It is the HTTP
// wire shape, deliberately distinct from store.Project so the persistence
// layout can evolve without breaking the public contract.
//
// Version is the database-owned optimistic-concurrency token. It is
// exposed so future PATCH /v1/projects/{project_id} (BE-0127) callers can
// echo it back as the If-Match precondition without re-reading the row.
type projectResource struct {
	ProjectID      string `json:"project_id"`
	OrganizationID string `json:"organization_id"`
	Slug           string `json:"slug"`
	DisplayName    string `json:"display_name"`
	Version        int64  `json:"version"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// projectResourceOf projects a store.Project into the stable wire shape.
// Timestamps are rendered as UTC RFC 3339 strings so the contract is
// independent of the database driver's time representation and the
// response is deterministic for a given row.
func projectResourceOf(p store.Project) projectResource {
	return projectResource{
		ProjectID:      p.ID,
		OrganizationID: p.OrganizationID,
		Slug:           p.Slug,
		DisplayName:    p.DisplayName,
		Version:        p.Version,
		CreatedAt:      p.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:      p.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

// listProjectsHandler builds the GET /v1/projects handler. It lists the
// projects visible to the authenticated principal — resolved by
// RequireAuth and carried on the request context — by reading them from
// the source-of-truth database through the ProjectReader port.
//
// The route uses a nil resolver, so RequireAuth gates the call on action
// project.read against the principal's home organization before the
// handler runs. project.read is a CapRead action, so the gate admits the
// principal's organization-wide roles (owner, admin, developer, viewer,
// ci) and a support principal performing a read; a grant-only principal
// whose grants are narrower than the home organization is denied at the
// boundary because the engine asks whether the grant scope contains the
// resource scope, not the other way around. The handler never widens or
// narrows that decision: it reads only the principal's own home
// organization, so the tenant boundary is structural here — there is no
// caller input that could point the read at another tenant.
//
// A request that arrives here with no principal is a wiring error and is
// reported as a typed internal error rather than reading for a zero
// principal. A reader-store outage surfaces as its own typed 5xx, and an
// organization with no projects is a deterministic empty list — the
// project list has no "not found" path of its own, mirroring every list
// endpoint.
func listProjectsHandler(reader ProjectReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoProjectReader))
			return
		}
		projects, err := reader.ListProjects(r.Context(), p.OrganizationID)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]projectResource, 0, len(projects))
		for _, project := range projects {
			out = append(out, projectResourceOf(project))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listProjectsPayload{Projects: out})
	}
}
