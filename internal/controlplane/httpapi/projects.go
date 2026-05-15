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

// errNoProjectReader is returned when GET /v1/projects is reached without a
// project reader wired into NewHandler. Like errNoOrganizationReader it can
// only happen through a wiring error — a programming mistake, not a client
// error — so the handler reports it as a typed internal failure rather than
// serving an empty or misleading list.
var errNoProjectReader = errors.New("httpapi: no project reader configured")

// errNoProjectCreator is returned when POST /v1/projects is reached without
// a project creator wired into NewHandler. Like errNoProjectReader it can
// only happen through a wiring error — a programming mistake, not a client
// error — so the handler reports it as a typed internal failure rather than
// silently failing to persist the resource.
var errNoProjectCreator = errors.New("httpapi: no project creator configured")

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

// ProjectCreator is the narrow persistence port POST /v1/projects depends on.
// *store.ProjectService satisfies it in production; tests supply a fake.
// Like ProjectReader it is an interface declared here so the handler stays
// unit-testable without a real database — the concrete orchestrator (the
// in-transaction authorization, quota reservation, desired-state write,
// provisioning-job enqueue, and audit record) lives in the store layer.
type ProjectCreator interface {
	Create(ctx context.Context, in store.CreateProjectInput) (store.Project, error)
}

// createProjectRequest is the decoded POST /v1/projects request body.
// ProjectID is the caller-supplied canonical project id — the agent contract
// mints ids client-side so an idempotent retry is structural rather than
// header-encoded. Slug is the canonical [a-z0-9-] identifier the project is
// addressed by within its organization; DisplayName is its human-authored
// label. The store layer validates every field before any database work, so
// an invalid request never opens a transaction — and the request body never
// carries credential material.
type createProjectRequest struct {
	ProjectID   string `json:"project_id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// createProjectPayload is the data block of the POST /v1/projects success
// envelope: the project that was created, in the same stable wire shape
// GET /v1/projects returns. It carries no credential material — a projects
// row stores no secrets.
type createProjectPayload struct {
	Project projectResource `json:"project"`
}

// createProjectHandler builds the POST /v1/projects handler. It decodes and
// delegates: the request body is strictly decoded (oversized, malformed, or
// unknown-field bodies become a typed 400 that never echoes the input), then
// the create-project unit of work — authorize, reserve quota, write the
// project row, enqueue the provisioning job, append the audit record, all in
// one transaction — runs in the store layer through the ProjectCreator port.
//
// RequireAuth gates the route on action project.create before the handler
// runs and attaches the resolved principal, so a request that reaches the
// handler with no principal is a wiring error reported as a typed internal
// error. project.create is a CapWrite action, so the gate admits the
// principal's organization-wide write roles (owner, admin, developer, ci) but
// denies viewer, denies support (a support principal is CapRead-only), and
// denies a grant-only principal whose grants are narrower than the home
// organization — a project-, environment-, or service-level grant cannot
// create a sibling project through this endpoint because the engine asks
// whether the grant scope contains the resource scope, never the reverse.
//
// The route uses a nil resolver: the new project does not exist yet, so the
// resource scope authorized against is the principal's home organization.
// The handler never widens or narrows that decision — it creates only inside
// the principal's home organization, so the tenant boundary is structural
// here: there is no caller input that could point the write at another
// tenant. The principal and the request correlation identifiers are passed
// to the creator so the audit record names the actor; a validation failure,
// a slug conflict, an exhausted quota, and a datastore outage each surface
// as their own typed status, never disguised as one another.
func createProjectHandler(creator ProjectCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if creator == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoProjectCreator))
			return
		}

		var req createProjectRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		project, err := creator.Create(r.Context(), store.CreateProjectInput{
			OrganizationID: p.OrganizationID,
			ProjectID:      req.ProjectID,
			Slug:           req.Slug,
			DisplayName:    req.DisplayName,
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

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), createProjectPayload{
			Project: projectResourceOf(project),
		})
	}
}
