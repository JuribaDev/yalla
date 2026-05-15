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

// errNoProjectEnvironmentReader is returned when GET
// /v1/projects/{project_id}/environments is reached without an environment
// reader wired into NewHandler. Like errNoProjectVariableReader it can
// only happen through a wiring error — a programming mistake, not a
// client error — so the handler reports it as a typed internal failure
// rather than serving an empty or misleading list.
var errNoProjectEnvironmentReader = errors.New("httpapi: no project environment reader configured")

// errNoEnvironmentCreator is returned when POST
// /v1/projects/{project_id}/environments is reached without an
// EnvironmentCreator wired into NewHandler. Like errNoProjectCreator it
// can only happen through a wiring error and is reported as a typed
// internal failure rather than a misleading 2xx with no side effect.
var errNoEnvironmentCreator = errors.New("httpapi: no environment creator configured")

// ProjectEnvironmentReader is the narrow persistence port GET
// /v1/projects/{project_id}/environments depends on.
// *store.EnvironmentReader satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database, the same way ProjectVariableReader
// keeps the project-variables surface testable.
//
// The read is tenant scoped at the persistence layer: the adapter Gets
// the project under (organization_id, project_id) before listing its
// environments, so a cross-tenant or unknown project_id surfaces as a
// typed apierr.NotFound — never as an empty list, which would invite an
// agent to believe the project exists with no environments. The route
// uses projectIDResolver which authorizes the call against the
// (principal home org, path project_id) resource before the handler
// runs, so a project-scoped grant for THAT project authorizes the read
// while a sibling-project grant is rejected at the boundary; the
// support principal's deliberate cross-tenant read exception does NOT
// apply here because the resource scope is pinned to the principal's
// home organization, not the path's tenant (see projectIDResolver).
type ProjectEnvironmentReader interface {
	ListProjectEnvironments(ctx context.Context, organizationID, projectID string) ([]store.Environment, error)
}

// listProjectEnvironmentsPayload is the data block of the GET
// /v1/projects/{project_id}/environments success envelope: every
// environment the project owns, in deterministic (slug, id) order.
// Environments is always a non-nil slice so agents can iterate it
// without a nil check; a live project with no configured environments
// yields [].
type listProjectEnvironmentsPayload struct {
	Environments []projectEnvironment `json:"environments"`
}

// projectEnvironment is one entry in a listProjectEnvironmentsPayload.
//
// The wire shape carries no credential material — the environments
// table stores only structural identifiers, a slug, a display name, an
// optimistic-concurrency version, and lifecycle timestamps; environment-
// scoped variables and other secrets live behind their own endpoints
// (a later story) where the redaction policy applies. CreatedAt and
// UpdatedAt are RFC 3339 timestamps with the same semantics as every
// other dated resource the API surfaces; Version is the database-owned
// optimistic-concurrency counter callers use as an If-Match precondition
// on PATCH / DELETE in later stories.
type projectEnvironment struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	ProjectID      string    `json:"project_id"`
	Slug           string    `json:"slug"`
	DisplayName    string    `json:"display_name"`
	Version        int64     `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// projectEnvironmentOf projects a store.Environment into the stable
// wire shape. No field requires redaction at this seam — the
// environments table itself carries no credential material — but the
// projection remains the single chokepoint so a future column added to
// store.Environment is reviewed for its wire exposure here rather than
// leaking by default.
func projectEnvironmentOf(e store.Environment) projectEnvironment {
	return projectEnvironment{
		ID:             e.ID,
		OrganizationID: e.OrganizationID,
		ProjectID:      e.ProjectID,
		Slug:           e.Slug,
		DisplayName:    e.DisplayName,
		Version:        e.Version,
		CreatedAt:      e.CreatedAt,
		UpdatedAt:      e.UpdatedAt,
	}
}

// listProjectEnvironmentsHandler builds the GET
// /v1/projects/{project_id}/environments handler. It reads the
// environments of the project named by the {project_id} path parameter
// from the source-of-truth database through the ProjectEnvironmentReader
// port, and renders them in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action environment.read before the
// handler runs — authorized through projectIDResolver against the
// (principal home organization, {project_id}) resource the path names —
// and attaches the resolved principal, so a request that reaches the
// handler has already cleared the tenant boundary against the
// principal's home organization combined with the path id.
// environment.read is a CapRead action, so the gate admits the
// principal's organization-wide read roles (owner, admin, developer,
// viewer, ci); the support principal's cross-tenant read exception does
// NOT apply here because projectIDResolver pins the resource scope to
// the principal's own home organization, not the path's tenant. A
// scoped grant covering the resource (for example a project-scoped
// Viewer grant for THAT project) authorizes the read; a grant that
// names only a SIBLING project, an unrelated environment, or an
// unrelated service is rejected at the boundary because the policy
// engine asks whether the grant scope contains the resource scope,
// never the reverse.
//
// A request that arrives here with no principal is a wiring error and
// is reported as a typed internal error rather than reading for a zero
// principal. A reader-store outage surfaces as its own typed 5xx; a
// cross-tenant or unknown project_id reaches the persistence layer with
// the principal's home organization id and is rejected as a
// deterministic 404 by the reader's project existence check — never
// disguised as an empty success.
func listProjectEnvironmentsHandler(reader ProjectEnvironmentReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoProjectEnvironmentReader))
			return
		}
		envs, err := reader.ListProjectEnvironments(r.Context(), p.OrganizationID, r.PathValue("project_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]projectEnvironment, 0, len(envs))
		for _, e := range envs {
			out = append(out, projectEnvironmentOf(e))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listProjectEnvironmentsPayload{Environments: out})
	}
}

// EnvironmentCreator is the narrow persistence port POST
// /v1/projects/{project_id}/environments depends on.
// *store.EnvironmentService satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler unit-
// testable without a real database — the concrete orchestrator (the
// authorize / quota / desired-state write / provisioning-job / audit
// composition committed in one transaction) lives in the store layer.
//
// The HTTP boundary is the authoritative authorization gate: RequireAuth
// authorizes action environment.create against the (principal home
// organization, {project_id}) resource the path names through
// projectIDResolver, so a request that reaches the creator has already
// cleared the policy boundary. The store layer still re-authorizes
// inside the same *Tx as the desired-state write — defense-in-depth
// against a grant change that landed between the HTTP authorize and the
// quota reservation.
type EnvironmentCreator interface {
	Create(ctx context.Context, in store.CreateEnvironmentInput) (store.Environment, error)
}

// createProjectEnvironmentRequest is the decoded POST
// /v1/projects/{project_id}/environments request body.
// EnvironmentID is the caller-supplied canonical environment id — the
// agent contract mints ids client-side so an idempotent retry is
// structural rather than header-encoded; Slug is the canonical
// [a-z0-9-] identifier the environment is addressed by within its
// project; DisplayName is its human-authored label. The request body
// intentionally exposes no organization_id or project_id field: the
// organization is derived from the authenticated principal's home
// organization and the project comes from the {project_id} path
// parameter, never from the body. The store layer validates every
// field before any database work, so an invalid request never opens a
// transaction — and the request body never carries credential
// material.
type createProjectEnvironmentRequest struct {
	EnvironmentID string `json:"environment_id"`
	Slug          string `json:"slug"`
	DisplayName   string `json:"display_name"`
}

// createProjectEnvironmentPayload is the data block of the POST
// /v1/projects/{project_id}/environments success envelope: the
// environment that was created, in the same stable wire shape GET
// /v1/projects/{project_id}/environments returns. It carries no
// credential material — an environments row stores no secrets.
type createProjectEnvironmentPayload struct {
	Environment projectEnvironment `json:"environment"`
}

// createProjectEnvironmentHandler builds the POST
// /v1/projects/{project_id}/environments handler. It decodes and
// delegates: the request body is strictly decoded (oversized,
// malformed, or unknown-field bodies become a typed 400 that never
// echoes the input), then the create-environment unit of work —
// re-authorize, reserve quota, write the environment row, enqueue the
// provisioning job, append the audit record, all in one transaction —
// runs in the store layer through the EnvironmentCreator port.
//
// RequireAuth gates the route on action environment.create through
// projectIDResolver before the handler runs and attaches the resolved
// principal, so a request that reaches the handler with no principal
// is a wiring error reported as a typed internal error.
// environment.create is a CapWrite action evaluated against the
// (principal home organization, {project_id}) resource, so the gate
// admits the principal's organization-wide write roles (owner, admin,
// developer, ci) and a scoped grant that covers the project (a
// project-scoped Admin grant for THIS project, an environment- or
// service-scoped grant under it), denies viewer (CapRead only), denies
// support (CapRead-only — support is a deliberate cross-tenant READ
// exception, never a write one), and denies a grant that names only a
// sibling project, an unrelated environment, or an unrelated service
// because the policy engine asks whether the grant scope contains the
// resource scope, never the reverse.
//
// The handler resolves the organization id from the authenticated
// principal's home organization and the project id from the {project_id}
// PATH parameter — never from the request body — so the tenant
// boundary is structural here: there is no caller input that could
// point the write at another tenant. A cross-tenant project_id
// reaches the persistence layer with the principal's home organization
// id and is rejected as a deterministic 404 by the store-layer's
// tenant-scoped project existence check (the same property GET
// /v1/projects/{project_id}/environments inherits), never disguised as
// a 200 or a 403 that would confirm the foreign project's existence.
// The principal and the request correlation identifiers are passed to
// the creator so the audit record names the actor; a validation
// failure, a slug conflict, an exhausted quota, a denied in-tx
// authorize, and a datastore outage each surface as their own typed
// status, never disguised as one another.
func createProjectEnvironmentHandler(creator EnvironmentCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if creator == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentCreator))
			return
		}

		var req createProjectEnvironmentRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		environment, err := creator.Create(r.Context(), store.CreateEnvironmentInput{
			OrganizationID: p.OrganizationID,
			ProjectID:      r.PathValue("project_id"),
			EnvironmentID:  req.EnvironmentID,
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

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), createProjectEnvironmentPayload{
			Environment: projectEnvironmentOf(environment),
		})
	}
}
