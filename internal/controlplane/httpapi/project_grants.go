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

// errNoProjectGrantReader is returned when GET
// /v1/projects/{project_id}/grants is reached without a grant reader wired
// into NewHandler. Like errNoProjectReader it can only happen through a
// wiring error — a programming mistake, not a client error — so the
// handler reports it as a typed internal failure rather than serving an
// empty or misleading list.
var errNoProjectGrantReader = errors.New("httpapi: no project grant reader configured")

// errNoProjectGrantReplacer is returned when PUT
// /v1/projects/{project_id}/grants is reached without a grant replacer wired
// into NewHandler. Like errNoProjectGrantReader it can only happen through a
// wiring error — a programming mistake, not a client error — so the handler
// reports it as a typed internal failure rather than silently failing to
// persist the change.
var errNoProjectGrantReplacer = errors.New("httpapi: no project grant replacer configured")

// errProjectGrantsBodyMissing is the closed-set rejection reason for a PUT
// /v1/projects/{project_id}/grants body that decodes successfully but does
// not name the "grants" field at all. An explicit empty array is a
// meaningful clear and reaches the store layer; a missing field is a client
// error so a misencoded request is never a silent clear.
const errProjectGrantsBodyMissing = "must be supplied (provide an empty array to clear every grant)"

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

// ProjectGrantReplacer is the narrow persistence port PUT
// /v1/projects/{project_id}/grants depends on. *store.ProjectGrantService
// satisfies it in production; tests supply a fake. Like ProjectGrantReader
// it is an interface declared here so the handler stays unit-testable
// without a real database — the concrete orchestrator (the tenant-scoped
// project existence check, the per-grant upsert, the bulk
// delete-by-exclusion, the audit record, and the post-write re-read, all
// in one transaction) lives in the store layer.
type ProjectGrantReplacer interface {
	Replace(ctx context.Context, in store.ReplaceProjectGrantsInput) ([]store.ProjectGrant, error)
}

// projectGrantRequest is one entry in a replaceProjectGrantsRequest body:
// the (principal_id, principal_kind, role, optional environment_id,
// optional service_id) tuple the caller asks to persist for the project
// named by the {project_id} path parameter.
//
// PrincipalKind is closed to "usr" or "sa" — the two principal kinds the
// policy engine resolves — and Role is closed to one of the six built-in
// role names. EnvironmentID and ServiceID are pointers so the wire
// distinguishes "project-scoped grant" (both null) from
// "environment-scoped grant" (only environment set) from "service-scoped
// grant" (both set); a service-scoped grant must also name its parent
// environment_id. Each field is validated in the store-layer unit of
// work before any database write — an invalid request never opens a
// transaction — and the handler does no per-field validation beyond
// strict-decoding the body (oversized, malformed, or unknown-field bodies
// become a typed 400 that never echoes the input).
type projectGrantRequest struct {
	PrincipalID   string  `json:"principal_id"`
	PrincipalKind string  `json:"principal_kind"`
	Role          string  `json:"role"`
	EnvironmentID *string `json:"environment_id,omitempty"`
	ServiceID     *string `json:"service_id,omitempty"`
}

// replaceProjectGrantsRequest is the decoded PUT
// /v1/projects/{project_id}/grants request body: the complete set of
// grants the caller asks to install for the project in one transaction.
// Grants is a pointer to a slice so the body's omission of the field is
// structurally distinguishable from an explicit empty array — PUT
// replaces the entire set, so an explicit empty array means "clear every
// grant" while a missing field is a stable 400.
type replaceProjectGrantsRequest struct {
	Grants *[]projectGrantRequest `json:"grants"`
}

// replaceProjectGrantsPayload is the data block of the PUT
// /v1/projects/{project_id}/grants success envelope: the project's grants
// after the replace, in the same stable wire shape GET
// /v1/projects/{project_id}/grants returns. The endpoint always re-reads
// the grants in the same transaction that committed the upsert + delete,
// so the body always reflects the state that just persisted.
type replaceProjectGrantsPayload struct {
	Grants []projectGrantResource `json:"grants"`
}

// replaceProjectGrantsHandler builds the PUT
// /v1/projects/{project_id}/grants handler. It decodes and delegates: the
// request body is strictly decoded (oversized, malformed, or unknown-field
// bodies become a typed 400 that never echoes the input), then the
// replace-grants unit of work — verify the project, upsert each grant,
// delete every grant not in the replacement set, append the audit record,
// re-read the committed grants, all in one transaction — runs in the
// store layer through the ProjectGrantReplacer port.
//
// RequireAuth gates the route on action project.grants.write before the
// handler runs — authorized through projectIDResolver against the
// (principal home organization, {project_id}) resource the path names —
// and attaches the resolved principal, so a request that reaches the
// handler has already cleared the tenant boundary against the principal's
// home organization combined with the path id. A request that arrives
// here with no principal is therefore a wiring error and is reported as
// a typed internal error. The principal and the request correlation
// identifiers are passed to the replacer so the audit record names the
// actor; a validation failure (missing grants field, blank principal_id,
// unknown principal_kind, unknown role, duplicate scope tuple,
// service-scope without environment), a not-found {project_id}, and a
// datastore outage each surface as their own typed status, never
// disguised as one another.
//
// project.grants.write is a CapAdmin action: only the owner and admin
// roles, or a principal holding a scope-covering admin grant, can
// replace a project's grants. Viewer, developer, ci, and support are all
// denied at the policy boundary, never reaching this handler. The
// support principal's cross-tenant read exception does NOT apply because
// project.grants.write is a write action — CapSupport never satisfies
// CapAdmin in the engine.
func replaceProjectGrantsHandler(replacer ProjectGrantReplacer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if replacer == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoProjectGrantReplacer))
			return
		}

		var req replaceProjectGrantsRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if req.Grants == nil {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
				Field:  "grants",
				Reason: errProjectGrantsBodyMissing,
			}))
			return
		}

		items := make([]store.ProjectGrantReplace, 0, len(*req.Grants))
		for _, item := range *req.Grants {
			items = append(items, store.ProjectGrantReplace{
				PrincipalID:   item.PrincipalID,
				PrincipalKind: item.PrincipalKind,
				Role:          item.Role,
				EnvironmentID: cloneOptionalString(item.EnvironmentID),
				ServiceID:     cloneOptionalString(item.ServiceID),
			})
		}

		correlation := telemetry.FromContext(r.Context())
		grants, err := replacer.Replace(r.Context(), store.ReplaceProjectGrantsInput{
			OrganizationID: p.OrganizationID,
			ProjectID:      r.PathValue("project_id"),
			Grants:         items,
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

		payload := replaceProjectGrantsPayload{
			Grants: make([]projectGrantResource, 0, len(grants)),
		}
		for _, g := range grants {
			payload.Grants = append(payload.Grants, projectGrantResourceOf(g))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}

// cloneOptionalString returns a fresh *string carrying the same value as
// in. It is used when copying caller-supplied nullable pointers from the
// decoded request body into the store input so the store layer cannot
// observe or mutate the caller's backing string memory. A nil input
// stays nil — the project / environment / service scope distinction
// reaches the store intact.
func cloneOptionalString(in *string) *string {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}
