package httpapi

import (
	"net/http"
	"sort"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/openapi"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// OpenAPI operation tags. They group endpoints in the published document.
const (
	tagOperations    = "operations"
	tagMeta          = "meta"
	tagIdentity      = "identity"
	tagOrganizations = "organizations"
	tagMembers       = "members"
	tagLimits        = "limits"
	tagUsage         = "usage"
	tagAuditEvents   = "audit-events"
	tagAPIKeys       = "api-keys"
	tagVariables     = "variables"
	tagProjects      = "projects"
	tagEnvironments  = "environments"
)

// apiRoute couples a served HTTP route with the OpenAPI metadata that
// documents it. The route table returned by newRouteTable is the single
// source of truth: NewHandler registers every entry on the mux *and* feeds the
// same entries into the generated OpenAPI document, so a route can never be
// served without being documented. TestEveryRegisteredRouteIsDocumented
// enforces that invariant in CI.
//
// When endpoint.RequiresAuth is true, NewHandler wraps handler in RequireAuth
// for endpoint.RequiredAction. resolver derives the policy.Resource the request
// acts on from its path and query parameters; a nil resolver authorizes against
// the principal's own organization scope, which suits self and organization-root
// actions that have no deeper target.
type apiRoute struct {
	endpoint openapi.Endpoint
	handler  http.HandlerFunc
	resolver ResourceResolver
}

// healthzPayload is the data block of the GET /healthz success envelope.
type healthzPayload struct {
	Status string `json:"status"`
}

// readyzPayload is the data block of the GET /readyz success envelope. Checks
// names every startup dependency gate and whether it is passing, so operators
// and agents can see exactly which dependency is degraded. Gate names are
// fixed, non-secret identifiers (for example "database", "migrations",
// "queue", "dokploy").
type readyzPayload struct {
	Status string          `json:"status"`
	Checks map[string]bool `json:"checks"`
}

// versionPayload is the data block of the GET /version success envelope. It
// carries both the build identity (Version/Commit/Date) and the contract
// identity: APISchemaVersion is the stable API contract version and
// MigrationVersion is the applied database schema version.
type versionPayload struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	Date             string `json:"date"`
	APISchemaVersion string `json:"api_schema_version"`
	MigrationVersion string `json:"migration_version"`
}

// newRouteTable returns every API route paired with its OpenAPI metadata. The
// /openapi.json route is intentionally absent — its handler is built from the
// document these routes describe, so openAPIDocument folds it back in (see
// openAPIEndpoint) and NewHandler registers it last.
//
// readiness drives /readyz; meta drives the dynamic fields of /version. Both
// may be nil: a nil readiness is treated as always-ready and a nil meta
// reports an unknown migration version, which suits tests and processes with
// no startup dependencies wired yet.
//
// orgs backs the organization read endpoints, creator backs POST
// /v1/organizations, updater backs PATCH /v1/organizations/{org_id}, deleter
// backs DELETE /v1/organizations/{org_id}, members backs GET
// /v1/organizations/{org_id}/members, memberCreator backs POST
// /v1/organizations/{org_id}/members, memberUpdater backs PATCH
// /v1/organizations/{org_id}/members/{member_id}, memberRemover backs
// DELETE /v1/organizations/{org_id}/members/{member_id}, limits backs GET
// /v1/organizations/{org_id}/limits, limitsUpdater backs PATCH
// /v1/organizations/{org_id}/limits, usage backs GET
// /v1/organizations/{org_id}/usage, auditEvents backs GET
// /v1/organizations/{org_id}/audit-events, orgVariables backs GET
// /v1/organizations/{org_id}/variables, orgVariableReplacer backs PUT
// /v1/organizations/{org_id}/variables, orgVariablePatcher backs PATCH
// /v1/organizations/{org_id}/variables/{key}, orgVariableDeleter backs
// DELETE /v1/organizations/{org_id}/variables/{key}, apiKeys backs GET
// /v1/organizations/{org_id}/api-keys and GET
// /v1/organizations/{org_id}/api-keys/{key_id}, apiKeyCreator backs POST
// /v1/organizations/{org_id}/api-keys, apiKeyUpdater backs PATCH
// /v1/organizations/{org_id}/api-keys/{key_id}, apiKeyRevoker backs
// DELETE /v1/organizations/{org_id}/api-keys/{key_id}, and apiKeyRotator
// backs POST /v1/organizations/{org_id}/api-keys/{key_id}/rotate.
// projectCreator backs POST /v1/projects, projectUpdater backs PATCH
// /v1/projects/{project_id}, projectDeleter backs DELETE
// /v1/projects/{project_id}, projectRestorer backs POST
// /v1/projects/{project_id}/restore, projectGrants backs GET
// /v1/projects/{project_id}/grants, projectGrantReplacer backs PUT
// /v1/projects/{project_id}/grants, projectVariables backs GET
// /v1/projects/{project_id}/variables, projectVariableReplacer backs
// PUT /v1/projects/{project_id}/variables, projectEnvironments backs
// GET /v1/projects/{project_id}/environments, environmentCreator
// backs POST /v1/projects/{project_id}/environments,
// environmentReader backs GET /v1/environments/{environment_id},
// environmentUpdater backs PATCH /v1/environments/{environment_id},
// environmentDeleter backs DELETE /v1/environments/{environment_id},
// and environmentCloner backs
// POST /v1/environments/{environment_id}/clone.
// Any may be nil for tests and tooling that only inspect the route
// table's metadata; a request that actually reaches a handler with a
// nil dependency is reported as a typed internal error rather than a
// misleading empty list or a silently dropped write.
func newRouteTable(build runtime.BuildInfo, readiness runtime.ReadinessReporter, meta runtime.MetaReporter, orgs OrganizationReader, creator OrganizationCreator, updater OrganizationUpdater, deleter OrganizationDeleter, members MembershipReader, memberCreator MembershipCreator, memberUpdater MembershipUpdater, memberRemover MembershipRemover, limits LimitsReader, limitsUpdater LimitsUpdater, usage UsageReader, auditEvents AuditEventReader, orgVariables OrganizationVariableReader, orgVariableReplacer OrganizationVariableReplacer, orgVariablePatcher OrganizationVariablePatcher, orgVariableDeleter OrganizationVariableDeleter, apiKeys APIKeyReader, apiKeyCreator APIKeyCreator, apiKeyUpdater APIKeyUpdater, apiKeyRevoker APIKeyRevoker, apiKeyRotator APIKeyRotator, projects ProjectReader, projectCreator ProjectCreator, projectUpdater ProjectUpdater, projectDeleter ProjectDeleter, projectRestorer ProjectRestorer, projectGrants ProjectGrantReader, projectGrantReplacer ProjectGrantReplacer, projectVariables ProjectVariableReader, projectVariableReplacer ProjectVariableReplacer, projectEnvironments ProjectEnvironmentReader, environmentCreator EnvironmentCreator, environmentReader EnvironmentReader, environmentUpdater EnvironmentUpdater, environmentDeleter EnvironmentDeleter, environmentCloner EnvironmentCloner, environmentGrants EnvironmentGrantReader) []apiRoute {
	build = build.Normalized()

	return []apiRoute{
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/healthz",
				OperationID:        "getHealthz",
				Summary:            "Liveness probe",
				Description:        "Reports process liveness without touching any downstream dependency. Load balancers use it to decide whether the process is alive.",
				Tags:               []string{tagOperations},
				SuccessDescription: "The process is alive and serving HTTP.",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Liveness: the process is running and can serve HTTP. It does
				// not depend on downstream dependencies — that is /readyz.
				apienvelope.WriteData(w, http.StatusOK, requestID(r), healthzPayload{Status: "ok"})
			},
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/readyz",
				OperationID:        "getReadyz",
				Summary:            "Readiness probe",
				Description:        "Reports whether every startup dependency check — database connectivity, migration state, queue readiness, and the Dokploy dependency when configured — has passed. Returns 200 with the per-check status once ready, or 503 with a yalla.error.v1 envelope naming the pending checks until then.",
				Tags:               []string{tagOperations},
				SuccessDescription: "Every startup dependency check has passed; the data block reports each check.",
			},
			handler: readyzHandler(readiness),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/version",
				OperationID:        "getVersion",
				Summary:            "Build and contract version",
				Description:        "Returns the running process identity: build version, source commit, build date, the stable API schema version, and the applied database migration version.",
				Tags:               []string{tagMeta},
				SuccessDescription: "The build and contract identity of the running process.",
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				migrationVersion := runtime.MigrationVersionUnknown
				if meta != nil {
					migrationVersion = meta.MigrationVersion()
				}
				apienvelope.WriteData(w, http.StatusOK, requestID(r), versionPayload{
					Version:          build.Version,
					Commit:           build.Commit,
					Date:             build.Date,
					APISchemaVersion: runtime.APISchemaVersion,
					MigrationVersion: migrationVersion,
				})
			},
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/me",
				OperationID:        "getMe",
				Summary:            "Current principal identity",
				Description:        "Returns the identity of the authenticated principal — its id, kind, home organization, organization role, and scoped grants — exactly as the control plane resolved it from the request credential. The response is derived from the authenticated principal alone and never reveals another tenant's data. It carries no credential material.",
				Tags:               []string{tagIdentity},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionAuthMe),
				SuccessDescription: "The authenticated principal's identity.",
			},
			// A nil resolver authorizes against the principal's own organization
			// scope. auth.me is a CapSelf action — allowed for any authenticated,
			// enabled principal — so the endpoint has no deeper resource target.
			handler: meHandler(),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/me/organizations",
				OperationID:        "getMeOrganizations",
				Summary:            "Organizations visible to the current principal",
				Description:        "Lists the organizations the authenticated principal can see through the control plane, with the principal's organization-wide role and scoped grants in each. The response is derived from the authenticated principal alone — its home organization and scoped grants — and never reveals another tenant's data. It carries no credential material. A principal is bound to a single home organization, so the list has one entry today; the array shape is forward-compatible with credentials that may span organizations later.",
				Tags:               []string{tagIdentity},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionAuthOrgs),
				SuccessDescription: "The organizations visible to the authenticated principal.",
			},
			// A nil resolver authorizes against the principal's own organization
			// scope. auth.orgs is a CapSelf action — allowed for any
			// authenticated, enabled principal — and the endpoint only ever
			// reports the principal's own organization, so it has no deeper
			// resource target.
			handler: meOrganizationsHandler(),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/organizations",
				OperationID:        "listOrganizations",
				Summary:            "Organizations visible to the caller",
				Description:        "Lists the organizations the authenticated principal can see through the control plane, as the source-of-truth database stores them — each with its id, slug, display name, and lifecycle timestamps. A principal is bound to a single home organization, so the list has one entry today; the array shape is forward-compatible with credentials that may span organizations later. The response carries no credential material and never reveals another tenant's data: the read is scoped to the principal's own home organization with no caller-supplied parameter that could point it elsewhere.",
				Tags:               []string{tagOrganizations},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionOrganizationRead),
				SuccessDescription: "The organizations visible to the authenticated principal.",
			},
			// A nil resolver authorizes action organization.read against the
			// principal's own organization scope. The endpoint carries no path
			// parameter and the handler only ever reads the principal's home
			// organization, so there is no deeper or cross-tenant resource
			// target to resolve.
			handler: organizationsHandler(orgs),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodGet,
				Path:               "/v1/projects",
				OperationID:        "listProjects",
				Summary:            "Projects visible to the caller",
				Description:        "Lists the projects the authenticated principal can see through the control plane, as the source-of-truth database stores them — each with its id, the id of the organization that owns it, slug, display name, optimistic-concurrency version, and lifecycle timestamps. The endpoint carries no path parameter and the handler only ever reads the principal's own home organization's projects, so the tenant boundary is structural: there is no caller-supplied parameter that could point the read at another tenant. Projects are returned in deterministic (slug, id) order so a given set of rows always renders the same response. Action project.read is authorized against the principal's home organization before the handler runs — a CapRead action gated by an organization-wide role (owner, admin, developer, viewer, ci) or, for cross-tenant reads, a support principal; a grant-only principal whose grants are narrower than the home organization is rejected at the boundary because the policy engine asks whether the grant scope contains the resource scope, never the reverse, so a project-, environment-, or service-level grant cannot list sibling projects, unrelated environments, or parent secrets through this endpoint. The response carries no credential material — a projects row stores no secrets — and an organization with no projects is the deterministic empty list every list endpoint returns.",
				Tags:               []string{tagProjects},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionProjectRead),
				SuccessDescription: "The projects visible to the authenticated principal.",
			},
			// A nil resolver authorizes action project.read against the
			// principal's own organization scope. The endpoint carries no path
			// parameter and the handler only ever reads the principal's home
			// organization's projects, so there is no deeper or cross-tenant
			// resource target to resolve.
			handler: listProjectsHandler(projects),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/projects",
				OperationID:        "createProject",
				Summary:            "Create a project",
				Description:        "Creates a project — the second level of Yalla's Organization -> Project -> Environment -> Service hierarchy — inside the authenticated principal's home organization. The request body supplies the caller-minted canonical project id (an idempotent retry is structural, not header-encoded), the canonical [a-z0-9-] slug the project is addressed by within its organization, and the human-authored display name. Every field is validated before any database work; an invalid request never opens a transaction. The project row, the durable provisioning job that mirrors it into Dokploy, and an immutable audit record naming the authenticated principal are committed in one transaction — a created project can never exist without its provisioning job or its audit trail, and a duplicate slug rolls the whole transaction back as a deterministic 409. Action project.create is authorized against the principal's home organization before the handler runs: project.create is a CapWrite action, so the gate admits organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only), and denies a grant-only principal whose grants are narrower than the home organization — a project-, environment-, or service-level grant cannot create a sibling project through this endpoint. The response carries no credential material.",
				Tags:               []string{tagProjects},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionProjectCreate),
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The project was created.",
			},
			// A nil resolver authorizes action project.create against the
			// principal's own organization scope. The created project does
			// not exist yet, so there is no deeper resource target to
			// resolve; the handler creates only inside the principal's home
			// organization, so the tenant boundary is structural — there is
			// no caller input that could point the write at another tenant.
			handler: createProjectHandler(projectCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/projects/{project_id}",
				OperationID:    "getProject",
				Summary:        "Get a project",
				Description:    "Returns the project named by the {project_id} path parameter, as the source-of-truth database stores it — its id, the id of the organization that owns it, slug, display name, optimistic-concurrency version, and lifecycle timestamps. Action project.read is authorized against the (home organization, project_id) resource before the handler runs: project.read is a CapRead action, so the gate admits the principal's organization-wide roles (owner, admin, developer, viewer, ci) and a support principal performing a read; it also admits a scoped grant that covers the resource (for example, a project-scoped Admin grant for THAT project), but denies a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. The handler reads from the principal's home organization id only — it never trusts a caller-supplied organization id — so a cross-tenant project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's data. The response carries no credential material — a projects row stores no secrets.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectRead),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project to retrieve.",
				}},
				SuccessDescription: "The requested project.",
			},
			// projectIDResolver authorizes action project.read against the
			// (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization, so
			// a scoped grant that names THIS project authorizes the read
			// while a grant that names only a SIBLING project does not.
			// The organization id is taken from the principal's home org
			// (never the caller), so a cross-tenant project_id still hits
			// the tenant-scoped repository query and surfaces as a 404 at
			// the persistence boundary.
			resolver: projectIDResolver,
			handler:  getProjectHandler(projects),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/projects/{project_id}",
				OperationID:    "updateProject",
				Summary:        "Update a project",
				Description:    "Updates the project named by the {project_id} path parameter in the source-of-truth database. The request body is a partial update: it may carry a new canonical slug, a new human-authored display name, or both — every supplied field is validated before any database work, and a patch that names no field is rejected with a stable 400. The request body intentionally exposes no organization_id field: the tenant is derived from the authenticated principal's home organization, never from the body or path query. Action project.update is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: project.update is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant), and admits a scoped grant that covers the resource (for example, a project-scoped Admin grant for THAT project) while denying a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. A cross-tenant project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never mutating another tenant's data. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. The updated project row and an immutable audit record naming the authenticated principal are committed in one transaction: an update can never be persisted without its audit trail. The response carries no credential material and mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectUpdate),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project to update.",
				}},
				SuccessDescription: "The updated project.",
			},
			// projectIDResolver authorizes action project.update against the
			// (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization,
			// so a scoped grant that names THIS project authorizes the
			// write while a grant that names only a SIBLING project does
			// not. The organization id is taken from the principal's home
			// org (never the caller), so a cross-tenant project_id still
			// hits the tenant-scoped repository query and surfaces as a
			// 404 at the persistence boundary.
			resolver: projectIDResolver,
			handler:  updateProjectHandler(projectUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/projects/{project_id}",
				OperationID:    "deleteProject",
				Summary:        "Schedule a project for deletion",
				Description:    "Schedules the project named by the {project_id} path parameter for deletion in the source-of-truth database. The deletion is scheduled, not immediate: the project's deletion_scheduled_at stamp is set and the destructive teardown — the ON DELETE CASCADE that removes its environments, services, and audit log — is carried out by a later worker story, so the project and its audit trail still exist when this returns. Action project.delete is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: project.delete is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant), and admits a scoped grant that covers the resource (for example, a project-scoped Admin grant for THAT project) while denying a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. A cross-tenant project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never scheduling another tenant's data for teardown. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. Scheduling deletion for a project already scheduled for deletion is a stable 409. The soft-delete write and an immutable audit record naming the authenticated principal are committed in one transaction: a scheduled deletion can never be persisted without its audit trail. The response carries no credential material and mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectDelete),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project to schedule for deletion.",
				}},
				SuccessStatus:      http.StatusAccepted,
				SuccessDescription: "The project was scheduled for deletion.",
			},
			// projectIDResolver authorizes action project.delete against the
			// (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization,
			// so a scoped grant that names THIS project authorizes the
			// teardown while a grant that names only a SIBLING project
			// does not. The organization id is taken from the principal's
			// home org (never the caller), so a cross-tenant project_id
			// still hits the tenant-scoped repository query and surfaces
			// as a 404 at the persistence boundary.
			resolver: projectIDResolver,
			handler:  deleteProjectHandler(projectDeleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/projects/{project_id}/restore",
				OperationID:    "restoreProject",
				Summary:        "Restore a soft-deleted project",
				Description:    "Restores the project named by the {project_id} path parameter that was previously scheduled for deletion by DELETE /v1/projects/{project_id} but has not yet been destructively torn down by the worker. The restore is the inverse of the soft-delete: it clears the project's deletion_scheduled_at stamp in the source-of-truth database so the project is live again, and its environments, services, and audit trail (which the destructive teardown has not yet cascaded away) are recovered intact. Action project.restore is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: project.restore is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant), and admits a scoped grant that covers the resource (for example, a project-scoped Admin grant for THAT project) while denying a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. A cross-tenant project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never restoring another tenant's data. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. Restoring a project that is not currently scheduled for deletion is a stable 409: the caller's view of the resource lifecycle is stale, so a silent success would write a misleading audit record. The clear-stamp write and an immutable audit record naming the authenticated principal are committed in one transaction: a restore can never be persisted without its audit trail. The request body is empty. The response carries no credential material and mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectRestore),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project to restore from soft-deletion.",
				}},
				SuccessDescription: "The project was restored from soft-deletion.",
			},
			// projectIDResolver authorizes action project.restore against the
			// (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization,
			// so a scoped grant that names THIS project authorizes the
			// restore while a grant that names only a SIBLING project
			// does not. The organization id is taken from the principal's
			// home org (never the caller), so a cross-tenant project_id
			// still hits the tenant-scoped repository query and surfaces
			// as a 404 at the persistence boundary.
			resolver: projectIDResolver,
			handler:  restoreProjectHandler(projectRestorer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/projects/{project_id}/grants",
				OperationID:    "listProjectGrants",
				Summary:        "List project grants",
				Description:    "Lists the scoped grants attached to the project named by the {project_id} path parameter, as the source-of-truth database stores them — each with its id, the id of the organization that owns it, the id of the project it targets, the principal it confers a role on, the role it confers, optional further (environment, service) scoping, optimistic-concurrency version, and lifecycle timestamps. Grants narrow or widen a principal's authority below the organization level: a developer with a project-scoped Viewer grant for one project cannot mutate sibling projects, and a viewer with a project-scoped Admin grant for one project can mutate it without becoming an admin of the whole organization. Action project.grants.read is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: project.grants.read is a CapRead action, so the gate admits the principal's organization-wide read roles (owner, admin, developer, viewer, ci) and admits a scoped grant that covers the resource (a project-scoped Viewer grant for THAT project, an environment- or service-scoped grant under it) while denying a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's project existence check, never disguised as an empty success. A project with no grants is a deterministic empty list. The response carries no credential material — a grants row stores only structural identifiers and a role enum.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectGrantsRead),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose grants to list.",
				}},
				SuccessDescription: "The grants attached to the project.",
			},
			// projectIDResolver authorizes action project.grants.read against
			// the (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization, so a
			// scoped grant that names THIS project authorizes the read while
			// a grant that names only a SIBLING project does not. The
			// organization id is taken from the principal's home org (never
			// the caller), so a cross-tenant project_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary.
			resolver: projectIDResolver,
			handler:  listProjectGrantsHandler(projectGrants),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPut,
				Path:           "/v1/projects/{project_id}/grants",
				OperationID:    "replaceProjectGrants",
				Summary:        "Replace project grants",
				Description:    "Replaces the scoped grants attached to the project named by the {project_id} path parameter in one transaction. The request body supplies the complete replacement set — every grant absent from the body is removed, every grant present is upserted on its scope tuple (principal_id, environment_id, service_id), so a re-submission with the same set is structurally idempotent. An explicit empty array means \"clear every grant of this project\" — a meaningful (extreme) operation, never a silent no-op. Every field is validated before any database work; an invalid request (missing grants field, blank principal_id, unknown principal_kind, unknown role, duplicate scope tuple, service-scope without environment) never opens a transaction. Action project.grants.write is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: project.grants.write is a CapAdmin action, so the gate admits the principal's organization-wide admin roles (owner, admin) or a scoped grant that covers the resource (a project-scoped Admin grant for THAT project) while denying viewer, developer, ci, support, and grants that name only a sibling project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. project.grants.write is a CapAdmin action, so there is no cross-tenant support exception — a support principal cannot replace another tenant's grants. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the project existence check, never disguised as an empty success. The replace, the audit record, and the post-write re-read are committed in one transaction so a partial replace and an orphaned audit row are both impossible. The response carries the persisted grants in the same stable wire shape GET /v1/projects/{project_id}/grants returns — every column projected onto the deterministic (principal_id, environment_id NULLS FIRST, service_id NULLS FIRST, id) order. A grant carries no credential material — the schema stores only structural identifiers and a role enum.",
				Tags:           []string{tagProjects},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionProjectGrantsWrite),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose grants to replace.",
				}},
				SuccessDescription: "The grants attached to the project after the replace.",
			},
			// projectIDResolver authorizes action project.grants.write against
			// the (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization, so a
			// scoped admin grant that names THIS project authorizes the write
			// while a grant that names only a SIBLING project does not. The
			// organization id is taken from the principal's home org (never
			// the caller — there is no organization id in the request body),
			// so a cross-tenant project_id still hits the tenant-scoped
			// repository query and surfaces as a 404 at the persistence
			// boundary. project.grants.write is a CapAdmin action and has no
			// cross-tenant support exception — unlike CapRead actions, the
			// support principal cannot replace grants in another tenant.
			resolver: projectIDResolver,
			handler:  replaceProjectGrantsHandler(projectGrantReplacer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/projects/{project_id}/variables",
				OperationID:    "listProjectVariables",
				Summary:        "List project variables",
				Description:    "Lists the project-scoped environment variables configured for the project named by the {project_id} path parameter, in deterministic (key, id) order. Each entry carries the variable's id, the id of the organization that owns it, the id of the project it targets, key (a POSIX shell environment variable name), value, is_secret flag, optimistic-concurrency version, and lifecycle timestamps. Project-scoped variables are the second-from-lowest precedence layer of the Organization -> Project -> Environment -> Service variable hierarchy the Dokploy renderer composes: a value set here is a project-wide default every service in the project inherits unless overridden by a higher-scope variable, and it shadows any organization-scoped variable of the same key for services inside the project. Secret values are ALWAYS redacted on the wire — a customer can never read a secret value back through this endpoint by design, mirroring every credential-bearing resource in this API; non-secret values are projected verbatim so the customer can audit their own project-wide defaults. Action env.read is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: env.read is a CapRead action, so the gate admits the principal's organization-wide read roles (owner, admin, developer, viewer, ci) and admits a scoped grant that covers the resource (a project-scoped Viewer grant for THAT project, an environment- or service-scoped grant under it) while denying a grant that names only a SIBLING project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's project existence check, never disguised as an empty success. A project with no variables is a deterministic empty list.",
				Tags:           []string{tagProjects, tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvRead),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose variables to list.",
				}},
				SuccessDescription: "The variables of the project.",
			},
			// projectIDResolver authorizes action env.read against the
			// (principal home organization, {project_id}) resource the path
			// names, not merely the principal's home organization, so a
			// scoped grant that names THIS project authorizes the read while
			// a grant that names only a SIBLING project does not. The
			// organization id is taken from the principal's home org (never
			// the caller), so a cross-tenant project_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary.
			resolver: projectIDResolver,
			handler:  listProjectVariablesHandler(projectVariables),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPut,
				Path:           "/v1/projects/{project_id}/variables",
				OperationID:    "replaceProjectVariables",
				Summary:        "Replace project variables",
				Description:    "Replaces the project-scoped environment variables attached to the project named by the {project_id} path parameter in one transaction. The request body supplies the complete replacement set — every variable absent from the body is removed, every variable present is upserted on (organization_id, project_id, key), so a re-submission with the same set is structurally idempotent. An explicit empty array means \"clear every project-scoped variable\" — a meaningful (extreme) operation, never a silent no-op. Every field is validated before any database work; an invalid request (missing variables field, non-POSIX key, duplicate key, oversize value, invalid UTF-8, NUL byte in value) never opens a transaction. Action env.write is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: env.write is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) or a scoped grant that covers the resource (a project-scoped Developer / Admin / Owner grant for THAT project, an environment- or service-scoped grant under it) while denying viewer, support, and grants that name only a sibling project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. env.write is a CapWrite action, so there is no cross-tenant support exception — a support principal cannot replace another tenant's variables. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the project existence check, never disguised as an empty success. The replace, the audit record, and the post-write re-read are committed in one transaction so a partial replace and an orphaned audit row are both impossible. The response carries the persisted variables in the same stable wire shape GET /v1/projects/{project_id}/variables returns — every column projected onto the deterministic (key, id) order. Secret values are still redacted on the wire to the sentinel, so PUT cannot leak a secret value the customer just submitted; non-secret values project verbatim.",
				Tags:           []string{tagProjects, tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvWrite),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose variables to replace.",
				}},
				SuccessDescription: "The variables of the project after the replace.",
			},
			// projectIDResolver authorizes action env.write against the
			// (principal home organization, {project_id}) resource the path
			// names, not merely the principal's home organization, so a
			// scoped write grant that names THIS project authorizes the write
			// while a grant that names only a SIBLING project does not. The
			// organization id is taken from the principal's home org (never
			// the caller — there is no organization id in the request body),
			// so a cross-tenant project_id still hits the tenant-scoped
			// repository query and surfaces as a 404 at the persistence
			// boundary. env.write is a CapWrite action and has no
			// cross-tenant support exception — unlike CapRead actions, the
			// support principal cannot replace variables in another tenant.
			resolver: projectIDResolver,
			handler:  replaceProjectVariablesHandler(projectVariableReplacer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/projects/{project_id}/environments",
				OperationID:    "listProjectEnvironments",
				Summary:        "List project environments",
				Description:    "Lists the environments configured for the project named by the {project_id} path parameter, in deterministic (slug, id) order. Each entry carries the environment's id, the id of the organization that owns it, the id of the project it belongs to, slug (unique within the project), display name, optimistic-concurrency version, and lifecycle timestamps. Environments are the third layer of the Organization -> Project -> Environment -> Service hierarchy the Dokploy provisioning model mirrors; an environment groups the services that share a deployment target (for example production, staging, preview) within a project. Action environment.read is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: a CapRead action gated by an organization-wide role (owner, admin, developer, viewer, ci) or a scoped grant that covers the resource (a project-, environment-, or service-scoped grant inside this project) while a grant that names only a sibling project, an unrelated environment, or an unrelated service is rejected at the boundary because the policy engine asks whether the grant scope contains the resource scope, never the reverse. The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's project existence check, never disguised as an empty success. A project with no environments is a deterministic empty list. The response carries no credential material — the environments table stores only structural identifiers, a slug, a display name, an optimistic-concurrency version, and lifecycle timestamps.",
				Tags:           []string{tagProjects, tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentRead),
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project whose environments to list.",
				}},
				SuccessDescription: "The environments of the project.",
			},
			// projectIDResolver authorizes action environment.read against
			// the (principal home organization, {project_id}) resource the
			// path names, not merely the principal's home organization, so
			// a scoped grant that names THIS project authorizes the read
			// while a grant that names only a SIBLING project does not. The
			// organization id is taken from the principal's home org (never
			// the caller), so a cross-tenant project_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary.
			resolver: projectIDResolver,
			handler:  listProjectEnvironmentsHandler(projectEnvironments),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/projects/{project_id}/environments",
				OperationID:    "createProjectEnvironment",
				Summary:        "Create a project environment",
				Description:    "Creates an environment — the third level of Yalla's Organization -> Project -> Environment -> Service hierarchy — inside the project named by the {project_id} path parameter. The request body supplies the caller-minted canonical environment id (an idempotent retry is structural, not header-encoded), the canonical [a-z0-9-] slug the environment is addressed by within its project, and the human-authored display name. Every field is validated before any database work; an invalid request never opens a transaction. The environment row, the durable provisioning job that mirrors it into Dokploy, and an immutable audit record naming the authenticated principal are committed in one transaction — a created environment can never exist without its provisioning job or its audit trail, and a duplicate slug within the same project rolls the whole transaction back as a deterministic 409. Action environment.create is authorized against the (principal home organization, {project_id}) resource the path names before the handler runs: environment.create is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci), admits a scoped grant that covers the project (a project-scoped Admin grant for THIS project, an environment- or service-scoped grant under it), denies viewer (CapRead only), denies support (CapRead-only — support is a deliberate cross-tenant READ exception, never a write one), and denies a grant that names only a sibling project, an unrelated environment, or an unrelated service because the policy engine asks whether the grant scope contains the resource scope, never the reverse. A cross-tenant or unknown project_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the store-layer project existence check, never disguised as a 200 or a 403 that would confirm the foreign project's existence. The response carries no credential material.",
				Tags:           []string{tagProjects, tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentCreate),
				SuccessStatus:  http.StatusCreated,
				PathParams: []openapi.PathParam{{
					Name:        "project_id",
					Description: "The id of the project the new environment will belong to.",
				}},
				SuccessDescription: "The environment was created.",
			},
			// projectIDResolver authorizes action environment.create against
			// the (principal home organization, {project_id}) resource the
			// path names, so a scoped grant that names THIS project
			// authorizes the write while a grant that names only a SIBLING
			// project does not. The organization id on the persistence
			// input is taken from the principal's home org (never the
			// caller), so a cross-tenant project_id still hits the
			// tenant-scoped repository query and surfaces as a 404 at the
			// persistence boundary — never disguised as a 200 with an
			// environment minted under another tenant. environment.create
			// is a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, the support principal
			// cannot create environments in another tenant.
			resolver: projectIDResolver,
			handler:  createProjectEnvironmentHandler(environmentCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/environments/{environment_id}",
				OperationID:    "getEnvironment",
				Summary:        "Get an environment",
				Description:    "Returns the environment named by the {environment_id} path parameter, as the source-of-truth database stores it — its id, the id of the organization that owns it, the id of the project it belongs to, slug, display name, optimistic-concurrency version, and lifecycle timestamps. Environments are the third layer of the Organization -> Project -> Environment -> Service hierarchy the Dokploy provisioning model mirrors. Action environment.read is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: a CapRead action gated by the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path env's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary because the engine asks whether the grant scope (which pins ProjectID) covers the resource scope (which does not), never the reverse; principals whose only access is a scoped grant must use the parent-scoped GET /v1/projects/{project_id}/environments to address an environment by its (project, environment) tuple. The handler reads from the principal's home organization id only — it never trusts a caller-supplied organization id — so a cross-tenant environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped GetByID query, never revealing another tenant's environment. The response carries no credential material — the environments table itself stores only structural identifiers, a slug, a display name, an optimistic-concurrency version, and lifecycle timestamps; environment-scoped variables and other secrets live behind their own endpoints where the redaction policy applies.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentRead),
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment to return.",
				}},
				SuccessDescription: "The requested environment.",
			},
			// environmentIDResolver authorizes action environment.read
			// against the (principal home organization, {environment_id})
			// resource the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller), so a cross-tenant
			// environment_id still hits the tenant-scoped GetByID query
			// and surfaces as a 404 at the persistence boundary. The
			// path carries no parent project_id, so the resource scope
			// pins only OrganizationID and EnvironmentID — project- and
			// environment-scoped grants are denied at the policy
			// boundary by design (the engine's covers() rule), forcing
			// scoped-grant-only principals onto the parent-scoped
			// /v1/projects/{project_id}/environments route.
			resolver: environmentIDResolver,
			handler:  getEnvironmentHandler(environmentReader),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/environments/{environment_id}",
				OperationID:    "updateEnvironment",
				Summary:        "Update an environment",
				Description:    "Partially updates the environment named by the {environment_id} path parameter, as the source-of-truth database stores it. The request body is a partial-update document: both slug and display_name are optional pointers, so omitting a field leaves it unchanged. A patch that names no updatable field is a stable 400 — a mutation that changes nothing is a client error, not a silent success. Every supplied field is validated before any database work; an invalid request never opens a transaction. The desired-state write and an immutable audit record naming the authenticated principal are committed in one transaction — an update can never be persisted without its audit trail, and a duplicate slug within the same project rolls the whole transaction back as a deterministic 409. Action environment.update is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: environment.update is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule; principals whose only access is a scoped grant must use a parent-scoped route to address an environment by its (project, environment) tuple. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's environment. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. The response mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition. The response carries no credential material — the environments table itself stores no secrets; environment-scoped variables and other secrets live behind their own endpoints where the redaction policy applies.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentUpdate),
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment to update.",
				}},
				SuccessDescription: "The environment was updated.",
			},
			// environmentIDResolver authorizes action environment.update
			// against the (principal home organization, {environment_id})
			// resource the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller — there is no
			// organization id in the request body), so a cross-tenant
			// environment_id still hits the tenant-scoped repository
			// query and surfaces as a 404 at the persistence boundary.
			// The path carries no parent project_id, so the resource
			// scope pins only OrganizationID and EnvironmentID —
			// project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. environment.update is a CapWrite
			// action and has no cross-tenant support exception — unlike
			// CapRead actions, a support principal cannot mutate
			// environments in another tenant.
			resolver: environmentIDResolver,
			handler:  updateEnvironmentHandler(environmentUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/environments/{environment_id}",
				OperationID:    "deleteEnvironment",
				Summary:        "Schedule an environment for deletion",
				Description:    "Schedules the environment named by the {environment_id} path parameter for deletion in the source-of-truth database. The deletion is scheduled, not immediate: the environment's deletion_scheduled_at stamp is set and the destructive teardown — the ON DELETE CASCADE that removes its services and audit log — is carried out by a later worker story, so the environment and its audit trail still exist when this returns. Action environment.delete is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: environment.delete is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address an environment by its (project, environment) tuple. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's environment. The optional If-Match request header carries the row's optimistic-concurrency version (a strong ETag of the form \"<n>\"); a stale version is rejected as a deterministic 409 carrying the row's authoritative version under details.current_version. Scheduling deletion for an environment already scheduled for deletion is a stable 409. The soft-delete write and an immutable audit record naming the authenticated principal are committed in one transaction: a scheduled deletion can never be persisted without its audit trail. The response carries no credential material and mirrors the row's new version into the ETag response header so the caller can echo it back as the next If-Match precondition.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentDelete),
				SuccessStatus:  http.StatusAccepted,
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment to schedule for deletion.",
				}},
				SuccessDescription: "The environment was scheduled for deletion.",
			},
			// environmentIDResolver authorizes action environment.delete
			// against the (principal home organization, {environment_id})
			// resource the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller), so a cross-tenant
			// environment_id still hits the tenant-scoped repository
			// query and surfaces as a 404 at the persistence boundary.
			// The path carries no parent project_id, so the resource
			// scope pins only OrganizationID and EnvironmentID —
			// project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. environment.delete is a CapWrite
			// action and has no cross-tenant support exception — unlike
			// CapRead actions, a support principal cannot mutate
			// environments in another tenant.
			resolver: environmentIDResolver,
			handler:  deleteEnvironmentHandler(environmentDeleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/environments/{environment_id}/clone",
				OperationID:    "cloneEnvironment",
				Summary:        "Clone an environment",
				Description:    "Clones the environment named by the {environment_id} path parameter into a new environment that inherits the source environment's parent project — the new environment lives in the same Organization -> Project -> Environment -> Service hierarchy as its source, never crossing a tenant or project boundary. The request body supplies the caller-minted canonical id for the new environment (an idempotent retry is structural, not header-encoded), the canonical [a-z0-9-] slug it is addressed by within the inherited project, and its human-authored display name. The request body intentionally exposes no organization_id, project_id, or source_environment_id field: the organization is derived from the authenticated principal's home organization, the source environment_id comes from the {environment_id} path parameter, and the new environment inherits the source's project_id — there is no caller-supplied parameter that could redirect the clone at another tenant or another project. Every supplied field is validated before any database work; an invalid request never opens a transaction. The new environment row, the provisioning job that mirrors it into Dokploy, and an immutable audit record naming the authenticated principal and the source environment are committed in one transaction — a cloned environment can never exist without its provisioning job or its audit trail, and a duplicate slug within the inherited project rolls the whole transaction back as a deterministic 409. Action environment.create is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: environment.create is a CapWrite action, so the gate admits the principal's organization-wide write roles (owner, admin, developer, ci) and denies viewer, denies support (CapRead-only — a support principal cannot mutate even within its home tenant). The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must use a parent-scoped route to address an environment by its (project, environment) tuple. A cross-tenant or unknown source {environment_id} reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the tenant-scoped repository query, never revealing another tenant's environment. A source environment already scheduled for teardown is rejected as a deterministic 409 — a lifecycle-dead row is not a valid clone source. The new environment's id must differ from the source environment's id; cloning onto the same id is a stable 400. The response carries no credential material — the environments table itself stores no secrets; environment-scoped variables and other secrets live behind their own endpoints where the redaction policy applies. (Variables and secrets are not yet copied across by this endpoint; a later worker story owns that propagation, so the clone here writes only the structural row.) The response mirrors the new row's authoritative version into the ETag response header so the caller can echo it back as the next If-Match precondition without re-reading the row.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentCreate),
				SuccessStatus:  http.StatusCreated,
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the source environment to clone from.",
				}},
				SuccessDescription: "The environment was cloned.",
			},
			// environmentIDResolver authorizes action environment.create
			// against the (principal home organization, {environment_id})
			// resource the path names, not merely the principal's home
			// organization. The organization id is taken from the
			// principal's home org (never the caller — there is no
			// organization id in the request body), so a cross-tenant
			// source environment_id still hits the tenant-scoped
			// repository query and surfaces as a 404 at the persistence
			// boundary. The path carries no parent project_id, so the
			// resource scope pins only OrganizationID and EnvironmentID —
			// project-, environment-, and service-scoped grants are
			// denied at the policy boundary by design (the engine's
			// covers() rule), forcing scoped-grant-only principals onto
			// parent-scoped routes. environment.create is a CapWrite
			// action and has no cross-tenant support exception — unlike
			// CapRead actions, a support principal cannot clone
			// environments in another tenant.
			resolver: environmentIDResolver,
			handler:  cloneEnvironmentHandler(environmentCloner),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/environments/{environment_id}/grants",
				OperationID:    "listEnvironmentGrants",
				Summary:        "List environment grants",
				Description:    "Lists the scoped grants attached to the environment named by the {environment_id} path parameter, as the source-of-truth database stores them — each with its id, the id of the organization that owns it, the id of the environment it targets, the principal it confers a role on, the role it confers, optional further (service) scoping, optimistic-concurrency version, and lifecycle timestamps. Environment grants narrow or widen a principal's authority below the project level: a developer with an environment-scoped Viewer grant for one environment cannot mutate sibling environments, and a viewer with an environment-scoped Admin grant for one environment can mutate it without becoming an admin of the whole project. Action environment.grants.read is authorized against the (principal home organization, {environment_id}) resource the path names before the handler runs: a CapRead action gated by the principal's organization-wide read roles (owner, admin, developer, viewer, ci). The support principal's deliberate cross-tenant read exception does NOT apply through this endpoint because the resource scope is pinned to the principal's home organization, not the path env's tenant; support cross-tenant reads remain available through endpoints whose path carries an {org_id}. The path carries no parent project_id, so the policy engine cannot pin the ProjectID leg of the resource scope at authorization time — project-, environment-, and service-scoped grants are denied at the boundary by the engine's covers() rule (a grant with a pinned ProjectID cannot cover a resource with no ProjectID); principals whose only access is a scoped grant must address grants through a parent-scoped route. A cross-tenant or unknown environment_id reaches the persistence layer with the principal's home organization id and is rejected as a deterministic 404 by the reader's environment existence check, never disguised as an empty success. An environment with no grants is a deterministic empty list. The response carries no credential material — a grants row stores only structural identifiers and a role enum.",
				Tags:           []string{tagEnvironments},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvironmentGrantsRead),
				PathParams: []openapi.PathParam{{
					Name:        "environment_id",
					Description: "The id of the environment whose grants to list.",
				}},
				SuccessDescription: "The grants attached to the environment.",
			},
			// environmentIDResolver authorizes action
			// environment.grants.read against the (principal home
			// organization, {environment_id}) resource the path names,
			// not merely the principal's home organization. The
			// organization id is taken from the principal's home org
			// (never the caller), so a cross-tenant environment_id
			// still hits the tenant-scoped repository query and
			// surfaces as a 404 at the persistence boundary. The path
			// carries no parent project_id, so the resource scope
			// pins only OrganizationID and EnvironmentID — project-,
			// environment-, and service-scoped grants are denied at
			// the policy boundary by design (the engine's covers()
			// rule), forcing scoped-grant-only principals onto
			// parent-scoped routes.
			resolver: environmentIDResolver,
			handler:  listEnvironmentGrantsHandler(environmentGrants),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}",
				OperationID:    "getOrganization",
				Summary:        "Get an organization",
				Description:    "Returns the organization named by the {org_id} path parameter, as the source-of-truth database stores it — its id, slug, display name, and lifecycle timestamps. Action organization.read is authorized against the organization the path names before the handler runs: a principal requesting an organization outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's data. The response carries no credential material.",
				Tags:           []string{tagOrganizations},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionOrganizationRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization to retrieve.",
				}},
				SuccessDescription: "The requested organization.",
			},
			// organizationIDResolver authorizes action organization.read against
			// the organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data.
			resolver: organizationIDResolver,
			handler:  getOrganizationHandler(orgs),
		},
		{
			endpoint: openapi.Endpoint{
				Method:             http.MethodPost,
				Path:               "/v1/organizations",
				OperationID:        "createOrganization",
				Summary:            "Create an organization",
				Description:        "Creates an organization — the tenant root of Yalla's Organization -> Project -> Environment -> Service hierarchy — in the source-of-truth database. The request body supplies the canonical slug and the human-authored display name; both are validated before any database work, so an invalid request never opens a transaction. The organization row and an immutable audit record naming the authenticated principal are committed in one transaction: a created organization can never exist without its audit trail. The response carries no credential material.",
				Tags:               []string{tagOrganizations},
				RequiresAuth:       true,
				RequiredAction:     string(policy.ActionOrganizationCreate),
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The organization was created.",
			},
			// A nil resolver authorizes action organization.create against the
			// principal's own organization scope. organization.create is a
			// CapSelf action — permitted for any authenticated, enabled
			// principal — and the created organization does not exist yet, so
			// there is no deeper resource target to resolve.
			handler: createOrganizationHandler(creator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/organizations/{org_id}",
				OperationID:    "updateOrganization",
				Summary:        "Update an organization",
				Description:    "Updates the organization named by the {org_id} path parameter in the source-of-truth database. The request body is a partial update: it may carry a new canonical slug, a new human-authored display name, or both — every supplied field is validated before any database work, and a patch that names no field is rejected with a stable 400. Action organization.update is authorized against the organization the path names before the handler runs: a principal updating an organization outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's data. The updated organization row and an immutable audit record naming the authenticated principal are committed in one transaction: an update can never be persisted without its audit trail. The response carries no credential material.",
				Tags:           []string{tagOrganizations},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionOrganizationUpdate),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization to update.",
				}},
				SuccessDescription: "The updated organization.",
			},
			// organizationIDResolver authorizes action organization.update
			// against the organization the {org_id} path parameter names, not
			// merely the principal's home organization, so a cross-tenant id is
			// denied at the policy boundary before the handler mutates any data.
			resolver: organizationIDResolver,
			handler:  updateOrganizationHandler(updater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/organizations/{org_id}",
				OperationID:    "deleteOrganization",
				Summary:        "Schedule an organization for deletion",
				Description:    "Schedules the organization named by the {org_id} path parameter for deletion in the source-of-truth database. The deletion is scheduled, not immediate: the organization's deletion_scheduled_at stamp is set and the destructive teardown — the cascade that removes its projects, environments, services, and audit log — is carried out by a later worker story, so the organization and its audit trail still exist when this returns. Action organization.delete is authorized against the organization the path names before the handler runs: a principal deleting an organization outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never affect another tenant's data. Scheduling deletion for an organization already scheduled for deletion is a stable 409. The soft-delete write and an immutable audit record naming the authenticated principal are committed in one transaction. The response carries no credential material.",
				Tags:           []string{tagOrganizations},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionOrganizationDelete),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization to schedule for deletion.",
				}},
				SuccessStatus:      http.StatusAccepted,
				SuccessDescription: "The organization was scheduled for deletion.",
			},
			// organizationIDResolver authorizes action organization.delete
			// against the organization the {org_id} path parameter names, not
			// merely the principal's home organization, so a cross-tenant id is
			// denied at the policy boundary before the handler mutates any data.
			resolver: organizationIDResolver,
			handler:  deleteOrganizationHandler(deleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/members",
				OperationID:    "listOrganizationMembers",
				Summary:        "List members of an organization",
				Description:    "Lists the memberships of the organization named by the {org_id} path parameter, joined with each member's global user identity — user id, email, display name, role, role version, and lifecycle timestamps. Action members.read is authorized against the organization the path names before the handler runs: a principal listing members outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's members. The response carries no credential material — a membership row stores a role, never a secret — and the list is ordered deterministically by creation time then user id so a given set of rows always renders the same response.",
				Tags:           []string{tagMembers},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMembersRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose members are listed.",
				}},
				SuccessDescription: "The memberships of the organization.",
			},
			// organizationIDResolver authorizes action members.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies.
			resolver: organizationIDResolver,
			handler:  listMembersHandler(members),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/organizations/{org_id}/members",
				OperationID:    "addOrganizationMember",
				Summary:        "Add a member to an organization",
				Description:    "Adds an existing global user to the organization named by the {org_id} path parameter, with the requested organization-wide role, in the source-of-truth database. The request body supplies the user identifier and the role; both are validated before any database work, so an invalid request never opens a transaction. Action members.manage is authorized against the organization the path names before the handler runs: a principal adding a member outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's membership graph. The memberships row and an immutable audit record naming the authenticated principal are committed in one transaction: a created membership can never exist without its audit trail. The role must be one of owner, admin, or member; a user that does not exist is a stable 404, and a user that is already a member of the organization is a stable 409. The response carries no credential material.",
				Tags:           []string{tagMembers},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMembersManage),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization to add the member to.",
				}},
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The membership was created.",
			},
			// organizationIDResolver authorizes action members.manage against
			// the organization the {org_id} path parameter names, not merely
			// the principal's home organization, so a cross-tenant id is
			// denied at the policy boundary before the handler mutates any
			// data. members.manage is a CapManage action and has no
			// cross-tenant support exception — unlike CapRead actions, the
			// support principal cannot manage members of another tenant.
			resolver: organizationIDResolver,
			handler:  addMemberHandler(memberCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/members/{member_id}",
				OperationID:    "getOrganizationMember",
				Summary:        "Get a member of an organization",
				Description:    "Returns the single membership of the organization named by the {org_id} path parameter for the user named by the {member_id} path parameter, joined with that user's global identity — user id, email, display name, role, role version, and lifecycle timestamps. Action members.read is authorized against the organization the path names before the handler runs: a principal reading a member outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's membership. A user id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant has that member. The response carries no credential material — a membership row stores a role, never a secret.",
				Tags:           []string{tagMembers},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMembersRead),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the member belongs to."},
					{Name: "member_id", Description: "The id of the user whose membership is read."},
				},
				SuccessDescription: "The membership of the organization.",
			},
			// organizationIDResolver authorizes action members.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for CapRead actions.
			resolver: organizationIDResolver,
			handler:  getMemberHandler(members),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/organizations/{org_id}/members/{member_id}",
				OperationID:    "updateOrganizationMember",
				Summary:        "Update a member of an organization",
				Description:    "Updates the role of the member named by ({org_id}, {member_id}) in the source-of-truth database. The request body supplies the new role; it is validated before any database work, so an invalid request never opens a transaction. Action members.manage is authorized against the organization the path names before the handler runs: a principal updating a member outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's membership graph. A user id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant has that member. The role update atomically bumps the member's role_version, which invalidates every outstanding session token issued to the member — making a single role change a complete session sweep without a denylist. The updated membership row and an immutable audit record naming the authenticated principal are committed in one transaction: an update can never be persisted without its audit trail. The role must be one of owner, admin, or member. The response carries no credential material.",
				Tags:           []string{tagMembers},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMembersManage),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the member belongs to."},
					{Name: "member_id", Description: "The id of the user whose membership is updated."},
				},
				SuccessDescription: "The updated membership.",
			},
			// memberIDResolver authorizes action members.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// members.manage is a CapManage action and has no cross-tenant
			// support exception — unlike CapRead actions, the support
			// principal cannot manage members of another tenant.
			resolver: memberIDResolver,
			handler:  updateMemberHandler(memberUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/organizations/{org_id}/members/{member_id}",
				OperationID:    "removeOrganizationMember",
				Summary:        "Remove a member from an organization",
				Description:    "Removes the member named by ({org_id}, {member_id}) from the source-of-truth database. The deletion is immediate, not scheduled: the memberships row is dropped and an immutable audit record naming the authenticated principal — and capturing the role the member held at removal time — is committed in the same transaction, so the audit trail of who removed whom survives the row. Action members.manage is authorized against the organization the path names before the handler runs: a principal removing a member outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's membership graph. A user id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant has that member. The response carries the membership exactly as it stood at the moment of removal, in the same wire shape every other membership endpoint returns; it carries no credential material — a membership row stores a role, never a secret.",
				Tags:           []string{tagMembers},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionMembersManage),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the member belongs to."},
					{Name: "member_id", Description: "The id of the user whose membership is removed."},
				},
				SuccessDescription: "The removed membership.",
			},
			// memberIDResolver authorizes action members.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// members.manage is a CapManage action and has no cross-tenant
			// support exception — unlike CapRead actions, the support
			// principal cannot manage members of another tenant.
			resolver: memberIDResolver,
			handler:  removeMemberHandler(memberRemover),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/limits",
				OperationID:    "getOrganizationLimits",
				Summary:        "Get effective limits of an organization",
				Description:    "Returns the effective quota limits configured for the organization named by the {org_id} path parameter, in deterministic resource order. Each entry carries the resource dimension, the numeric ceiling, the enforcement mode (hard, soft, metered, or disabled), and the source scope that produced the value — \"organization\" when the limit is an organization-level override, \"plan_default\" when it is inherited from the tenant's plan. Organization overrides take precedence over plan defaults for the same resource, and the resolution is done in a single SQL statement so the wire shape can never disagree with what the quota checker evaluates at allocation time. Resources without any policy at either scope are unconstrained and omitted from the list, so the absence of a resource means \"no ceiling is configured for this dimension\" rather than \"the limit is zero\". Action limits.read is authorized against the organization the path names before the handler runs: a principal reading limits outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's limits. The response carries no credential material — quota dimensions and counts are not sensitive — and the read is tenant scoped at the persistence layer, so a cross-tenant {org_id} yields the same empty list a missing policy would, never another tenant's data.",
				Tags:           []string{tagLimits},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionLimitsRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose effective limits are read.",
				}},
				SuccessDescription: "The effective limits of the organization.",
			},
			// organizationIDResolver authorizes action limits.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for CapRead actions.
			resolver: organizationIDResolver,
			handler:  listLimitsHandler(limits),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/organizations/{org_id}/limits",
				OperationID:    "updateOrganizationLimits",
				Summary:        "Update organization-scoped quota limits",
				Description:    "Upserts the organization-scoped quota policies of the organization named by the {org_id} path parameter in the source-of-truth database. The request body carries a non-empty list of {resource, limit_value, enforcement_mode} entries; each entry creates an organization override for the named quota dimension if none exists, or overwrites the limit_value and enforcement_mode of the existing override otherwise. Plan defaults are untouched: this endpoint is the customer-facing override surface. Every entry is validated before any database work (resource must be in the closed quota_resource set, limit_value must be zero or positive, and enforcement_mode if supplied must be one of hard, soft, metered, or disabled — empty defaults to hard, matching the schema), and a patch with no entries or a duplicated resource is itself a stable 400 — a mutation that changes nothing or is internally inconsistent is a client error, not a silent success. Action limits.write is authorized against the organization the path names before the handler runs: a principal updating limits outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's limits, and unlike limits.read (a CapRead action) limits.write has NO cross-tenant support exception — only an owner or admin in the tenant can update limits, never a support principal. An {org_id} with no row is the typed 404 the repository produces. The organization-scoped policy upserts and an immutable audit record naming the authenticated principal and the affected resources are committed in one transaction, then the effective limits are re-read inside the same transaction so the response always reflects exactly the state that just persisted. The response carries no credential material — quota dimensions and counts are not sensitive — and uses the same stable wire shape GET /v1/organizations/{org_id}/limits returns.",
				Tags:           []string{tagLimits},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionLimitsWrite),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose limits are updated.",
				}},
				SuccessDescription: "The effective limits of the organization after the upsert.",
			},
			// organizationIDResolver authorizes action limits.write against
			// the organization the {org_id} path parameter names, not merely
			// the principal's home organization, so a cross-tenant id is
			// denied at the policy boundary before the handler mutates any
			// data. limits.write is a CapAdmin action and has no cross-tenant
			// support exception — unlike CapRead actions, the support
			// principal cannot update limits in another tenant.
			resolver: organizationIDResolver,
			handler:  updateLimitsHandler(limitsUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/usage",
				OperationID:    "getOrganizationUsage",
				Summary:        "Get current resource usage of an organization",
				Description:    "Returns the current resource usage of the organization named by the {org_id} path parameter, paired with the effective quota limit configured for each resource (when any limit is configured at all), in deterministic resource order. Each entry carries the resource dimension, the live used_value counter, and a nullable limit object — when limit is non-null it carries the numeric ceiling, the enforcement mode (hard, soft, metered, or disabled), and the source scope that produced the value (\"organization\" for an organization-level override, \"plan_default\" for the tenant's plan default); when limit is null the dimension is unconstrained at this tenant's scope. Resources without any usage counter and without any configured policy are omitted, so the absence of a resource means \"no usage and no limit\" rather than \"used_value is zero\". used_value is the same counter the quota checker reads at allocation time (zero until the first reservation materializes the counter row), and the join with the effective limit is computed in a single SQL statement so the wire shape can never disagree with what the quota checker would observe. Action limits.read is authorized against the organization the path names before the handler runs: a principal reading usage outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's usage. The response carries no credential material — quota dimensions, counts, and ceilings are not sensitive — and the read is tenant scoped at the persistence layer, so a cross-tenant {org_id} yields the same empty list a tenant with no usage and no policies would, never another tenant's data.",
				Tags:           []string{tagUsage},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionLimitsRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose current resource usage is read.",
				}},
				SuccessDescription: "The current resource usage of the organization.",
			},
			// organizationIDResolver authorizes action limits.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for CapRead actions.
			resolver: organizationIDResolver,
			handler:  listUsageHandler(usage),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/audit-events",
				OperationID:    "listOrganizationAuditEvents",
				Summary:        "List audit events of an organization",
				Description:    "Returns the most recent audit events recorded for the organization named by the {org_id} path parameter, newest first, capped at the effective page size. Every event is one immutable authorization decision the control plane recorded — both allowed and denied — and carries the action that was attempted, the verdict (allowed or denied), the stable policy reason for that verdict, the actor that triggered it (a user, an API key, an internal service account, or null for an unauthenticated denied request), the resource the action named (or null for an organization-root or self action), the request id and correlation id the request travelled under, the ip address and user agent the request arrived with, and a free-form metadata map of diff/context detail. Every value reaches this endpoint already redacted at the persistence boundary — secret-shaped metadata keys (token, secret, password, credential, ...) are replaced wholesale with the redaction sentinel, every other metadata value, ip address, and user agent is scrubbed through the structural redactor, all before AuditRepository.Append persists the row — so a secret can structurally never reach the wire. Action audit.read is authorized against the organization the path names before the handler runs: a principal reading audit events outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's decisions. audit.read is a CapAdmin action: a viewer, developer, or ci principal cannot list the organization's audit log; only an owner or admin in the tenant (and a support principal performing a cross-tenant read) can. The read is tenant scoped at the persistence layer, so a cross-tenant {org_id} yields the same empty list a tenant with no audit history would, never another tenant's events. The endpoint accepts an optional ?limit= query parameter in the range [1, 200]; an absent value defaults to 50, and a malformed or out-of-range value is rejected as a stable 400.",
				Tags:           []string{tagAuditEvents},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionAuditRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose audit events are listed.",
				}},
				SuccessDescription: "The most recent audit events of the organization, newest first.",
			},
			// organizationIDResolver authorizes action audit.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for read actions.
			resolver: organizationIDResolver,
			handler:  listAuditEventsHandler(auditEvents),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/variables",
				OperationID:    "listOrganizationVariables",
				Summary:        "List organization-scoped variables",
				Description:    "Lists the organization-scoped variables configured for the organization named by the {org_id} path parameter, in deterministic (key, id) order. Each entry carries the variable's id, key (a POSIX shell environment variable name), value, is_secret flag, optimistic-concurrency version, and lifecycle timestamps. Organization-scoped variables are the lowest-precedence layer of the Organization -> Project -> Environment -> Service variable hierarchy the Dokploy renderer composes: a value set here is the organization-wide default every service in the tenant inherits unless overridden by a higher-scope variable. Secret values are ALWAYS redacted on the wire — a customer can never read a secret value back through this endpoint by design, mirroring every credential-bearing resource in this API; non-secret values are projected verbatim so the customer can audit their own organization-wide defaults. Action env.read is authorized against the organization the path names before the handler runs: a principal listing variables outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's configuration. The read is tenant-scoped at the persistence layer, so a cross-tenant {org_id} yields the same empty list a tenant with no configured variables would, never another tenant's data.",
				Tags:           []string{tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose variables are listed.",
				}},
				SuccessDescription: "The organization-scoped variables of the organization.",
			},
			// organizationIDResolver authorizes action env.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for read actions.
			resolver: organizationIDResolver,
			handler:  listOrganizationVariablesHandler(orgVariables),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPut,
				Path:           "/v1/organizations/{org_id}/variables",
				OperationID:    "replaceOrganizationVariables",
				Summary:        "Replace organization-scoped variables",
				Description:    "Replaces the organization-scoped variables of the organization named by the {org_id} path parameter in the source-of-truth database. The request body carries the complete variable set the caller wants installed; the unit of work upserts every entry on (organization_id, key) — preserving the row's id and bumping its optimistic-concurrency version through the schema's bump_version trigger when a row already exists — and deletes every variable not named in the body, so the tenant's post-condition is exactly the submitted set. An explicit empty array clears every organization-scoped variable; omitting the variables field altogether is a stable 400 (so a misencoded request is never a silent clear). Each entry is validated before any database work: a key that is not a POSIX environment variable name ([A-Za-z_][A-Za-z0-9_]*) or that exceeds the length ceiling, a duplicated key, a value that is not valid UTF-8, a value carrying an embedded NUL byte, or a value above the per-kind size ceiling (32 KiB for plain values, larger for is_secret=true entries) each surfaces as a stable apierr.InvalidInput naming the offending field path — never echoing the submitted value, so a secret can never reach a validation reason. Action env.write is authorized against the organization the path names before the handler runs: a principal replacing variables outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's configuration, and unlike env.read (a CapRead action) env.write has NO cross-tenant support exception — only an owner, admin, developer, or CI principal in the tenant can replace variables. An {org_id} with no organizations row is the typed 404 the repository produces. The replacement set, the bulk delete of the rest, and an immutable audit record naming the authenticated principal (with metadata that records only variable and secret counts, never variable keys or values) are committed in one transaction, then the committed variables are re-read inside the same transaction so the response always reflects exactly the state that just persisted. The response carries the persisted variables in the same stable wire shape GET /v1/organizations/{org_id}/variables returns; secret values are ALWAYS redacted on the wire as the redaction sentinel — a customer can never read a secret value back through this endpoint by design, including immediately after submitting it.",
				Tags:           []string{tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvWrite),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose variables are replaced.",
				}},
				SuccessDescription: "The organization-scoped variables of the organization after the replace.",
			},
			// organizationIDResolver authorizes action env.write against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// env.write is a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, the support principal
			// cannot replace variables in another tenant.
			resolver: organizationIDResolver,
			handler:  replaceOrganizationVariablesHandler(orgVariableReplacer),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/organizations/{org_id}/variables/{key}",
				OperationID:    "patchOrganizationVariable",
				Summary:        "Patch an organization-scoped variable",
				Description:    "Patches the organization-scoped variable named by the {key} path parameter inside the organization named by the {org_id} path parameter. The request body is a partial update over the mutable fields — value and is_secret — and omitting a field leaves the corresponding column unchanged; a PATCH that names neither field is itself a stable 400, so a mutation that changes nothing is never a silent success. Each supplied field is validated before any database work: a value that is not valid UTF-8 or that carries an embedded NUL byte each surfaces as a stable apierr.InvalidInput naming the offending field path — never echoing the submitted value, so a secret can never reach a validation reason. The per-kind size ceiling (32 KiB for plain values, 64 KiB for is_secret=true entries) is enforced against the final post-patch state inside the transaction so a demotion to is_secret=false cannot smuggle a value above the non-secret ceiling. Action env.write is authorized against the organization the path names before the handler runs: a principal patching a variable outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's configuration, and unlike env.read (a CapRead action) env.write has NO cross-tenant support exception — only an owner, admin, developer, or CI principal in the tenant can patch a variable. An {org_id} with no organizations row, or a {key} that does not exist in this tenant (the persistence read filters by organization_id first, so a cross-tenant key is indistinguishable from a missing row), is the typed 404 the repository produces. The single-row update and an immutable audit record naming the authenticated principal (with metadata that records only the variable's stable id and the closed-set names of the fields the patch changed — never the customer-supplied key or value) are committed in one transaction, then the committed row is returned so the response always reflects exactly the state that just persisted. The response carries the persisted variable in the same stable wire shape GET /v1/organizations/{org_id}/variables returns; secret values are ALWAYS redacted on the wire as the redaction sentinel — a customer can never read a secret value back through this endpoint by design, including immediately after submitting it.",
				Tags:           []string{tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvWrite),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization whose variable is patched."},
					{Name: "key", Description: "The POSIX environment variable name of the organization-scoped variable to patch."},
				},
				SuccessDescription: "The organization-scoped variable after the patch.",
			},
			// organizationIDResolver authorizes action env.write against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// env.write is a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, the support principal
			// cannot patch a variable in another tenant. The {key} path
			// parameter does not change the policy scope: variables live
			// inside the organization and are addressed by name; the policy
			// boundary is the organization the path names.
			resolver: organizationIDResolver,
			handler:  patchOrganizationVariableHandler(orgVariablePatcher),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/organizations/{org_id}/variables/{key}",
				OperationID:    "deleteOrganizationVariable",
				Summary:        "Delete an organization-scoped variable",
				Description:    "Removes the organization-scoped variable named by the {key} path parameter from the organization named by the {org_id} path parameter. Action env.write is authorized against the organization the path names before the handler runs: a principal deleting a variable outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's configuration, and unlike env.read (a CapRead action) env.write has NO cross-tenant support exception — only an owner, admin, developer, or CI principal in the tenant can delete a variable. An {org_id} with no organizations row, or a {key} that does not exist in this tenant (the persistence delete filters by organization_id first, so a cross-tenant key is indistinguishable from a missing row), is the typed 404 the repository produces. The single-row delete and an immutable audit record naming the authenticated principal (with metadata that records only the variable's stable id — never the customer-supplied key or value) are committed in one transaction, so a deletion can never be persisted without its audit trail. The response carries the variable exactly as it stood at the moment of removal, in the same stable wire shape every other variable endpoint returns; secret values are still redacted to the sentinel on the wire, so a DELETE cannot leak a secret value the customer had previously stored. The row is gone from the database by the time the response reaches the wire; an audit trail of the deletion lives independently of the row.",
				Tags:           []string{tagVariables},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionEnvWrite),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization whose variable is deleted."},
					{Name: "key", Description: "The POSIX environment variable name of the organization-scoped variable to delete."},
				},
				SuccessDescription: "The organization-scoped variable as it stood at the moment of removal.",
			},
			// organizationIDResolver authorizes action env.write against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// env.write is a CapWrite action and has no cross-tenant support
			// exception — unlike CapRead actions, the support principal
			// cannot delete a variable in another tenant. The {key} path
			// parameter does not change the policy scope: variables live
			// inside the organization and are addressed by name; the policy
			// boundary is the organization the path names.
			resolver: organizationIDResolver,
			handler:  deleteOrganizationVariableHandler(orgVariableDeleter),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/api-keys",
				OperationID:    "listOrganizationAPIKeys",
				Summary:        "List API keys of an organization",
				Description:    "Lists the API keys owned by the organization named by the {org_id} path parameter, in deterministic creation order — each entry carries the key's id, public prefix, name, scopes, ownership identifiers (the user who minted it and the optional owning service account), and lifecycle timestamps. Action keys.read is authorized against the organization the path names before the handler runs: a principal listing API keys outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's keys. The response carries no credential material — the secret hash is never projected onto the wire and the plaintext token (the only usable credential) is shown to its owner once at creation and never reaches this endpoint. keys.read is a CapAdmin action: a viewer or developer cannot list the organization's keys; only an owner or admin in the tenant (and a support principal performing a cross-tenant read) can.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysRead),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization whose API keys are listed.",
				}},
				SuccessDescription: "The API keys owned by the organization.",
			},
			// organizationIDResolver authorizes action keys.read against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler reads any data — the lone
			// exception is the support principal's deliberate cross-tenant
			// read, exactly as the policy matrix specifies for CapRead actions.
			resolver: organizationIDResolver,
			handler:  listAPIKeysHandler(apiKeys),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodGet,
				Path:           "/v1/organizations/{org_id}/api-keys/{key_id}",
				OperationID:    "getOrganizationAPIKey",
				Summary:        "Get an API key of an organization",
				Description:    "Returns the single API key named by ({org_id}, {key_id}) from the source-of-truth database — its id, public prefix, name, scopes, ownership identifiers (the user who minted it and the optional owning service account), and lifecycle timestamps. Action keys.read is authorized against the organization the path names before the handler runs: a principal reading a key outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never reveal another tenant's keys. A key id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant owns that key. The response carries no credential material — the secret hash is never projected onto the wire and the plaintext token (the only usable credential) is shown to its owner once at creation and never reaches this endpoint. keys.read is a CapAdmin action: a viewer or developer cannot read the organization's keys; only an owner or admin in the tenant can — and unlike CapRead actions there is no cross-tenant support exception.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysRead),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the API key belongs to."},
					{Name: "key_id", Description: "The id of the API key to read."},
				},
				SuccessDescription: "The API key identified by ({org_id}, {key_id}).",
			},
			// organizationIDResolver authorizes action keys.read against the
			// organization the {org_id} path parameter names, so a cross-tenant
			// id is denied at the policy boundary before the handler reads any
			// data. keys.read is a CapAdmin action, so the support cross-tenant
			// exception (a CapRead-only allow) does not apply — privileged
			// Yalla support that needs key visibility goes through the explicit
			// break-glass admin tooling, not this customer-facing endpoint.
			resolver: organizationIDResolver,
			handler:  getAPIKeyHandler(apiKeys),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/organizations/{org_id}/api-keys",
				OperationID:    "createOrganizationAPIKey",
				Summary:        "Create an API key for an organization",
				Description:    "Mints a fresh API key for the organization named by the {org_id} path parameter and persists it through the store-layer unit of work. The request body supplies the human-authored name, the machine-readable scopes (may be empty), an optional RFC 3339 expires_at, and an optional service_account_id that transfers ownership of the key from the authenticated user to a non-human principal; every field is validated before any database work, so an invalid request never opens a transaction. Action keys.manage is authorized against the organization the path names before the handler runs: a principal minting a key outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never plant a credential in another tenant. The credential primitive is generated server-side (a client cannot supply its own prefix or hash), the api_keys row and an immutable audit record naming the authenticated principal are committed in one transaction, and a service_account_id that does not exist in the target tenant rolls the whole transaction back as a stable 404. The response carries the persisted key projection and — exactly once — the plaintext token; the secret never reaches a log line, an audit record, or any subsequent read endpoint, so a key not captured at creation time is unrecoverable by design. keys.manage is a CapManage action: a viewer or developer cannot mint keys, only an owner or admin in the tenant can; unlike CapRead actions there is no cross-tenant support exception.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysManage),
				PathParams: []openapi.PathParam{{
					Name:        "org_id",
					Description: "The id of the organization the API key is minted in.",
				}},
				SuccessStatus:      http.StatusCreated,
				SuccessDescription: "The API key was minted; the plaintext token is shown exactly once.",
			},
			// organizationIDResolver authorizes action keys.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied at
			// the policy boundary before the handler mints any credential.
			// keys.manage is a CapManage action and has no cross-tenant support
			// exception — unlike CapRead actions, the support principal cannot
			// mint keys in another tenant.
			resolver: organizationIDResolver,
			handler:  createAPIKeyHandler(apiKeyCreator),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPatch,
				Path:           "/v1/organizations/{org_id}/api-keys/{key_id}",
				OperationID:    "updateOrganizationAPIKey",
				Summary:        "Update an API key of an organization",
				Description:    "Updates the mutable fields of the API key named by ({org_id}, {key_id}) in the source-of-truth database. The request body supplies the new name and/or scopes; each value is validated before any database work, so an invalid request never opens a transaction, and a patch that names no mutable field is itself a stable 400 — a mutation that changes nothing is a client error, not a silent success. Action keys.manage is authorized against the organization the path names before the handler runs: a principal updating a key outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never mutate another tenant's keys. A key id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant owns that key. The updated row and an immutable audit record naming the authenticated principal are committed in one transaction: an update can never be persisted without its audit trail. The response carries no credential material — the secret hash is never projected onto the wire and the plaintext token (the only usable credential) is shown to its owner once at creation and never reaches this endpoint, so an update endpoint can never reveal or rotate a credential. keys.manage is a CapManage action: a viewer or developer cannot update keys, only an owner or admin in the tenant can; unlike CapRead actions there is no cross-tenant support exception.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysManage),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the API key belongs to."},
					{Name: "key_id", Description: "The id of the API key to update."},
				},
				SuccessDescription: "The updated API key.",
			},
			// apiKeyIDResolver authorizes action keys.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// keys.manage is a CapManage action and has no cross-tenant
			// support exception — unlike CapRead actions, the support
			// principal cannot update keys in another tenant.
			resolver: apiKeyIDResolver,
			handler:  updateAPIKeyHandler(apiKeyUpdater),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodDelete,
				Path:           "/v1/organizations/{org_id}/api-keys/{key_id}",
				OperationID:    "revokeOrganizationAPIKey",
				Summary:        "Revoke an API key of an organization",
				Description:    "Revokes the API key named by ({org_id}, {key_id}) in the source-of-truth database. Revocation is the customer-facing soft delete for an API key: the api_keys row stays in the database so the audit trail of who minted it remains linked to a live row, but the credential is permanently unusable from that moment on — every subsequent authentication attempt fails through the same uniform invalid-credentials path. There is no un-revoke; a retired key can only be replaced by a fresh mint. Action keys.manage is authorized against the organization the path names before the handler runs: a principal revoking a key outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never retire another tenant's credential. A key id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant owns that key. Revoking a key that is already revoked is a stable 409 — the caller's view of the resource lifecycle is stale, not a silent success that would write a misleading audit record. The revocation stamp and an immutable audit record naming the authenticated principal are committed in one transaction: a revocation can never be persisted without its audit trail. The response carries the api key exactly as it stood at the moment of revocation, in the same wire shape every other api-key endpoint returns; it carries no credential material — the secret hash is never projected onto the wire and the plaintext token is shown to its owner once at creation and never reaches this endpoint, so a revocation endpoint can never reveal a credential. keys.manage is a CapManage action: a viewer or developer cannot revoke keys, only an owner or admin in the tenant can; unlike CapRead actions there is no cross-tenant support exception.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysManage),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the API key belongs to."},
					{Name: "key_id", Description: "The id of the API key to revoke."},
				},
				SuccessDescription: "The API key was revoked.",
			},
			// apiKeyIDResolver authorizes action keys.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mutates any data.
			// keys.manage is a CapManage action and has no cross-tenant
			// support exception — unlike CapRead actions, the support
			// principal cannot revoke keys in another tenant.
			resolver: apiKeyIDResolver,
			handler:  revokeAPIKeyHandler(apiKeyRevoker),
		},
		{
			endpoint: openapi.Endpoint{
				Method:         http.MethodPost,
				Path:           "/v1/organizations/{org_id}/api-keys/{key_id}/rotate",
				OperationID:    "rotateOrganizationAPIKey",
				Summary:        "Rotate an API key of an organization",
				Description:    "Rotates the credential body of the API key named by ({org_id}, {key_id}) in the source-of-truth database. Rotation swaps the credential primitives (the public prefix and the one-way secret hash) in place: the api_keys row keeps its id, name, scopes, ownership identifiers (created_by, service_account_id), and lifecycle stamps (expires_at) — only the credential body changes. The OLD credential body becomes permanently unusable from the moment the row is committed: the prefix-lookup authentication path only ever sees the row's current prefix, so every subsequent authentication attempt with the old token misses through the same uniform invalid-credentials path that a non-existent key produces. The new credential primitive is generated server-side (a client cannot supply its own prefix or hash). Action keys.manage is authorized against the organization the path names before the handler runs: a principal rotating a key outside its own tenant is rejected with a deterministic 403, so a cross-tenant id can never rotate another tenant's credential. A key id paired with the wrong organization is the same deterministic 404 as a missing row, so the endpoint can never reveal whether another tenant owns that key. Rotating a key that is revoked or expired is a stable 409 — the caller's view of the resource lifecycle is stale, and a fresh credential body cannot revive a row that is permanently out of authentication service; the customer must mint a new key through POST /v1/organizations/{org_id}/api-keys instead. The rotated row and an immutable audit record naming the authenticated principal are committed in one transaction: a rotation can never be persisted without its audit trail. The response carries the rotated api-key projection and — exactly once — the plaintext token of the new credential body; the secret never reaches a log line, an audit record, or any subsequent read endpoint, so a rotated credential not captured at rotation time is unrecoverable by design. keys.manage is a CapManage action: a viewer or developer cannot rotate keys, only an owner or admin in the tenant can; unlike CapRead actions there is no cross-tenant support exception.",
				Tags:           []string{tagAPIKeys},
				RequiresAuth:   true,
				RequiredAction: string(policy.ActionKeysManage),
				PathParams: []openapi.PathParam{
					{Name: "org_id", Description: "The id of the organization the API key belongs to."},
					{Name: "key_id", Description: "The id of the API key to rotate."},
				},
				SuccessDescription: "The API key was rotated; the plaintext token of the new credential body is shown exactly once.",
			},
			// apiKeyIDResolver authorizes action keys.manage against the
			// organization the {org_id} path parameter names, not merely the
			// principal's home organization, so a cross-tenant id is denied
			// at the policy boundary before the handler mints any
			// credential. keys.manage is a CapManage action and has no
			// cross-tenant support exception — unlike CapRead actions, the
			// support principal cannot rotate keys in another tenant.
			resolver: apiKeyIDResolver,
			handler:  rotateAPIKeyHandler(apiKeyRotator),
		},
	}
}

// readyzHandler builds the GET /readyz handler. When every startup gate is
// passing it renders a 200 yalla.output.v1 envelope listing each check; while
// any gate is still failing it renders a 503 yalla.error.v1 envelope whose
// hint names the pending checks. The 503 is an explicit override of the error
// code's default status because "not ready yet" is a liveness signal, not an
// upstream fault. A nil reporter is treated as always-ready, which suits
// tests and processes with no startup dependencies.
func readyzHandler(readiness runtime.ReadinessReporter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		checks := map[string]bool{}
		ready := true
		if readiness != nil {
			checks = readiness.Snapshot()
			ready = readiness.Ready()
		}
		if ready {
			apienvelope.WriteData(w, http.StatusOK, requestID(r), readyzPayload{
				Status: "ready",
				Checks: checks,
			})
			return
		}
		// Not ready yet: report 503 with a stable error envelope so probes and
		// agents see a deterministic code while startup completes. The hint
		// names the pending checks — fixed, non-secret gate identifiers — so
		// operators can see which dependency is blocking readiness.
		hint := "startup dependency checks have not passed yet"
		if pending := pendingChecks(checks); len(pending) > 0 {
			hint = "pending dependency checks: " + strings.Join(pending, ", ")
		}
		apienvelope.WriteErrorStatus(w, http.StatusServiceUnavailable, requestID(r),
			yerr.New(yerr.CodeServer, "service is not ready").WithHint(hint))
	}
}

// pendingChecks returns the sorted names of every check that is not passing.
// Check names are fixed, non-secret identifiers, so they are safe to surface
// in an error hint.
func pendingChecks(checks map[string]bool) []string {
	pending := make([]string, 0, len(checks))
	for name, passing := range checks {
		if !passing {
			pending = append(pending, name)
		}
	}
	sort.Strings(pending)
	return pending
}

// openAPIEndpoint is the OpenAPI metadata for GET /openapi.json. It is kept
// out of newRouteTable because its handler is constructed from the very
// document these endpoints describe; openAPIDocument folds it back in so the
// published document still lists the discovery endpoint itself.
func openAPIEndpoint() openapi.Endpoint {
	return openapi.Endpoint{
		Method:             http.MethodGet,
		Path:               "/openapi.json",
		OperationID:        "getOpenAPIDocument",
		Summary:            "OpenAPI document",
		Description:        "Returns the OpenAPI 3.1 document describing this API. Served without authentication so tools and agents can discover the contract. The body is the raw OpenAPI document, not a yalla.output.v1 envelope, because OpenAPI tooling expects the standard format.",
		Tags:               []string{tagMeta},
		SuccessDescription: "The OpenAPI 3.1 document for this API.",
		SuccessSchema:      openapi.SchemaOpenAPIDocument,
	}
}

// endpointsOf projects the OpenAPI metadata out of a route table.
func endpointsOf(table []apiRoute) []openapi.Endpoint {
	eps := make([]openapi.Endpoint, 0, len(table)+1)
	for _, rt := range table {
		eps = append(eps, rt.endpoint)
	}
	return eps
}

// openAPIDocument assembles the published OpenAPI document from the route
// table. It appends openAPIEndpoint so the document lists the discovery
// endpoint itself, keeping "served routes" and "documented routes" identical.
func openAPIDocument(build runtime.BuildInfo, table []apiRoute) openapi.Document {
	build = build.Normalized()
	eps := append(endpointsOf(table), openAPIEndpoint())
	return openapi.Build(openapi.Info{
		Title:       "Yalla Control Plane API",
		Version:     build.Version,
		Description: "Intent-based API for managing Dokploy-backed infrastructure. Customers, agents, and CI call this control plane; they never call Dokploy directly.",
	}, eps)
}
