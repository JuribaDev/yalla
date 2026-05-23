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
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// errNoEnvironmentReader is returned when GET
// /v1/environments/{environment_id} is reached without an environment
// reader wired into NewHandler. Like errNoProjectEnvironmentReader it
// can only happen through a wiring error — a programming mistake, not a
// client error — so the handler reports it as a typed internal failure
// rather than serving a misleading not-found.
var errNoEnvironmentReader = errors.New("httpapi: no environment reader configured")

// errNoEnvironmentUpdater is returned when PATCH
// /v1/environments/{environment_id} is reached without an environment
// updater wired into NewHandler. Like errNoEnvironmentReader it can
// only happen through a wiring error — a programming mistake, not a
// client error — so the handler reports it as a typed internal failure
// rather than silently failing to persist the mutation.
var errNoEnvironmentUpdater = errors.New("httpapi: no environment updater configured")

// errNoEnvironmentDeleter is returned when DELETE
// /v1/environments/{environment_id} is reached without an environment
// deleter wired into NewHandler. Like errNoEnvironmentUpdater it can
// only happen through a wiring error — a programming mistake, not a
// client error — so the handler reports it as a typed internal failure
// rather than silently failing to persist the soft-delete.
var errNoEnvironmentDeleter = errors.New("httpapi: no environment deleter configured")

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

// EnvironmentUpdater is the narrow persistence port PATCH
// /v1/environments/{environment_id} depends on.
// *store.EnvironmentService satisfies it in production; tests supply a
// fake. Like EnvironmentCreator it is an interface declared here so
// the handler stays unit-testable without a real database — the
// concrete orchestrator (the desired-state write and the immutable
// audit record committed in one transaction) lives in the store layer.
type EnvironmentUpdater interface {
	Update(ctx context.Context, in store.UpdateEnvironmentInput) (store.Environment, error)
}

// updateEnvironmentRequest is the decoded PATCH
// /v1/environments/{environment_id} request body. Both fields are
// optional pointers: a nil pointer means the caller did not include
// the field and it is left unchanged, which is what makes the
// endpoint a partial update. The store layer validates every supplied
// field before any database work and rejects a patch that names no
// field at all — a mutation that changes nothing is a client error,
// not a silent success. Neither field carries credential material.
//
// The request body intentionally exposes no organization_id,
// project_id, or environment_id field: the organization is derived
// from the authenticated principal's home organization and the
// environment_id comes from the path, never from the body, so a
// caller cannot point the mutation at another tenant's environment
// even if the strict decoder were bypassed. The parent project_id is
// not mutable through this endpoint: an environment belongs to
// exactly one project for its lifetime, and reparenting is a
// deliberate operation that would belong to a separate move endpoint
// behind a different action constant.
type updateEnvironmentRequest struct {
	Slug        *string `json:"slug"`
	DisplayName *string `json:"display_name"`
}

// updateEnvironmentPayload is the data block of the PATCH
// /v1/environments/{environment_id} success envelope: the environment
// after the update, in the same stable wire shape the other
// environment endpoints return. It carries no credential material —
// the environments table itself stores no secrets; environment-scoped
// variables and other secrets live behind their own endpoints where
// the redaction policy applies.
type updateEnvironmentPayload struct {
	Environment projectEnvironment `json:"environment"`
}

// updateEnvironmentHandler builds the PATCH
// /v1/environments/{environment_id} handler. It decodes and delegates:
// the request body is strictly decoded (oversized, malformed, or
// unknown-field bodies become a typed 400 that never echoes the
// input), the If-Match header is parsed as an optional
// optimistic-concurrency precondition, and then the update-environment
// unit of work — validate, read the current row, apply the patch,
// write the row back, append the audit record, all in one transaction
// — runs in the store layer through the EnvironmentUpdater port.
//
// RequireAuth gates the route on action environment.update before the
// handler runs — authorized through environmentIDResolver against the
// (principal home organization, {environment_id}) resource the path
// names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the policy boundary.
// environment.update is a CapWrite action, so the gate admits the
// principal's organization-wide write roles (owner, admin, developer,
// ci) and denies viewer, denies support (a support principal is
// CapRead-only and cannot mutate even within its home tenant). The
// path carries no parent project_id, so the policy engine cannot pin
// the ProjectID leg of the resource scope at authorization time —
// project-, environment-, and service-scoped grants are denied at the
// boundary by the engine's covers() rule (a grant with a pinned
// ProjectID cannot cover a resource with no ProjectID); principals
// whose only access is a scoped grant must use a parent-scoped route
// to address an environment by its (project, environment) tuple.
//
// The handler never trusts a caller-supplied organization id: the
// store call is built from principal.OrganizationID and
// r.PathValue("environment_id"), so a cross-tenant environment_id
// reaches the tenant-scoped repository query with the principal's
// home organization id and is reported as a deterministic NotFound by
// the persistence layer, never another tenant's row. A request that
// arrives with no principal is a wiring error reported as a typed
// internal error; a validation failure, a slug conflict, a not-found
// {environment_id}, a stale If-Match version, and a datastore outage
// each surface as their own typed status, never disguised as one
// another. On success, the handler mirrors the row's authoritative
// version into the ETag response header so the caller can echo it
// back as the next If-Match precondition without re-reading the row.
func updateEnvironmentHandler(updater EnvironmentUpdater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if updater == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentUpdater))
			return
		}

		ifMatchVersion, ifMatchErr := parseIfMatchVersion(r)
		if ifMatchErr != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(ifMatchErr))
			return
		}

		var req updateEnvironmentRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		environment, err := updater.Update(r.Context(), store.UpdateEnvironmentInput{
			OrganizationID: p.OrganizationID,
			EnvironmentID:  r.PathValue("environment_id"),
			Slug:           req.Slug,
			DisplayName:    req.DisplayName,
			IfMatchVersion: ifMatchVersion,
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

		writeOrganizationETag(w, environment.Version)
		apienvelope.WriteData(w, http.StatusOK, requestID(r), updateEnvironmentPayload{
			Environment: projectEnvironmentOf(environment),
		})
	}
}

// EnvironmentDeleter is the narrow persistence port DELETE
// /v1/environments/{environment_id} depends on.
// *store.EnvironmentService satisfies it in production; tests supply a
// fake. Like EnvironmentUpdater it is an interface declared here so the
// handler stays unit-testable without a real database — the concrete
// orchestrator (the desired-state soft-delete stamp and the immutable
// audit record committed in one transaction) lives in the store layer.
type EnvironmentDeleter interface {
	ScheduleDeletion(ctx context.Context, in store.DeleteEnvironmentInput) (store.Environment, error)
}

// deleteEnvironmentPayload is the data block of the DELETE
// /v1/environments/{environment_id} success envelope: the environment
// with its deletion_scheduled_at stamp set, in the same stable wire
// shape the other environment endpoints return. It carries no credential
// material — the environments table itself stores no secrets;
// environment-scoped variables and other secrets live behind their own
// endpoints where the redaction policy applies.
type deleteEnvironmentPayload struct {
	Environment projectEnvironment `json:"environment"`
}

// deleteEnvironmentHandler builds the DELETE
// /v1/environments/{environment_id} handler. It schedules the
// environment for teardown by stamping deletion_scheduled_at in the
// source-of-truth database through the EnvironmentDeleter port, then
// renders the persisted row in a stable yalla.output.v1 envelope. The
// teardown is scheduled, not immediate: the destructive cascade that
// removes services and the audit log under the environment is a later
// worker story, so the environment and its audit trail still exist when
// this returns.
//
// RequireAuth gates the route on action environment.delete before the
// handler runs — authorized through environmentIDResolver against the
// (principal home organization, {environment_id}) resource the path
// names — and attaches the resolved principal, so a request that reaches
// the handler has already cleared the policy boundary.
// environment.delete is a CapWrite action, so the gate admits the
// principal's organization-wide write roles (owner, admin, developer,
// ci) and denies viewer, denies support (a support principal is
// CapRead-only and cannot mutate even within its home tenant). The path
// carries no parent project_id, so the policy engine cannot pin the
// ProjectID leg of the resource scope at authorization time — project-,
// environment-, and service-scoped grants are denied at the boundary by
// the engine's covers() rule (a grant with a pinned ProjectID cannot
// cover a resource with no ProjectID); principals whose only access is a
// scoped grant must use a parent-scoped route to address an environment
// by its (project, environment) tuple.
//
// The handler never trusts a caller-supplied organization id: the store
// call is built from principal.OrganizationID and
// r.PathValue("environment_id"), so a cross-tenant environment_id
// reaches the tenant-scoped repository query with the principal's home
// organization id and is reported as a deterministic NotFound by the
// persistence layer, never another tenant's row. A request that arrives
// with no principal is a wiring error reported as a typed internal
// error; an If-Match parse failure, a stale If-Match version, a
// not-found {environment_id}, an environment whose deletion is already
// scheduled, and a datastore outage each surface as their own typed
// status, never disguised as one another. On success, the handler
// mirrors the row's authoritative version into the ETag response header
// so the caller can echo it back as the next If-Match precondition
// without re-reading the row, and returns 202 Accepted — the scheduling
// is durable but the destructive teardown is a later worker job.
func deleteEnvironmentHandler(deleter EnvironmentDeleter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if deleter == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentDeleter))
			return
		}

		ifMatchVersion, ifMatchErr := parseIfMatchVersion(r)
		if ifMatchErr != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(ifMatchErr))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		environment, err := deleter.ScheduleDeletion(r.Context(), store.DeleteEnvironmentInput{
			OrganizationID: p.OrganizationID,
			EnvironmentID:  r.PathValue("environment_id"),
			IfMatchVersion: ifMatchVersion,
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

		writeOrganizationETag(w, environment.Version)
		apienvelope.WriteData(w, http.StatusAccepted, requestID(r), deleteEnvironmentPayload{
			Environment: projectEnvironmentOf(environment),
		})
	}
}

// errNoEnvironmentCloner is returned when POST
// /v1/environments/{environment_id}/clone is reached without an
// environment cloner wired into NewHandler. Like errNoEnvironmentDeleter
// it can only happen through a wiring error — a programming mistake,
// not a client error — so the handler reports it as a typed internal
// failure rather than silently failing to persist the clone.
var errNoEnvironmentCloner = errors.New("httpapi: no environment cloner configured")

// EnvironmentCloner is the narrow persistence port POST
// /v1/environments/{environment_id}/clone depends on.
// *store.EnvironmentService satisfies it in production; tests supply
// a fake. Like EnvironmentCreator it is an interface declared here so
// the handler stays unit-testable without a real database — the
// concrete orchestrator (the source read, in-tx authorize, quota
// reservation, desired-state write, provisioning-job enqueue, and
// immutable audit record committed in one transaction) lives in the
// store layer.
//
// The HTTP boundary is the authoritative authorization gate: RequireAuth
// authorizes action environment.create against the (principal home
// organization, {environment_id}) resource the path names through
// environmentIDResolver, so a request that reaches the cloner has
// already cleared the policy boundary. The store layer still
// re-authorizes inside the same *Tx as the desired-state write —
// defense-in-depth against a grant change that landed between the HTTP
// authorize and the quota reservation.
type EnvironmentCloner interface {
	Clone(ctx context.Context, in store.CloneEnvironmentInput) (store.Environment, error)
}

// cloneEnvironmentRequest is the decoded POST
// /v1/environments/{environment_id}/clone request body.
// EnvironmentID is the caller-supplied canonical id for the NEW
// environment — the agent contract mints ids client-side so an
// idempotent retry is structural rather than header-encoded; Slug is
// the canonical [a-z0-9-] identifier the new environment is addressed
// by within its (inherited) project; DisplayName is its human-authored
// label. The request body intentionally exposes no organization_id,
// project_id, or source_environment_id field: the organization is
// derived from the authenticated principal's home organization, the
// source environment_id comes from the {environment_id} PATH parameter,
// and the new environment inherits the source's project_id, never from
// the body or path. The store layer validates every field before any
// database work, so an invalid request never opens a transaction —
// and the request body never carries credential material.
type cloneEnvironmentRequest struct {
	EnvironmentID string `json:"environment_id"`
	Slug          string `json:"slug"`
	DisplayName   string `json:"display_name"`
}

// cloneEnvironmentPayload is the data block of the POST
// /v1/environments/{environment_id}/clone success envelope: the
// newly-cloned environment, in the same stable wire shape every other
// environment endpoint returns. It carries no credential material —
// the environments table itself stores no secrets; environment-scoped
// variables and other secrets live behind their own endpoints where
// the redaction policy applies. (The variable surface for cloned
// environments is provisioned by a later worker story; the clone
// operation here writes only the structural row.)
type cloneEnvironmentPayload struct {
	Environment projectEnvironment `json:"environment"`
}

// cloneEnvironmentHandler builds the POST
// /v1/environments/{environment_id}/clone handler. It decodes and
// delegates: the request body is strictly decoded (oversized,
// malformed, or unknown-field bodies become a typed 400 that never
// echoes the input), then the clone-environment unit of work — read
// the source row, re-authorize, reserve quota, write the new
// environment row inheriting the source's project_id, enqueue the
// provisioning job, append the audit record, all in one transaction —
// runs in the store layer through the EnvironmentCloner port.
//
// RequireAuth gates the route on action environment.create before the
// handler runs — authorized through environmentIDResolver against the
// (principal home organization, {environment_id}) resource the path
// names — and attaches the resolved principal, so a request that
// reaches the handler with no principal is a wiring error reported as
// a typed internal error. environment.create is a CapWrite action, so
// the gate admits the principal's organization-wide write roles (owner,
// admin, developer, ci) and denies viewer, denies support (CapRead-only
// — a support principal cannot mutate even within its home tenant).
// The path carries no parent project_id, so the policy engine cannot
// pin the ProjectID leg of the resource scope at authorization time —
// project-, environment-, and service-scoped grants are denied at the
// boundary by the engine's covers() rule (a grant with a pinned
// ProjectID cannot cover a resource with no ProjectID); principals
// whose only access is a scoped grant must use a parent-scoped route
// to address an environment by its (project, environment) tuple.
//
// The handler never trusts a caller-supplied organization id: the
// store call is built from principal.OrganizationID and
// r.PathValue("environment_id"), so a cross-tenant source environment_id
// reaches the tenant-scoped repository query with the principal's home
// organization id and is reported as a deterministic NotFound by the
// persistence layer, never another tenant's row. A source environment
// already scheduled for teardown is rejected as a typed Conflict — a
// lifecycle-dead row is not a valid clone source. A validation
// failure, a slug conflict in the target project, an exhausted quota,
// a denied in-tx authorize, and a datastore outage each surface as
// their own typed status, never disguised as one another. On success,
// the handler returns 201 Created with the new environment's row in
// the standard wire shape and mirrors the row's authoritative version
// into the ETag response header.
func cloneEnvironmentHandler(cloner EnvironmentCloner) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if cloner == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentCloner))
			return
		}

		var req cloneEnvironmentRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		environment, err := cloner.Clone(r.Context(), store.CloneEnvironmentInput{
			OrganizationID:      p.OrganizationID,
			SourceEnvironmentID: r.PathValue("environment_id"),
			NewEnvironmentID:    req.EnvironmentID,
			NewSlug:             req.Slug,
			NewDisplayName:      req.DisplayName,
			ActorID:             p.ID,
			ActorKind:           string(p.Kind),
			ActorOrgID:          p.OrganizationID,
			RequestID:           correlation.RequestID,
			CorrelationID:       correlation.CorrelationID,
		})
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		writeOrganizationETag(w, environment.Version)
		apienvelope.WriteData(w, http.StatusCreated, requestID(r), cloneEnvironmentPayload{
			Environment: projectEnvironmentOf(environment),
		})
	}
}
