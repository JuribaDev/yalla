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

// errNoEnvironmentGrantReader is returned when GET
// /v1/environments/{environment_id}/grants is reached without a grant reader
// wired into NewHandler. Like errNoProjectGrantReader it can only happen
// through a wiring error — a programming mistake, not a client error — so
// the handler reports it as a typed internal failure rather than serving an
// empty or misleading list.
var errNoEnvironmentGrantReader = errors.New("httpapi: no environment grant reader configured")

// errNoEnvironmentGrantReplacer is returned when PUT
// /v1/environments/{environment_id}/grants is reached without a grant
// replacer wired into NewHandler. Like errNoEnvironmentGrantReader it can
// only happen through a wiring error — a programming mistake, not a client
// error — so the handler reports it as a typed internal failure rather than
// silently failing to persist the change.
var errNoEnvironmentGrantReplacer = errors.New("httpapi: no environment grant replacer configured")

// errEnvironmentGrantsBodyMissing is the closed-set rejection reason for a
// PUT /v1/environments/{environment_id}/grants body that decodes successfully
// but does not name the "grants" field at all. An explicit empty array is a
// meaningful clear and reaches the store layer; a missing field is a client
// error so a misencoded request is never a silent clear.
const errEnvironmentGrantsBodyMissing = "must be supplied (provide an empty array to clear every grant)"

// EnvironmentGrantReader is the narrow persistence port GET
// /v1/environments/{environment_id}/grants depends on.
// *store.EnvironmentGrantReader satisfies it in production; tests supply a
// fake. Keeping the dependency an interface keeps the handler unit-testable
// without a real database, the same way ProjectGrantReader keeps the
// project-grants surface testable.
//
// The read is tenant scoped at the persistence layer: the adapter GetByID's
// the environment under (organization_id, environment_id) before listing its
// grants, so a cross-tenant or unknown environment_id surfaces as a typed
// apierr.NotFound — never as an empty list, which would invite an agent to
// believe the environment exists with no grants. The route uses
// environmentIDResolver which authorizes the call against the (principal
// home org, path environment_id) resource before the handler runs. The
// resolver pins the EnvironmentID leg of the policy scope but cannot pin
// the ProjectID leg — the bare top-level path carries no parent project_id.
// As a consequence the policy engine admits org-wide read roles (owner,
// admin, developer, viewer, ci) and org-wide grants but denies project-,
// environment-, and service-scoped grants by the engine's covers() rule (a
// grant with a pinned ProjectID cannot cover a resource with no ProjectID);
// the support principal's deliberate cross-tenant read exception does NOT
// apply here because the resource scope is pinned to the principal's home
// organization, not the path env's tenant.
type EnvironmentGrantReader interface {
	ListEnvironmentGrants(ctx context.Context, organizationID, environmentID string) ([]store.EnvironmentGrant, error)
}

// listEnvironmentGrantsPayload is the data block of the GET
// /v1/environments/{environment_id}/grants success envelope: every grant
// attached to the environment addressed by the {environment_id} path
// parameter, in deterministic (principal_id, service_id NULLS FIRST, id)
// order. Grants is always a non-nil slice so agents can iterate it without a
// nil check; a live environment with no configured grants yields [].
type listEnvironmentGrantsPayload struct {
	Grants []environmentGrantResource `json:"grants"`
}

// environmentGrantResource is one entry in a listEnvironmentGrantsPayload:
// the source-of-truth grant resource — its id, the id of the organization
// that owns it, the id of the environment it targets, the principal it
// confers a role on, the role it confers, optional further (service)
// scoping, optimistic-concurrency version, and lifecycle timestamps. A
// grant carries no credential material — the schema stores only structural
// identifiers and a role enum — so the payload is safe to log and audit
// verbatim, mirroring the projectGrantResource posture.
//
// The principal is projected as a nested object so an agent reads one
// boolean (principal.kind == "usr") instead of branching on coupled
// scalars. ServiceID is a nullable pointer so the wire distinguishes
// "environment-scoped grant" (null) from "service-scoped grant" (set) —
// the same precedence the renderer reads it with.
type environmentGrantResource struct {
	GrantID        string                    `json:"grant_id"`
	OrganizationID string                    `json:"organization_id"`
	EnvironmentID  string                    `json:"environment_id"`
	Principal      environmentGrantPrincipal `json:"principal"`
	Role           string                    `json:"role"`
	ServiceID      *string                   `json:"service_id"`
	Version        int64                     `json:"version"`
	CreatedAt      string                    `json:"created_at"`
	UpdatedAt      string                    `json:"updated_at"`
}

// environmentGrantPrincipal is the nested principal block of an
// environmentGrantResource: the identity the grant confers a role on. Kind
// is closed to "usr" (a user) or "sa" (a service account) — the two
// principal kinds the policy engine resolves — so an agent can branch on
// the value as a stable enum.
type environmentGrantPrincipal struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// environmentGrantResourceOf projects a store.EnvironmentGrant onto the
// stable wire shape. Timestamps are rendered as UTC RFC 3339 strings so the
// contract is independent of the database driver's time representation and
// the response is deterministic for a given row. The store struct's
// ServiceID *string pointer is copied verbatim — a nil stays nil — so the
// (environment | service)-scoped distinction reaches the wire intact.
func environmentGrantResourceOf(g store.EnvironmentGrant) environmentGrantResource {
	resource := environmentGrantResource{
		GrantID:        g.ID,
		OrganizationID: g.OrganizationID,
		EnvironmentID:  g.EnvironmentID,
		Principal: environmentGrantPrincipal{
			ID:   g.PrincipalID,
			Kind: g.PrincipalKind,
		},
		Role:      g.Role,
		Version:   g.Version,
		CreatedAt: g.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt: g.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if g.ServiceID != nil {
		svcID := *g.ServiceID
		resource.ServiceID = &svcID
	}
	return resource
}

// listEnvironmentGrantsHandler builds the GET
// /v1/environments/{environment_id}/grants handler. It reads the grants of
// the environment named by the {environment_id} path parameter from the
// source-of-truth database through the EnvironmentGrantReader port and
// renders them in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action environment.grants.read before the
// handler runs — authorized through environmentIDResolver against the
// (principal home organization, {environment_id}) resource — and attaches
// the resolved principal. environment.grants.read is a CapRead action, so
// the gate admits the principal's organization-wide read roles (owner,
// admin, developer, viewer, ci). The path carries no parent project_id, so
// the policy engine cannot pin the ProjectID leg of the resource scope at
// authorization time — project-, environment-, and service-scoped grants
// are denied at the boundary by the engine's covers() rule (a grant with a
// pinned ProjectID cannot cover a resource with no ProjectID). The support
// principal's deliberate cross-tenant read exception does NOT apply here
// because the resolver pins the resource scope to the principal's own home
// organization, not the path env's tenant.
//
// A request that arrives here with no principal is a wiring error and is
// reported as a typed internal error rather than reading for a zero
// principal. A reader-store outage surfaces as its own typed 5xx; a
// cross-tenant or unknown environment_id reaches the persistence layer with
// the principal's home organization id and is rejected as a deterministic
// 404 by the reader's environment existence check — never disguised as an
// empty success.
func listEnvironmentGrantsHandler(reader EnvironmentGrantReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentGrantReader))
			return
		}
		grants, err := reader.ListEnvironmentGrants(r.Context(), p.OrganizationID, r.PathValue("environment_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]environmentGrantResource, 0, len(grants))
		for _, g := range grants {
			out = append(out, environmentGrantResourceOf(g))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listEnvironmentGrantsPayload{Grants: out})
	}
}

// EnvironmentGrantReplacer is the narrow persistence port PUT
// /v1/environments/{environment_id}/grants depends on.
// *store.EnvironmentGrantService satisfies it in production; tests supply
// a fake. Like EnvironmentGrantReader it is an interface declared here so
// the handler stays unit-testable without a real database — the concrete
// orchestrator (the tenant-scoped environment existence check, the
// per-grant upsert, the bulk delete-by-exclusion, the audit record, and
// the post-write re-read, all in one transaction) lives in the store
// layer.
type EnvironmentGrantReplacer interface {
	Replace(ctx context.Context, in store.ReplaceEnvironmentGrantsInput) ([]store.EnvironmentGrant, error)
}

// environmentGrantRequest is one entry in a replaceEnvironmentGrantsRequest
// body: the (principal_id, principal_kind, role, optional service_id) tuple
// the caller asks to persist for the environment named by the
// {environment_id} path parameter.
//
// PrincipalKind is closed to "usr" or "sa" — the two principal kinds the
// policy engine resolves — and Role is closed to one of the six built-in
// role names. ServiceID is a pointer so the wire distinguishes
// "environment-scoped grant" (null) from "service-scoped grant" (set).
// Each field is validated in the store-layer unit of work before any
// database write — an invalid request never opens a transaction — and the
// handler does no per-field validation beyond strict-decoding the body
// (oversized, malformed, or unknown-field bodies become a typed 400 that
// never echoes the input).
type environmentGrantRequest struct {
	PrincipalID   string  `json:"principal_id"`
	PrincipalKind string  `json:"principal_kind"`
	Role          string  `json:"role"`
	ServiceID     *string `json:"service_id,omitempty"`
}

// replaceEnvironmentGrantsRequest is the decoded PUT
// /v1/environments/{environment_id}/grants request body: the complete set
// of grants the caller asks to install for the environment in one
// transaction. Grants is a pointer to a slice so the body's omission of
// the field is structurally distinguishable from an explicit empty array
// — PUT replaces the entire set, so an explicit empty array means "clear
// every grant" while a missing field is a stable 400.
type replaceEnvironmentGrantsRequest struct {
	Grants *[]environmentGrantRequest `json:"grants"`
}

// replaceEnvironmentGrantsPayload is the data block of the PUT
// /v1/environments/{environment_id}/grants success envelope: the
// environment's grants after the replace, in the same stable wire shape
// GET /v1/environments/{environment_id}/grants returns. The endpoint
// always re-reads the grants in the same transaction that committed the
// upsert + delete, so the body always reflects the state that just
// persisted.
type replaceEnvironmentGrantsPayload struct {
	Grants []environmentGrantResource `json:"grants"`
}

// replaceEnvironmentGrantsHandler builds the PUT
// /v1/environments/{environment_id}/grants handler. It decodes and
// delegates: the request body is strictly decoded (oversized, malformed,
// or unknown-field bodies become a typed 400 that never echoes the
// input), then the replace-grants unit of work — verify the environment,
// upsert each grant, delete every grant not in the replacement set,
// append the audit record, re-read the committed grants, all in one
// transaction — runs in the store layer through the
// EnvironmentGrantReplacer port.
//
// RequireAuth gates the route on action environment.grants.write before
// the handler runs — authorized through environmentIDResolver against
// the (principal home organization, {environment_id}) resource the path
// names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the tenant boundary against
// the principal's home organization combined with the path id. A
// request that arrives here with no principal is therefore a wiring
// error and is reported as a typed internal error. The principal and
// the request correlation identifiers are passed to the replacer so the
// audit record names the actor; a validation failure (missing grants
// field, blank principal_id, unknown principal_kind, unknown role,
// duplicate scope tuple), a not-found {environment_id}, and a datastore
// outage each surface as their own typed status, never disguised as one
// another.
//
// environment.grants.write is a CapAdmin action: only the owner and
// admin roles, or a principal holding a scope-covering admin grant, can
// replace an environment's grants. Viewer, developer, ci, and support
// are all denied at the policy boundary, never reaching this handler.
// The support principal's cross-tenant read exception does NOT apply
// because environment.grants.write is a write action — CapSupport never
// satisfies CapAdmin in the engine. The path carries no parent
// project_id, so project-, environment-, and service-scoped grants are
// denied at the boundary by the engine's covers() rule (a grant with a
// pinned ProjectID cannot cover a resource with no ProjectID);
// scoped-grant-only principals must address grants through a
// parent-scoped route.
func replaceEnvironmentGrantsHandler(replacer EnvironmentGrantReplacer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if replacer == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentGrantReplacer))
			return
		}

		var req replaceEnvironmentGrantsRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if req.Grants == nil {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
				Field:  "grants",
				Reason: errEnvironmentGrantsBodyMissing,
			}))
			return
		}

		items := make([]store.EnvironmentGrantReplace, 0, len(*req.Grants))
		for _, item := range *req.Grants {
			items = append(items, store.EnvironmentGrantReplace{
				PrincipalID:   item.PrincipalID,
				PrincipalKind: item.PrincipalKind,
				Role:          item.Role,
				ServiceID:     cloneOptionalString(item.ServiceID),
			})
		}

		correlation := telemetry.FromContext(r.Context())
		grants, err := replacer.Replace(r.Context(), store.ReplaceEnvironmentGrantsInput{
			OrganizationID: p.OrganizationID,
			EnvironmentID:  r.PathValue("environment_id"),
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

		payload := replaceEnvironmentGrantsPayload{
			Grants: make([]environmentGrantResource, 0, len(grants)),
		}
		for _, g := range grants {
			payload.Grants = append(payload.Grants, environmentGrantResourceOf(g))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}
