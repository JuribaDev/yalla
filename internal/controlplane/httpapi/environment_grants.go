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

// errNoEnvironmentGrantReader is returned when GET
// /v1/environments/{environment_id}/grants is reached without a grant reader
// wired into NewHandler. Like errNoProjectGrantReader it can only happen
// through a wiring error — a programming mistake, not a client error — so
// the handler reports it as a typed internal failure rather than serving an
// empty or misleading list.
var errNoEnvironmentGrantReader = errors.New("httpapi: no environment grant reader configured")

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
