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

// errNoEnvironmentVariableReader is returned when GET
// /v1/environments/{environment_id}/variables is reached without a
// variable reader wired into NewHandler. It can only happen through a
// wiring error — a programming mistake, not a client error — so the
// handler reports it as a typed internal failure rather than serving an
// empty or misleading list.
var errNoEnvironmentVariableReader = errors.New("httpapi: no environment variable reader configured")

// EnvironmentVariableReader is the narrow persistence port GET
// /v1/environments/{environment_id}/variables depends on.
// *store.EnvironmentVariableReader satisfies it in production; tests
// supply a fake. Keeping the dependency an interface keeps the handler
// unit-testable without a real database, the same way
// ProjectVariableReader keeps the project-variables surface testable.
//
// The read is tenant scoped at the persistence layer: the adapter Gets
// the environment under (organization_id, environment_id) before
// listing its variables, so a cross-tenant or unknown environment_id
// surfaces as a typed apierr.NotFound — never as an empty list, which
// would invite an agent to believe the environment exists with no
// variables. The route uses environmentIDResolver which authorizes the
// call against the (principal home org, path environment_id) resource
// before the handler runs; the support principal's deliberate
// cross-tenant read exception does NOT apply here because the resource
// scope is pinned to the principal's home organization, not the path's
// tenant. Project- and environment-scoped grants whose pinned ProjectID
// is unknown to the resolver — the bare path carries only the
// environment_id — are denied by the engine; principals whose only
// access is a scoped grant must use the parent-scoped route family to
// address an environment by its (project, environment) tuple.
type EnvironmentVariableReader interface {
	ListEnvironmentVariables(ctx context.Context, organizationID, environmentID string) ([]store.EnvironmentVariable, error)
}

// listEnvironmentVariablesPayload is the data block of the GET
// /v1/environments/{environment_id}/variables success envelope: every
// environment-scoped variable the environment owns, in deterministic
// (key, id) order. Variables is always a non-nil slice so agents can
// iterate it without a nil check; a live environment with no configured
// variables yields [].
type listEnvironmentVariablesPayload struct {
	Variables []environmentVariable `json:"variables"`
}

// environmentVariable is one entry in a listEnvironmentVariablesPayload.
//
// Value is the wire-level redaction chokepoint. Secret variables ALWAYS
// project as output.Sentinel — the customer can never read a secret
// value through this endpoint by design, the same posture every
// credential-bearing resource in this API takes. Non-secret variables
// project verbatim so the customer can audit their own environment-wide
// defaults.
//
// CreatedAt and UpdatedAt are RFC 3339 timestamps with the same
// semantics as every other dated resource the API surfaces; Version is
// the database-owned optimistic-concurrency counter callers use as an
// If-Match precondition on PATCH / DELETE in later stories.
type environmentVariable struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	EnvironmentID  string    `json:"environment_id"`
	Key            string    `json:"key"`
	Value          string    `json:"value"`
	IsSecret       bool      `json:"is_secret"`
	Version        int64     `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// environmentVariableOf projects a store.EnvironmentVariable into the
// stable wire shape. Secret values are replaced with output.Sentinel
// here — the projection is the chokepoint, not the caller. A future
// regression that adds another caller of this shape cannot accidentally
// skip the redaction.
func environmentVariableOf(v store.EnvironmentVariable) environmentVariable {
	value := v.Value
	if v.IsSecret {
		value = output.Sentinel
	}
	return environmentVariable{
		ID:             v.ID,
		OrganizationID: v.OrganizationID,
		EnvironmentID:  v.EnvironmentID,
		Key:            v.Key,
		Value:          value,
		IsSecret:       v.IsSecret,
		Version:        v.Version,
		CreatedAt:      v.CreatedAt,
		UpdatedAt:      v.UpdatedAt,
	}
}

// listEnvironmentVariablesHandler builds the GET
// /v1/environments/{environment_id}/variables handler. It reads the
// environment-scoped variables of the environment named by the
// {environment_id} path parameter from the source-of-truth database
// through the EnvironmentVariableReader port, and renders them in a
// stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action env.read before the handler
// runs — authorized through environmentIDResolver against the
// (principal home organization, environment_id) resource — and
// attaches the resolved principal, so a request that reaches the
// handler has already cleared the tenant boundary against the
// principal's home organization combined with the path id. env.read is
// a CapRead action, so the gate admits the principal's organization-
// wide read roles (owner, admin, developer, viewer, ci); the support
// principal's cross-tenant read exception does NOT apply here because
// environmentIDResolver pins the resource scope to the principal's own
// home organization, not the path env's tenant. Project-, environment-,
// and service-scoped grants are denied at the policy boundary by the
// engine's covers() rule (a grant with a pinned ProjectID cannot cover
// a resource with no ProjectID); principals whose only access is a
// scoped grant must use a parent-scoped route to address an
// environment-scoped resource.
//
// A request that arrives here with no principal is a wiring error and
// is reported as a typed internal error rather than reading for a zero
// principal. A reader-store outage surfaces as its own typed 5xx; a
// cross-tenant or unknown environment_id reaches the persistence layer
// with the principal's home organization id and is rejected as a
// deterministic 404 by the reader's environment existence check — never
// disguised as an empty success.
func listEnvironmentVariablesHandler(reader EnvironmentVariableReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentVariableReader))
			return
		}
		vars, err := reader.ListEnvironmentVariables(r.Context(), p.OrganizationID, r.PathValue("environment_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]environmentVariable, 0, len(vars))
		for _, v := range vars {
			out = append(out, environmentVariableOf(v))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listEnvironmentVariablesPayload{Variables: out})
	}
}
