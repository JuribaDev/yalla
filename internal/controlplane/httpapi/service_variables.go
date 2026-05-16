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

// errNoServiceVariableReader is returned when GET
// /v1/services/{service_id}/variables is reached without a variable
// reader wired into NewHandler. It can only happen through a wiring
// error — a programming mistake, not a client error — so the handler
// reports it as a typed internal failure rather than serving an empty
// or misleading list.
var errNoServiceVariableReader = errors.New("httpapi: no service variable reader configured")

// ServiceVariableReader is the narrow persistence port GET
// /v1/services/{service_id}/variables depends on.
// *store.ServiceVariableReader satisfies it in production; tests
// supply a fake. Keeping the dependency an interface keeps the handler
// unit-testable without a real database, the same way
// EnvironmentVariableReader keeps the environment-variables surface
// testable.
//
// The read is tenant scoped at the persistence layer: the adapter Gets
// the service under (organization_id, service_id) before listing its
// variables, so a cross-tenant or unknown service_id surfaces as a
// typed apierr.NotFound — never as an empty list, which would invite an
// agent to believe the service exists with no variables. The route
// uses serviceIDResolver which authorizes the call against the
// (principal home org, path service_id) resource before the handler
// runs; the support principal's deliberate cross-tenant read exception
// does NOT apply here because the resource scope is pinned to the
// principal's home organization, not the path's tenant. Project-,
// environment-, and service-scoped grants whose pinned ProjectID is
// unknown to the resolver — the bare path carries only the service_id —
// are denied by the engine; principals whose only access is a scoped
// grant must use the parent-scoped route family to address a service
// by its (project, environment, service) tuple.
type ServiceVariableReader interface {
	ListServiceVariables(ctx context.Context, organizationID, serviceID string) ([]store.ServiceVariable, error)
}

// listServiceVariablesPayload is the data block of the GET
// /v1/services/{service_id}/variables success envelope: every
// service-scoped variable the service owns, in deterministic (key, id)
// order. Variables is always a non-nil slice so agents can iterate it
// without a nil check; a live service with no configured variables
// yields [].
type listServiceVariablesPayload struct {
	Variables []serviceVariable `json:"variables"`
}

// serviceVariable is one entry in a listServiceVariablesPayload.
//
// Value is the wire-level redaction chokepoint. Secret variables ALWAYS
// project as output.Sentinel — the customer can never read a secret
// value through this endpoint by design, the same posture every
// credential-bearing resource in this API takes. Non-secret variables
// project verbatim so the customer can audit their own service-scoped
// values.
//
// CreatedAt and UpdatedAt are RFC 3339 timestamps with the same
// semantics as every other dated resource the API surfaces; Version is
// the database-owned optimistic-concurrency counter callers use as an
// If-Match precondition on PATCH / DELETE in later stories.
type serviceVariable struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	ServiceID      string    `json:"service_id"`
	Key            string    `json:"key"`
	Value          string    `json:"value"`
	IsSecret       bool      `json:"is_secret"`
	Version        int64     `json:"version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// serviceVariableOf projects a store.ServiceVariable into the stable
// wire shape. Secret values are replaced with output.Sentinel here —
// the projection is the chokepoint, not the caller. A future
// regression that adds another caller of this shape cannot accidentally
// skip the redaction.
func serviceVariableOf(v store.ServiceVariable) serviceVariable {
	value := v.Value
	if v.IsSecret {
		value = output.Sentinel
	}
	return serviceVariable{
		ID:             v.ID,
		OrganizationID: v.OrganizationID,
		ServiceID:      v.ServiceID,
		Key:            v.Key,
		Value:          value,
		IsSecret:       v.IsSecret,
		Version:        v.Version,
		CreatedAt:      v.CreatedAt,
		UpdatedAt:      v.UpdatedAt,
	}
}

// listServiceVariablesHandler builds the GET
// /v1/services/{service_id}/variables handler. It reads the
// service-scoped variables of the service named by the {service_id}
// path parameter from the source-of-truth database through the
// ServiceVariableReader port, and renders them in a stable
// yalla.output.v1 envelope.
//
// RequireAuth gates the route on action env.read before the handler
// runs — authorized through serviceIDResolver against the (principal
// home organization, service_id) resource — and attaches the resolved
// principal, so a request that reaches the handler has already cleared
// the tenant boundary against the principal's home organization
// combined with the path id. env.read is a CapRead action, so the gate
// admits the principal's organization-wide read roles (owner, admin,
// developer, viewer, ci); the support principal's cross-tenant read
// exception does NOT apply here because serviceIDResolver pins the
// resource scope to the principal's own home organization, not the
// path service's tenant. Project-, environment-, and service-scoped
// grants are denied at the policy boundary by the engine's covers()
// rule (a grant with a pinned ProjectID cannot cover a resource with
// no ProjectID); principals whose only access is a scoped grant must
// use a parent-scoped route to address a service-scoped resource.
//
// A request that arrives here with no principal is a wiring error and
// is reported as a typed internal error rather than reading for a
// zero principal. A reader-store outage surfaces as its own typed
// 5xx; a cross-tenant or unknown service_id reaches the persistence
// layer with the principal's home organization id and is rejected as
// a deterministic 404 by the reader's service existence check —
// never disguised as an empty success.
func listServiceVariablesHandler(reader ServiceVariableReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceVariableReader))
			return
		}
		vars, err := reader.ListServiceVariables(r.Context(), p.OrganizationID, r.PathValue("service_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]serviceVariable, 0, len(vars))
		for _, v := range vars {
			out = append(out, serviceVariableOf(v))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listServiceVariablesPayload{Variables: out})
	}
}
