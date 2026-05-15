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

// errNoOrgVariableReader is returned when GET
// /v1/organizations/{org_id}/variables is reached without a variable
// reader wired into NewHandler. Like errNoUsageReader / errNoAuditEventReader
// it can only happen through a wiring error — a programming mistake, not a
// client error — so the handler reports it as a typed internal failure
// rather than serving an empty or misleading list.
var errNoOrgVariableReader = errors.New("httpapi: no organization variable reader configured")

// OrganizationVariableReader is the narrow persistence port GET
// /v1/organizations/{org_id}/variables depends on.
// *store.OrganizationVariableReader satisfies it in production; tests supply
// a fake. Keeping the dependency an interface keeps the handler
// unit-testable without a real database, the same way UsageReader and
// AuditEventReader do for their endpoints.
//
// The read is tenant-scoped at the persistence layer: the repository filters
// by organization_id, so a cross-tenant {org_id} simply matches no rows and
// yields an empty list, never another organization's variables. The
// organizationIDResolver this route uses authorizes the call against the
// {org_id} path parameter before the handler runs, so a cross-tenant id is
// rejected as a 403 long before this port is reached (with the support
// principal's deliberate cross-tenant read exception preserved by the policy
// engine for read actions).
type OrganizationVariableReader interface {
	ListByOrganization(ctx context.Context, organizationID string) ([]store.OrganizationVariable, error)
}

// listOrganizationVariablesPayload is the data block of the GET
// /v1/organizations/{org_id}/variables success envelope: every organization-
// scoped variable the organization owns, in deterministic (key, id) order.
// Variables is always a non-nil slice so agents can iterate it without a nil
// check; an organization with no configured variables yields [].
type listOrganizationVariablesPayload struct {
	Variables []organizationVariable `json:"variables"`
}

// organizationVariable is one entry in a listOrganizationVariablesPayload.
//
// Value is the wire-level redaction chokepoint. Secret variables ALWAYS
// project as output.Sentinel — the customer can never read a secret value
// through this endpoint by design, the same posture every credential-bearing
// resource in this API takes. Non-secret variables project verbatim so the
// customer can audit their own organization-wide defaults.
//
// CreatedAt and UpdatedAt are RFC 3339 timestamps with the same semantics as
// every other dated resource the API surfaces; Version is the database-owned
// optimistic-concurrency counter callers use as an If-Match precondition on
// PATCH / DELETE in later stories.
type organizationVariable struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	IsSecret  bool      `json:"is_secret"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// organizationVariableOf projects a store.OrganizationVariable into the
// stable wire shape. Secret values are replaced with output.Sentinel here —
// the projection is the chokepoint, not the caller. A future regression
// that adds another caller of this shape cannot accidentally skip the
// redaction.
func organizationVariableOf(v store.OrganizationVariable) organizationVariable {
	value := v.Value
	if v.IsSecret {
		value = output.Sentinel
	}
	return organizationVariable{
		ID:        v.ID,
		Key:       v.Key,
		Value:     value,
		IsSecret:  v.IsSecret,
		Version:   v.Version,
		CreatedAt: v.CreatedAt,
		UpdatedAt: v.UpdatedAt,
	}
}

// listOrganizationVariablesHandler builds the GET
// /v1/organizations/{org_id}/variables handler. It reads the organization-
// scoped variables of the organization named by the {org_id} path parameter
// from the source-of-truth database through the OrganizationVariableReader
// port, and renders them in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action env.read before the handler runs —
// authorized through organizationIDResolver against the organization the
// path names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the tenant boundary: a
// cross-tenant {org_id} was rejected as a 403 by the policy engine, never
// reaching this code. A request that arrives here with no principal is
// therefore a wiring error and is reported as a typed internal error rather
// than reading for a zero principal. A reader-store outage surfaces as its
// own typed 5xx, and an {org_id} with no configured variables is a
// deterministic empty list — the variables read has no "not found" path of
// its own, mirroring every list endpoint.
func listOrganizationVariablesHandler(reader OrganizationVariableReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoOrgVariableReader))
			return
		}

		vars, err := reader.ListByOrganization(r.Context(), r.PathValue("org_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		payload := listOrganizationVariablesPayload{
			Variables: make([]organizationVariable, 0, len(vars)),
		}
		for _, v := range vars {
			payload.Variables = append(payload.Variables, organizationVariableOf(v))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}
