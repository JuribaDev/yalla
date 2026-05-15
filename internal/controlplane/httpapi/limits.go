package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// errNoLimitsReader is returned when GET /v1/organizations/{org_id}/limits
// is reached without a limits reader wired into NewHandler. Like
// errNoOrganizationReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it as a
// typed internal failure rather than serving an empty or misleading list.
var errNoLimitsReader = errors.New("httpapi: no limits reader configured")

// LimitsReader is the narrow persistence port GET
// /v1/organizations/{org_id}/limits depends on. *store.LimitsReader satisfies
// it in production; tests supply a fake. Keeping the dependency an interface
// keeps the handler unit-testable without a real database, the same way
// OrganizationReader and MembershipReader do for their endpoints.
//
// The read is tenant scoped at the persistence layer: the repository filters
// by organization_id and the named plan, so a cross-tenant {org_id} simply
// matches no rows and yields an empty list, never another organization's
// limits. The organizationIDResolver this route uses authorizes the call
// against the {org_id} path parameter before the handler runs, so a
// cross-tenant id is rejected as a 403 long before this port is reached
// (with the support principal's deliberate cross-tenant read exception
// preserved by the policy engine, exactly as the matrix specifies for
// CapRead actions).
type LimitsReader interface {
	ListEffectiveLimits(ctx context.Context, organizationID string) ([]store.EffectiveQuotaLimit, error)
}

// listLimitsPayload is the data block of the GET
// /v1/organizations/{org_id}/limits success envelope: every effective limit
// configured for the organization named by the {org_id} path parameter, in
// deterministic resource order. Every field is a non-secret identifier,
// numeric ceiling, or enforcement-mode name — the endpoint never returns
// credential material, so the payload is safe to log and audit verbatim.
// Limits is always a non-nil slice so agents can iterate it without a nil
// check; resources with no policy at either scope are omitted.
type listLimitsPayload struct {
	Limits []limitResource `json:"limits"`
}

// limitResource is one entry in a listLimitsPayload: the effective limit for
// one resource dimension, with the scope that produced it.
//
// Source is "plan_default" when the value is inherited from the
// organization's plan, and "organization" when it is an organization-level
// override that takes precedence over the plan default; the two values match
// the quota_policies.scope_kind column verbatim. EnforcementMode is one of
// hard, soft, metered, or disabled — the same closed set the database
// enforces through the quota_enforcement_mode domain.
type limitResource struct {
	Resource        string `json:"resource"`
	LimitValue      int64  `json:"limit_value"`
	EnforcementMode string `json:"enforcement_mode"`
	Source          string `json:"source"`
}

// limitResourceOf projects a store.EffectiveQuotaLimit into the stable wire
// shape. The wire field names are the stable contract; the persistence shape
// can evolve without changing the response.
func limitResourceOf(l store.EffectiveQuotaLimit) limitResource {
	return limitResource{
		Resource:        l.Resource.String(),
		LimitValue:      l.LimitValue,
		EnforcementMode: string(l.EnforcementMode),
		Source:          string(l.Scope),
	}
}

// listLimitsHandler builds the GET /v1/organizations/{org_id}/limits handler.
// It reads the effective limits of the organization named by the {org_id}
// path parameter — resolved as "organization override if present, else plan
// default" — from the source-of-truth database through the LimitsReader port,
// and renders them in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action limits.read before the handler runs
// — authorized through organizationIDResolver against the organization the
// path names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the tenant boundary: a
// cross-tenant {org_id} was rejected as a 403 by the policy engine, never
// reaching this code. A request that arrives here with no principal is
// therefore a wiring error and is reported as a typed internal error rather
// than reading for a zero principal. A reader-store outage surfaces as its
// own typed 5xx, and an {org_id} with no configured policies is a
// deterministic empty list — the limits read has no "not found" path of its
// own, mirroring every list endpoint.
func listLimitsHandler(reader LimitsReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoLimitsReader))
			return
		}

		limits, err := reader.ListEffectiveLimits(r.Context(), r.PathValue("org_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		resources := make([]limitResource, 0, len(limits))
		for _, l := range limits {
			resources = append(resources, limitResourceOf(l))
		}

		apienvelope.WriteData(w, http.StatusOK, requestID(r), listLimitsPayload{
			Limits: resources,
		})
	}
}
