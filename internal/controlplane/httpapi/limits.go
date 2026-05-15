package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// errNoLimitsReader is returned when GET /v1/organizations/{org_id}/limits
// is reached without a limits reader wired into NewHandler. Like
// errNoOrganizationReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it as a
// typed internal failure rather than serving an empty or misleading list.
var errNoLimitsReader = errors.New("httpapi: no limits reader configured")

// errNoLimitsUpdater is returned when PATCH /v1/organizations/{org_id}/limits
// is reached without a limits updater wired into NewHandler. Like
// errNoLimitsReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it as a
// typed internal failure rather than silently failing to persist the change.
var errNoLimitsUpdater = errors.New("httpapi: no limits updater configured")

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

// LimitsUpdater is the narrow persistence port PATCH
// /v1/organizations/{org_id}/limits depends on. *store.LimitsService
// satisfies it in production; tests supply a fake. Like LimitsReader it is an
// interface declared here so the handler stays unit-testable without a real
// database — the concrete orchestrator (the tenant existence check, the
// organization-scoped policy upserts, the audit record, and the post-write
// re-read, all in one transaction) lives in the store layer.
type LimitsUpdater interface {
	UpdateLimits(ctx context.Context, in store.UpdateLimitsInput) ([]store.EffectiveQuotaLimit, error)
}

// limitUpdateRequest is one entry in an updateLimitsRequest body: the
// organization-scoped override the caller asks to apply to one resource
// dimension. Resource and LimitValue are the mandatory fields; EnforcementMode
// is optional and defaults to "hard" on the server side when omitted, which
// matches the schema default for an INSERT. None of the fields carries
// credential material — a quota policy stores a numeric ceiling, a closed-set
// resource identifier, and a closed-set enforcement mode, and nothing else.
//
// LimitValue is a pointer so the absence of the field surfaces as a stable
// validation failure naming "limit_value" rather than silently defaulting to
// zero — a zero ceiling is a meaningful (extreme) value and must be explicit,
// not the result of forgetting to send the field.
type limitUpdateRequest struct {
	Resource        string `json:"resource"`
	LimitValue      *int64 `json:"limit_value,omitempty"`
	EnforcementMode string `json:"enforcement_mode,omitempty"`
}

// updateLimitsRequest is the decoded PATCH /v1/organizations/{org_id}/limits
// request body: a non-empty list of organization-scoped overrides the caller
// asks to upsert in one transaction. The store layer validates every supplied
// field before any database work — an invalid request never opens a
// transaction — and a patch with an empty list is itself a 400, the same way
// a partial-update endpoint that names no field is.
type updateLimitsRequest struct {
	Limits []limitUpdateRequest `json:"limits"`
}

// updateLimitsPayload is the data block of the PATCH
// /v1/organizations/{org_id}/limits success envelope: the organization's
// effective limits after the upsert, in the same stable wire shape GET
// /v1/organizations/{org_id}/limits returns. The endpoint always re-reads the
// limits in the same transaction that committed the upsert, so the body
// always reflects the state that just persisted; it carries no credential
// material.
type updateLimitsPayload struct {
	Limits []limitResource `json:"limits"`
}

// updateLimitsHandler builds the PATCH /v1/organizations/{org_id}/limits
// handler. It decodes and delegates: the request body is strictly decoded
// (oversized, malformed, or unknown-field bodies become a typed 400 that
// never echoes the input), then the update-limits unit of work — verify the
// organization, upsert each organization-scoped policy, append the audit
// record, re-read the effective limits, all in one transaction — runs in the
// store layer through the LimitsUpdater port.
//
// RequireAuth gates the route on action limits.write before the handler runs
// — authorized through organizationIDResolver against the organization the
// path names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the tenant boundary: a
// cross-tenant {org_id} was rejected as a 403 by the policy engine, never
// reaching this code. A request that arrives here with no principal is
// therefore a wiring error and is reported as a typed internal error. The
// principal and the request correlation identifiers are passed to the
// updater so the audit record names the actor; a validation failure (empty
// patch, unknown resource, negative limit, bad enforcement mode), a
// not-found {org_id}, and a datastore outage each surface as their own typed
// status, never disguised as one another.
//
// limits.write is a CapAdmin action: a viewer, developer, or support
// principal in the tenant cannot mutate limits, only an owner or admin in
// the tenant can — and unlike CapRead actions there is no cross-tenant
// support exception. The handler relies on the policy engine for that
// decision; it never re-checks the role itself.
func updateLimitsHandler(updater LimitsUpdater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if updater == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoLimitsUpdater))
			return
		}

		var req updateLimitsRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if len(req.Limits) == 0 {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
				Field:  "limits",
				Reason: "must contain at least one entry",
			}))
			return
		}
		// Surface the missing-limit_value violation here so the wire reports a
		// stable, agent-friendly field path before the store layer's
		// identical rejection runs. The store still re-validates every field
		// it accepts, so this is a contract symmetry, not the only line of
		// defence.
		items := make([]store.LimitUpdate, 0, len(req.Limits))
		for i, item := range req.Limits {
			if item.LimitValue == nil {
				apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
					Field:  "limits[" + itoaIndex(i) + "].limit_value",
					Reason: "must be supplied",
				}))
				return
			}
			items = append(items, store.LimitUpdate{
				Resource:        store.QuotaResource(item.Resource),
				LimitValue:      *item.LimitValue,
				EnforcementMode: store.EnforcementMode(item.EnforcementMode),
			})
		}

		correlation := telemetry.FromContext(r.Context())
		limits, err := updater.UpdateLimits(r.Context(), store.UpdateLimitsInput{
			OrganizationID: r.PathValue("org_id"),
			Items:          items,
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

		resources := make([]limitResource, 0, len(limits))
		for _, l := range limits {
			resources = append(resources, limitResourceOf(l))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), updateLimitsPayload{
			Limits: resources,
		})
	}
}

// itoaIndex renders a non-negative array index as a decimal string. It is the
// httpapi-side counterpart of the store-package itoa helper, kept here so the
// "limits[i].field" field paths the handler emits match the store layer's
// shape byte-for-byte.
func itoaIndex(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
