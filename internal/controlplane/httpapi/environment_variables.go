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
	"github.com/JuribaDev/yalla/internal/output"
)

// errNoEnvironmentVariableReader is returned when GET
// /v1/environments/{environment_id}/variables is reached without a
// variable reader wired into NewHandler. It can only happen through a
// wiring error — a programming mistake, not a client error — so the
// handler reports it as a typed internal failure rather than serving an
// empty or misleading list.
var errNoEnvironmentVariableReader = errors.New("httpapi: no environment variable reader configured")

// errNoEnvironmentVariableReplacer is returned when PUT
// /v1/environments/{environment_id}/variables is reached without a
// variable replacer wired into NewHandler. It can only happen through a
// wiring error — a programming mistake, not a client error — so the
// handler reports it as a typed internal failure rather than serving a
// misleading success.
var errNoEnvironmentVariableReplacer = errors.New("httpapi: no environment variable replacer configured")

// errEnvironmentVariablesBodyMissing is the violation reason returned
// when PUT /v1/environments/{environment_id}/variables is reached
// without a variables field in the request body. The endpoint replaces
// the entire set, so a missing field is structurally ambiguous (did the
// caller mean "clear every variable" or "leave the set unchanged"?) and
// is rejected as a stable 400. The empty-array path is the explicit
// "clear every variable" affordance — the same shape PUT
// /v1/projects/{project_id}/variables uses.
var errEnvironmentVariablesBodyMissing = "must be supplied (use an empty array to clear every variable)"

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

// EnvironmentVariableReplacer is the narrow persistence port PUT
// /v1/environments/{environment_id}/variables depends on.
// *store.EnvironmentVariableService satisfies it in production; tests
// supply a fake. Like EnvironmentVariableReader it is an interface
// declared here so the handler stays unit-testable without a real
// database — the concrete orchestrator (the tenant-scoped environment
// existence check, the per-variable upsert, the bulk delete-by-
// exclusion, the audit record, and the post-write re-read, all in one
// transaction) lives in the store layer.
type EnvironmentVariableReplacer interface {
	Replace(ctx context.Context, in store.ReplaceEnvironmentVariablesInput) ([]store.EnvironmentVariable, error)
}

// replaceEnvironmentVariablesRequest is the decoded PUT
// /v1/environments/{environment_id}/variables request body: the complete
// set of variables the caller asks to install in one transaction.
// Variables is a pointer to a slice so the body's omission of the field
// is structurally distinguishable from an explicit empty array — PUT
// replaces the entire set, so an explicit empty array means "clear every
// environment-scoped variable" (a meaningful extreme operation) while a
// missing field is almost always a misencoded request and is rejected as
// a stable 400.
type replaceEnvironmentVariablesRequest struct {
	Variables *[]environmentVariableRequest `json:"variables"`
}

// environmentVariableRequest is one entry in a
// replaceEnvironmentVariablesRequest body: the (key, value, is_secret)
// triple the caller asks to persist. Each field is validated in the
// store-layer unit of work before any database write — an invalid
// request never opens a transaction — and the handler does no per-field
// validation beyond strict-decoding the body (oversized, malformed, or
// unknown-field bodies become a typed 400 that never echoes the input).
// is_secret defaults to false when omitted, mirroring the schema
// default.
type environmentVariableRequest struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	IsSecret bool   `json:"is_secret,omitempty"`
}

// replaceEnvironmentVariablesPayload is the data block of the PUT
// /v1/environments/{environment_id}/variables success envelope: the
// environment's variables after the replace, in the same stable wire
// shape GET /v1/environments/{environment_id}/variables returns. The
// endpoint always re-reads the variables in the same transaction that
// committed the upsert + delete, so the body always reflects the state
// that just persisted; secret values are still redacted to the sentinel
// on the wire, so PUT cannot leak a secret value the customer just
// submitted.
type replaceEnvironmentVariablesPayload struct {
	Variables []environmentVariable `json:"variables"`
}

// replaceEnvironmentVariablesHandler builds the PUT
// /v1/environments/{environment_id}/variables handler. It decodes and
// delegates: the request body is strictly decoded (oversized, malformed,
// or unknown-field bodies become a typed 400 that never echoes the
// input), then the replace-variables unit of work — verify the
// environment, upsert each variable, delete every variable not in the
// replacement set, append the audit record, re-read the committed
// variables, all in one transaction — runs in the store layer through
// the EnvironmentVariableReplacer port.
//
// RequireAuth gates the route on action env.write before the handler
// runs — authorized through environmentIDResolver against the (principal
// home organization, {environment_id}) resource the path names — and
// attaches the resolved principal, so a request that reaches the handler
// has already cleared the tenant boundary: a cross-tenant environment_id
// was rejected as a 403 by the policy engine, never reaching this code.
// A request that arrives here with no principal is therefore a wiring
// error and is reported as a typed internal error. The principal and the
// request correlation identifiers are passed to the replacer so the
// audit record names the actor; a validation failure (missing variables
// field, non-POSIX key, duplicate key, oversize value, invalid UTF-8,
// embedded NUL), a not-found {environment_id}, and a datastore outage
// each surface as their own typed status, never disguised as one
// another.
//
// env.write is a CapWrite action: a viewer or support principal in the
// tenant cannot replace variables, only an owner, admin, developer, or
// CI principal can — and unlike CapRead actions there is no
// cross-tenant support exception. The handler relies on the policy
// engine for that decision; it never re-checks the role itself.
// environmentIDResolver pins no ProjectID leg on the resource scope, so
// project-, environment-, and service-scoped grants are denied at the
// policy boundary by the engine's covers() rule (a grant with a pinned
// ProjectID cannot cover a resource with no ProjectID); principals
// whose only access is a scoped grant must use a parent-scoped route to
// address an environment-scoped resource.
func replaceEnvironmentVariablesHandler(replacer EnvironmentVariableReplacer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if replacer == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoEnvironmentVariableReplacer))
			return
		}

		var req replaceEnvironmentVariablesRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if req.Variables == nil {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
				Field:  "variables",
				Reason: errEnvironmentVariablesBodyMissing,
			}))
			return
		}

		items := make([]store.EnvironmentVariableReplace, 0, len(*req.Variables))
		for _, item := range *req.Variables {
			items = append(items, store.EnvironmentVariableReplace{
				Key:      item.Key,
				Value:    item.Value,
				IsSecret: item.IsSecret,
			})
		}

		correlation := telemetry.FromContext(r.Context())
		// OrganizationID is taken from the principal's home org (never the
		// caller — the request body carries no organization id), so a
		// cross-tenant environment_id still hits the tenant-scoped
		// repository query and surfaces as a 404 at the persistence
		// boundary.
		vars, err := replacer.Replace(r.Context(), store.ReplaceEnvironmentVariablesInput{
			OrganizationID: p.OrganizationID,
			EnvironmentID:  r.PathValue("environment_id"),
			Variables:      items,
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

		payload := replaceEnvironmentVariablesPayload{
			Variables: make([]environmentVariable, 0, len(vars)),
		}
		for _, v := range vars {
			payload.Variables = append(payload.Variables, environmentVariableOf(v))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}
