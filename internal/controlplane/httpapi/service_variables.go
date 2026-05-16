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

// errNoServiceVariableReader is returned when GET
// /v1/services/{service_id}/variables is reached without a variable
// reader wired into NewHandler. It can only happen through a wiring
// error — a programming mistake, not a client error — so the handler
// reports it as a typed internal failure rather than serving an empty
// or misleading list.
var errNoServiceVariableReader = errors.New("httpapi: no service variable reader configured")

// errNoServiceVariableReplacer is returned when PUT
// /v1/services/{service_id}/variables is reached without a variable
// replacer wired into NewHandler. It can only happen through a wiring
// error — a programming mistake, not a client error — so the handler
// reports it as a typed internal failure rather than serving a
// misleading success.
var errNoServiceVariableReplacer = errors.New("httpapi: no service variable replacer configured")

// errServiceVariablesBodyMissing is the violation reason returned when
// PUT /v1/services/{service_id}/variables is reached without a
// variables field in the request body. The endpoint replaces the entire
// set, so a missing field is structurally ambiguous (did the caller
// mean "clear every variable" or "leave the set unchanged"?) and is
// rejected as a stable 400. The empty-array path is the explicit
// "clear every variable" affordance — the same shape PUT
// /v1/environments/{environment_id}/variables uses.
var errServiceVariablesBodyMissing = "must be supplied (use an empty array to clear every variable)"

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

// ServiceVariableReplacer is the narrow persistence port PUT
// /v1/services/{service_id}/variables depends on.
// *store.ServiceVariableService satisfies it in production; tests supply
// a fake. Like ServiceVariableReader it is an interface declared here so
// the handler stays unit-testable without a real database — the concrete
// orchestrator (the tenant-scoped service existence check, the
// per-variable upsert, the bulk delete-by-exclusion, the audit record,
// and the post-write re-read, all in one transaction) lives in the
// store layer.
type ServiceVariableReplacer interface {
	Replace(ctx context.Context, in store.ReplaceServiceVariablesInput) ([]store.ServiceVariable, error)
}

// replaceServiceVariablesRequest is the decoded PUT
// /v1/services/{service_id}/variables request body: the complete set of
// variables the caller asks to install in one transaction. Variables is
// a pointer to a slice so the body's omission of the field is
// structurally distinguishable from an explicit empty array — PUT
// replaces the entire set, so an explicit empty array means "clear
// every service-scoped variable" (a meaningful extreme operation) while
// a missing field is almost always a misencoded request and is rejected
// as a stable 400.
type replaceServiceVariablesRequest struct {
	Variables *[]serviceVariableRequest `json:"variables"`
}

// serviceVariableRequest is one entry in a replaceServiceVariablesRequest
// body: the (key, value, is_secret) triple the caller asks to persist.
// Each field is validated in the store-layer unit of work before any
// database write — an invalid request never opens a transaction — and
// the handler does no per-field validation beyond strict-decoding the
// body (oversized, malformed, or unknown-field bodies become a typed 400
// that never echoes the input). is_secret defaults to false when omitted,
// mirroring the schema default.
type serviceVariableRequest struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	IsSecret bool   `json:"is_secret,omitempty"`
}

// replaceServiceVariablesPayload is the data block of the PUT
// /v1/services/{service_id}/variables success envelope: the service's
// variables after the replace, in the same stable wire shape GET
// /v1/services/{service_id}/variables returns. The endpoint always
// re-reads the variables in the same transaction that committed the
// upsert + delete, so the body always reflects the state that just
// persisted; secret values are still redacted to the sentinel on the
// wire, so PUT cannot leak a secret value the customer just submitted.
type replaceServiceVariablesPayload struct {
	Variables []serviceVariable `json:"variables"`
}

// replaceServiceVariablesHandler builds the PUT
// /v1/services/{service_id}/variables handler. It decodes and delegates:
// the request body is strictly decoded (oversized, malformed, or
// unknown-field bodies become a typed 400 that never echoes the input),
// then the replace-variables unit of work — verify the service, upsert
// each variable, delete every variable not in the replacement set,
// append the audit record, re-read the committed variables, all in one
// transaction — runs in the store layer through the
// ServiceVariableReplacer port.
//
// RequireAuth gates the route on action env.write before the handler
// runs — authorized through serviceIDResolver against the (principal
// home organization, {service_id}) resource the path names — and
// attaches the resolved principal, so a request that reaches the handler
// has already cleared the tenant boundary: a cross-tenant service_id
// was rejected as a 403 by the policy engine, never reaching this code.
// A request that arrives here with no principal is therefore a wiring
// error and is reported as a typed internal error. The principal and the
// request correlation identifiers are passed to the replacer so the
// audit record names the actor; a validation failure (missing variables
// field, non-POSIX key, duplicate key, oversize value, invalid UTF-8,
// embedded NUL), a not-found {service_id}, and a datastore outage each
// surface as their own typed status, never disguised as one another.
//
// env.write is a CapWrite action: a viewer or support principal in the
// tenant cannot replace variables, only an owner, admin, developer, or
// CI principal can — and unlike CapRead actions there is no
// cross-tenant support exception. The handler relies on the policy
// engine for that decision; it never re-checks the role itself.
// serviceIDResolver pins no ProjectID leg on the resource scope, so
// project-, environment-, and service-scoped grants are denied at the
// policy boundary by the engine's covers() rule (a grant with a pinned
// ProjectID cannot cover a resource with no ProjectID); principals
// whose only access is a scoped grant must use a parent-scoped route to
// address a service-scoped resource.
func replaceServiceVariablesHandler(replacer ServiceVariableReplacer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if replacer == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoServiceVariableReplacer))
			return
		}

		var req replaceServiceVariablesRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if req.Variables == nil {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
				Field:  "variables",
				Reason: errServiceVariablesBodyMissing,
			}))
			return
		}

		items := make([]store.ServiceVariableReplace, 0, len(*req.Variables))
		for _, item := range *req.Variables {
			items = append(items, store.ServiceVariableReplace{
				Key:      item.Key,
				Value:    item.Value,
				IsSecret: item.IsSecret,
			})
		}

		correlation := telemetry.FromContext(r.Context())
		// OrganizationID is taken from the principal's home org (never the
		// caller — the request body carries no organization id), so a
		// cross-tenant service_id still hits the tenant-scoped repository
		// query and surfaces as a 404 at the persistence boundary.
		vars, err := replacer.Replace(r.Context(), store.ReplaceServiceVariablesInput{
			OrganizationID: p.OrganizationID,
			ServiceID:      r.PathValue("service_id"),
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

		payload := replaceServiceVariablesPayload{
			Variables: make([]serviceVariable, 0, len(vars)),
		}
		for _, v := range vars {
			payload.Variables = append(payload.Variables, serviceVariableOf(v))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}
