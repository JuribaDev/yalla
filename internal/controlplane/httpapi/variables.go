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

// errNoOrgVariableReader is returned when GET
// /v1/organizations/{org_id}/variables is reached without a variable
// reader wired into NewHandler. Like errNoUsageReader / errNoAuditEventReader
// it can only happen through a wiring error — a programming mistake, not a
// client error — so the handler reports it as a typed internal failure
// rather than serving an empty or misleading list.
var errNoOrgVariableReader = errors.New("httpapi: no organization variable reader configured")

// errNoOrgVariableReplacer is returned when PUT
// /v1/organizations/{org_id}/variables is reached without a variable
// replacer wired into NewHandler. Like errNoOrgVariableReader it can only
// happen through a wiring error — a programming mistake, not a client
// error — so the handler reports it as a typed internal failure rather
// than silently failing to persist the change.
var errNoOrgVariableReplacer = errors.New("httpapi: no organization variable replacer configured")

// errNoOrgVariablePatcher is returned when PATCH
// /v1/organizations/{org_id}/variables/{key} is reached without a
// variable patcher wired into NewHandler. Like errNoOrgVariableReplacer
// it can only happen through a wiring error — a programming mistake,
// not a client error — so the handler reports it as a typed internal
// failure rather than silently failing to persist the change.
var errNoOrgVariablePatcher = errors.New("httpapi: no organization variable patcher configured")

// errOrgVariablePatchEmpty is returned when PATCH
// /v1/organizations/{org_id}/variables/{key} decodes a body that names
// neither value nor is_secret. A PATCH that changes nothing is a client
// error (it would otherwise be a silent no-op write that still files an
// audit record), so the handler surfaces it as a stable 400 with a
// closed-set reason — agents can rely on the message to distinguish it
// from any other validation failure.
var errOrgVariablePatchEmpty = "at least one of value or is_secret must be provided"

// errOrgVariablesBodyMissing is returned when PUT
// /v1/organizations/{org_id}/variables decodes a body that does not name
// the "variables" field. Because PUT replaces the tenant's entire variable
// set, the difference between "send no field" and "send the empty array"
// is load-bearing: an empty array is an explicit clear, while a missing
// field is almost always a misencoded request. We surface the missing
// field as a stable 400 so an agent can distinguish the two without
// guessing.
var errOrgVariablesBodyMissing = "must be supplied (use an empty array to clear every variable)"

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

// OrganizationVariableReplacer is the narrow persistence port PUT
// /v1/organizations/{org_id}/variables depends on.
// *store.OrganizationVariableService satisfies it in production; tests
// supply a fake. Like OrganizationVariableReader it is an interface
// declared here so the handler stays unit-testable without a real
// database — the concrete orchestrator (the tenant existence check, the
// per-variable upsert, the bulk delete-by-exclusion, the audit record,
// and the post-write re-read, all in one transaction) lives in the store
// layer.
type OrganizationVariableReplacer interface {
	Replace(ctx context.Context, in store.ReplaceOrganizationVariablesInput) ([]store.OrganizationVariable, error)
}

// replaceOrganizationVariablesRequest is the decoded PUT
// /v1/organizations/{org_id}/variables request body: the complete set of
// variables the caller asks to install in one transaction. Variables is a
// pointer to a slice so the body's omission of the field is structurally
// distinguishable from an explicit empty array — PUT replaces the entire
// set, so an explicit empty array means "clear every variable" (a
// meaningful extreme operation) while a missing field is almost always a
// misencoded request and is rejected as a stable 400.
type replaceOrganizationVariablesRequest struct {
	Variables *[]organizationVariableRequest `json:"variables"`
}

// organizationVariableRequest is one entry in a
// replaceOrganizationVariablesRequest body: the (key, value, is_secret)
// triple the caller asks to persist. Each field is validated in the
// store-layer unit of work before any database write — an invalid request
// never opens a transaction — and the handler does no per-field
// validation beyond strict-decoding the body (oversized, malformed, or
// unknown-field bodies become a typed 400 that never echoes the input).
// is_secret defaults to false when omitted, mirroring the schema default.
type organizationVariableRequest struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	IsSecret bool   `json:"is_secret,omitempty"`
}

// replaceOrganizationVariablesPayload is the data block of the PUT
// /v1/organizations/{org_id}/variables success envelope: the
// organization's variables after the replace, in the same stable wire
// shape GET /v1/organizations/{org_id}/variables returns. The endpoint
// always re-reads the variables in the same transaction that committed
// the upsert + delete, so the body always reflects the state that just
// persisted; secret values are still redacted to the sentinel on the
// wire, so PUT cannot leak a secret value the customer just submitted.
type replaceOrganizationVariablesPayload struct {
	Variables []organizationVariable `json:"variables"`
}

// replaceOrganizationVariablesHandler builds the PUT
// /v1/organizations/{org_id}/variables handler. It decodes and delegates:
// the request body is strictly decoded (oversized, malformed, or
// unknown-field bodies become a typed 400 that never echoes the input),
// then the replace-variables unit of work — verify the organization,
// upsert each variable, delete every variable not in the replacement
// set, append the audit record, re-read the committed variables, all in
// one transaction — runs in the store layer through the
// OrganizationVariableReplacer port.
//
// RequireAuth gates the route on action env.write before the handler
// runs — authorized through organizationIDResolver against the
// organization the path names — and attaches the resolved principal, so
// a request that reaches the handler has already cleared the tenant
// boundary: a cross-tenant {org_id} was rejected as a 403 by the policy
// engine, never reaching this code. A request that arrives here with no
// principal is therefore a wiring error and is reported as a typed
// internal error. The principal and the request correlation identifiers
// are passed to the replacer so the audit record names the actor; a
// validation failure (missing variables field, non-POSIX key, duplicate
// key, oversize value, invalid UTF-8, embedded NUL), a not-found
// {org_id}, and a datastore outage each surface as their own typed
// status, never disguised as one another.
//
// env.write is a CapWrite action: a viewer or support principal in the
// tenant cannot replace variables, only an owner, admin, developer, or
// CI principal can — and unlike CapRead actions there is no cross-tenant
// support exception. The handler relies on the policy engine for that
// decision; it never re-checks the role itself.
func replaceOrganizationVariablesHandler(replacer OrganizationVariableReplacer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if replacer == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoOrgVariableReplacer))
			return
		}

		var req replaceOrganizationVariablesRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		if req.Variables == nil {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
				Field:  "variables",
				Reason: errOrgVariablesBodyMissing,
			}))
			return
		}

		items := make([]store.OrganizationVariableReplace, 0, len(*req.Variables))
		for _, item := range *req.Variables {
			items = append(items, store.OrganizationVariableReplace{
				Key:      item.Key,
				Value:    item.Value,
				IsSecret: item.IsSecret,
			})
		}

		correlation := telemetry.FromContext(r.Context())
		vars, err := replacer.Replace(r.Context(), store.ReplaceOrganizationVariablesInput{
			OrganizationID: r.PathValue("org_id"),
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

		payload := replaceOrganizationVariablesPayload{
			Variables: make([]organizationVariable, 0, len(vars)),
		}
		for _, v := range vars {
			payload.Variables = append(payload.Variables, organizationVariableOf(v))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), payload)
	}
}

// OrganizationVariablePatcher is the narrow persistence port PATCH
// /v1/organizations/{org_id}/variables/{key} depends on.
// *store.OrganizationVariableService satisfies it in production; tests
// supply a fake. Like OrganizationVariableReplacer it is an interface
// declared here so the handler stays unit-testable without a real
// database — the concrete orchestrator (the tenant-scoped existence
// read, the partial update of the mutable fields, and the immutable
// audit record committed in one transaction) lives in the store layer.
type OrganizationVariablePatcher interface {
	Patch(ctx context.Context, in store.PatchOrganizationVariableInput) (store.OrganizationVariable, error)
}

// patchOrganizationVariableRequest is the decoded PATCH
// /v1/organizations/{org_id}/variables/{key} request body. Value and
// IsSecret are the mutable fields on an organization_variables row; the
// immutable identity fields (id, organization_id, key) and the
// lifecycle stamps (created_at, updated_at, version) are deliberately
// not part of this surface — a PATCH cannot rename a variable in
// place, only mutate its value and its secret flag. The store layer
// validates every supplied value before any database work — an invalid
// request never opens a transaction — and the fields carry only the
// caller-supplied content the handler forwards verbatim.
//
// Value and IsSecret are pointers so a missing field can be
// distinguished from a supplied-but-empty one: omitting the field is
// "leave unchanged", supplying it with an invalid value is a typed
// validation failure naming the field, and a patch that names no
// field is itself a 400 — a mutation that changes nothing is a client
// error, not a silent success. is_secret accepts only the JSON
// literals true and false (the global JSON decoder rejects anything
// else as a stable 400 before the handler runs).
type patchOrganizationVariableRequest struct {
	Value    *string `json:"value,omitempty"`
	IsSecret *bool   `json:"is_secret,omitempty"`
}

// patchOrganizationVariablePayload is the data block of the PATCH
// /v1/organizations/{org_id}/variables/{key} success envelope: the
// variable after the mutation — including the trigger-refreshed
// version and updated_at — in the same stable wire shape every other
// variable endpoint returns. Secret values are still redacted to the
// sentinel on the wire, so a PATCH cannot leak a secret value the
// customer just submitted; a customer can never read a secret value
// back through this endpoint by design, including immediately after
// submitting it.
type patchOrganizationVariablePayload struct {
	Variable organizationVariable `json:"variable"`
}

// patchOrganizationVariableHandler builds the PATCH
// /v1/organizations/{org_id}/variables/{key} handler. It decodes and
// delegates: the request body is strictly decoded (oversized,
// malformed, or unknown-field bodies become a typed 400 that never
// echoes the input), then the patch-variable unit of work — read the
// current row, apply the caller-supplied fields, write the row, append
// the audit record, all in one transaction — runs in the store layer
// through the OrganizationVariablePatcher port.
//
// RequireAuth gates the route on action env.write before the handler
// runs — authorized through organizationIDResolver against the
// organization the path names — and attaches the resolved principal,
// so a request that reaches the handler has already cleared the
// tenant boundary: a cross-tenant {org_id} was rejected as a 403 by
// the policy engine, never reaching this code. A request that arrives
// here with no principal is therefore a wiring error and is reported
// as a typed internal error. The principal and the request correlation
// identifiers are passed to the patcher so the audit record names the
// actor; a validation failure (no fields, invalid value encoding,
// over-sized value), a not-found variable (cross-tenant or missing
// row), and a datastore outage each surface as their own typed
// status, never disguised as one another.
//
// env.write is a CapWrite action: a viewer or support principal in
// the tenant cannot patch a variable, only an owner, admin, developer,
// or CI principal can — and unlike CapRead actions there is no cross-
// tenant support exception. The handler relies on the policy engine
// for that decision; it never re-checks the role itself.
func patchOrganizationVariableHandler(patcher OrganizationVariablePatcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if patcher == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoOrgVariablePatcher))
			return
		}

		var req patchOrganizationVariableRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		// A PATCH that names neither mutable field is itself a client
		// error: the store layer rejects it the same way, but surfacing
		// it here keeps the handler/store contract symmetric and gives
		// agents a stable 400 for "patch with no field" before the
		// store layer's identical rejection runs. The field name in
		// the violation matches what the store layer reports, so the
		// wire contract is identical regardless of where the rejection
		// originates.
		if req.Value == nil && req.IsSecret == nil {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
				Field:  "value",
				Reason: errOrgVariablePatchEmpty,
			}))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		v, err := patcher.Patch(r.Context(), store.PatchOrganizationVariableInput{
			OrganizationID: r.PathValue("org_id"),
			Key:            r.PathValue("key"),
			Value:          req.Value,
			IsSecret:       req.IsSecret,
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

		apienvelope.WriteData(w, http.StatusOK, requestID(r), patchOrganizationVariablePayload{
			Variable: organizationVariableOf(v),
		})
	}
}
