package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// errNoAPIKeyReader is returned when GET /v1/organizations/{org_id}/api-keys
// is reached without an api-key reader wired into NewHandler. Like
// errNoMembershipReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it as a
// typed internal failure rather than serving an empty or misleading list.
var errNoAPIKeyReader = errors.New("httpapi: no api key reader configured")

// errNoAPIKeyCreator is returned when POST /v1/organizations/{org_id}/api-keys
// is reached without an api-key creator wired into NewHandler. Like
// errNoAPIKeyReader it can only happen through a wiring error — a programming
// mistake, not a client error — so the handler reports it as a typed
// internal failure rather than silently failing to mint a credential.
var errNoAPIKeyCreator = errors.New("httpapi: no api key creator configured")

// errNoAPIKeyUpdater is returned when PATCH
// /v1/organizations/{org_id}/api-keys/{key_id} is reached without an
// api-key updater wired into NewHandler. Like errNoAPIKeyCreator it can only
// happen through a wiring error — a programming mistake, not a client error —
// so the handler reports it as a typed internal failure rather than
// silently dropping a write.
var errNoAPIKeyUpdater = errors.New("httpapi: no api key updater configured")

// errNoAPIKeyRevoker is returned when DELETE
// /v1/organizations/{org_id}/api-keys/{key_id} is reached without an
// api-key revoker wired into NewHandler. Like errNoAPIKeyUpdater it can only
// happen through a wiring error — a programming mistake, not a client error —
// so the handler reports it as a typed internal failure rather than
// silently dropping the revocation.
var errNoAPIKeyRevoker = errors.New("httpapi: no api key revoker configured")

// APIKeyReader is the narrow persistence port GET
// /v1/organizations/{org_id}/api-keys and GET
// /v1/organizations/{org_id}/api-keys/{key_id} depend on. *store.APIKeyReader
// satisfies it in production; tests supply a fake. Keeping the dependency an
// interface keeps the handler unit-testable without a real database, the same
// way MembershipReader keeps GET /v1/organizations/{org_id}/members testable.
//
// Both reads are tenant scoped at the persistence layer: the repository filters
// by organization_id, so a cross-tenant id simply matches no rows — ListAPIKeys
// yields an empty list and GetAPIKey surfaces a typed not-found, never another
// organization's keys. Cross-tenant rejection at the policy boundary (the
// deterministic 403 organizationIDResolver produces) keeps an attacker from
// probing the endpoint at all; the persistence-layer scoping is a
// defence-in-depth backstop.
type APIKeyReader interface {
	ListAPIKeys(ctx context.Context, organizationID string) ([]store.APIKey, error)
	GetAPIKey(ctx context.Context, organizationID, keyID string) (store.APIKey, error)
}

// apiKeyResource is the wire shape of a single API key in the GET
// /v1/organizations/{org_id}/api-keys response. It is the public projection of
// store.APIKey, deliberately distinct from the persistence layout so the
// database can evolve without breaking the public contract.
//
// The struct never carries credential material: SecretHash is a one-way hash
// and is intentionally absent from the wire shape so a key's plaintext token —
// the value the caller sees once at creation — can never be recovered through
// this endpoint or any future one that reuses the resource. Prefix is the
// public, globally-unique lookup id of the key (the part of "yk_<prefix>_<secret>"
// before the secret) and is safe to surface; it is not itself a credential.
//
// Nullable timestamps render as the empty string when the underlying column is
// NULL: omitempty drops them from the JSON entirely, so an active key carries
// no revoked_at and a never-used key carries no last_used_at. created_at and
// updated_at are always present.
type apiKeyResource struct {
	KeyID            string   `json:"key_id"`
	Prefix           string   `json:"prefix"`
	Name             string   `json:"name"`
	Scopes           []string `json:"scopes"`
	CreatedBy        string   `json:"created_by,omitempty"`
	ServiceAccountID string   `json:"service_account_id,omitempty"`
	ExpiresAt        string   `json:"expires_at,omitempty"`
	RevokedAt        string   `json:"revoked_at,omitempty"`
	LastUsedAt       string   `json:"last_used_at,omitempty"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
}

// listAPIKeysPayload is the data block of the GET
// /v1/organizations/{org_id}/api-keys success envelope: every API key owned by
// the organization named by the {org_id} path parameter. APIKeys is always a
// non-nil slice so agents can iterate it without a nil check; an organization
// with no keys renders as a stable empty array rather than a JSON null.
//
// Every field on each entry is a non-secret identifier, role name, scope
// string, or timestamp — the endpoint never returns credential material, so
// the payload is safe to log and audit verbatim.
type listAPIKeysPayload struct {
	APIKeys []apiKeyResource `json:"api_keys"`
}

// getAPIKeyPayload is the data block of the GET
// /v1/organizations/{org_id}/api-keys/{key_id} success envelope: the single
// API key named by ({org_id}, {key_id}), in the same stable wire shape every
// other api-key endpoint returns. It carries no credential material — the
// secret hash never crosses the HTTP boundary and the plaintext token is
// shown to its owner exactly once at creation, never on a read.
type getAPIKeyPayload struct {
	APIKey apiKeyResource `json:"api_key"`
}

// apiKeyResourceOf projects a store.APIKey onto the wire shape. It normalises
// a nil Scopes slice to an empty slice so the rendered JSON is a stable empty
// array rather than null, formats every non-nil timestamp in RFC 3339 with
// nanosecond precision, and renders nullable timestamps as the empty string
// (which omitempty then drops from the wire). It deliberately drops SecretHash
// — a credential never crosses the HTTP boundary.
func apiKeyResourceOf(k store.APIKey) apiKeyResource {
	scopes := k.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	res := apiKeyResource{
		KeyID:            k.ID,
		Prefix:           k.Prefix,
		Name:             k.Name,
		Scopes:           scopes,
		CreatedBy:        k.CreatedBy,
		ServiceAccountID: k.ServiceAccountID,
		CreatedAt:        k.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:        k.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
	if k.ExpiresAt != nil {
		res.ExpiresAt = k.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	if k.RevokedAt != nil {
		res.RevokedAt = k.RevokedAt.UTC().Format(time.RFC3339Nano)
	}
	if k.LastUsedAt != nil {
		res.LastUsedAt = k.LastUsedAt.UTC().Format(time.RFC3339Nano)
	}
	return res
}

// APIKeyCreator is the narrow persistence port POST
// /v1/organizations/{org_id}/api-keys depends on. *store.APIKeyService
// satisfies it in production; tests supply a fake. Like APIKeyReader it is
// an interface declared here so the handler stays unit-testable without a
// real database — the concrete orchestrator (the existence checks, the
// api_keys row, and the audit record committed in one transaction) lives in
// the store layer.
//
// The plaintext credential never crosses this boundary. The handler mints
// it through internal/controlplane/auth.Generate, passes the (Prefix,
// SecretHash) pair into store.CreateAPIKeyInput, and surfaces the one-time
// plaintext token in the response — it never enters the store layer or the
// database.
type APIKeyCreator interface {
	Create(ctx context.Context, in store.CreateAPIKeyInput, now time.Time) (store.APIKey, error)
}

// createAPIKeyRequest is the decoded POST /v1/organizations/{org_id}/api-keys
// request body. Name is the human-authored label for the key; Scopes is the
// machine-readable capability list (may be empty). ExpiresAt is optional
// (an absent or null value means the key does not expire) and is supplied
// as an RFC 3339 timestamp string; the handler parses it before delegating
// so a malformed timestamp is a deterministic 400 naming the field.
// ServiceAccountID is optional and, when supplied, transfers ownership of
// the key from the authenticated user to that non-human principal — the
// store layer verifies the service account exists inside the same tenant.
//
// No field on this struct carries credential material: the secret half of
// the API key token is minted on the server, never accepted from the
// client, so an attacker cannot supply their own prefix or hash.
type createAPIKeyRequest struct {
	Name             string   `json:"name"`
	Scopes           []string `json:"scopes,omitempty"`
	ExpiresAt        *string  `json:"expires_at,omitempty"`
	ServiceAccountID *string  `json:"service_account_id,omitempty"`
}

// createAPIKeyPayload is the data block of the POST
// /v1/organizations/{org_id}/api-keys success envelope: the persisted key
// (in the same stable wire shape every other api-key endpoint returns) plus
// the one-time plaintext Token. The token field is the ONLY place the
// secret half of the credential is ever exposed — every read endpoint and
// every audit record renders only the public Prefix and the one-way
// SecretHash, so a key that is not captured at creation time is, by
// design, unrecoverable.
type createAPIKeyPayload struct {
	APIKey apiKeyResource `json:"api_key"`
	Token  string         `json:"token"`
}

// listAPIKeysHandler builds the GET /v1/organizations/{org_id}/api-keys
// handler. It lists the API keys owned by the organization named by the
// {org_id} path parameter, by reading them from the source-of-truth database
// through the APIKeyReader port.
//
// RequireAuth gates the route on action keys.read before the handler runs —
// authorized through organizationIDResolver against the organization the path
// names — and attaches the resolved principal, so a request that reaches the
// handler has already cleared the tenant boundary: a cross-tenant {org_id}
// was rejected as a 403 by the policy engine, never reaching this code. A
// request that arrives here with no principal is therefore a wiring error and
// is reported as a typed internal error rather than reading for a zero
// principal. A reader-store outage surfaces as its own typed 5xx, never
// disguised as an empty success.
//
// keys.read is a CapAdmin action: a viewer or developer in the tenant cannot
// list the organization's API keys, only an owner or admin (and a support
// principal performing a read across tenants by the standard CapRead-with-support
// allow) can — exactly as the policy catalog dictates. The handler relies on
// the policy engine for that decision; it never re-checks the role itself.
func listAPIKeysHandler(reader APIKeyReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAPIKeyReader))
			return
		}
		keys, err := reader.ListAPIKeys(r.Context(), r.PathValue("org_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]apiKeyResource, 0, len(keys))
		for _, k := range keys {
			out = append(out, apiKeyResourceOf(k))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listAPIKeysPayload{APIKeys: out})
	}
}

// getAPIKeyHandler builds the GET /v1/organizations/{org_id}/api-keys/{key_id}
// handler. It reads the single API key named by ({org_id}, {key_id}) from
// the source-of-truth database through the APIKeyReader port, and renders it
// in a stable yalla.output.v1 envelope.
//
// RequireAuth gates the route on action keys.read before the handler runs —
// authorized through organizationIDResolver against the organization the path
// names — and attaches the resolved principal, so a request that reaches the
// handler has already cleared the tenant boundary: a cross-tenant {org_id}
// was rejected as a 403 by the policy engine, never reaching this code. A
// request that arrives here with no principal is therefore a wiring error and
// is reported as a typed internal error rather than reading for a zero
// principal. A reader-store outage surfaces as its own typed 5xx, never
// disguised as a not-found.
//
// keys.read is a CapAdmin action: a viewer or developer in the tenant cannot
// read an API key, only an owner or admin in the tenant (and a support
// principal performing a read across tenants by the standard
// CapRead-with-support allow) can — exactly as the policy catalog dictates.
// keys.read sits at CapAdmin rather than CapRead, however, so the support
// cross-tenant exception does NOT apply to this route: a support principal
// cannot read another tenant's keys through this endpoint. The handler
// relies on the policy engine for that decision; it never re-checks the
// role itself.
//
// A {key_id} that does not exist in the tenant is reported as a typed
// E_NOT_FOUND by the store layer (the repository's tenant-scoped Get
// surfaces apierr.NotFound for both a missing row and a key id from another
// organization), so a cross-tenant key_id is indistinguishable from a
// missing row — the endpoint can never reveal whether another tenant owns
// that key.
func getAPIKeyHandler(reader APIKeyReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAPIKeyReader))
			return
		}
		key, err := reader.GetAPIKey(r.Context(), r.PathValue("org_id"), r.PathValue("key_id"))
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), getAPIKeyPayload{
			APIKey: apiKeyResourceOf(key),
		})
	}
}

// createAPIKeyHandler builds the POST /v1/organizations/{org_id}/api-keys
// handler. It mints a fresh credential, then delegates to the store layer
// for the persistence unit of work: the request body is strictly decoded
// (oversized, malformed, or unknown-field bodies become a typed 400 that
// never echoes the input), the auth-layer credential primitive is minted
// once on the server (so a client cannot supply its own prefix or hash),
// and the create-api-key unit of work — confirm the organization exists,
// confirm the optional service account exists in the same tenant, insert
// the api_keys row, append the audit record, all in one transaction —
// runs in the store layer through the APIKeyCreator port.
//
// RequireAuth gates the route on action keys.manage before the handler
// runs — authorized through organizationIDResolver against the
// organization the path names — and attaches the resolved principal, so a
// request that reaches the handler has already cleared the tenant
// boundary: a cross-tenant {org_id} was rejected as a 403 by the policy
// engine, never reaching this code. A request that arrives here with no
// principal is a wiring error and is reported as a typed internal error.
//
// The response is 201 Created carrying the persisted api-key projection
// and — exactly once — the plaintext token. Every subsequent read of the
// key (GET list and GET single) returns the same projection without the
// token, so a key not captured at creation time is unrecoverable. The
// plaintext is materialised through auth.Token.Reveal(), the only
// deliberately greppable escape hatch for the credential, immediately
// before the response is written; it never reaches a log line, an audit
// record, or the database.
func createAPIKeyHandler(creator APIKeyCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if creator == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAPIKeyCreator))
			return
		}

		var req createAPIKeyRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		// Parse the optional expires_at at the HTTP boundary so a malformed
		// timestamp is a deterministic 400 naming the field. The store-layer
		// validator then enforces the semantic rule (must be strictly in the
		// future) against the same wall clock the audit record carries — a
		// single now value flows through both checks.
		var expiresAt *time.Time
		if req.ExpiresAt != nil {
			parsed, err := time.Parse(time.RFC3339Nano, *req.ExpiresAt)
			if err != nil {
				apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
					Field:  "expires_at",
					Reason: "must be an RFC 3339 timestamp",
				}))
				return
			}
			parsed = parsed.UTC()
			expiresAt = &parsed
		}

		// Mint the credential on the server. auth.Generate produces 192 bits
		// of cryptographic entropy split into a public prefix and a secret
		// body; only the prefix and the secret hash are passed to the store
		// layer, so the plaintext never reaches persistence. A crypto/rand
		// failure is an environment fault, not client input, and surfaces
		// as a typed 5xx.
		generated, err := auth.Generate()
		if err != nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(err))
			return
		}

		// created_by is the user who minted the key. The api_keys.created_by
		// column references users(id), so it must be either a real user id
		// or empty. A service-account principal mints keys with no human
		// creator — the column is nullable for exactly this case.
		createdBy := ""
		if p.Kind == domain.KindUser {
			createdBy = p.ID
		}

		serviceAccountID := ""
		if req.ServiceAccountID != nil {
			serviceAccountID = *req.ServiceAccountID
		}

		correlation := telemetry.FromContext(r.Context())
		now := time.Now().UTC()
		key, err := creator.Create(r.Context(), store.CreateAPIKeyInput{
			OrganizationID:   r.PathValue("org_id"),
			Name:             req.Name,
			Scopes:           req.Scopes,
			ExpiresAt:        expiresAt,
			ServiceAccountID: serviceAccountID,
			CreatedBy:        createdBy,
			Prefix:           generated.Prefix,
			SecretHash:       generated.SecretHash,
			ActorID:          p.ID,
			ActorKind:        string(p.Kind),
			ActorOrgID:       p.OrganizationID,
			RequestID:        correlation.RequestID,
			CorrelationID:    correlation.CorrelationID,
		}, now)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusCreated, requestID(r), createAPIKeyPayload{
			APIKey: apiKeyResourceOf(key),
			Token:  generated.Token.Reveal(),
		})
	}
}

// APIKeyUpdater is the narrow persistence port PATCH
// /v1/organizations/{org_id}/api-keys/{key_id} depends on.
// *store.APIKeyService satisfies it in production; tests supply a fake. Like
// APIKeyCreator it is an interface declared here so the handler stays
// unit-testable without a real database — the concrete orchestrator (the
// tenant-scoped existence read, the partial update of the mutable fields,
// and the immutable audit record committed in one transaction) lives in the
// store layer.
type APIKeyUpdater interface {
	Update(ctx context.Context, in store.UpdateAPIKeyInput) (store.APIKey, error)
}

// updateAPIKeyRequest is the decoded PATCH
// /v1/organizations/{org_id}/api-keys/{key_id} request body. Name and Scopes
// are the currently-mutable fields on an api_keys row; the credential
// primitives (prefix and secret_hash), ownership identifiers (created_by and
// service_account_id), and lifecycle stamps (expires_at and revoked_at) are
// deliberately not part of this surface — the credential is minted once at
// create time and never re-written, ownership is fixed at mint, and lifecycle
// stamps are owned by their own dedicated endpoints (rotate and delete). The
// store layer validates every supplied value before any database work — an
// invalid request never opens a transaction — and the fields carry no
// credential material.
//
// Name and Scopes are pointers so a missing field can be distinguished from
// a supplied-but-empty one: omitting the field is "leave unchanged",
// supplying it with an invalid value (a blank name, or a malformed scope
// string) is a validation failure naming the field, and a patch that names
// no field is itself a 400 — a mutation that changes nothing is a client
// error, not a silent success.
type updateAPIKeyRequest struct {
	Name   *string   `json:"name,omitempty"`
	Scopes *[]string `json:"scopes,omitempty"`
}

// updateAPIKeyPayload is the data block of the PATCH
// /v1/organizations/{org_id}/api-keys/{key_id} success envelope: the api
// key after the mutation — including the trigger-refreshed updated_at — in
// the same stable wire shape every other api-key endpoint returns. It
// carries no credential material: the secret hash is never projected onto
// the wire, and the plaintext token is shown to its owner exactly once at
// creation and never reaches a read or update endpoint.
type updateAPIKeyPayload struct {
	APIKey apiKeyResource `json:"api_key"`
}

// apiKeyIDResolver derives the policy.Resource a PATCH (or future
// DELETE/rotate) /v1/organizations/{org_id}/api-keys/{key_id} request acts
// on from its path parameters. The resource scope is the organization the
// path names — the same scope used by the rest of the api-key endpoints —
// so action keys.manage is authorized against the tenant boundary the path
// declares. A cross-tenant {org_id} is denied at the policy boundary before
// the handler runs, so a cross-tenant key_id can never mutate another
// tenant's api-key graph.
func apiKeyIDResolver(r *http.Request) policy.Resource {
	return policy.Resource{
		Kind:  domain.KindAPIKey,
		Scope: policy.Scope{OrganizationID: r.PathValue("org_id")},
	}
}

// updateAPIKeyHandler builds the PATCH
// /v1/organizations/{org_id}/api-keys/{key_id} handler. It decodes and
// delegates: the request body is strictly decoded (oversized, malformed, or
// unknown-field bodies become a typed 400 that never echoes the input),
// then the update-api-key unit of work — read the current row, apply the
// caller-supplied fields, update the row, append the audit record, all in
// one transaction — runs in the store layer through the APIKeyUpdater port.
//
// RequireAuth gates the route on action keys.manage before the handler
// runs — authorized through apiKeyIDResolver against the organization the
// path names — and attaches the resolved principal, so a request that
// reaches the handler has already cleared the tenant boundary: a
// cross-tenant {org_id} was rejected as a 403 by the policy engine, never
// reaching this code. A request that arrives here with no principal is
// therefore a wiring error and is reported as a typed internal error. The
// principal and the request correlation identifiers are passed to the
// updater so the audit record names the actor; a validation failure (bad
// body, no fields, invalid name or scope), a not-found key (cross-tenant
// or missing row), and a datastore outage each surface as their own typed
// status, never disguised as one another.
//
// keys.manage is a CapManage action: a viewer or developer in the tenant
// cannot update an api key, only an owner or admin in the tenant can —
// unlike CapRead actions there is no cross-tenant support exception. The
// handler relies on the policy engine for that decision; it never
// re-checks the role itself.
func updateAPIKeyHandler(updater APIKeyUpdater) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if updater == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAPIKeyUpdater))
			return
		}

		var req updateAPIKeyRequest
		if err := validate.DecodeJSON(r.Body, &req, 0); err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		// A PATCH that names no mutable field is itself a client error: the
		// store layer rejects it the same way, but surfacing it here keeps
		// the handler/store contract symmetric and gives agents a stable
		// 400 for "patch with no field" before the store layer's identical
		// rejection runs. The field name in the violation matches what the
		// store layer reports, so the wire contract is identical regardless
		// of where the rejection originates.
		if req.Name == nil && req.Scopes == nil {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
				Field:  "name",
				Reason: "at least one of name or scopes must be provided",
			}))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		key, err := updater.Update(r.Context(), store.UpdateAPIKeyInput{
			OrganizationID: r.PathValue("org_id"),
			KeyID:          r.PathValue("key_id"),
			Name:           req.Name,
			Scopes:         req.Scopes,
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

		apienvelope.WriteData(w, http.StatusOK, requestID(r), updateAPIKeyPayload{
			APIKey: apiKeyResourceOf(key),
		})
	}
}

// APIKeyRevoker is the narrow persistence port DELETE
// /v1/organizations/{org_id}/api-keys/{key_id} depends on.
// *store.APIKeyService satisfies it in production; tests supply a fake. Like
// APIKeyUpdater it is an interface declared here so the handler stays
// unit-testable without a real database — the concrete orchestrator (the
// tenant-scoped existence read, the conflict check for an already-revoked
// key, the api_keys row revocation, and the immutable audit record committed
// in one transaction) lives in the store layer.
type APIKeyRevoker interface {
	Revoke(ctx context.Context, in store.RevokeAPIKeyInput, now time.Time) (store.APIKey, error)
}

// revokeAPIKeyPayload is the data block of the DELETE
// /v1/organizations/{org_id}/api-keys/{key_id} success envelope: the api key
// exactly as it stood at the moment of revocation, in the same stable wire
// shape every other api-key endpoint returns. Returning the terminal view
// (rather than 204 No Content) mirrors the members removal contract and lets
// agents and CI see the resolved revoked_at without a second request. The row
// still exists by the time the response is rendered — revocation is the
// customer-facing soft delete for an api key, not a hard delete — but the
// credential is permanently unusable from that moment on. It carries no
// credential material: the secret hash is never projected onto the wire and
// the plaintext token (the only usable credential) is shown to its owner
// once at creation and never reaches this endpoint, so a revocation endpoint
// can never reveal a credential.
type revokeAPIKeyPayload struct {
	APIKey apiKeyResource `json:"api_key"`
}

// revokeAPIKeyHandler builds the DELETE
// /v1/organizations/{org_id}/api-keys/{key_id} handler. It delegates to the
// revoke-api-key unit of work — read the current row, reject the call as a
// typed Conflict when the key is already revoked, mark it revoked, append
// the audit record, all in one transaction — which runs in the store layer
// through the APIKeyRevoker port.
//
// RequireAuth gates the route on action keys.manage before the handler runs
// — authorized through apiKeyIDResolver against the organization the path
// names — and attaches the resolved principal, so a request that reaches
// the handler has already cleared the tenant boundary: a cross-tenant
// {org_id} was rejected as a 403 by the policy engine, never reaching this
// code. A request that arrives here with no principal is therefore a wiring
// error and is reported as a typed internal error. The principal and the
// request correlation identifiers are passed to the revoker so the audit
// record names the actor; a not-found key (cross-tenant or missing row), an
// already-revoked key (typed 409), and a datastore outage each surface as
// their own typed status, never disguised as one another.
//
// keys.manage is a CapManage action: a viewer or developer in the tenant
// cannot revoke an api key, only an owner or admin in the tenant can —
// unlike CapRead actions there is no cross-tenant support exception. The
// handler relies on the policy engine for that decision; it never re-checks
// the role itself.
//
// The response is 200 OK carrying the api key exactly as it stood at the
// moment of revocation — the same wire shape every other api-key endpoint
// returns, projected from the row Postgres just stamped. revoked_at is the
// resolved revocation timestamp; updated_at reflects the trigger refresh.
// The row still exists when this returns; the body is the audit-grade record
// of which credential was retired and when, while the credential itself is
// permanently unusable from that moment on (every subsequent authentication
// attempt fails through the same uniform invalid-credentials path).
func revokeAPIKeyHandler(revoker APIKeyRevoker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if revoker == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoAPIKeyRevoker))
			return
		}

		correlation := telemetry.FromContext(r.Context())
		now := time.Now().UTC()
		key, err := revoker.Revoke(r.Context(), store.RevokeAPIKeyInput{
			OrganizationID: r.PathValue("org_id"),
			KeyID:          r.PathValue("key_id"),
			ActorID:        p.ID,
			ActorKind:      string(p.Kind),
			ActorOrgID:     p.OrganizationID,
			RequestID:      correlation.RequestID,
			CorrelationID:  correlation.CorrelationID,
		}, now)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}

		apienvelope.WriteData(w, http.StatusOK, requestID(r), revokeAPIKeyPayload{
			APIKey: apiKeyResourceOf(key),
		})
	}
}
