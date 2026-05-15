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

// errNoAPIKeyReader is returned when GET /v1/organizations/{org_id}/api-keys
// is reached without an api-key reader wired into NewHandler. Like
// errNoMembershipReader it can only happen through a wiring error — a
// programming mistake, not a client error — so the handler reports it as a
// typed internal failure rather than serving an empty or misleading list.
var errNoAPIKeyReader = errors.New("httpapi: no api key reader configured")

// APIKeyReader is the narrow persistence port GET
// /v1/organizations/{org_id}/api-keys depends on. *store.APIKeyReader satisfies
// it in production; tests supply a fake. Keeping the dependency an interface
// keeps the handler unit-testable without a real database, the same way
// MembershipReader keeps GET /v1/organizations/{org_id}/members testable.
//
// The read is tenant scoped at the persistence layer: the repository filters
// by organization_id, so a cross-tenant id simply matches no rows and yields
// an empty list. Cross-tenant rejection at the policy boundary (the deterministic
// 403 organizationIDResolver produces) keeps an attacker from probing the
// endpoint at all; the persistence-layer scoping is a defence-in-depth backstop.
type APIKeyReader interface {
	ListAPIKeys(ctx context.Context, organizationID string) ([]store.APIKey, error)
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
