package httpapi

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
)

// Contract, authorization, and tenant-isolation coverage for GET
// /v1/organizations/{org_id}/api-keys/{key_id} (BE-0082). The endpoint reads
// the single API key named by ({org_id}, {key_id}), routed through the
// APIKeyReader port; the tests drive it through NewHandler with a fake
// Authenticator, the real policy engine, and a fake reader — the same wiring
// a request hits in production, minus the database. The store-backed reader
// has its own isolated-Postgres integration coverage in store/apikey_test.go.
//
// keys.read is a CapAdmin action, not a CapRead action: a viewer or developer
// in the tenant cannot read an API key, only an owner or admin can — and
// unlike CapRead actions, support has no cross-tenant exception for
// keys.read. The happy-path tests therefore authenticate as RoleAdmin or
// RoleOwner; the support cross-tenant case asserts that the read is denied
// for a support principal exactly as the policy matrix specifies.
//
// This endpoint has no request body and no query parameters: its inputs are
// two opaque path parameters. There is therefore no syntactic request to
// reject — a key id that does not exist in the tenant surfaces as the same
// deterministic 404 a cross-tenant key id would, and an {org_id} outside
// the principal's tenant surfaces as the deterministic 403 the policy engine
// returns through organizationIDResolver. Those two paths plus the explicit
// not-found and authorization cases are the "validation", "authorization",
// and "not-found" coverage this story requires.

// getAPIKeySuccessEnvelope is the decoded shape of the GET
// /v1/organizations/{org_id}/api-keys/{key_id} success envelope.
type getAPIKeySuccessEnvelope struct {
	SchemaVersion string           `json:"schema_version"`
	OK            bool             `json:"ok"`
	RequestID     string           `json:"request_id"`
	Data          getAPIKeyPayload `json:"data"`
}

// getAPIKey issues GET /v1/organizations/{orgID}/api-keys/{keyID} against
// handler, optionally with a bearer token.
func getAPIKey(handler http.Handler, orgID, keyID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/"+orgID+"/api-keys/"+keyID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeGetAPIKey(t *testing.T, rec *httptest.ResponseRecorder) getAPIKeySuccessEnvelope {
	t.Helper()
	var env getAPIKeySuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode success envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if !env.OK {
		t.Errorf("ok = false, want true")
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want a generated id")
	}
	return env
}

// TestGetAPIKeyReturnsKey is the happy path: an authenticated admin
// principal requesting an API key in its own organization receives the key
// in a stable yalla.output.v1 envelope, with every source-of-truth field
// projected onto the wire shape. It also asserts that the secret_hash is
// never present in the rendered body.
func TestGetAPIKeyReturnsKey(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	key := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada's CLI key",
		[]string{"projects:read", "services:deploy"},
		"usr_ada", "", created, updated)
	reader := fakeAPIKeyReader{key: key}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil, reader)

	rec := getAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeGetAPIKey(t, rec)
	want := apiKeyResource{
		KeyID:     "key_ada",
		Prefix:    "yk_pf_ada",
		Name:      "Ada's CLI key",
		Scopes:    []string{"projects:read", "services:deploy"},
		CreatedBy: "usr_ada",
		CreatedAt: created.Format(time.RFC3339Nano),
		UpdatedAt: updated.Format(time.RFC3339Nano),
	}
	if !apiKeyResourceEqual(env.Data.APIKey, want) {
		t.Errorf("api_key = %+v, want %+v", env.Data.APIKey, want)
	}
	if body := rec.Body.String(); strings.Contains(body, "must-not-leak-secret-hash-sentinel") {
		t.Errorf("response body leaks the secret hash sentinel: %s", body)
	}
	if body := rec.Body.String(); strings.Contains(body, "secret_hash") {
		t.Errorf("response body carries a secret_hash field; the wire shape must omit it: %s", body)
	}
}

// TestGetAPIKeyProjectsNullableTimestampsAndScopes proves a key with each of
// the nullable timestamps set renders an RFC 3339 nanosecond timestamp, that
// a nil scopes slice renders "scopes": [] rather than "scopes": null, and that
// a service-account-owned key surfaces service_account_id on the wire.
func TestGetAPIKeyProjectsNullableTimestampsAndScopes(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)
	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	revoked := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	lastUsed := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)

	key := seedAPIKey("org_acme", "key_ci", "yk_pf_ci", "CI deploy key",
		nil, "usr_ada", "sa_ci", created, updated)
	key.ExpiresAt = &expires
	key.RevokedAt = &revoked
	key.LastUsedAt = &lastUsed

	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)}, nil,
		fakeAPIKeyReader{key: key})

	rec := getAPIKey(handler, "org_acme", "key_ci", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"scopes":[]`) {
		t.Errorf("body should render an empty scopes array; body %s", body)
	}
	if !strings.Contains(body, `"service_account_id":"sa_ci"`) {
		t.Errorf("body should carry the service_account_id; body %s", body)
	}
	if !strings.Contains(body, `"expires_at":"`+expires.Format(time.RFC3339Nano)+`"`) {
		t.Errorf("expires_at not rendered in RFC3339Nano; body %s", body)
	}
	if !strings.Contains(body, `"revoked_at":"`+revoked.Format(time.RFC3339Nano)+`"`) {
		t.Errorf("revoked_at not rendered in RFC3339Nano; body %s", body)
	}
	if !strings.Contains(body, `"last_used_at":"`+lastUsed.Format(time.RFC3339Nano)+`"`) {
		t.Errorf("last_used_at not rendered in RFC3339Nano; body %s", body)
	}
}

// TestGetAPIKeyScopesReadToPathParameters proves the handler reads exactly
// the key named by ({org_id}, {key_id}) — both path values reach the reader,
// in order, so the read is scoped to the tenant the path names and the key
// the path names, never just one or the other.
func TestGetAPIKeyScopesReadToPathParameters(t *testing.T) {
	t.Parallel()

	var gotOrg, gotKey string
	reader := fakeAPIKeyReader{
		key: seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada", nil,
			"usr_ada", "", time.Now().UTC(), time.Now().UTC()),
		gotKeyOrgID: &gotOrg,
		gotKeyID:    &gotKey,
	}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil, reader)

	rec := getAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if gotOrg != "org_acme" {
		t.Errorf("reader received organization id %q, want org_acme", gotOrg)
	}
	if gotKey != "key_ada" {
		t.Errorf("reader received key id %q, want key_ada", gotKey)
	}
}

// TestGetAPIKeyNotFoundIsStable proves a key id with no row in the tenant
// surfaces as a deterministic 404 E_NOT_FOUND — the typed contract that
// makes a cross-tenant key_id indistinguishable from a missing row.
func TestGetAPIKeyNotFoundIsStable(t *testing.T) {
	t.Parallel()

	reader := fakeAPIKeyReader{getErr: apierr.NotFound("api_key", "key_missing")}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil, reader)

	rec := getAPIKey(handler, "org_acme", "key_missing", "a-valid-session-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestGetAPIKeyCrossTenantIsForbidden proves a principal reading an API key
// of another tenant is denied with a deterministic 403 E_FORBIDDEN carrying
// the stable cross-tenant reason — and the reader is never reached, so a
// cross-tenant id can never reveal another tenant's keys or even whether
// that organization exists.
func TestGetAPIKeyCrossTenantIsForbidden(t *testing.T) {
	t.Parallel()

	var gotOrg, gotKey string
	reader := fakeAPIKeyReader{
		key: seedAPIKey("org_victim", "key_v", "yk_pf_v", "victim",
			nil, "usr_v", "", time.Now().UTC(), time.Now().UTC()),
		gotKeyOrgID: &gotOrg,
		gotKeyID:    &gotKey,
	}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner)}, nil, reader)

	rec := getAPIKey(handler, "org_victim", "key_v", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if gotOrg != "" || gotKey != "" {
		t.Errorf("reader was reached with org=%q key=%q on a cross-tenant request; it must never run", gotOrg, gotKey)
	}
	if body := rec.Body.String(); strings.Contains(body, "key_v") || strings.Contains(body, "yk_pf_v") {
		t.Errorf("forbidden response leaks victim-tenant key data: %s", body)
	}
}

// TestGetAPIKeyViewerIsForbidden proves a viewer or developer principal —
// CapRead but not CapAdmin — cannot read an API key even within its own
// tenant. keys.read is a CapAdmin action; the policy engine denies the
// request before the handler runs.
func TestGetAPIKeyViewerIsForbidden(t *testing.T) {
	t.Parallel()

	var gotOrg, gotKey string
	reader := fakeAPIKeyReader{gotKeyOrgID: &gotOrg, gotKeyID: &gotKey}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_viewer", "org_acme", policy.RoleViewer)}, nil, reader)

	rec := getAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if gotOrg != "" || gotKey != "" {
		t.Errorf("reader was reached with org=%q key=%q for an unauthorised viewer; it must never run", gotOrg, gotKey)
	}
}

// TestGetAPIKeySupportCannotReadCrossTenant proves the support principal's
// CapRead-with-support exception does NOT extend to keys.read. Unlike
// members.read (a CapRead action where the support principal can read across
// tenants by design), keys.read is a CapAdmin action — and support has only
// CapSelf, CapRead, and CapSupport. The cross-tenant attempt is therefore a
// stable 403 E_FORBIDDEN, and the reader is never reached. Privileged Yalla
// support that needs key visibility goes through the explicit break-glass
// admin tooling, not this customer-facing endpoint.
func TestGetAPIKeySupportCannotReadCrossTenant(t *testing.T) {
	t.Parallel()

	var gotOrg, gotKey string
	reader := fakeAPIKeyReader{
		key: seedAPIKey("org_customer", "key_c", "yk_pf_c", "customer",
			[]string{"projects:read"}, "usr_c", "", time.Now().UTC(), time.Now().UTC()),
		gotKeyOrgID: &gotOrg,
		gotKeyID:    &gotKey,
	}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_support", "org_yalla", policy.RoleSupport)}, nil, reader)

	rec := getAPIKey(handler, "org_customer", "key_c", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if gotOrg != "" || gotKey != "" {
		t.Errorf("reader was reached with org=%q key=%q for support cross-tenant read; it must never run", gotOrg, gotKey)
	}
	if body := rec.Body.String(); strings.Contains(body, "key_c") || strings.Contains(body, "yk_pf_c") {
		t.Errorf("forbidden response leaks customer-tenant key data: %s", body)
	}
}

// TestGetAPIKeyRequiresAuthentication proves a request with no credential is
// a stable 401 E_AUTH and never reaches the reader.
func TestGetAPIKeyRequiresAuthentication(t *testing.T) {
	t.Parallel()

	handler := listAPIKeysHandlerFor(auth.Identity{}, nil,
		fakeAPIKeyReader{getErr: stderrors.New("reader must not be called")})

	rec := getAPIKey(handler, "org_acme", "key_ada", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_AUTH")
	if env.Error.Message != "authentication is required" {
		t.Errorf("message = %q, want %q", env.Error.Message, "authentication is required")
	}
}

// TestGetAPIKeyInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH — identical to the missing-credential contract.
func TestGetAPIKeyInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := listAPIKeysHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeAPIKeyReader{getErr: stderrors.New("reader must not be called")})

	rec := getAPIKey(handler, "org_acme", "key_ada", "yk_bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestGetAPIKeyDisabledPrincipal proves a revoked or expired credential
// surfaces as a disabled principal and is denied with a 403 E_FORBIDDEN
// carrying the stable reason — and the reader is never reached.
func TestGetAPIKeyDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	handler := listAPIKeysHandlerFor(auth.Identity{Principal: disabled}, nil,
		fakeAPIKeyReader{getErr: stderrors.New("reader must not be called")})

	rec := getAPIKey(handler, "org_acme", "key_ada", "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestGetAPIKeyReaderUnavailable proves a datastore outage surfaces as its
// own typed 5xx, never disguised as a not-found or an empty success — and
// the wrapped driver cause never reaches the user-facing message.
func TestGetAPIKeyReaderUnavailable(t *testing.T) {
	t.Parallel()

	reader := fakeAPIKeyReader{
		getErr: apierr.StoreUnavailable(stderrors.New("connection refused")),
	}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil, reader)

	rec := getAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection refused") {
		t.Errorf("error message %q leaks the wrapped datastore cause", env.Error.Message)
	}
}

// TestGetAPIKeyHandlerWithNilReaderIsInternal proves a route registered
// without an api-key reader is a wiring error reported as a typed internal
// failure — never a misleading not-found. The bare handler is dispatched
// through telemetry.Correlate via the run helper so a request_id is resolved
// even though the test is bypassing the full RequireAuth middleware (the
// handler is invoked with a principal pre-attached to the request context).
func TestGetAPIKeyHandlerWithNilReaderIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme/api-keys/key_ada", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)))
	rec := run(getAPIKeyHandler(nil), req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestGetAPIKeyPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestGetAPIKeyPropagatesRequestID(t *testing.T) {
	t.Parallel()

	reader := fakeAPIKeyReader{key: seedAPIKey(
		"org_acme", "key_ada", "yk_pf_ada", "Ada's CLI key", nil,
		"usr_ada", "", time.Now().UTC(), time.Now().UTC(),
	)}
	handler := listAPIKeysHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)}, nil, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/organizations/org_acme/api-keys/key_ada", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set("X-Request-Id", "req-from-client-12345")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Request-Id"); got != "req-from-client-12345" {
		t.Errorf("X-Request-Id header = %q, want the echoed inbound id", got)
	}
	env := decodeGetAPIKey(t, rec)
	if env.RequestID != "req-from-client-12345" {
		t.Errorf("envelope request_id = %q, want the echoed inbound id", env.RequestID)
	}
}

// TestGetAPIKeyIsDocumentedInOpenAPI proves the served route is also a
// documented route: GET /v1/organizations/{org_id}/api-keys/{key_id} appears
// in the OpenAPI document requiring the API-key security scheme, naming its
// policy action through the x-required-action extension, declaring both
// {org_id} and {key_id} path parameters, and documenting a 200 success
// response.
func TestGetAPIKeyIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := listAPIKeysHandlerFor(auth.Identity{}, nil, fakeAPIKeyReader{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	paths, _ := doc["paths"].(map[string]any)
	path, _ := paths["/v1/organizations/{org_id}/api-keys/{key_id}"].(map[string]any)
	op, _ := path["get"].(map[string]any)
	if op == nil {
		t.Fatalf("GET /v1/organizations/{org_id}/api-keys/{key_id} missing from openapi.json: %s", rec.Body.String())
	}
	if got, _ := op["operationId"].(string); got != "getOrganizationAPIKey" {
		t.Errorf("operationId = %q, want getOrganizationAPIKey", got)
	}
	if got, _ := op["x-required-action"].(string); got != string(policy.ActionKeysRead) {
		t.Errorf("x-required-action = %q, want %q", got, policy.ActionKeysRead)
	}
	security, _ := op["security"].([]any)
	if len(security) == 0 {
		t.Errorf("operation security = %v, want a non-empty requirement (route is authenticated)", security)
	}
	responses, _ := op["responses"].(map[string]any)
	if _, ok := responses["200"]; !ok {
		t.Errorf("operation responses = %v, want a documented 200", responses)
	}
	params, _ := op["parameters"].([]any)
	gotParams := map[string]bool{}
	for _, p := range params {
		if m, ok := p.(map[string]any); ok {
			if name, _ := m["name"].(string); name != "" {
				gotParams[name] = true
			}
		}
	}
	if !gotParams["org_id"] {
		t.Errorf("operation parameters missing org_id; got %v", gotParams)
	}
	if !gotParams["key_id"] {
		t.Errorf("operation parameters missing key_id; got %v", gotParams)
	}
}
