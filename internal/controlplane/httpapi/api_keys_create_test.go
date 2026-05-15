package httpapi

import (
	"context"
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
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// Contract, authorization, and wiring coverage for POST
// /v1/organizations/{org_id}/api-keys (BE-0079). The endpoint mints a fresh
// credential, persists the api-keys row through the APIKeyCreator port, and
// returns the persisted projection together with the one-time plaintext
// token. The tests drive it through NewHandler with a fake Authenticator,
// the real policy engine, and a fake creator — the same wiring a request
// hits in production, minus the database. The store-backed orchestrator
// (store.APIKeyService) has its own isolated-Postgres integration coverage
// in store/apikeyservice_test.go and white-box validation coverage in
// store/apikeyservice_internal_test.go.

// createAPIKeySuccessEnvelope is the decoded shape of the POST
// /v1/organizations/{org_id}/api-keys success envelope.
type createAPIKeySuccessEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	OK            bool                `json:"ok"`
	RequestID     string              `json:"request_id"`
	Data          createAPIKeyPayload `json:"data"`
}

// createAPIKeyHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// APIKeyCreator. It is the production request path: the POST
// /v1/organizations/{org_id}/api-keys route is wrapped in RequireAuth for
// action keys.manage and goes through organizationIDResolver.
func createAPIKeyHandlerFor(id auth.Identity, authErr error, creator APIKeyCreator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeAPIKeyReader{}, creator, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, nil)
}

// postAPIKey issues POST /v1/organizations/{orgID}/api-keys against handler
// with body, optionally with a bearer token.
func postAPIKey(handler http.Handler, orgID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/organizations/"+orgID+"/api-keys", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCreateAPIKey(t *testing.T, rec *httptest.ResponseRecorder) createAPIKeySuccessEnvelope {
	t.Helper()
	var env createAPIKeySuccessEnvelope
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

// TestCreateAPIKeySuccess is the happy path: a valid request mints the key,
// the handler returns 201 with the stable yalla.output.v1 envelope, the
// plaintext token is surfaced exactly once, and every store-layer input —
// including the server-minted Prefix and SecretHash — is forwarded
// unchanged. The persisted projection never exposes the secret_hash.
func TestCreateAPIKeySuccess(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		[]string{"projects:read", "services:deploy"},
		"usr_ada", "", now, now)

	var got store.CreateAPIKeyInput
	creator := fakeAPIKeyCreator{key: persisted, got: &got}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postAPIKey(handler, "org_acme", "a-valid-session-token",
		`{"name":"Ada CLI","scopes":["projects:read","services:deploy"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateAPIKey(t, rec)

	// The persisted projection is rendered verbatim from the store.APIKey
	// the creator returns.
	if env.Data.APIKey.KeyID != "key_ada" || env.Data.APIKey.Prefix != "yk_pf_ada" {
		t.Errorf("response api_key = %+v, want the persisted key", env.Data.APIKey)
	}
	if env.Data.APIKey.Name != "Ada CLI" {
		t.Errorf("response name = %q, want %q", env.Data.APIKey.Name, "Ada CLI")
	}
	// The plaintext token is present, of the documented shape, and is not
	// the redaction sentinel.
	if env.Data.Token == "" {
		t.Fatal("response token is empty, want a one-time plaintext")
	}
	if !strings.HasPrefix(env.Data.Token, "yk_") {
		t.Errorf("response token %q does not carry the documented yk_ namespace", env.Data.Token)
	}
	if strings.Contains(env.Data.Token, "REDACTED") {
		t.Errorf("response token is the redaction sentinel; the handler must Reveal() the plaintext")
	}

	// The secret_hash sentinel from seedAPIKey must never appear in the
	// rendered body — the wire projection drops the hash by design.
	if strings.Contains(rec.Body.String(), "must-not-leak-secret-hash-sentinel") {
		t.Errorf("response body leaks the secret_hash sentinel: %s", rec.Body.String())
	}

	// The handler forwards the validated request and the authenticated
	// actor unchanged. The (Prefix, SecretHash) pair is server-minted via
	// auth.Generate and must be non-empty before reaching the store layer.
	if got.OrganizationID != "org_acme" {
		t.Errorf("creator org_id = %q, want %q", got.OrganizationID, "org_acme")
	}
	if got.Name != "Ada CLI" {
		t.Errorf("creator name = %q, want %q", got.Name, "Ada CLI")
	}
	if got.CreatedBy != "usr_ada" {
		t.Errorf("creator created_by = %q, want the authenticated user id", got.CreatedBy)
	}
	if !strings.HasPrefix(got.Prefix, "yk_") || got.SecretHash == "" {
		t.Errorf("creator input prefix/hash = %q/%q, want server-minted credential primitives", got.Prefix, got.SecretHash)
	}
	if got.Prefix == got.SecretHash {
		t.Errorf("creator input prefix == secret_hash; the auth layer must produce distinct primitives")
	}
	if got.ActorID != "usr_ada" {
		t.Errorf("creator actor_id = %q, want the principal id", got.ActorID)
	}
}

// TestCreateAPIKeyWithExpiresAtAndServiceAccount proves the optional fields
// are accepted and forwarded: an RFC 3339 expires_at parses into the
// CreateAPIKeyInput, a non-empty service_account_id transfers ownership of
// the key, and an empty/nil scopes list is accepted.
func TestCreateAPIKeyWithExpiresAtAndServiceAccount(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	persisted := seedAPIKey("org_acme", "key_ci", "yk_pf_ci", "CI Deploy",
		[]string{}, "usr_ada", "sa_ci", now, now)

	var got store.CreateAPIKeyInput
	creator := fakeAPIKeyCreator{key: persisted, got: &got}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postAPIKey(handler, "org_acme", "a-valid-session-token",
		`{"name":"CI Deploy","expires_at":"2026-12-31T23:59:59Z","service_account_id":"sa_ci"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if got.ExpiresAt == nil || got.ExpiresAt.Year() != 2026 || got.ExpiresAt.Month() != time.December {
		t.Errorf("creator expires_at = %v, want 2026-12-31T23:59:59Z", got.ExpiresAt)
	}
	if got.ServiceAccountID != "sa_ci" {
		t.Errorf("creator service_account_id = %q, want sa_ci", got.ServiceAccountID)
	}
}

// TestCreateAPIKeyMalformedExpiresAtIsTyped400 proves a non-RFC-3339
// expires_at is a deterministic 400 naming the field, never forwarded to
// the store layer (which has its own future-time check but should not be
// asked to re-parse).
func TestCreateAPIKeyMalformedExpiresAtIsTyped400(t *testing.T) {
	t.Parallel()

	called := false
	creator := apiKeyCreatorFn(func(_ context.Context, _ store.CreateAPIKeyInput, _ time.Time) (store.APIKey, error) {
		called = true
		return store.APIKey{}, nil
	})
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postAPIKey(handler, "org_acme", "a-valid-session-token",
		`{"name":"Bad","expires_at":"not-a-timestamp"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	body := rec.Body.String()
	if !strings.Contains(body, "expires_at") {
		t.Errorf("error body %q does not name the offending field", body)
	}
	if strings.Contains(body, "not-a-timestamp") {
		t.Errorf("error body %q echoes the rejected value", body)
	}
	if called {
		t.Error("creator was called for a request that should have been rejected at the handler")
	}
}

// TestCreateAPIKeyMalformedBodyIsTyped400 proves an oversized, malformed,
// or unknown-field body is a typed 400 — never echoes the input.
func TestCreateAPIKeyMalformedBodyIsTyped400(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{"unparseable json", `{"name": "x"`},
		{"unknown field", `{"name":"x","secret":"smuggled"}`},
		{"trailing data", `{"name":"x"}garbage`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			creator := fakeAPIKeyCreator{err: stderrors.New("creator must not be called")}
			handler := createAPIKeyHandlerFor(
				auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
				nil, creator)

			rec := postAPIKey(handler, "org_acme", "a-valid-session-token", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			decodeError(t, rec, "E_INVALID_INPUT")
		})
	}
}

// TestCreateAPIKeyValidationFailureFromStore proves a typed InvalidInput
// from the store-layer validator surfaces as 400 E_INVALID_INPUT, never
// disguised as a 500 or a success — the AC's "validation failure" path.
func TestCreateAPIKeyValidationFailureFromStore(t *testing.T) {
	t.Parallel()

	creator := fakeAPIKeyCreator{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "name",
		Reason: "must not be blank",
	})}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postAPIKey(handler, "org_acme", "a-valid-session-token",
		`{"name":"   ","scopes":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestCreateAPIKeyOrgNotFound proves an unknown organization id surfaces
// as the typed 404 E_NOT_FOUND the store layer produces — exactly the AC's
// "not-found" path.
func TestCreateAPIKeyOrgNotFound(t *testing.T) {
	t.Parallel()

	creator := fakeAPIKeyCreator{err: apierr.NotFound("organization", "org_ghost")}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	// The path uses org_acme (the principal's home org) so policy admits the
	// request; the store-layer NotFound is what triggers the 404 — this
	// exercises the typed-error mapping, not the policy boundary (which has
	// its own dedicated tests below).
	rec := postAPIKey(handler, "org_acme", "a-valid-session-token",
		`{"name":"Doomed"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestCreateAPIKeyServiceAccountNotFound proves a service_account_id that
// the store-layer existence check rejects is a stable 404, the same shape
// a missing organization produces.
func TestCreateAPIKeyServiceAccountNotFound(t *testing.T) {
	t.Parallel()

	creator := fakeAPIKeyCreator{err: apierr.NotFound("service_account", "sa_ghost")}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postAPIKey(handler, "org_acme", "a-valid-session-token",
		`{"name":"CI","service_account_id":"sa_ghost"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestCreateAPIKeyUnauthenticated proves a request with no credential is
// a stable 401 E_AUTH and never reaches the handler — the creator is
// never called.
func TestCreateAPIKeyUnauthenticated(t *testing.T) {
	t.Parallel()

	creator := fakeAPIKeyCreator{err: stderrors.New("creator must not be called")}
	handler := createAPIKeyHandlerFor(auth.Identity{}, nil, creator)
	rec := postAPIKey(handler, "org_acme", "", `{"name":"x"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestCreateAPIKeyInvalidCredentials proves an unverifiable credential is
// a stable 401 — identical to the missing-credential contract.
func TestCreateAPIKeyInvalidCredentials(t *testing.T) {
	t.Parallel()

	creator := fakeAPIKeyCreator{err: stderrors.New("creator must not be called")}
	handler := createAPIKeyHandlerFor(auth.Identity{}, apierr.Unauthenticated("invalid api key token"), creator)
	rec := postAPIKey(handler, "org_acme", "an-unverifiable-token", `{"name":"x"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestCreateAPIKeyCrossTenantIsForbidden proves a principal in one tenant
// minting a key in another is denied with a deterministic 403 carrying the
// stable cross-tenant reason — the AC's "authorization failure" path —
// and the creator is never reached. The error never echoes the foreign
// org id.
func TestCreateAPIKeyCrossTenantIsForbidden(t *testing.T) {
	t.Parallel()

	creator := fakeAPIKeyCreator{err: stderrors.New("creator must not be called")}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postAPIKey(handler, "org_victim", "a-valid-session-token", `{"name":"intruder"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedCrossTenant)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedCrossTenant)
	}
	if strings.Contains(env.Error.Message, "org_victim") {
		t.Errorf("error message %q echoes the cross-tenant organization id", env.Error.Message)
	}
}

// TestCreateAPIKeyDisabledPrincipal proves a revoked or expired credential
// surfaces as a disabled principal and is denied with a 403 carrying the
// stable reason — and the creator is never reached.
func TestCreateAPIKeyDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	creator := fakeAPIKeyCreator{err: stderrors.New("creator must not be called")}
	handler := createAPIKeyHandlerFor(auth.Identity{Principal: disabled, Method: auth.MethodSession}, nil, creator)

	rec := postAPIKey(handler, "org_acme", "a-revoked-session-token", `{"name":"x"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_FORBIDDEN")
	if !strings.Contains(env.Error.Message, string(policy.ReasonDeniedPrincipalDisabled)) {
		t.Errorf("message = %q, want it to carry the stable reason %q",
			env.Error.Message, policy.ReasonDeniedPrincipalDisabled)
	}
}

// TestCreateAPIKeyDependencyFailureIsTyped5xx proves a datastore outage
// surfaces as its own typed 5xx — never disguised as a 400, a 409, or a
// success — and the wrapped driver cause never reaches the user-facing
// message (no connection string, no credential leak).
func TestCreateAPIKeyDependencyFailureIsTyped5xx(t *testing.T) {
	t.Parallel()

	creator := fakeAPIKeyCreator{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postAPIKey(handler, "org_acme", "a-valid-session-token", `{"name":"x"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection refused") {
		t.Errorf("error message %q leaks the wrapped datastore cause", env.Error.Message)
	}
}

// TestCreateAPIKeyPropagatesRequestID proves the resolved request_id
// reaches both the response envelope and the echoed response header — a
// per-request correlation contract the agent SDK relies on.
func TestCreateAPIKeyPropagatesRequestID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		nil, "usr_ada", "", now, now)
	creator := fakeAPIKeyCreator{key: persisted}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations/org_acme/api-keys",
		strings.NewReader(`{"name":"Ada CLI"}`))
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set(telemetry.HeaderRequestID, "caller-supplied-id")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateAPIKey(t, rec)
	if env.RequestID != "caller-supplied-id" {
		t.Errorf("envelope request_id = %q, want caller-supplied-id", env.RequestID)
	}
	if got := rec.Header().Get(telemetry.HeaderRequestID); got != "caller-supplied-id" {
		t.Errorf("response header request_id = %q, want caller-supplied-id", got)
	}
}

// TestCreateAPIKeyHandlerWithoutPrincipalIsInternal proves the defensive
// path: if the handler is ever reached without RequireAuth having placed a
// principal on the context, it reports a typed internal error rather than
// minting a credential for a zero principal.
func TestCreateAPIKeyHandlerWithoutPrincipalIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations/org_acme/api-keys",
		strings.NewReader(`{"name":"x"}`))
	rec := run(createAPIKeyHandler(fakeAPIKeyCreator{}), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestCreateAPIKeyHandlerWithNilCreatorIsInternal proves a route registered
// without an api-key creator is a wiring error reported as a typed internal
// failure — never a silently dropped mint.
func TestCreateAPIKeyHandlerWithNilCreatorIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/v1/organizations/org_acme/api-keys",
		strings.NewReader(`{"name":"x"}`))
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)))
	rec := run(createAPIKeyHandler(nil), req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestCreateAPIKeyIsDocumentedInOpenAPI proves the served route is also a
// documented route: POST /v1/organizations/{org_id}/api-keys appears in
// the OpenAPI document requiring the API-key security scheme, naming its
// policy action through the x-required-action extension, declaring the
// {org_id} path parameter, and documenting a 201 success response.
func TestCreateAPIKeyIsDocumentedInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := createAPIKeyHandlerFor(auth.Identity{}, nil, fakeAPIKeyCreator{})
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
	path, _ := paths["/v1/organizations/{org_id}/api-keys"].(map[string]any)
	op, _ := path["post"].(map[string]any)
	if op == nil {
		t.Fatalf("POST /v1/organizations/{org_id}/api-keys missing from openapi.json: %s", rec.Body.String())
	}
	if got, _ := op["x-required-action"].(string); got != string(policy.ActionKeysManage) {
		t.Errorf("x-required-action = %q, want %q", got, policy.ActionKeysManage)
	}
	security, _ := op["security"].([]any)
	if len(security) == 0 {
		t.Errorf("operation security = %v, want a non-empty requirement (route is authenticated)", security)
	}
	responses, _ := op["responses"].(map[string]any)
	if _, ok := responses["201"]; !ok {
		t.Errorf("operation responses = %v, want a documented 201", responses)
	}
}

// TestCreateAPIKeyTokenIsNotPersisted is a guard against a future
// regression: the plaintext token must reach the response body but must
// never appear anywhere else — not the persisted projection, not the
// response headers, not the secret_hash field. The fake creator returns a
// fixed projection so we can prove the token is only in the documented
// place.
func TestCreateAPIKeyTokenIsNotPersisted(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		nil, "usr_ada", "", now, now)
	creator := fakeAPIKeyCreator{key: persisted}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, creator)

	rec := postAPIKey(handler, "org_acme", "a-valid-session-token", `{"name":"Ada CLI"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateAPIKey(t, rec)
	token := env.Data.Token
	if token == "" {
		t.Fatal("token is empty, want a plaintext credential")
	}
	// The token must not appear anywhere except the dedicated field.
	body := rec.Body.String()
	if strings.Count(body, token) != 1 {
		t.Errorf("token appears %d times in body, want exactly 1 (the dedicated field)", strings.Count(body, token))
	}
	for _, header := range []string{"Authorization", telemetry.HeaderRequestID, "Set-Cookie"} {
		if v := rec.Header().Get(header); v != "" && strings.Contains(v, token) {
			t.Errorf("response header %s leaks the plaintext token: %q", header, v)
		}
	}
}

// TestCreateAPIKeyHandlerMintsDistinctCredentials is a guard on the
// auth-layer wiring: two consecutive requests must mint distinct (Prefix,
// SecretHash) pairs. The handler routes through auth.Generate every
// request, so a regression that reused entropy across requests would
// fail here. The plaintext tokens in the responses are exposed only
// through Token.Reveal(), so this also proves the explicit-reveal path
// works under normal usage.
func TestCreateAPIKeyHandlerMintsDistinctCredentials(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		nil, "usr_ada", "", now, now)
	var got1, got2 store.CreateAPIKeyInput
	creator1 := fakeAPIKeyCreator{key: persisted, got: &got1}
	creator2 := fakeAPIKeyCreator{key: persisted, got: &got2}

	for _, pair := range []struct {
		c   APIKeyCreator
		got *store.CreateAPIKeyInput
	}{{creator1, &got1}, {creator2, &got2}} {
		handler := createAPIKeyHandlerFor(
			auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
			nil, pair.c)
		rec := postAPIKey(handler, "org_acme", "a-valid-session-token", `{"name":"Ada CLI"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
		}
	}
	if got1.Prefix == got2.Prefix || got1.SecretHash == got2.SecretHash {
		t.Errorf("two consecutive mints produced identical primitives: prefixes equal=%t hashes equal=%t",
			got1.Prefix == got2.Prefix, got1.SecretHash == got2.SecretHash)
	}
}

// TestCreateAPIKeyServiceAccountActorHasEmptyCreatedBy proves a service
// account minting a key produces an api_keys row with no human creator —
// the api_keys.created_by column stores SQL NULL. The handler must not
// populate CreatedBy with the SA id (that column references users(id)).
func TestCreateAPIKeyServiceAccountActorHasEmptyCreatedBy(t *testing.T) {
	t.Parallel()

	saPrincipal := policy.Principal{
		ID:             "sa_ci",
		Kind:           "sa",
		OrganizationID: "org_acme",
		Role:           policy.RoleAdmin,
	}
	now := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC)
	persisted := seedAPIKey("org_acme", "key_new", "yk_pf_new", "New", nil, "", "sa_ci", now, now)

	var got store.CreateAPIKeyInput
	creator := fakeAPIKeyCreator{key: persisted, got: &got}
	handler := createAPIKeyHandlerFor(
		auth.Identity{Principal: saPrincipal, Method: auth.MethodAPIKey},
		nil, creator)

	rec := postAPIKey(handler, "org_acme", "a-valid-api-key", `{"name":"New"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if got.CreatedBy != "" {
		t.Errorf("creator created_by = %q, want empty for a service-account actor", got.CreatedBy)
	}
	if got.ActorID != "sa_ci" || got.ActorKind != "sa" {
		t.Errorf("creator actor = %q/%q, want sa_ci/sa", got.ActorID, got.ActorKind)
	}
}

// apiKeyCreatorFn is a function-valued APIKeyCreator, useful when a test
// needs to observe whether the creator was invoked without storing the
// last input. fakeAPIKeyCreator is the canned struct for everything else.
type apiKeyCreatorFn func(ctx context.Context, in store.CreateAPIKeyInput, now time.Time) (store.APIKey, error)

func (f apiKeyCreatorFn) Create(ctx context.Context, in store.CreateAPIKeyInput, now time.Time) (store.APIKey, error) {
	return f(ctx, in, now)
}
