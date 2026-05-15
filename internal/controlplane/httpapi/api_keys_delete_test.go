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
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Contract, authorization, and tenant-isolation coverage for DELETE
// /v1/organizations/{org_id}/api-keys/{key_id} (BE-0088). The endpoint
// revokes the api key named by ({org_id}, {key_id}) through the APIKeyRevoker
// port; the tests drive it through NewHandler with a fake Authenticator, the
// real policy engine, and a fake revoker — the same wiring a request hits in
// production, minus the database. The store-backed revoker has its own
// isolated-Postgres integration coverage in store/apikeyservice_test.go.
//
// keys.manage is a CapManage action: a viewer or developer in the tenant
// cannot revoke an API key, only an owner or admin in the tenant can — and
// unlike CapRead actions there is no cross-tenant support exception. The
// happy-path tests therefore authenticate as RoleAdmin or RoleOwner; the
// authorization matrix lives in api_keys_delete_policy_test.go (BE-0090).
//
// Validation surface: this endpoint has no request body and no query
// parameters. Its only input is the {org_id} / {key_id} path-parameter pair,
// an opaque identifier — a malformed or unknown id surfaces as a 404 from
// the store layer when the principal is authorized for the tenant, or, for
// an id outside the principal's tenant, as the deterministic 403 the policy
// engine returns through apiKeyIDResolver. Those two paths are the
// "validation" and "authorization" coverage for this story.

// revokeAPIKeySuccessEnvelope is the decoded shape of the DELETE
// /v1/organizations/{org_id}/api-keys/{key_id} success envelope.
type revokeAPIKeySuccessEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	OK            bool                `json:"ok"`
	RequestID     string              `json:"request_id"`
	Data          revokeAPIKeyPayload `json:"data"`
}

// revokeAPIKeyHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// APIKeyRevoker. It is the production request path: the DELETE
// /v1/organizations/{org_id}/api-keys/{key_id} route is wrapped in
// RequireAuth for action keys.manage and goes through apiKeyIDResolver.
func revokeAPIKeyHandlerFor(id auth.Identity, authErr error, revoker APIKeyRevoker) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, revoker, fakeAPIKeyRotator{}, nil)
}

// deleteAPIKey issues DELETE /v1/organizations/{orgID}/api-keys/{keyID}
// against handler, optionally with a bearer token.
func deleteAPIKey(handler http.Handler, orgID, keyID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete,
		"/v1/organizations/"+orgID+"/api-keys/"+keyID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeRevokeAPIKey(t *testing.T, rec *httptest.ResponseRecorder) revokeAPIKeySuccessEnvelope {
	t.Helper()
	var env revokeAPIKeySuccessEnvelope
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

// TestRevokeAPIKeyReturnsRevokedKey is the happy path: an authenticated
// admin principal revoking its own organization's api key receives the
// row exactly as it stood at the moment of revocation, in a stable
// yalla.output.v1 envelope projecting every source-of-truth field onto
// the wire — including the resolved revoked_at stamp. The secret_hash
// sentinel must never appear in the rendered body.
func TestRevokeAPIKeyReturnsRevokedKey(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	revokedAt := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		[]string{"projects:read"}, "usr_ada", "", created, updated)
	persisted.RevokedAt = &revokedAt

	var got store.RevokeAPIKeyInput
	revoker := fakeAPIKeyRevoker{key: persisted, got: &got}
	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, revoker)

	rec := deleteAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}

	env := decodeRevokeAPIKey(t, rec)
	if env.Data.APIKey.KeyID != "key_ada" {
		t.Errorf("api_key.key_id = %q, want key_ada", env.Data.APIKey.KeyID)
	}
	if env.Data.APIKey.RevokedAt != revokedAt.Format(time.RFC3339Nano) {
		t.Errorf("api_key.revoked_at = %q, want the resolved revocation timestamp",
			env.Data.APIKey.RevokedAt)
	}
	// The handler must forward the path params and the authenticated actor
	// verbatim to the revoker.
	if got.OrganizationID != "org_acme" {
		t.Errorf("revoker org_id = %q, want org_acme", got.OrganizationID)
	}
	if got.KeyID != "key_ada" {
		t.Errorf("revoker key_id = %q, want key_ada", got.KeyID)
	}
	if got.ActorID != "usr_ada" {
		t.Errorf("revoker actor_id = %q, want usr_ada", got.ActorID)
	}
	if got.ActorOrgID != "org_acme" {
		t.Errorf("revoker actor_org_id = %q, want org_acme", got.ActorOrgID)
	}
	// The secret hash sentinel must never appear in the rendered body.
	if strings.Contains(rec.Body.String(), "must-not-leak-secret-hash-sentinel") {
		t.Errorf("response body leaked secret_hash; body=%s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret_hash") {
		t.Errorf("response body carries a secret_hash field; the wire shape must omit it: %s", rec.Body.String())
	}
}

// TestRevokeAPIKeyForwardsCorrelationToRevoker proves the request_id and
// correlation_id resolved by the telemetry middleware reach the store layer
// verbatim — the audit record the unit of work writes must name the same
// correlation ids the response envelope reports.
func TestRevokeAPIKeyForwardsCorrelationToRevoker(t *testing.T) {
	t.Parallel()

	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		[]string{}, "usr_ada", "",
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC))

	var got store.RevokeAPIKeyInput
	revoker := fakeAPIKeyRevoker{key: persisted, got: &got}
	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, revoker)

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/organizations/org_acme/api-keys/key_ada", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set("X-Request-Id", "req-from-client-99")
	req.Header.Set("X-Correlation-Id", "corr-from-client-99")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got.RequestID != "req-from-client-99" {
		t.Errorf("revoker request_id = %q, want the echoed inbound id", got.RequestID)
	}
	if got.CorrelationID != "corr-from-client-99" {
		t.Errorf("revoker correlation_id = %q, want the echoed inbound id", got.CorrelationID)
	}
}

// TestRevokeAPIKeyForwardsNotFound asserts that a typed NotFound from the
// store layer (cross-tenant key_id or simply missing row) surfaces as a
// deterministic 404 — never as a 5xx and never disguised as a 403, so an
// attacker cannot use the endpoint as a presence oracle for keys in
// another tenant.
func TestRevokeAPIKeyForwardsNotFound(t *testing.T) {
	t.Parallel()

	revoker := fakeAPIKeyRevoker{err: apierr.NotFound("api_key", "key_ghost")}
	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, revoker)

	rec := deleteAPIKey(handler, "org_acme", "key_ghost", "a-valid-session-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestRevokeAPIKeyForwardsAlreadyRevokedConflict asserts that a typed
// Conflict from the store layer (re-revoking an already-revoked key)
// surfaces as a deterministic 409. The caller's view of the resource
// lifecycle is stale, so the endpoint reports that — never disguised as a
// silent success that would write a misleading audit record.
func TestRevokeAPIKeyForwardsAlreadyRevokedConflict(t *testing.T) {
	t.Parallel()

	revoker := fakeAPIKeyRevoker{err: apierr.Conflict("api key is already revoked")}
	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, revoker)

	rec := deleteAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
}

// TestRevokeAPIKeyForwardsStoreValidationError proves that a typed
// InvalidInput from the store layer (for example an id-shape violation)
// surfaces as the 400 it was built as — never disguised as a 5xx or
// swallowed. The handler's job is only to forward the typed error.
func TestRevokeAPIKeyForwardsStoreValidationError(t *testing.T) {
	t.Parallel()

	revoker := fakeAPIKeyRevoker{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "key_id",
		Reason: "must be a valid api key identifier",
	})}
	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, revoker)

	rec := deleteAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "key_id") {
		t.Errorf("body does not name the failing field: %s", rec.Body.String())
	}
}

// TestRevokeAPIKeyForwardsStoreOutage proves that a typed StoreUnavailable
// surfaces as a 5xx — never disguised as a 404 or 409. The endpoint must
// distinguish "the key is not here" from "the database is not here" so
// operators have an unambiguous signal, and the wrapped driver cause must
// never reach the user-facing message.
func TestRevokeAPIKeyForwardsStoreOutage(t *testing.T) {
	t.Parallel()

	revoker := fakeAPIKeyRevoker{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, revoker)

	rec := deleteAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want 5xx; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("body leaked the outage cause: %s", rec.Body.String())
	}
}

// TestRevokeAPIKeyRejectsUnauthenticated proves an anonymous request is
// rejected as 401 by the auth middleware before the handler runs — the
// revoker must not be invoked.
func TestRevokeAPIKeyRejectsUnauthenticated(t *testing.T) {
	t.Parallel()

	revoker := fakeAPIKeyRevoker{err: stderrors.New("revoker must not be called")}
	handler := revokeAPIKeyHandlerFor(auth.Identity{}, nil, revoker)

	rec := deleteAPIKey(handler, "org_acme", "key_ada", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
}

// TestRevokeAPIKeyInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH — identical to the missing-credential contract.
func TestRevokeAPIKeyInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := revokeAPIKeyHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeAPIKeyRevoker{err: stderrors.New("revoker must not be called")})

	rec := deleteAPIKey(handler, "org_acme", "key_ada", "yk_bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestRevokeAPIKeyDeniesCrossTenant proves the policy engine rejects a
// principal revoking a key in another organization with a deterministic
// 403 — the revoker must not be invoked. The check happens at the policy
// boundary (apiKeyIDResolver) before the handler runs, so a cross-tenant
// {org_id} can never mutate another tenant's api-key graph.
func TestRevokeAPIKeyDeniesCrossTenant(t *testing.T) {
	t.Parallel()

	revoker := fakeAPIKeyRevoker{err: stderrors.New("revoker must not be called")}
	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner), Method: auth.MethodSession},
		nil, revoker)

	rec := deleteAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
}

// TestRevokeAPIKeyDeniesViewer proves that a viewer in the tenant cannot
// revoke the organization's api key — keys.manage is a CapManage action.
// The policy engine returns 403; the revoker must not be invoked.
func TestRevokeAPIKeyDeniesViewer(t *testing.T) {
	t.Parallel()

	revoker := fakeAPIKeyRevoker{err: stderrors.New("revoker must not be called")}
	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_eve", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, revoker)

	rec := deleteAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
}

// TestRevokeAPIKeyDisabledPrincipal proves a principal authenticated against
// a token but flagged as a disabled principal is denied with a 403
// E_FORBIDDEN — and the revoker is never reached.
func TestRevokeAPIKeyDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	handler := revokeAPIKeyHandlerFor(auth.Identity{Principal: disabled}, nil,
		fakeAPIKeyRevoker{err: stderrors.New("revoker must not be called")})

	rec := deleteAPIKey(handler, "org_acme", "key_ada", "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
}

// TestRevokeAPIKeyReportsInternalWhenRevokerMissing proves that a nil
// revoker wired into NewHandler is reported as a typed internal error —
// not as an empty success or a silent 404. A misconfigured server must
// surface its misconfiguration on the wire.
func TestRevokeAPIKeyReportsInternalWhenRevokerMissing(t *testing.T) {
	t.Parallel()

	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, nil)

	rec := deleteAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want 5xx; body %s", rec.Code, rec.Body.String())
	}
}

// TestRevokeAPIKeyHandlerWithNilRevokerIsInternal proves a route registered
// without an api-key revoker is a wiring error reported as a typed internal
// failure — never a misleading empty success. The bare handler is
// dispatched through telemetry.Correlate via the run helper so a
// request_id is resolved even though the test is bypassing the full
// RequireAuth middleware (the handler is invoked with a principal
// pre-attached to the request context).
func TestRevokeAPIKeyHandlerWithNilRevokerIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/organizations/org_acme/api-keys/key_ada", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)))
	rec := run(revokeAPIKeyHandler(nil), req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestRevokeAPIKeyPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestRevokeAPIKeyPropagatesRequestID(t *testing.T) {
	t.Parallel()

	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		[]string{}, "usr_ada", "",
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC))
	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, fakeAPIKeyRevoker{key: persisted})

	req := httptest.NewRequest(http.MethodDelete,
		"/v1/organizations/org_acme/api-keys/key_ada", nil)
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
	env := decodeRevokeAPIKey(t, rec)
	if env.RequestID != "req-from-client-12345" {
		t.Errorf("envelope request_id = %q, want the echoed inbound id", env.RequestID)
	}
}

// TestRevokeAPIKeyDocumentsRouteInOpenAPI is the OpenAPI publication
// invariant: the DELETE route registered on the mux must also appear in
// the published /openapi.json. The route table is the single source of
// truth; this test asserts NewHandler folds it into the document.
func TestRevokeAPIKeyDocumentsRouteInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := revokeAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, fakeAPIKeyRevoker{})

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi.json: %v", err)
	}
	paths, _ := doc["paths"].(map[string]any)
	path, _ := paths["/v1/organizations/{org_id}/api-keys/{key_id}"].(map[string]any)
	if _, ok := path["delete"]; !ok {
		t.Fatalf("DELETE /v1/organizations/{org_id}/api-keys/{key_id} missing from openapi.json: %s", rec.Body.String())
	}
}
