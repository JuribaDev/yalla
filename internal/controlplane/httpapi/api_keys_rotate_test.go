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

// Contract, authorization, and tenant-isolation coverage for POST
// /v1/organizations/{org_id}/api-keys/{key_id}/rotate (BE-0091). The endpoint
// swaps the credential primitives of the api key named by ({org_id}, {key_id})
// through the APIKeyRotator port; the tests drive it through NewHandler with a
// fake Authenticator, the real policy engine, and a fake rotator — the same
// wiring a request hits in production, minus the database. The store-backed
// rotator has its own isolated-Postgres integration coverage in
// store/apikeyservice_test.go.
//
// keys.manage is a CapManage action: a viewer or developer in the tenant
// cannot rotate an API key, only an owner or admin in the tenant can — and
// unlike CapRead actions there is no cross-tenant support exception. The
// happy-path tests therefore authenticate as RoleAdmin or RoleOwner; the
// authorization matrix lives in api_keys_rotate_policy_test.go (BE-0093).
//
// Validation surface: this endpoint has no request body and no query
// parameters. Its only input is the {org_id} / {key_id} path-parameter
// pair, an opaque identifier — a malformed or unknown id surfaces as a 404
// from the store layer when the principal is authorized for the tenant, or,
// for an id outside the principal's tenant, as the deterministic 403 the
// policy engine returns through apiKeyIDResolver. Those two paths are the
// "validation" and "authorization" coverage for this story.

// rotateAPIKeySuccessEnvelope is the decoded shape of the POST
// /v1/organizations/{org_id}/api-keys/{key_id}/rotate success envelope.
type rotateAPIKeySuccessEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	OK            bool                `json:"ok"`
	RequestID     string              `json:"request_id"`
	Data          rotateAPIKeyPayload `json:"data"`
}

// rotateAPIKeyHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// APIKeyRotator. It is the production request path: the POST
// /v1/organizations/{org_id}/api-keys/{key_id}/rotate route is wrapped in
// RequireAuth for action keys.manage and goes through apiKeyIDResolver.
func rotateAPIKeyHandlerFor(id auth.Identity, authErr error, rotator APIKeyRotator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, rotator, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// rotateAPIKey issues POST
// /v1/organizations/{orgID}/api-keys/{keyID}/rotate against handler,
// optionally with a bearer token.
func rotateAPIKey(handler http.Handler, orgID, keyID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost,
		"/v1/organizations/"+orgID+"/api-keys/"+keyID+"/rotate", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeRotateAPIKey(t *testing.T, rec *httptest.ResponseRecorder) rotateAPIKeySuccessEnvelope {
	t.Helper()
	var env rotateAPIKeySuccessEnvelope
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

// TestRotateAPIKeyReturnsRotatedKeyAndToken is the happy path: an
// authenticated admin principal rotating its own organization's api key
// receives the row exactly as it stood at the moment of rotation, in a stable
// yalla.output.v1 envelope projecting every source-of-truth field onto the
// wire — including the NEW prefix the rotator just persisted — plus the
// plaintext token of the new credential body, shown exactly once. The
// secret_hash sentinel must never appear in the rendered body.
func TestRotateAPIKeyReturnsRotatedKeyAndToken(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	// The "persisted" key returned by the fake rotator carries the NEW prefix
	// — that is the row Postgres returns after the UPDATE.
	persisted := seedAPIKey("org_acme", "key_ada", "yk_new_prefix_after_rotate", "Ada CLI",
		[]string{"projects:read"}, "usr_ada", "", created, updated)

	var got store.RotateAPIKeyInput
	rotator := fakeAPIKeyRotator{key: persisted, got: &got}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	env := decodeRotateAPIKey(t, rec)
	if env.Data.APIKey.KeyID != "key_ada" {
		t.Errorf("api_key.key_id = %q, want key_ada", env.Data.APIKey.KeyID)
	}
	if env.Data.APIKey.Prefix != "yk_new_prefix_after_rotate" {
		t.Errorf("api_key.prefix = %q, want the NEW prefix the row now serves", env.Data.APIKey.Prefix)
	}
	if env.Data.Token == "" {
		t.Error("response token is empty; the plaintext of the rotated credential must be shown once")
	}
	// The handler must forward the path params and the authenticated actor
	// verbatim to the rotator, plus a freshly-minted credential primitive.
	if got.OrganizationID != "org_acme" {
		t.Errorf("rotator org_id = %q, want org_acme", got.OrganizationID)
	}
	if got.KeyID != "key_ada" {
		t.Errorf("rotator key_id = %q, want key_ada", got.KeyID)
	}
	if got.ActorID != "usr_ada" {
		t.Errorf("rotator actor_id = %q, want usr_ada", got.ActorID)
	}
	if got.ActorOrgID != "org_acme" {
		t.Errorf("rotator actor_org_id = %q, want org_acme", got.ActorOrgID)
	}
	if got.Prefix == "" {
		t.Error("rotator received an empty prefix; the handler must mint one with auth.Generate")
	}
	if got.SecretHash == "" {
		t.Error("rotator received an empty secret_hash; the handler must mint one with auth.Generate")
	}
	// The minted prefix the handler forwarded to the store must match the
	// plaintext token's public lookup id (the part before the secret).
	if !strings.HasPrefix(env.Data.Token, got.Prefix) {
		t.Errorf("token %q does not start with the minted prefix %q", env.Data.Token, got.Prefix)
	}
	// The handler must never forward a plaintext secret to the store layer:
	// only the prefix and the hash cross the boundary.
	if strings.Contains(got.SecretHash, "yk_") || got.SecretHash == env.Data.Token {
		t.Errorf("secret_hash %q looks like a plaintext token; the handler must forward only the hash", got.SecretHash)
	}
	// The secret hash sentinel must never appear in the rendered body, and
	// the wire shape must not carry a secret_hash field at all.
	if strings.Contains(rec.Body.String(), "must-not-leak-secret-hash-sentinel") {
		t.Errorf("response body leaked secret_hash; body=%s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret_hash") {
		t.Errorf("response body carries a secret_hash field; the wire shape must omit it: %s", rec.Body.String())
	}
}

// TestRotateAPIKeyForwardsCorrelationToRotator proves the request_id and
// correlation_id resolved by the telemetry middleware reach the store layer
// verbatim — the audit record the unit of work writes must name the same
// correlation ids the response envelope reports.
func TestRotateAPIKeyForwardsCorrelationToRotator(t *testing.T) {
	t.Parallel()

	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_new", "Ada CLI",
		[]string{}, "usr_ada", "",
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC))

	var got store.RotateAPIKeyInput
	rotator := fakeAPIKeyRotator{key: persisted, got: &got}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator)

	req := httptest.NewRequest(http.MethodPost,
		"/v1/organizations/org_acme/api-keys/key_ada/rotate", nil)
	req.Header.Set("Authorization", "Bearer a-valid-session-token")
	req.Header.Set("X-Request-Id", "req-from-client-99")
	req.Header.Set("X-Correlation-Id", "corr-from-client-99")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got.RequestID != "req-from-client-99" {
		t.Errorf("rotator request_id = %q, want the echoed inbound id", got.RequestID)
	}
	if got.CorrelationID != "corr-from-client-99" {
		t.Errorf("rotator correlation_id = %q, want the echoed inbound id", got.CorrelationID)
	}
}

// TestRotateAPIKeyForwardsNotFound asserts that a typed NotFound from the
// store layer (cross-tenant key_id or simply missing row) surfaces as a
// deterministic 404 — never as a 5xx and never disguised as a 403, so an
// attacker cannot use the endpoint as a presence oracle for keys in another
// tenant.
func TestRotateAPIKeyForwardsNotFound(t *testing.T) {
	t.Parallel()

	rotator := fakeAPIKeyRotator{err: apierr.NotFound("api_key", "key_ghost")}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator)

	rec := rotateAPIKey(handler, "org_acme", "key_ghost", "a-valid-session-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestRotateAPIKeyForwardsRevokedKeyConflict proves the rotator's "key is
// revoked" verdict reaches the wire as a stable 409 E_CONFLICT — a revoked
// key cannot be revived by minting a fresh credential body; the customer
// must mint a new key through Create instead.
func TestRotateAPIKeyForwardsRevokedKeyConflict(t *testing.T) {
	t.Parallel()

	rotator := fakeAPIKeyRotator{err: apierr.Conflict("api key is revoked")}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
}

// TestRotateAPIKeyForwardsExpiredKeyConflict proves the rotator's "key is
// expired" verdict reaches the wire as a stable 409 E_CONFLICT — the
// calendar has already taken the key out of authentication service.
func TestRotateAPIKeyForwardsExpiredKeyConflict(t *testing.T) {
	t.Parallel()

	rotator := fakeAPIKeyRotator{err: apierr.Conflict("api key is expired")}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_CONFLICT")
}

// TestRotateAPIKeyForwardsStoreValidationError proves that a typed
// InvalidInput from the store layer (for example an id-shape violation)
// surfaces as the 400 it was built as — never disguised as a 5xx or
// swallowed.
func TestRotateAPIKeyForwardsStoreValidationError(t *testing.T) {
	t.Parallel()

	rotator := fakeAPIKeyRotator{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "key_id",
		Reason: "must be a valid api key identifier",
	})}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "key_id") {
		t.Errorf("body does not name the failing field: %s", rec.Body.String())
	}
}

// TestRotateAPIKeyForwardsStoreOutage proves that a typed StoreUnavailable
// surfaces as a 5xx — never disguised as a 404 or 409. The wrapped driver
// cause must never reach the user-facing message.
func TestRotateAPIKeyForwardsStoreOutage(t *testing.T) {
	t.Parallel()

	rotator := fakeAPIKeyRotator{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want 5xx; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("body leaked the outage cause: %s", rec.Body.String())
	}
}

// TestRotateAPIKeyRejectsUnauthenticated proves an anonymous request is
// rejected as 401 by the auth middleware before the handler runs — the
// rotator must not be invoked.
func TestRotateAPIKeyRejectsUnauthenticated(t *testing.T) {
	t.Parallel()

	rotator := fakeAPIKeyRotator{err: stderrors.New("rotator must not be called")}
	handler := rotateAPIKeyHandlerFor(auth.Identity{}, nil, rotator)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
}

// TestRotateAPIKeyInvalidCredentials proves an unverifiable credential is a
// stable 401 E_AUTH — identical to the missing-credential contract.
func TestRotateAPIKeyInvalidCredentials(t *testing.T) {
	t.Parallel()

	handler := rotateAPIKeyHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials,
		fakeAPIKeyRotator{err: stderrors.New("rotator must not be called")})

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "yk_bogus")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestRotateAPIKeyDeniesCrossTenant proves the policy engine rejects a
// principal rotating a key in another organization with a deterministic
// 403 — the rotator must not be invoked.
func TestRotateAPIKeyDeniesCrossTenant(t *testing.T) {
	t.Parallel()

	rotator := fakeAPIKeyRotator{err: stderrors.New("rotator must not be called")}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner), Method: auth.MethodSession},
		nil, rotator)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
}

// TestRotateAPIKeyDeniesViewer proves that a viewer in the tenant cannot
// rotate the organization's api key — keys.manage is a CapManage action.
func TestRotateAPIKeyDeniesViewer(t *testing.T) {
	t.Parallel()

	rotator := fakeAPIKeyRotator{err: stderrors.New("rotator must not be called")}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_eve", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, rotator)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
}

// TestRotateAPIKeyDisabledPrincipal proves a principal authenticated against
// a token but flagged as a disabled principal is denied with a 403
// E_FORBIDDEN — and the rotator is never reached.
func TestRotateAPIKeyDisabledPrincipal(t *testing.T) {
	t.Parallel()

	disabled := orgPrincipal("usr_ada", "org_acme", policy.RoleOwner)
	disabled.Disabled = true
	handler := rotateAPIKeyHandlerFor(auth.Identity{Principal: disabled}, nil,
		fakeAPIKeyRotator{err: stderrors.New("rotator must not be called")})

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "a-revoked-session-token")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
}

// TestRotateAPIKeyReportsInternalWhenRotatorMissing proves that a nil
// rotator wired into NewHandler is reported as a typed internal error —
// not as an empty success or a silent 404. A misconfigured server must
// surface its misconfiguration on the wire.
func TestRotateAPIKeyReportsInternalWhenRotatorMissing(t *testing.T) {
	t.Parallel()

	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, nil)

	rec := rotateAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token")
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want 5xx; body %s", rec.Code, rec.Body.String())
	}
}

// TestRotateAPIKeyHandlerWithNilRotatorIsInternal proves a route registered
// without an api-key rotator is a wiring error reported as a typed internal
// failure — never a misleading empty success. The bare handler is
// dispatched through telemetry.Correlate via the run helper so a
// request_id is resolved even though the test is bypassing the full
// RequireAuth middleware (the handler is invoked with a principal
// pre-attached to the request context).
func TestRotateAPIKeyHandlerWithNilRotatorIsInternal(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost,
		"/v1/organizations/org_acme/api-keys/key_ada/rotate", nil)
	req = req.WithContext(policy.WithPrincipal(req.Context(),
		orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin)))
	rec := run(rotateAPIKeyHandler(nil), req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INTERNAL")
}

// TestRotateAPIKeyPropagatesRequestID proves the resolved request_id reaches
// both the response envelope and the echoed response header.
func TestRotateAPIKeyPropagatesRequestID(t *testing.T) {
	t.Parallel()

	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_new", "Ada CLI",
		[]string{}, "usr_ada", "",
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC))

	rotator := fakeAPIKeyRotator{key: persisted}
	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, rotator)

	req := httptest.NewRequest(http.MethodPost,
		"/v1/organizations/org_acme/api-keys/key_ada/rotate", nil)
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
	env := decodeRotateAPIKey(t, rec)
	if env.RequestID != "req-from-client-12345" {
		t.Errorf("envelope request_id = %q, want the echoed inbound id", env.RequestID)
	}
}

// TestRotateAPIKeyDocumentsRouteInOpenAPI is the OpenAPI publication
// invariant: the POST .../rotate route registered on the mux must also
// appear in the published /openapi.json, with the stable x-required-action
// extension set to keys.manage.
func TestRotateAPIKeyDocumentsRouteInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := rotateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, fakeAPIKeyRotator{})

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
	path, _ := paths["/v1/organizations/{org_id}/api-keys/{key_id}/rotate"].(map[string]any)
	op, _ := path["post"].(map[string]any)
	if op == nil {
		t.Fatalf("POST /v1/organizations/{org_id}/api-keys/{key_id}/rotate missing from openapi.json: %s", rec.Body.String())
	}
	if got, _ := op["x-required-action"].(string); got != "keys.manage" {
		t.Errorf("x-required-action = %q, want keys.manage", got)
	}
}
