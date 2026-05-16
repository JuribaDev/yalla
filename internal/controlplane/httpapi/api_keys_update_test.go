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

// Contract and tenant-isolation coverage for PATCH
// /v1/organizations/{org_id}/api-keys/{key_id} (BE-0085). The endpoint
// updates the mutable fields (name and scopes) of the api key named by
// ({org_id}, {key_id}), routed through the APIKeyUpdater port; the tests
// drive it through NewHandler with a fake Authenticator, the real policy
// engine, and a fake updater — the same wiring a request hits in production,
// minus the database. The store-backed updater has its own isolated-Postgres
// integration coverage in store/apikeyservice_test.go.
//
// keys.manage is a CapManage action: a viewer or developer in the tenant
// cannot mutate an API key, only an owner or admin in the tenant can — and
// unlike CapRead actions there is no cross-tenant support exception. The
// happy-path tests therefore authenticate as RoleAdmin or RoleOwner. The
// authorization matrix lives in api_keys_update_policy_test.go (BE-0087).
//
// Validation surface: the body decoder rejects oversized/malformed/
// unknown-field bodies as 400 (the global validate.DecodeJSON contract),
// and the handler additionally surfaces a 400 when no mutable field is
// supplied (the symmetric early reject of the store-layer "patch with no
// field" violation). Field-level validation (blank name, malformed scope
// string, etc.) is the store-layer's job and is asserted through the
// updater error path here, not by re-validating in the handler.

// updateAPIKeySuccessEnvelope is the decoded shape of the PATCH
// /v1/organizations/{org_id}/api-keys/{key_id} success envelope.
type updateAPIKeySuccessEnvelope struct {
	SchemaVersion string              `json:"schema_version"`
	OK            bool                `json:"ok"`
	RequestID     string              `json:"request_id"`
	Data          updateAPIKeyPayload `json:"data"`
}

// updateAPIKeyHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// APIKeyUpdater. It is the production request path: the PATCH
// /v1/organizations/{org_id}/api-keys/{key_id} route is wrapped in
// RequireAuth for action keys.manage and goes through apiKeyIDResolver.
func updateAPIKeyHandlerFor(id auth.Identity, authErr error, updater APIKeyUpdater) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, updater, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// patchAPIKey issues PATCH /v1/organizations/{orgID}/api-keys/{keyID}
// against handler with body, optionally with a bearer token.
func patchAPIKey(handler http.Handler, orgID, keyID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/organizations/"+orgID+"/api-keys/"+keyID,
		strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeUpdateAPIKey(t *testing.T, rec *httptest.ResponseRecorder) updateAPIKeySuccessEnvelope {
	t.Helper()
	var env updateAPIKeySuccessEnvelope
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

// TestUpdateAPIKeyReturnsUpdatedKey is the happy path: an authenticated admin
// principal PATCHing its own organization's api key receives the persisted
// row in a stable yalla.output.v1 envelope, projecting every source-of-truth
// field onto the wire. The secret_hash sentinel must never appear in the
// rendered body.
func TestUpdateAPIKeyReturnsUpdatedKey(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC)
	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI v2",
		[]string{"projects:read", "services:deploy"}, "usr_ada", "", created, updated)

	var got store.UpdateAPIKeyInput
	updater := fakeAPIKeyUpdater{key: persisted, got: &got}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	body := `{"name":"Ada CLI v2","scopes":["projects:read","services:deploy"]}`
	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeUpdateAPIKey(t, rec)
	if env.Data.APIKey.KeyID != "key_ada" {
		t.Errorf("api_key.key_id = %q, want key_ada", env.Data.APIKey.KeyID)
	}
	if env.Data.APIKey.Name != "Ada CLI v2" {
		t.Errorf("api_key.name = %q, want %q", env.Data.APIKey.Name, "Ada CLI v2")
	}
	if len(env.Data.APIKey.Scopes) != 2 {
		t.Errorf("api_key.scopes = %v, want two persisted scopes", env.Data.APIKey.Scopes)
	}
	// The handler must forward the path params, the body fields, and the
	// authenticated actor verbatim to the updater.
	if got.OrganizationID != "org_acme" {
		t.Errorf("updater org_id = %q, want org_acme", got.OrganizationID)
	}
	if got.KeyID != "key_ada" {
		t.Errorf("updater key_id = %q, want key_ada", got.KeyID)
	}
	if got.Name == nil || *got.Name != "Ada CLI v2" {
		t.Errorf("updater name = %v, want pointer to %q", got.Name, "Ada CLI v2")
	}
	if got.Scopes == nil || len(*got.Scopes) != 2 {
		t.Errorf("updater scopes = %v, want pointer to a 2-element slice", got.Scopes)
	}
	if got.ActorID != "usr_ada" {
		t.Errorf("updater actor_id = %q, want usr_ada", got.ActorID)
	}
	if got.ActorOrgID != "org_acme" {
		t.Errorf("updater actor_org_id = %q, want org_acme", got.ActorOrgID)
	}
	// The secret hash sentinel must never appear in the rendered body.
	if strings.Contains(rec.Body.String(), "must-not-leak-secret-hash-sentinel") {
		t.Errorf("response body leaked secret_hash; body=%s", rec.Body.String())
	}
}

// TestUpdateAPIKeyForwardsOnlyNameWhenScopesOmitted proves the handler
// forwards a nil pointer for an omitted field — the store layer is the
// authority on "leave unchanged" semantics, so the handler must not
// fabricate a value for a field the caller did not supply.
func TestUpdateAPIKeyForwardsOnlyNameWhenScopesOmitted(t *testing.T) {
	t.Parallel()

	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI v3",
		[]string{"projects:read"}, "usr_ada", "",
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC))

	var got store.UpdateAPIKeyInput
	updater := fakeAPIKeyUpdater{key: persisted, got: &got}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	body := `{"name":"Ada CLI v3"}`
	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got.Name == nil || *got.Name != "Ada CLI v3" {
		t.Errorf("updater name = %v, want pointer to %q", got.Name, "Ada CLI v3")
	}
	if got.Scopes != nil {
		t.Errorf("updater scopes = %v, want nil (omitted field must not be fabricated)", got.Scopes)
	}
}

// TestUpdateAPIKeyForwardsOnlyScopesWhenNameOmitted is the mirror case of
// TestUpdateAPIKeyForwardsOnlyNameWhenScopesOmitted.
func TestUpdateAPIKeyForwardsOnlyScopesWhenNameOmitted(t *testing.T) {
	t.Parallel()

	persisted := seedAPIKey("org_acme", "key_ada", "yk_pf_ada", "Ada CLI",
		[]string{"services:deploy"}, "usr_ada", "",
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Date(2026, 5, 15, 6, 7, 8, 0, time.UTC))

	var got store.UpdateAPIKeyInput
	updater := fakeAPIKeyUpdater{key: persisted, got: &got}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	body := `{"scopes":["services:deploy"]}`
	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got.Name != nil {
		t.Errorf("updater name = %v, want nil (omitted field must not be fabricated)", got.Name)
	}
	if got.Scopes == nil || len(*got.Scopes) != 1 || (*got.Scopes)[0] != "services:deploy" {
		t.Errorf("updater scopes = %v, want pointer to [services:deploy]", got.Scopes)
	}
}

// TestUpdateAPIKeyRejectsEmptyPatch proves a PATCH that names no mutable
// field is rejected at the boundary as a typed 400, without invoking the
// updater. The wire contract for "patch with no field" must be stable
// regardless of whether the rejection originates in the handler or the
// store layer.
func TestUpdateAPIKeyRejectsEmptyPatch(t *testing.T) {
	t.Parallel()

	updater := fakeAPIKeyUpdater{err: stderrors.New("updater must not be called")}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "E_INVALID_INPUT") {
		t.Errorf("body does not name E_INVALID_INPUT: %s", body)
	}
}

// TestUpdateAPIKeyRejectsMalformedBody asserts the global JSON decoder
// rejects an unparseable body as 400 without invoking the updater.
func TestUpdateAPIKeyRejectsMalformedBody(t *testing.T) {
	t.Parallel()

	updater := fakeAPIKeyUpdater{err: stderrors.New("updater must not be called")}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", `{`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateAPIKeyRejectsUnknownField asserts the strict JSON decoder
// rejects an unknown field as 400 without invoking the updater. This is
// the global validate.DecodeJSON contract, exercised here to prove the
// PATCH endpoint inherits it.
func TestUpdateAPIKeyRejectsUnknownField(t *testing.T) {
	t.Parallel()

	updater := fakeAPIKeyUpdater{err: stderrors.New("updater must not be called")}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	body := `{"name":"x","wat":"no"}`
	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateAPIKeyForwardsStoreValidationError proves that a typed
// InvalidInput from the store layer (for example a blank-name violation)
// surfaces as the 400 it was built as — never disguised as a 5xx or
// swallowed. The handler's job is only to forward the typed error; the
// store layer is the authority on field-level validation.
func TestUpdateAPIKeyForwardsStoreValidationError(t *testing.T) {
	t.Parallel()

	updater := fakeAPIKeyUpdater{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "name",
		Reason: "must not be blank",
	})}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", `{"name":"   "}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "name") {
		t.Errorf("body does not name the failing field: %s", rec.Body.String())
	}
}

// TestUpdateAPIKeyForwardsNotFound asserts that a typed NotFound from the
// store layer (cross-tenant key_id or simply missing row) surfaces as a
// deterministic 404 — never as a 5xx and never disguised as a 403, so an
// attacker cannot use the endpoint as a presence oracle for keys in
// another tenant.
func TestUpdateAPIKeyForwardsNotFound(t *testing.T) {
	t.Parallel()

	updater := fakeAPIKeyUpdater{err: apierr.NotFound("api_key", "key_ghost")}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	rec := patchAPIKey(handler, "org_acme", "key_ghost", "a-valid-session-token", `{"name":"renamed"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateAPIKeyForwardsStoreOutage proves that a typed
// StoreUnavailable surfaces as a 5xx — never disguised as a 404 or 400.
// The endpoint must distinguish "the key is not here" from "the database
// is not here" so operators have an unambiguous signal.
func TestUpdateAPIKeyForwardsStoreOutage(t *testing.T) {
	t.Parallel()

	updater := fakeAPIKeyUpdater{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, updater)

	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", `{"name":"x"}`)
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want 5xx; body %s", rec.Code, rec.Body.String())
	}
	// The outage cause is logged server-side; it must never reach the
	// rendered envelope.
	if strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("body leaked the outage cause: %s", rec.Body.String())
	}
}

// TestUpdateAPIKeyRejectsUnauthenticated proves an anonymous request is
// rejected as 401 by the auth middleware before the handler runs — the
// updater must not be invoked.
func TestUpdateAPIKeyRejectsUnauthenticated(t *testing.T) {
	t.Parallel()

	updater := fakeAPIKeyUpdater{err: stderrors.New("updater must not be called")}
	handler := updateAPIKeyHandlerFor(auth.Identity{}, nil, updater)

	rec := patchAPIKey(handler, "org_acme", "key_ada", "", `{"name":"x"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateAPIKeyDeniesCrossTenant proves the policy engine rejects a
// principal updating a key in another organization with a deterministic
// 403 — the updater must not be invoked. The check happens at the policy
// boundary (apiKeyIDResolver) before the handler runs, so a cross-tenant
// {org_id} can never mutate another tenant's api-key graph.
func TestUpdateAPIKeyDeniesCrossTenant(t *testing.T) {
	t.Parallel()

	updater := fakeAPIKeyUpdater{err: stderrors.New("updater must not be called")}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_mallory", "org_attacker", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", `{"name":"x"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateAPIKeyDeniesViewer proves that a viewer in the tenant cannot
// PATCH the organization's api key — keys.manage is a CapManage action.
// The policy engine returns 403; the updater must not be invoked.
func TestUpdateAPIKeyDeniesViewer(t *testing.T) {
	t.Parallel()

	updater := fakeAPIKeyUpdater{err: stderrors.New("updater must not be called")}
	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_eve", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, updater)

	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", `{"name":"x"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateAPIKeyReportsInternalWhenUpdaterMissing proves that a nil
// updater wired into NewHandler is reported as a typed internal error —
// not as an empty success or a silent 404. A misconfigured server must
// surface its misconfiguration on the wire.
func TestUpdateAPIKeyReportsInternalWhenUpdaterMissing(t *testing.T) {
	t.Parallel()

	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, nil)

	rec := patchAPIKey(handler, "org_acme", "key_ada", "a-valid-session-token", `{"name":"x"}`)
	if rec.Code < 500 || rec.Code >= 600 {
		t.Fatalf("status = %d, want 5xx; body %s", rec.Code, rec.Body.String())
	}
}

// TestUpdateAPIKeyDocumentsRouteInOpenAPI is the OpenAPI publication
// invariant: the PATCH route registered on the mux must also appear in
// the published /openapi.json. The route table is the single source of
// truth; this test asserts NewHandler folds it into the document.
func TestUpdateAPIKeyDocumentsRouteInOpenAPI(t *testing.T) {
	t.Parallel()

	handler := updateAPIKeyHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
		nil, fakeAPIKeyUpdater{})

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
	if _, ok := path["patch"]; !ok {
		t.Fatalf("PATCH /v1/organizations/{org_id}/api-keys/{key_id} missing from openapi.json: %s", rec.Body.String())
	}
}
