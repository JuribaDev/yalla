package httpapi

import (
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/output"
)

// Contract and tenant-isolation coverage for PATCH
// /v1/organizations/{org_id}/variables/{key} (BE-0112 + BE-0113). The
// endpoint patches a single organization-scoped variable through the
// OrganizationVariablePatcher port; the tests drive it through NewHandler
// with a fake Authenticator, the real policy engine, and a fake patcher
// — the same wiring a request hits in production, minus the database.
// The store-backed patcher has its own isolated-Postgres integration
// coverage planned alongside the repository tests; this file exercises
// the HTTP surface in isolation.
//
// env.write is a CapWrite action: a viewer or support principal in the
// tenant cannot patch a variable, only an owner, admin, developer, or
// CI principal can — and unlike CapRead actions there is no
// cross-tenant support exception. The happy-path tests therefore
// authenticate as RoleOwner. The authorization matrix lives in
// variables_patch_policy_test.go (BE-0114).
//
// Validation surface: the body decoder rejects oversized/malformed/
// unknown-field bodies as 400 (the global validate.DecodeJSON
// contract), the handler additionally surfaces a 400 for a body that
// names neither value nor is_secret (a PATCH that changes nothing is a
// client error). Field-level validation of value encoding, value
// size, and the path-parameter key shape is the store-layer's job and
// is asserted through the patcher error path here, not by
// re-validating in the handler.

// patchOrgVariableSuccessEnvelope is the decoded shape of the PATCH
// /v1/organizations/{org_id}/variables/{key} success envelope.
type patchOrgVariableSuccessEnvelope struct {
	SchemaVersion string                           `json:"schema_version"`
	OK            bool                             `json:"ok"`
	RequestID     string                           `json:"request_id"`
	Data          patchOrganizationVariablePayload `json:"data"`
}

// patchOrgVariableHandlerFor builds an http.Handler that points at the
// PATCH /v1/organizations/{org_id}/variables/{key} route, wired through
// the same NewHandler the production binary uses. id and authErr drive
// the fake authenticator; patcher is the OrganizationVariablePatcher
// the handler delegates to.
func patchOrgVariableHandlerFor(id auth.Identity, authErr error, patcher OrganizationVariablePatcher) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, patcher, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeBreakGlassController{}, nil, nil)
}

// patchOrgVariable issues PATCH /v1/organizations/{orgID}/variables/{key}
// against handler with body, optionally with a bearer token.
func patchOrgVariable(handler http.Handler, orgID, key, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPatch,
		"/v1/organizations/"+orgID+"/variables/"+key,
		strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// decodePatchOrgVariable decodes the JSON success body returned by PATCH
// /v1/organizations/{org_id}/variables/{key} into the wire shape the
// contract pins down.
func decodePatchOrgVariable(t *testing.T, rec *httptest.ResponseRecorder) patchOrgVariableSuccessEnvelope {
	t.Helper()
	var env patchOrgVariableSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, rec.Body)
	}
	return env
}

// TestPatchOrgVariableReturnsPersistedVariable is the happy path: a
// PATCH carrying value and is_secret is forwarded to the patcher
// verbatim, the resulting committed row is projected onto the stable
// wire shape, the envelope's request_id propagates, and the secret
// value is redacted on the wire even after the customer just submitted
// it.
func TestPatchOrgVariableReturnsPersistedVariable(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const key = "DATABASE_URL"
	committed := store.OrganizationVariable{
		ID: "ovar_db", OrganizationID: orgID, Key: key,
		Value: "postgres://user:hunter2@db/app", IsSecret: true, Version: 2,
	}
	var got store.PatchOrganizationVariableInput
	patcher := fakeOrgVariablePatcher{v: committed, got: &got}
	handler := patchOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, patcher)

	body := `{"value":"postgres://user:hunter2@db/app","is_secret":true}`
	rec := patchOrgVariable(handler, orgID, key, "a-valid-session-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	env := decodePatchOrgVariable(t, rec)
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty; envelope must propagate the request id")
	}

	// Wire-level redaction chokepoint: the secret value must never reach
	// the response body — including the customer that just submitted it.
	bodyStr := rec.Body.String()
	if strings.Contains(bodyStr, "hunter2") {
		t.Errorf("response body leaked the secret value: %s", bodyStr)
	}
	if strings.Contains(bodyStr, "postgres://") {
		t.Errorf("response body leaked the secret value prefix: %s", bodyStr)
	}
	if env.Data.Variable.ID != committed.ID {
		t.Errorf("variable.id = %q, want %q", env.Data.Variable.ID, committed.ID)
	}
	if env.Data.Variable.Key != key {
		t.Errorf("variable.key = %q, want %q", env.Data.Variable.Key, key)
	}
	if !env.Data.Variable.IsSecret {
		t.Errorf("variable.is_secret = false, want true")
	}
	if env.Data.Variable.Value != output.Sentinel {
		t.Errorf("variable.value = %q, want sentinel", env.Data.Variable.Value)
	}
	if env.Data.Variable.Version != 2 {
		t.Errorf("variable.version = %d, want 2", env.Data.Variable.Version)
	}

	// The handler must forward the decoded request to the patcher
	// exactly, including the {org_id} and {key} path parameters (so a
	// cross-tenant smuggling attempt is impossible at this seam) and
	// the principal/correlation fields needed to file the audit
	// record.
	if got.OrganizationID != orgID {
		t.Errorf("patcher received org_id %q, want the path parameter %q", got.OrganizationID, orgID)
	}
	if got.Key != key {
		t.Errorf("patcher received key %q, want the path parameter %q", got.Key, key)
	}
	if got.Value == nil || *got.Value != "postgres://user:hunter2@db/app" {
		t.Errorf("patcher received value pointer %+v, want pointer to the submitted secret", got.Value)
	}
	if got.IsSecret == nil || !*got.IsSecret {
		t.Errorf("patcher received is_secret pointer %+v, want pointer to true", got.IsSecret)
	}
	if got.ActorID != "usr_ada" || got.ActorOrgID != orgID {
		t.Errorf("patcher received actor=(%q, %q), want (usr_ada, %q)",
			got.ActorID, got.ActorOrgID, orgID)
	}
	if got.RequestID == "" {
		t.Errorf("patcher received empty RequestID; the handler must forward the correlation identifiers")
	}
}

// TestPatchOrgVariableForwardsValueOnly proves a PATCH that omits
// is_secret reaches the patcher with a nil IsSecret pointer — the
// store layer reads "field not supplied" from the nil and preserves
// the column's current state. The handler must not silently materialise
// a false (or a current-state guess) for the missing field.
func TestPatchOrgVariableForwardsValueOnly(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const key = "REGION"
	committed := store.OrganizationVariable{
		ID: "ovar_region", OrganizationID: orgID, Key: key,
		Value: "eu-west-1", IsSecret: false, Version: 2,
	}
	var got store.PatchOrganizationVariableInput
	patcher := fakeOrgVariablePatcher{v: committed, got: &got}
	handler := patchOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, patcher)

	rec := patchOrgVariable(handler, orgID, key, "a-valid-session-token",
		`{"value":"eu-west-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.Value == nil || *got.Value != "eu-west-1" {
		t.Errorf("patcher Value = %+v, want pointer to \"eu-west-1\"", got.Value)
	}
	if got.IsSecret != nil {
		t.Errorf("patcher IsSecret = %+v, want nil for an omitted field", got.IsSecret)
	}
	env := decodePatchOrgVariable(t, rec)
	if env.Data.Variable.Value != "eu-west-1" {
		t.Errorf("response value = %q, want \"eu-west-1\" (non-secret variables project verbatim)", env.Data.Variable.Value)
	}
}

// TestPatchOrgVariableForwardsIsSecretOnly proves a PATCH that omits
// value reaches the patcher with a nil Value pointer — the store layer
// reads "field not supplied" from the nil and preserves the column's
// current state. The handler must not silently materialise an empty
// string (or a current-state guess) for the missing field.
func TestPatchOrgVariableForwardsIsSecretOnly(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const key = "REGION"
	committed := store.OrganizationVariable{
		ID: "ovar_region", OrganizationID: orgID, Key: key,
		Value: "eu-west-1", IsSecret: true, Version: 2,
	}
	var got store.PatchOrganizationVariableInput
	patcher := fakeOrgVariablePatcher{v: committed, got: &got}
	handler := patchOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, patcher)

	rec := patchOrgVariable(handler, orgID, key, "a-valid-session-token",
		`{"is_secret":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.Value != nil {
		t.Errorf("patcher Value = %+v, want nil for an omitted field", got.Value)
	}
	if got.IsSecret == nil || !*got.IsSecret {
		t.Errorf("patcher IsSecret = %+v, want pointer to true", got.IsSecret)
	}
	env := decodePatchOrgVariable(t, rec)
	if env.Data.Variable.Value != output.Sentinel {
		t.Errorf("variable.value = %q, want sentinel after promotion to is_secret=true", env.Data.Variable.Value)
	}
}

// TestPatchOrgVariableRejectsEmptyBody proves the missing-field guard:
// a PATCH whose body names neither value nor is_secret is rejected as
// a stable 400, the patcher is never reached, and the error envelope
// carries the documented E_INVALID_INPUT code.
func TestPatchOrgVariableRejectsEmptyBody(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.PatchOrganizationVariableInput
	patcher := fakeOrgVariablePatcher{got: &got}
	handler := patchOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, patcher)

	rec := patchOrgVariable(handler, orgID, "DATABASE_URL", "a-valid-session-token", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	if got.OrganizationID != "" || got.Key != "" {
		t.Errorf("patcher was reached for an empty-body request: %+v", got)
	}
}

// TestPatchOrgVariableRejectsMalformedJSON proves the global decoder
// contract: a malformed body is rejected as a stable 400 that never
// echoes the bad input, and the patcher is never reached.
func TestPatchOrgVariableRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.PatchOrganizationVariableInput
	patcher := fakeOrgVariablePatcher{got: &got}
	handler := patchOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, patcher)

	rec := patchOrgVariable(handler, orgID, "DATABASE_URL", "a-valid-session-token", `{"value":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	if got.OrganizationID != "" {
		t.Errorf("patcher was reached for a malformed request: %+v", got)
	}
}

// TestPatchOrgVariableRejectsUnknownField proves the strict-decode
// contract: an unknown field becomes a stable 400, never silently
// accepted. A future field added at the wire must go through a deliberate
// extension, not a silent acceptance.
func TestPatchOrgVariableRejectsUnknownField(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.PatchOrganizationVariableInput
	patcher := fakeOrgVariablePatcher{got: &got}
	handler := patchOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, patcher)

	rec := patchOrgVariable(handler, orgID, "DATABASE_URL", "a-valid-session-token",
		`{"value":"x","unexpected":"field"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	if got.OrganizationID != "" {
		t.Errorf("patcher was reached for an unknown-field request: %+v", got)
	}
}

// TestPatchOrgVariableForwardsStoreNotFound proves that a NotFound
// result from the patcher (e.g. a key that exists in another tenant
// — the tenant-scoped repository read filters by organization_id
// first, so a cross-tenant {key} is indistinguishable from a missing
// row) reaches the wire as a typed 404 carrying the documented
// E_NOT_FOUND code. The handler must not disguise it as a 5xx, and
// must not echo any value back into the error message.
func TestPatchOrgVariableForwardsStoreNotFound(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const key = "MISSING_KEY"
	patcher := fakeOrgVariablePatcher{err: apierr.NotFound("organization_variable", key)}
	handler := patchOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, patcher)

	rec := patchOrgVariable(handler, orgID, key, "a-valid-session-token",
		`{"value":"x"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_NOT_FOUND")
	if strings.Contains(env.Error.Message, "\"x\"") {
		t.Errorf("error message echoed the submitted value: %q", env.Error.Message)
	}
}

// TestPatchOrgVariableStoreOutageIsTypedFailure proves a transient
// datastore outage surfaces as a typed 5xx (E_DB_UNAVAILABLE) rather
// than a leaked driver error or a panic.
func TestPatchOrgVariableStoreOutageIsTypedFailure(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	patcher := fakeOrgVariablePatcher{
		err: apierr.StoreUnavailable(stderrors.New("connection reset")),
	}
	handler := patchOrgVariableHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, patcher)

	rec := patchOrgVariable(handler, orgID, "DATABASE_URL", "a-valid-session-token",
		`{"value":"x"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if strings.Contains(env.Error.Message, "connection reset") {
		t.Errorf("error message leaked the driver cause: %q", env.Error.Message)
	}
}

// TestPatchOrgVariableRequiresAuthentication proves the auth gate: a
// request missing or carrying an invalid credential is the typed 401
// the authenticator path emits, not a leaked panic, and the patcher
// never runs.
func TestPatchOrgVariableRequiresAuthentication(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var got store.PatchOrganizationVariableInput
	patcher := fakeOrgVariablePatcher{got: &got}

	handler := patchOrgVariableHandlerFor(auth.Identity{}, apierr.Unauthenticated("missing token"), patcher)
	rec := patchOrgVariable(handler, orgID, "DATABASE_URL", "", `{"value":"x"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != "" {
		t.Errorf("patcher ran for an unauthenticated request: %+v", got)
	}
}

// TestPatchOrgVariableDeniesCrossTenantPrincipal proves the policy
// engine rejects an {org_id} the principal does not own — the
// variables PATCH route uses organizationIDResolver, so a cross-tenant
// id is denied as a 403 before the handler runs, and the patcher never
// sees the request. env.write is a CapWrite action with no cross-tenant
// support exception.
func TestPatchOrgVariableDeniesCrossTenantPrincipal(t *testing.T) {
	t.Parallel()
	const homeOrg = "org_attacker"
	const victimOrg = "org_acme"
	var got store.PatchOrganizationVariableInput
	patcher := fakeOrgVariablePatcher{got: &got}

	id := auth.Identity{
		Principal: orgPrincipal("usr_mallory", homeOrg, policy.RoleOwner),
		Method:    auth.MethodSession,
	}
	handler := patchOrgVariableHandlerFor(id, nil, patcher)
	rec := patchOrgVariable(handler, victimOrg, "DATABASE_URL", "a-valid-session-token",
		`{"value":"smuggled"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if got.OrganizationID != "" {
		t.Errorf("patcher ran for a cross-tenant request: %+v", got)
	}
}

// TestPatchOrgVariableMissingPatcherReturns500 proves the wiring guard:
// a route registered with a nil patcher reports the documented
// E_INTERNAL through the same envelope shape as every other internal
// failure — never an empty body, a panic, or a misleading 4xx.
func TestPatchOrgVariableMissingPatcherReturns500(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	a := fakeAuthenticator{identity: orgVariableActorIdentity(orgID, "usr_ada")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, nil, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeBreakGlassController{}, nil, nil)
	rec := patchOrgVariable(handler, orgID, "DATABASE_URL", "a-valid-session-token",
		`{"value":"x"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// TestPatchOrgVariableRouteIsRegistered proves the OpenAPI document
// carries the PATCH /v1/organizations/{org_id}/variables/{key}
// operation with the stable operationId, the env.write required
// action, and the variables tag — every detail an agent reads to
// discover the endpoint.
func TestPatchOrgVariableRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeBreakGlassController{})
	var found bool
	for _, rt := range table {
		if rt.endpoint.Method != http.MethodPatch ||
			rt.endpoint.Path != "/v1/organizations/{org_id}/variables/{key}" {
			continue
		}
		found = true
		if rt.endpoint.OperationID != "patchOrganizationVariable" {
			t.Errorf("operationId = %q, want patchOrganizationVariable", rt.endpoint.OperationID)
		}
		if rt.endpoint.RequiredAction != string(policy.ActionEnvWrite) {
			t.Errorf("requiredAction = %q, want %q", rt.endpoint.RequiredAction, policy.ActionEnvWrite)
		}
		if !rt.endpoint.RequiresAuth {
			t.Errorf("requiresAuth = false, want true")
		}
		var keyPathParam bool
		for _, p := range rt.endpoint.PathParams {
			if p.Name == "key" {
				keyPathParam = true
			}
		}
		if !keyPathParam {
			t.Errorf("path param 'key' not declared on the endpoint: %+v", rt.endpoint.PathParams)
		}
		var hasVariables bool
		for _, tg := range rt.endpoint.Tags {
			if tg == tagVariables {
				hasVariables = true
			}
		}
		if !hasVariables {
			t.Errorf("tags = %+v, want to include %q", rt.endpoint.Tags, tagVariables)
		}
	}
	if !found {
		t.Fatalf("PATCH /v1/organizations/{org_id}/variables/{key} not registered in route table")
	}
}
