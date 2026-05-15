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

// Contract and tenant-isolation coverage for PUT
// /v1/organizations/{org_id}/variables (BE-0109). The endpoint replaces
// the organization-scoped variables of the organization through the
// OrganizationVariableReplacer port; the tests drive it through
// NewHandler with a fake Authenticator, the real policy engine, and a
// fake replacer — the same wiring a request hits in production, minus
// the database. The store-backed replacer has its own isolated-Postgres
// integration coverage in store/organization_variable_service_test.go —
// this file exercises the HTTP surface in isolation.
//
// env.write is a CapWrite action: a viewer or support principal in the
// tenant cannot replace variables, only an owner, admin, developer, or
// CI principal can — and unlike CapRead actions there is no cross-tenant
// support exception. The happy-path tests therefore authenticate as
// RoleOwner. The authorization matrix lives in
// variables_put_policy_test.go (BE-0111).
//
// Validation surface: the body decoder rejects oversized/malformed/
// unknown-field bodies as 400 (the global validate.DecodeJSON contract),
// the handler additionally surfaces a 400 for a body that does not name
// the "variables" field (so a misencoded request is never a silent
// clear). Field-level validation of key shape, duplicates, and value
// size/encoding is the store-layer's job and is asserted through the
// replacer error path here, not by re-validating in the handler.

// updateOrgVariablesSuccessEnvelope is the decoded shape of the PUT
// /v1/organizations/{org_id}/variables success envelope.
type updateOrgVariablesSuccessEnvelope struct {
	SchemaVersion string                              `json:"schema_version"`
	OK            bool                                `json:"ok"`
	RequestID     string                              `json:"request_id"`
	Data          replaceOrganizationVariablesPayload `json:"data"`
}

// replaceOrgVariablesHandlerFor builds an http.Handler that points at the
// PUT /v1/organizations/{org_id}/variables route, wired through the same
// NewHandler the production binary uses. id and authErr drive the fake
// authenticator; replacer is the OrganizationVariableReplacer the
// handler delegates to.
func replaceOrgVariablesHandlerFor(id auth.Identity, authErr error, replacer OrganizationVariableReplacer) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, replacer, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, nil)
}

// putOrgVariables issues PUT /v1/organizations/{orgID}/variables against
// handler with body, optionally with a bearer token.
func putOrgVariables(handler http.Handler, orgID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut,
		"/v1/organizations/"+orgID+"/variables",
		strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// decodeUpdateOrgVariables decodes the JSON success body returned by PUT
// /v1/organizations/{org_id}/variables into the wire shape the contract
// pins down.
func decodeUpdateOrgVariables(t *testing.T, rec *httptest.ResponseRecorder) updateOrgVariablesSuccessEnvelope {
	t.Helper()
	var env updateOrgVariablesSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, rec.Body)
	}
	return env
}

// TestReplaceOrgVariablesReturnsPersistedVariables is the happy path: a
// PUT carrying a fresh replacement set is forwarded to the replacer
// verbatim, the resulting committed rows are projected onto the stable
// wire shape, the envelope's request_id propagates, and secret values
// are redacted on the wire even after the customer just submitted them.
func TestReplaceOrgVariablesReturnsPersistedVariables(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	post := []store.OrganizationVariable{
		{
			ID: "ovar_db", OrganizationID: orgID, Key: "DATABASE_URL",
			Value: "postgres://user:hunter2@db/app", IsSecret: true, Version: 1,
		},
		{
			ID: "ovar_region", OrganizationID: orgID, Key: "REGION",
			Value: "us-east-1", IsSecret: false, Version: 1,
		},
	}
	var got store.ReplaceOrganizationVariablesInput
	replacer := fakeOrgVariableReplacer{vars: post, got: &got}
	handler := replaceOrgVariablesHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, replacer)

	body := `{"variables":[` +
		`{"key":"DATABASE_URL","value":"postgres://user:hunter2@db/app","is_secret":true},` +
		`{"key":"REGION","value":"us-east-1"}` +
		`]}`
	rec := putOrgVariables(handler, orgID, "a-valid-session-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeUpdateOrgVariables(t, rec)
	if env.SchemaVersion != "yalla.output.v1" {
		t.Errorf("schema_version = %q, want yalla.output.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty; envelope must propagate the request id")
	}
	if len(env.Data.Variables) != 2 {
		t.Fatalf("variables len = %d, want 2 (got %+v)", len(env.Data.Variables), env.Data.Variables)
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
	for _, v := range env.Data.Variables {
		if v.IsSecret && v.Value != output.Sentinel {
			t.Errorf("secret variable value = %q, want sentinel", v.Value)
		}
		if !v.IsSecret && v.Key == "REGION" && v.Value != "us-east-1" {
			t.Errorf("non-secret variable value = %q, want \"us-east-1\"", v.Value)
		}
	}

	// The handler must forward the decoded request to the replacer
	// exactly, including the {org_id} path parameter (so a cross-tenant
	// smuggling attempt is impossible at this seam) and the
	// principal/correlation fields needed to file the audit record.
	if got.OrganizationID != orgID {
		t.Errorf("replacer received org_id %q, want the path parameter %q", got.OrganizationID, orgID)
	}
	if len(got.Variables) != 2 {
		t.Fatalf("replacer received %d items, want 2: %+v", len(got.Variables), got.Variables)
	}
	if got.Variables[0].Key != "DATABASE_URL" || got.Variables[0].Value != "postgres://user:hunter2@db/app" || !got.Variables[0].IsSecret {
		t.Errorf("items[0] = %+v, want DATABASE_URL/<value>/is_secret=true", got.Variables[0])
	}
	if got.Variables[1].Key != "REGION" || got.Variables[1].Value != "us-east-1" || got.Variables[1].IsSecret {
		t.Errorf("items[1] = %+v, want REGION/us-east-1/is_secret=false", got.Variables[1])
	}
	if got.ActorID != "usr_ada" || got.ActorOrgID != orgID {
		t.Errorf("replacer received actor=(%q, %q), want (usr_ada, %q)",
			got.ActorID, got.ActorOrgID, orgID)
	}
}

// TestReplaceOrgVariablesForwardsEmptyListAsExplicitClear proves the
// empty-array semantics reach the store layer: the handler must not
// reject "variables: []" as a no-op — an explicit clear is a meaningful
// (extreme) operation.
func TestReplaceOrgVariablesForwardsEmptyListAsExplicitClear(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.ReplaceOrganizationVariablesInput
	replacer := fakeOrgVariableReplacer{vars: []store.OrganizationVariable{}, got: &got}
	handler := replaceOrgVariablesHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, replacer)

	rec := putOrgVariables(handler, orgID, "a-valid-session-token", `{"variables":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != orgID {
		t.Errorf("replacer received org_id %q, want %q (an empty replace must reach the store layer)",
			got.OrganizationID, orgID)
	}
	if got.Variables == nil {
		t.Errorf("replacer received nil Variables, want a non-nil empty slice — the store layer distinguishes nil from explicit empty")
	}
	if len(got.Variables) != 0 {
		t.Errorf("replacer received %d items, want 0", len(got.Variables))
	}
	env := decodeUpdateOrgVariables(t, rec)
	if env.Data.Variables == nil {
		t.Errorf("response variables is nil, want a non-nil empty slice")
	}
	if len(env.Data.Variables) != 0 {
		t.Errorf("response variables = %+v, want []", env.Data.Variables)
	}
}

// TestReplaceOrgVariablesRejectsMissingVariablesField proves the
// missing-field guard: a body that omits the "variables" field
// altogether is rejected as a stable 400 (apierr.InvalidInput), never
// silently treated as a clear. An empty array reaches the store layer
// (as in TestReplaceOrgVariablesForwardsEmptyListAsExplicitClear); a
// missing field does not.
func TestReplaceOrgVariablesRejectsMissingVariablesField(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.ReplaceOrganizationVariablesInput
	replacer := fakeOrgVariableReplacer{got: &got}
	handler := replaceOrgVariablesHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, replacer)

	rec := putOrgVariables(handler, orgID, "a-valid-session-token", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	if got.OrganizationID != "" {
		t.Errorf("replacer was reached for an invalid request: %+v", got)
	}
}

// TestReplaceOrgVariablesRejectsMalformedJSON proves the global decoder
// contract: a malformed body is rejected as a stable 400 that never
// echoes the bad input, and the replacer is never reached.
func TestReplaceOrgVariablesRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.ReplaceOrganizationVariablesInput
	replacer := fakeOrgVariableReplacer{got: &got}
	handler := replaceOrgVariablesHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, replacer)

	rec := putOrgVariables(handler, orgID, "a-valid-session-token", `{"variables":[`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	if got.OrganizationID != "" {
		t.Errorf("replacer was reached for a malformed request: %+v", got)
	}
}

// TestReplaceOrgVariablesRejectsUnknownField proves the strict-decode
// contract: an unknown field becomes a stable 400, never silently
// accepted.
func TestReplaceOrgVariablesRejectsUnknownField(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	var got store.ReplaceOrganizationVariablesInput
	replacer := fakeOrgVariableReplacer{got: &got}
	handler := replaceOrgVariablesHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, replacer)

	rec := putOrgVariables(handler, orgID, "a-valid-session-token",
		`{"variables":[],"unexpected":"field"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	if got.OrganizationID != "" {
		t.Errorf("replacer was reached for an unknown-field request: %+v", got)
	}
}

// TestReplaceOrgVariablesRequiresAuthentication proves the auth gate: a
// request missing or carrying an invalid credential is the typed 401
// the authenticator path emits, not a leaked panic, and the replacer
// never runs.
func TestReplaceOrgVariablesRequiresAuthentication(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	var got store.ReplaceOrganizationVariablesInput
	replacer := fakeOrgVariableReplacer{got: &got}

	handler := replaceOrgVariablesHandlerFor(auth.Identity{}, apierr.Unauthenticated("missing token"), replacer)
	rec := putOrgVariables(handler, orgID, "", `{"variables":[]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != "" {
		t.Errorf("replacer ran for an unauthenticated request: %+v", got)
	}
}

// TestReplaceOrgVariablesDeniesCrossTenantPrincipal proves the policy
// engine rejects an {org_id} the principal does not own — the variables
// route uses organizationIDResolver, so a cross-tenant id is denied as a
// 403 before the handler runs, and the replacer never sees the request.
// env.write is a CapWrite action with no cross-tenant support exception.
func TestReplaceOrgVariablesDeniesCrossTenantPrincipal(t *testing.T) {
	t.Parallel()
	const homeOrg = "org_attacker"
	const victimOrg = "org_acme"
	var got store.ReplaceOrganizationVariablesInput
	replacer := fakeOrgVariableReplacer{got: &got}

	id := auth.Identity{
		Principal: orgPrincipal("usr_mallory", homeOrg, policy.RoleOwner),
		Method:    auth.MethodSession,
	}
	handler := replaceOrgVariablesHandlerFor(id, nil, replacer)
	rec := putOrgVariables(handler, victimOrg, "a-valid-session-token",
		`{"variables":[{"key":"BAD","value":"x"}]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != "" {
		t.Errorf("replacer ran for a cross-tenant principal: %+v", got)
	}
	if strings.Contains(rec.Body.String(), "BAD") {
		t.Errorf("forbidden response leaked the submitted key: %s", rec.Body.String())
	}
}

// TestReplaceOrgVariablesPropagatesNotFoundOrganization proves the
// store layer's typed NotFound becomes a 404 on the wire — never
// disguised as a 5xx, and never echoing a cross-tenant id back to the
// caller.
func TestReplaceOrgVariablesPropagatesNotFoundOrganization(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	replacer := fakeOrgVariableReplacer{err: apierr.NotFound("organization", "org_acme")}
	handler := replaceOrgVariablesHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, replacer)

	rec := putOrgVariables(handler, orgID, "a-valid-session-token",
		`{"variables":[{"key":"X","value":"y"}]}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestReplaceOrgVariablesPropagatesInvalidInputFromStore proves the
// store layer's typed InvalidInput (a non-POSIX key, a duplicate key,
// an over-sized value) becomes a 400 on the wire without echoing the
// submitted value content.
func TestReplaceOrgVariablesPropagatesInvalidInputFromStore(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	storeErr := apierr.InvalidInput(apierr.FieldViolation{
		Field:  "variables[0].key",
		Reason: "must be a POSIX environment variable name ([A-Za-z_][A-Za-z0-9_]*)",
	})
	replacer := fakeOrgVariableReplacer{err: storeErr}
	handler := replaceOrgVariablesHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, replacer)

	rec := putOrgVariables(handler, orgID, "a-valid-session-token",
		`{"variables":[{"key":"BAD-KEY","value":"x"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestReplaceOrgVariablesForwardsStoreUnavailableAsTypedFiveHundred
// proves a database outage becomes a stable 5xx envelope, not a leaked
// driver error.
func TestReplaceOrgVariablesForwardsStoreUnavailableAsTypedFiveHundred(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	replacer := fakeOrgVariableReplacer{err: apierr.StoreUnavailable(stderrors.New("connection reset"))}
	handler := replaceOrgVariablesHandlerFor(
		orgVariableActorIdentity(orgID, "usr_ada"), nil, replacer)

	rec := putOrgVariables(handler, orgID, "a-valid-session-token",
		`{"variables":[{"key":"X","value":"y"}]}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection reset") {
		t.Errorf("body leaked the raw driver error: %s", rec.Body.String())
	}
}

// TestReplaceOrgVariablesMissingReplacerIsTypedInternalError proves a
// nil replacer is a wiring error reported as a typed Internal — a
// programming mistake, not a misleading silent success.
func TestReplaceOrgVariablesMissingReplacerIsTypedInternalError(t *testing.T) {
	t.Parallel()
	const orgID = "org_acme"
	a := fakeAuthenticator{identity: orgVariableActorIdentity(orgID, "usr_ada")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, nil, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, nil)

	rec := putOrgVariables(handler, orgID, "a-valid-session-token",
		`{"variables":[{"key":"X","value":"y"}]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// TestReplaceOrgVariablesRouteIsRegistered proves the OpenAPI document
// carries the PUT /v1/organizations/{org_id}/variables operation with
// the stable operationId, the env.write required action, and the
// variables tag — every detail an agent reads to discover the endpoint.
func TestReplaceOrgVariablesRouteIsRegistered(t *testing.T) {
	t.Parallel()
	a := fakeAuthenticator{identity: orgVariableActorIdentity("org_acme", "usr_ada")}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200", rec.Code)
	}

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string   `json:"operationId"`
			Tags           []string `json:"tags"`
			RequiredAction string   `json:"x-required-action"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	op, ok := doc.Paths["/v1/organizations/{org_id}/variables"]["put"]
	if !ok {
		t.Fatalf("PUT /v1/organizations/{org_id}/variables missing from OpenAPI document")
	}
	if op.OperationID != "replaceOrganizationVariables" {
		t.Errorf("operationId = %q, want replaceOrganizationVariables", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionEnvWrite) {
		t.Errorf("x-required-action = %q, want %q", op.RequiredAction, policy.ActionEnvWrite)
	}
	foundTag := false
	for _, tag := range op.Tags {
		if tag == "variables" {
			foundTag = true
			break
		}
	}
	if !foundTag {
		t.Errorf("tags = %v, want it to include \"variables\"", op.Tags)
	}
}
