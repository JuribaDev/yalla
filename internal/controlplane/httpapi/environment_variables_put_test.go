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
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// Contract, authorization, and tenant-isolation coverage for PUT
// /v1/environments/{environment_id}/variables (BE-0175). The endpoint
// replaces the environment-scoped variables attached to the environment
// through the EnvironmentVariableReplacer port; the tests drive it
// through NewHandler with a fake Authenticator, the real policy engine,
// and a fake replacer — the same wiring a request hits in production,
// minus the database. The store-backed replacer has its own isolated-
// Postgres integration coverage in store/environment_variable_test.go —
// this file exercises the HTTP surface in isolation. The full role x
// tenant x grant-scope matrix lives in
// environment_variables_put_policy_test.go (BE-0177).
//
// env.write is a CapWrite action: viewer and support principals in the
// tenant cannot replace variables — only owner, admin, developer, and
// CI principals can. The happy-path tests therefore authenticate as
// RoleDeveloper to keep the role matrix focused on the policy suite.
//
// Validation surface: the body decoder rejects oversized/malformed/
// unknown-field bodies as 400 (the global validate.DecodeJSON contract),
// the handler additionally surfaces a 400 for a body that does not name
// the "variables" field (so a misencoded request is never a silent
// clear). Field-level validation of key shape, duplicate key, value
// size, UTF-8, embedded NUL is the store-layer's job and is asserted
// through the replacer error path here, not by re-validating in the
// handler. Wire-level secret redaction (the post-write re-read still
// renders is_secret=true rows as output.Sentinel) is asserted on the
// happy-path response so PUT cannot leak a secret value the customer
// just submitted.

// replaceEnvironmentVariablesHandlerFor builds an http.Handler that
// points at the PUT /v1/environments/{environment_id}/variables route,
// wired through the same NewHandler the production binary uses. id and
// authErr drive the fake authenticator; replacer is the
// EnvironmentVariableReplacer the handler delegates to.
func replaceEnvironmentVariablesHandlerFor(id auth.Identity, authErr error, replacer EnvironmentVariableReplacer) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, replacer, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// putEnvironmentVariables issues PUT
// /v1/environments/{environmentID}/variables against handler with body,
// optionally with a bearer token.
func putEnvironmentVariables(handler http.Handler, environmentID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut,
		"/v1/environments/"+environmentID+"/variables",
		strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// decodeReplaceEnvironmentVariables decodes the JSON success body returned
// by PUT /v1/environments/{environment_id}/variables into the wire shape
// the contract pins down.
func decodeReplaceEnvironmentVariables(t *testing.T, rec *httptest.ResponseRecorder) replaceEnvironmentVariablesSuccessEnvelope {
	t.Helper()
	var env replaceEnvironmentVariablesSuccessEnvelope
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

// environmentVariablesWriterIdentity returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// env.write is a CapWrite action and CapWrite is admitted via owner,
// admin, developer, and ci roles, so the happy-path tests authenticate
// the actor at RoleDeveloper to keep the role matrix focused on the
// environment_variables_put_policy_test.go suite (BE-0177).
func environmentVariablesWriterIdentity(organizationID, principalID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             principalID,
			Kind:           "usr",
			OrganizationID: organizationID,
			Role:           policy.RoleDeveloper,
		},
		Method: auth.MethodSession,
	}
}

// TestReplaceEnvironmentVariablesReturnsPersistedVariables is the happy
// path: a PUT carrying a fresh replacement set is forwarded to the
// replacer verbatim, the resulting committed rows are projected onto
// the stable wire shape, the envelope's request_id propagates, every
// variable column reaches the wire, and the wire-level redaction
// chokepoint still fires on the post-write re-read — a secret value
// the customer just submitted projects as output.Sentinel, never the
// seeded plaintext.
func TestReplaceEnvironmentVariablesReturnsPersistedVariables(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 14, 6, 7, 8, 0, time.UTC)

	post := []store.EnvironmentVariable{
		seedEnvironmentVariableWire("evar_db", orgID, envID, "DATABASE_URL", "postgres://user:hunter2@db.internal/yalla", true, 2, created, updated),
		seedEnvironmentVariableWire("evar_region", orgID, envID, "REGION", "us-east-1", false, 1, created, created),
	}
	var got store.ReplaceEnvironmentVariablesInput
	replacer := fakeEnvironmentVariableReplacer{vars: post, got: &got}
	handler := replaceEnvironmentVariablesHandlerFor(
		environmentVariablesWriterIdentity(orgID, "usr_dev"), nil, replacer)

	body := `{"variables":[` +
		`{"key":"DATABASE_URL","value":"postgres://user:hunter2@db.internal/yalla","is_secret":true},` +
		`{"key":"REGION","value":"us-east-1"}` +
		`]}`
	rec := putEnvironmentVariables(handler, envID, "a-valid-session-token", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	env := decodeReplaceEnvironmentVariables(t, rec)
	if len(env.Data.Variables) != 2 {
		t.Fatalf("variables len = %d, want 2 (got %+v)", len(env.Data.Variables), env.Data.Variables)
	}

	got0 := env.Data.Variables[0]
	if got0.ID != "evar_db" || got0.Key != "DATABASE_URL" || !got0.IsSecret {
		t.Errorf("variables[0] = %+v, want evar_db/DATABASE_URL/is_secret=true", got0)
	}
	// Wire-level redaction chokepoint: even on the post-write re-read the
	// secret value is the sentinel, never the seeded plaintext.
	if got0.Value != output.Sentinel {
		t.Errorf("variables[0].Value = %q, want output.Sentinel for a secret variable", got0.Value)
	}
	if got0.OrganizationID != orgID || got0.EnvironmentID != envID {
		t.Errorf("variables[0] org/env = (%q, %q), want (%q, %q)", got0.OrganizationID, got0.EnvironmentID, orgID, envID)
	}
	if got0.Version != 2 {
		t.Errorf("variables[0].Version = %d, want 2", got0.Version)
	}

	got1 := env.Data.Variables[1]
	if got1.ID != "evar_region" || got1.Key != "REGION" || got1.IsSecret {
		t.Errorf("variables[1] = %+v, want evar_region/REGION/is_secret=false", got1)
	}
	// Non-secret values project verbatim on the wire.
	if got1.Value != "us-east-1" {
		t.Errorf("variables[1].Value = %q, want us-east-1", got1.Value)
	}

	// Response body must never echo the secret plaintext nor any
	// recognisable fragment of it — even on the success path, where the
	// caller just submitted the plaintext.
	bodyStr := rec.Body.String()
	for _, leak := range []string{"hunter2", "postgres://user", "db.internal"} {
		if strings.Contains(bodyStr, leak) {
			t.Errorf("response body leaks secret fragment %q: %s", leak, bodyStr)
		}
	}

	// The replacer MUST receive (principal home org, path environment_id)
	// and every body field verbatim — never a caller-controlled
	// organization id (there isn't one on the wire, but pin the
	// structural property).
	if got.OrganizationID != orgID {
		t.Errorf("replacer received org_id %q, want the principal's home org %q", got.OrganizationID, orgID)
	}
	if got.EnvironmentID != envID {
		t.Errorf("replacer received environment_id %q, want the path parameter %q", got.EnvironmentID, envID)
	}
	if len(got.Variables) != 2 {
		t.Fatalf("replacer received %d variables, want 2: %+v", len(got.Variables), got.Variables)
	}
	if got.Variables[0].Key != "DATABASE_URL" || !got.Variables[0].IsSecret || got.Variables[0].Value != "postgres://user:hunter2@db.internal/yalla" {
		t.Errorf("variables[0] = %+v, want DATABASE_URL/is_secret=true/postgres URL", got.Variables[0])
	}
	if got.Variables[1].Key != "REGION" || got.Variables[1].IsSecret || got.Variables[1].Value != "us-east-1" {
		t.Errorf("variables[1] = %+v, want REGION/is_secret=false/us-east-1", got.Variables[1])
	}
	if got.ActorID != "usr_dev" || got.ActorOrgID != orgID || got.ActorKind != "usr" {
		t.Errorf("replacer received actor=(%q, %q, %q), want (usr_dev, %q, usr)",
			got.ActorID, got.ActorOrgID, got.ActorKind, orgID)
	}
}

// TestReplaceEnvironmentVariablesForwardsEmptyListAsExplicitClear proves
// the empty-array semantics reach the store layer: the handler must not
// reject "variables: []" as a no-op — an explicit clear is a meaningful
// (extreme) operation, and the body must serialise an explicit `[]`,
// never `null`, so agents can iterate without a nil check.
func TestReplaceEnvironmentVariablesForwardsEmptyListAsExplicitClear(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	var got store.ReplaceEnvironmentVariablesInput
	replacer := fakeEnvironmentVariableReplacer{vars: []store.EnvironmentVariable{}, got: &got}
	handler := replaceEnvironmentVariablesHandlerFor(
		environmentVariablesWriterIdentity(orgID, "usr_dev"), nil, replacer)

	rec := putEnvironmentVariables(handler, envID, "a-valid-session-token", `{"variables":[]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != orgID {
		t.Errorf("replacer received org_id %q, want %q (an empty replace must reach the store layer)",
			got.OrganizationID, orgID)
	}
	if got.EnvironmentID != envID {
		t.Errorf("replacer received environment_id %q, want %q", got.EnvironmentID, envID)
	}
	if got.Variables == nil {
		t.Errorf("replacer received nil Variables, want a non-nil empty slice")
	}
	if len(got.Variables) != 0 {
		t.Errorf("replacer received %d items, want 0", len(got.Variables))
	}
	env := decodeReplaceEnvironmentVariables(t, rec)
	if env.Data.Variables == nil {
		t.Errorf("response variables is nil, want a non-nil empty slice")
	}
	if len(env.Data.Variables) != 0 {
		t.Errorf("response variables = %+v, want []", env.Data.Variables)
	}
	if !strings.Contains(rec.Body.String(), `"variables":[]`) {
		t.Errorf("body missing empty variables array: %s", rec.Body.String())
	}
}

// TestReplaceEnvironmentVariablesRejectsMissingVariablesField proves the
// missing-field guard: a body that omits the "variables" field
// altogether is rejected as a stable 400 (apierr.InvalidInput) naming
// the offending field, never silently treated as a clear. An empty
// array reaches the store layer; a missing field does not.
func TestReplaceEnvironmentVariablesRejectsMissingVariablesField(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentVariableReplacer{callCount: &callCount}
	handler := replaceEnvironmentVariablesHandlerFor(
		environmentVariablesWriterIdentity(orgID, "usr_dev"), nil, replacer)

	rec := putEnvironmentVariables(handler, envID, "a-valid-session-token", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, string(yerr.CodeInvalidInput))
	// The error must name the offending field so an agent can correct the
	// body shape without re-reading the OpenAPI document. The renderer
	// emits the field path inside the hint as "<field>: <reason>".
	if !strings.Contains(rec.Body.String(), "variables: ") {
		t.Errorf("invalid-input body does not name the offending field: %s", rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (a missing variables field never reaches the store)", callCount)
	}
}

// TestReplaceEnvironmentVariablesRejectsMalformedJSON proves a malformed
// body becomes a stable 400 through the global validate.DecodeJSON
// contract — the replacer must never run on a body the decoder rejected.
func TestReplaceEnvironmentVariablesRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentVariableReplacer{callCount: &callCount}
	handler := replaceEnvironmentVariablesHandlerFor(
		environmentVariablesWriterIdentity(orgID, "usr_dev"), nil, replacer)

	rec := putEnvironmentVariables(handler, envID, "a-valid-session-token", `{"variables":[`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, string(yerr.CodeInvalidInput))
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (a malformed body never reaches the store)", callCount)
	}
}

// TestReplaceEnvironmentVariablesRejectsUnknownField proves the
// strict-decode contract: an unknown field at the top level becomes a
// stable 400, never silently accepted. The same contract rejects
// unknown fields nested inside variables[i] — both directions are
// load-bearing for the agent contract.
func TestReplaceEnvironmentVariablesRejectsUnknownField(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentVariableReplacer{callCount: &callCount}
	handler := replaceEnvironmentVariablesHandlerFor(
		environmentVariablesWriterIdentity(orgID, "usr_dev"), nil, replacer)

	rec := putEnvironmentVariables(handler, envID, "a-valid-session-token",
		`{"variables":[],"unexpected":"field"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (a body with an unknown field never reaches the store)", callCount)
	}
}

// TestReplaceEnvironmentVariablesRequiresAuthentication proves an
// unauthenticated request is the typed 401 the authenticator path
// emits, not a leaked panic, and the replacer never runs. The body
// must never echo a variable key, value, or id back to an
// unauthenticated caller — even the seeded plaintext secret that a
// previous successful PUT might have left in the fake.
func TestReplaceEnvironmentVariablesRequiresAuthentication(t *testing.T) {
	t.Parallel()

	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentVariableReplacer{
		vars: []store.EnvironmentVariable{
			seedEnvironmentVariableWire("evar_db", "org_acme", envID, "DATABASE_URL", "leak-me-plaintext", true, 1, time.Now(), time.Now()),
		},
		callCount: &callCount,
	}
	handler := replaceEnvironmentVariablesHandlerFor(auth.Identity{}, auth.ErrNoCredentials, replacer)

	rec := putEnvironmentVariables(handler, envID, "", `{"variables":[]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, string(yerr.CodeAuth))
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (RequireAuth must reject before the handler runs)", callCount)
	}
	for _, leak := range []string{"evar_db", "DATABASE_URL", "leak-me-plaintext"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("401 body leaks replacer-side identifier %q: %s", leak, rec.Body.String())
		}
	}
}

// TestReplaceEnvironmentVariablesDeniesViewerInTenant proves a viewer
// principal in the environment's tenant is rejected with 403 before
// the replacer runs. env.write is a CapWrite action; viewer holds
// CapRead only — and unlike CapRead actions there is no cross-tenant
// support exception either.
func TestReplaceEnvironmentVariablesDeniesViewerInTenant(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentVariableReplacer{callCount: &callCount}

	id := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_viewer",
			Kind:           "usr",
			OrganizationID: orgID,
			Role:           policy.RoleViewer,
		},
		Method: auth.MethodSession,
	}
	handler := replaceEnvironmentVariablesHandlerFor(id, nil, replacer)
	rec := putEnvironmentVariables(handler, envID, "a-valid-session-token", `{"variables":[]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, string(yerr.CodeForbidden))
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (a viewer must be denied at the policy boundary)", callCount)
	}
}

// TestReplaceEnvironmentVariablesDeniesSupportInTenant proves a support
// principal in the environment's tenant is denied 403 — env.write is a
// CapWrite action and CapWrite has no support exception (only CapRead
// admits support, and only cross-tenant at that). Locking this with a
// concrete contract test makes a future regression that widens
// CapWrite to support visible immediately.
func TestReplaceEnvironmentVariablesDeniesSupportInTenant(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	callCount := 0
	replacer := fakeEnvironmentVariableReplacer{callCount: &callCount}

	id := auth.Identity{
		Principal: policy.Principal{
			ID:             "usr_support",
			Kind:           "usr",
			OrganizationID: orgID,
			Role:           policy.RoleSupport,
		},
		Method: auth.MethodSession,
	}
	handler := replaceEnvironmentVariablesHandlerFor(id, nil, replacer)
	rec := putEnvironmentVariables(handler, envID, "a-valid-session-token", `{"variables":[]}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, string(yerr.CodeForbidden))
	if callCount != 0 {
		t.Errorf("replacer call count = %d, want 0 (support must be denied env.write at the policy boundary — CapWrite has no support exception)", callCount)
	}
}

// TestReplaceEnvironmentVariablesPropagatesNotFoundEnvironment proves the
// store layer's typed NotFound becomes a 404 on the wire — never
// disguised as a 5xx, and never echoing a cross-tenant id back to the
// caller. The store-backed replacer surfaces a cross-tenant or unknown
// environment_id as apierr.NotFound, which this handler must propagate
// verbatim.
func TestReplaceEnvironmentVariablesPropagatesNotFoundEnvironment(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	replacer := fakeEnvironmentVariableReplacer{err: apierr.NotFound("environment", "env_unknown")}
	handler := replaceEnvironmentVariablesHandlerFor(
		environmentVariablesWriterIdentity(orgID, "usr_dev"), nil, replacer)

	rec := putEnvironmentVariables(handler, "env_unknown", "a-valid-session-token", `{"variables":[]}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestReplaceEnvironmentVariablesPropagatesInvalidInputFromStore proves
// a store-layer validation failure (a non-POSIX key, a duplicate key,
// an oversize value, invalid UTF-8, an embedded NUL) becomes a stable
// 400 carrying the store's field-path shape — the handler never
// re-validates and the wire body names the offending field.
func TestReplaceEnvironmentVariablesPropagatesInvalidInputFromStore(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	storeErr := apierr.InvalidInput(apierr.FieldViolation{
		Field:  "variables[0].key",
		Reason: "must match [A-Z_][A-Z0-9_]* (POSIX environment variable name)",
	})
	replacer := fakeEnvironmentVariableReplacer{err: storeErr}
	handler := replaceEnvironmentVariablesHandlerFor(
		environmentVariablesWriterIdentity(orgID, "usr_dev"), nil, replacer)

	rec := putEnvironmentVariables(handler, envID, "a-valid-session-token",
		`{"variables":[{"key":"123bad","value":"x"}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, string(yerr.CodeInvalidInput))
	if !strings.Contains(rec.Body.String(), "variables[0].key") {
		t.Errorf("invalid-input body does not name the offending field path: %s", rec.Body.String())
	}
}

// TestReplaceEnvironmentVariablesForwardsStoreUnavailableAsTypedFiveHundred
// proves a database outage becomes a stable 5xx envelope, not a leaked
// driver error. The raw pgx cause must never reach the wire.
func TestReplaceEnvironmentVariablesForwardsStoreUnavailableAsTypedFiveHundred(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	replacer := fakeEnvironmentVariableReplacer{err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused"))}
	handler := replaceEnvironmentVariablesHandlerFor(
		environmentVariablesWriterIdentity(orgID, "usr_dev"), nil, replacer)

	rec := putEnvironmentVariables(handler, envID, "a-valid-session-token", `{"variables":[]}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, string(yerr.CodeUnavailable))
	for _, leak := range []string{"dial tcp", "connection refused"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("response leaks driver-level cause %q: %s", leak, rec.Body.String())
		}
	}
}

// TestReplaceEnvironmentVariablesReturnsInternalWhenReplacerUnwired
// proves an unwired replacer (a programming wiring error, not a client
// error) is reported as a typed internal failure rather than silently
// failing to persist the change. The invariant matches every other
// replacer port.
func TestReplaceEnvironmentVariablesReturnsInternalWhenReplacerUnwired(t *testing.T) {
	t.Parallel()

	const orgID = "org_acme"
	const envID = "env_acme_prod"
	handler := replaceEnvironmentVariablesHandlerFor(
		environmentVariablesWriterIdentity(orgID, "usr_dev"), nil, nil)

	rec := putEnvironmentVariables(handler, envID, "a-valid-session-token", `{"variables":[]}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	_ = decodeError(t, rec, string(yerr.CodeInternal))
}

// TestReplaceEnvironmentVariablesRouteIsRegistered proves the OpenAPI
// document carries the PUT /v1/environments/{environment_id}/variables
// operation with the stable operationId, the env.write required
// action, and the environments + variables tags — every detail an
// agent reads to discover the endpoint.
func TestReplaceEnvironmentVariablesRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodPut && rt.endpoint.Path == "/v1/environments/{environment_id}/variables" {
			found = true
			if rt.endpoint.OperationID != "replaceEnvironmentVariables" {
				t.Errorf("operation_id = %q, want replaceEnvironmentVariables", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionEnvWrite) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionEnvWrite)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
			var hasEnvironments, hasVariables bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagEnvironments {
					hasEnvironments = true
				}
				if tag == tagVariables {
					hasVariables = true
				}
			}
			if !hasEnvironments || !hasVariables {
				t.Errorf("tags = %v, want both %q and %q", rt.endpoint.Tags, tagEnvironments, tagVariables)
			}
		}
	}
	if !found {
		t.Errorf("PUT /v1/environments/{environment_id}/variables not in route table")
	}
}
