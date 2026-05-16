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
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// Contract and tenant-isolation coverage for GET
// /v1/environments/{environment_id}/variables (BE-0172). The endpoint
// lists the environment-scoped variables of the environment named by
// the {environment_id} path parameter — by reading them through the
// EnvironmentVariableReader port. The tests drive it through
// NewHandler with a fake Authenticator, the real policy engine, and a
// fake reader — the same wiring a request hits in production, minus
// the database. The store-backed reader has its own isolated-Postgres
// integration coverage in store/environment_variable_test.go — this
// file exercises the HTTP surface in isolation.
//
// This endpoint has a single {environment_id} path parameter, no
// request body, and no query parameters. The store-backed reader
// treats a cross-tenant or unknown environment_id as a deterministic
// 404; the policy-matrix coverage (BE-0174) drives the engine-level
// resource resolution.

// fakeEnvironmentVariableReader is a canned EnvironmentVariableReader
// for httpapi tests. The zero value returns an empty slice and no
// error from ListEnvironmentVariables, which is all the tests that
// never reach the handler (the public-surface, /v1/me, and other-route
// suites) need. Tests that drive this endpoint set vars/err and read
// gotOrgID + gotEnvironmentID back to prove the (org, env) pair
// forwarded to the store is the principal's home org plus the path
// environment_id — never a caller-controlled organization id.
type fakeEnvironmentVariableReader struct {
	vars             []store.EnvironmentVariable
	err              error
	gotOrgID         *string
	gotEnvironmentID *string
	callCount        *int
}

func (f fakeEnvironmentVariableReader) ListEnvironmentVariables(_ context.Context, organizationID, environmentID string) ([]store.EnvironmentVariable, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotEnvironmentID != nil {
		*f.gotEnvironmentID = environmentID
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.vars, f.err
}

// listEnvironmentVariablesSuccessEnvelope is the decoded shape of the
// GET /v1/environments/{environment_id}/variables success envelope.
type listEnvironmentVariablesSuccessEnvelope struct {
	SchemaVersion string                          `json:"schema_version"`
	OK            bool                            `json:"ok"`
	RequestID     string                          `json:"request_id"`
	Data          listEnvironmentVariablesPayload `json:"data"`
}

// fakeEnvironmentVariableReplacer is a canned EnvironmentVariableReplacer
// for httpapi tests. The zero value returns nil/nil from Replace, which
// is all the tests that never reach the handler (the public-surface,
// /v1/me, and other-route suites) need. Tests that drive this endpoint
// set vars/err and read got back to prove the
// ReplaceEnvironmentVariablesInput forwarded to the store carries the
// principal's home org plus the path environment_id — never a caller-
// controlled organization id — and the caller-supplied variable set.
type fakeEnvironmentVariableReplacer struct {
	vars      []store.EnvironmentVariable
	err       error
	got       *store.ReplaceEnvironmentVariablesInput
	callCount *int
}

func (f fakeEnvironmentVariableReplacer) Replace(_ context.Context, in store.ReplaceEnvironmentVariablesInput) ([]store.EnvironmentVariable, error) {
	if f.got != nil {
		*f.got = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.vars, f.err
}

// replaceEnvironmentVariablesSuccessEnvelope is the decoded shape of the
// PUT /v1/environments/{environment_id}/variables success envelope.
type replaceEnvironmentVariablesSuccessEnvelope struct {
	SchemaVersion string                             `json:"schema_version"`
	OK            bool                               `json:"ok"`
	RequestID     string                             `json:"request_id"`
	Data          replaceEnvironmentVariablesPayload `json:"data"`
}

// listEnvironmentVariablesHandlerFor builds the full NewHandler
// surface with an Authenticator that resolves every credential to id
// and the given EnvironmentVariableReader. It is the production
// request path: the /v1/environments/{environment_id}/variables route
// is wrapped in RequireAuth for action env.read.
func listEnvironmentVariablesHandlerFor(id auth.Identity, authErr error, reader EnvironmentVariableReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, reader, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// getEnvironmentVariables issues GET
// /v1/environments/{environment_id}/variables against handler,
// optionally with a bearer token.
func getEnvironmentVariables(handler http.Handler, environmentID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/environments/"+environmentID+"/variables", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListEnvironmentVariables(t *testing.T, rec *httptest.ResponseRecorder) listEnvironmentVariablesSuccessEnvelope {
	t.Helper()
	var env listEnvironmentVariablesSuccessEnvelope
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

// principalForEnvironmentVariables returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// env.read is a CapRead action so a developer in the principal's home
// tenant is admitted at the policy boundary; the tests use this to
// focus on downstream wire and persistence behavior, not on the role
// matrix (which is BE-0174's job).
func principalForEnvironmentVariables(principalID, organizationID string) auth.Identity {
	return auth.Identity{
		Principal: policy.Principal{
			ID:             principalID,
			Kind:           "usr",
			OrganizationID: organizationID,
			Role:           policy.RoleDeveloper,
		},
		Method: "api_key",
	}
}

// seedEnvironmentVariableWire builds a store.EnvironmentVariable
// fixture for the fakeEnvironmentVariableReader. It is a plain literal
// helper — no database — so the tests stay pure unit tests of the
// HTTP wire path.
func seedEnvironmentVariableWire(id, orgID, environmentID, key, value string, isSecret bool, version int64, created, updated time.Time) store.EnvironmentVariable {
	return store.EnvironmentVariable{
		ID:             id,
		OrganizationID: orgID,
		EnvironmentID:  environmentID,
		Key:            key,
		Value:          value,
		IsSecret:       isSecret,
		Version:        version,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
}

// TestListEnvironmentVariablesHappyPath drives the production request
// path against an environment the principal's home organization owns.
// The principal is an organization-wide Developer so the policy gate
// admits the read; the reader returns two variables — a non-secret
// REGION and a secret DATABASE_URL — and the assertions pin every
// load-bearing field of the wire shape, including the redaction
// chokepoint: the secret value renders as output.Sentinel, never the
// seeded plaintext.
func TestListEnvironmentVariablesHappyPath(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const env = "env_prod"
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	updated := created.Add(time.Hour)

	var gotOrg, gotEnv string
	callCount := 0
	reader := fakeEnvironmentVariableReader{
		vars: []store.EnvironmentVariable{
			seedEnvironmentVariableWire("evar_db", org, env, "DATABASE_URL", "postgres://user:hunter2@db.internal/yalla", true, 3, created, updated),
			seedEnvironmentVariableWire("evar_region", org, env, "REGION", "us-east-1", false, 1, created, created),
		},
		gotOrgID:         &gotOrg,
		gotEnvironmentID: &gotEnv,
		callCount:        &callCount,
	}

	handler := listEnvironmentVariablesHandlerFor(
		principalForEnvironmentVariables("usr_dev", org), nil, reader)

	rec := getEnvironmentVariables(handler, env, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1", callCount)
	}
	if gotOrg != org {
		t.Errorf("reader received organization id %q, want the principal's home org %q", gotOrg, org)
	}
	if gotEnv != env {
		t.Errorf("reader received environment id %q, want the path parameter %q", gotEnv, env)
	}

	envelope := decodeListEnvironmentVariables(t, rec)
	if len(envelope.Data.Variables) != 2 {
		t.Fatalf("variables len = %d, want 2; body %s", len(envelope.Data.Variables), rec.Body.String())
	}

	db := envelope.Data.Variables[0]
	if db.ID != "evar_db" || db.Key != "DATABASE_URL" || !db.IsSecret {
		t.Errorf("[0] = %+v, want (evar_db, DATABASE_URL, is_secret=true)", db)
	}
	// Wire-level redaction chokepoint: the secret value is the sentinel,
	// never the seeded plaintext.
	if db.Value != output.Sentinel {
		t.Errorf("[0].Value = %q, want output.Sentinel for a secret variable", db.Value)
	}
	if db.OrganizationID != org || db.EnvironmentID != env {
		t.Errorf("[0] org/env = (%q, %q), want (%q, %q)", db.OrganizationID, db.EnvironmentID, org, env)
	}
	if db.Version != 3 {
		t.Errorf("[0].Version = %d, want 3", db.Version)
	}

	region := envelope.Data.Variables[1]
	if region.ID != "evar_region" || region.Key != "REGION" || region.IsSecret {
		t.Errorf("[1] = %+v, want (evar_region, REGION, is_secret=false)", region)
	}
	// Non-secret values project verbatim.
	if region.Value != "us-east-1" {
		t.Errorf("[1].Value = %q, want us-east-1", region.Value)
	}

	// Response body must never echo the secret plaintext nor any
	// recognisable fragment of it.
	body := rec.Body.String()
	for _, leak := range []string{"hunter2", "postgres://user", "db.internal"} {
		if strings.Contains(body, leak) {
			t.Errorf("response body leaks secret fragment %q: %s", leak, body)
		}
	}
}

// TestListEnvironmentVariablesEmptyEnvironment proves a real
// environment with no variables yields a deterministic empty array
// (not null) so agents can iterate the field without a nil check.
func TestListEnvironmentVariablesEmptyEnvironment(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const env = "env_empty"
	reader := fakeEnvironmentVariableReader{vars: nil}

	handler := listEnvironmentVariablesHandlerFor(
		principalForEnvironmentVariables("usr_dev", org), nil, reader)

	rec := getEnvironmentVariables(handler, env, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	envelope := decodeListEnvironmentVariables(t, rec)
	if envelope.Data.Variables == nil {
		t.Errorf("variables = nil; want a non-nil empty slice")
	}
	if len(envelope.Data.Variables) != 0 {
		t.Errorf("variables len = %d, want 0", len(envelope.Data.Variables))
	}
	// The JSON literal must carry an explicit `[]`, never `null`, so
	// agents can iterate without a nil check.
	if !strings.Contains(rec.Body.String(), `"variables":[]`) {
		t.Errorf("body does not contain \"variables\":[]; got %s", rec.Body.String())
	}
}

// TestListEnvironmentVariablesNotFoundFromReader proves the store-
// layer apierr.NotFound (a cross-tenant or unknown environment_id)
// reaches the HTTP wire as a deterministic 404 yalla.error.v1
// envelope — never a silent empty success, never a 500 leaking the
// cause.
func TestListEnvironmentVariablesNotFoundFromReader(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	reader := fakeEnvironmentVariableReader{
		err: apierr.NotFound("environment", "env_unknown"),
	}

	handler := listEnvironmentVariablesHandlerFor(
		principalForEnvironmentVariables("usr_dev", org), nil, reader)

	rec := getEnvironmentVariables(handler, "env_unknown", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestListEnvironmentVariablesStoreUnavailable proves a datastore
// outage surfaces as the typed 503 — never disguised as a 5xx leaking
// the pgx cause, and never as a misleading empty list.
func TestListEnvironmentVariablesStoreUnavailable(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const env = "env_prod"
	reader := fakeEnvironmentVariableReader{
		err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused")),
	}

	handler := listEnvironmentVariablesHandlerFor(
		principalForEnvironmentVariables("usr_dev", org), nil, reader)

	rec := getEnvironmentVariables(handler, env, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	// The raw pgx cause must not leak to the wire.
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestListEnvironmentVariablesUnauthenticated proves a request without
// a valid credential is denied at the auth boundary with a 401 — the
// reader never runs, so no variable id, key, or value can leak.
func TestListEnvironmentVariablesUnauthenticated(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const env = "env_prod"
	callCount := 0
	reader := fakeEnvironmentVariableReader{
		vars: []store.EnvironmentVariable{
			seedEnvironmentVariableWire("evar_db", org, env, "DATABASE_URL", "leak-me", true, 1, time.Now(), time.Now()),
		},
		callCount: &callCount,
	}

	handler := listEnvironmentVariablesHandlerFor(
		auth.Identity{}, apierr.Unauthenticated("missing token"), reader)

	rec := getEnvironmentVariables(handler, env, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("reader call count = %d, want 0 (auth must short-circuit)", callCount)
	}
	for _, leak := range []string{"evar_db", "DATABASE_URL", "leak-me"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("401 body leaks reader-side identifier %q: %s", leak, rec.Body.String())
		}
	}
}

// TestListEnvironmentVariablesMissingReader proves a request that
// reaches a handler with a nil reader (a wiring error) surfaces as the
// typed internal error, never a misleading 200 with an empty list. The
// invariant matches every other reader-port: a missing dependency must
// not silently degrade the response.
func TestListEnvironmentVariablesMissingReader(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const env = "env_prod"
	handler := listEnvironmentVariablesHandlerFor(
		principalForEnvironmentVariables("usr_dev", org), nil, nil)

	rec := getEnvironmentVariables(handler, env, "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}

// TestListEnvironmentVariablesOpenAPIRouteIsRegistered proves the
// OpenAPI document carries the GET
// /v1/environments/{environment_id}/variables operation with the
// stable operationId, the env.read required action, and the
// environments + variables tags — every detail an agent reads to
// discover the endpoint.
func TestListEnvironmentVariablesOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/environments/{environment_id}/variables" {
			found = true
			if rt.endpoint.OperationID != "listEnvironmentVariables" {
				t.Errorf("operation_id = %q, want listEnvironmentVariables", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionEnvRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionEnvRead)
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
		t.Errorf("GET /v1/environments/{environment_id}/variables not in route table")
	}
}
