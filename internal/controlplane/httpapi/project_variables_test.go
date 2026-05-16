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
// /v1/projects/{project_id}/variables (BE-0142). The endpoint lists the
// project-scoped variables of the project named by the {project_id}
// path parameter — by reading them through the ProjectVariableReader
// port. The tests drive it through NewHandler with a fake Authenticator,
// the real policy engine, and a fake reader — the same wiring a request
// hits in production, minus the database. The store-backed reader has
// its own isolated-Postgres integration coverage in
// store/project_variable_test.go — this file exercises the HTTP surface
// in isolation.
//
// This endpoint has a single {project_id} path parameter, no request
// body, and no query parameters. The store-backed reader treats a
// cross-tenant or unknown project_id as a deterministic 404; the
// policy-matrix coverage (BE-0144) drives the engine-level resource
// resolution.

// fakeProjectVariableReader is a canned ProjectVariableReader for
// httpapi tests. The zero value returns an empty slice and no error
// from ListProjectVariables, which is all the tests that never reach
// the handler (the public-surface, /v1/me, and other-route suites)
// need. Tests that drive this endpoint set vars/err and read
// gotOrgID + gotProjectID back to prove the (org, project) pair
// forwarded to the store is the principal's home org plus the path
// project_id — never a caller-controlled organization id.
type fakeProjectVariableReader struct {
	vars         []store.ProjectVariable
	err          error
	gotOrgID     *string
	gotProjectID *string
	callCount    *int
}

func (f fakeProjectVariableReader) ListProjectVariables(_ context.Context, organizationID, projectID string) ([]store.ProjectVariable, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotProjectID != nil {
		*f.gotProjectID = projectID
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.vars, f.err
}

// fakeProjectVariableReplacer is the test double for the
// ProjectVariableReplacer port. The zero value returns nil/nil from
// Replace, which is all the tests that never reach the PUT handler (the
// public-surface, /v1/me, and other-route suites) need. Tests that drive
// the PUT endpoint set vars/err and read got back to prove the
// ReplaceProjectVariablesInput forwarded to the store carries the
// principal's home org and actor id verbatim — never a caller-controlled
// organization id, and never a leaked secret in audit metadata.
type fakeProjectVariableReplacer struct {
	vars      []store.ProjectVariable
	err       error
	got       *store.ReplaceProjectVariablesInput
	callCount *int
}

func (f fakeProjectVariableReplacer) Replace(_ context.Context, in store.ReplaceProjectVariablesInput) ([]store.ProjectVariable, error) {
	if f.got != nil {
		*f.got = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.vars, f.err
}

// listProjectVariablesSuccessEnvelope is the decoded shape of the GET
// /v1/projects/{project_id}/variables success envelope.
type listProjectVariablesSuccessEnvelope struct {
	SchemaVersion string                      `json:"schema_version"`
	OK            bool                        `json:"ok"`
	RequestID     string                      `json:"request_id"`
	Data          listProjectVariablesPayload `json:"data"`
}

// listProjectVariablesHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ProjectVariableReader. It is the production request path: the
// /v1/projects/{project_id}/variables route is wrapped in RequireAuth
// for action env.read.
func listProjectVariablesHandlerFor(id auth.Identity, authErr error, reader ProjectVariableReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, reader, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeBreakGlassController{}, nil, nil)
}

// getProjectVariables issues GET /v1/projects/{project_id}/variables
// against handler, optionally with a bearer token.
func getProjectVariables(handler http.Handler, projectID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/projects/"+projectID+"/variables", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListProjectVariables(t *testing.T, rec *httptest.ResponseRecorder) listProjectVariablesSuccessEnvelope {
	t.Helper()
	var env listProjectVariablesSuccessEnvelope
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

// replaceProjectVariablesSuccessEnvelope is the decoded shape of the PUT
// /v1/projects/{project_id}/variables success envelope.
type replaceProjectVariablesSuccessEnvelope struct {
	SchemaVersion string                         `json:"schema_version"`
	OK            bool                           `json:"ok"`
	RequestID     string                         `json:"request_id"`
	Data          replaceProjectVariablesPayload `json:"data"`
}

// replaceProjectVariablesHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ProjectVariableReplacer. It is the production request path: the
// PUT /v1/projects/{project_id}/variables route is wrapped in
// RequireAuth for action env.write.
func replaceProjectVariablesHandlerFor(id auth.Identity, authErr error, replacer ProjectVariableReplacer) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, replacer, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeBreakGlassController{}, nil, nil)
}

// putProjectVariables issues PUT /v1/projects/{project_id}/variables
// against handler, optionally with a bearer token.
func putProjectVariables(handler http.Handler, projectID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut,
		"/v1/projects/"+projectID+"/variables",
		strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeReplaceProjectVariables(t *testing.T, rec *httptest.ResponseRecorder) replaceProjectVariablesSuccessEnvelope {
	t.Helper()
	var env replaceProjectVariablesSuccessEnvelope
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

// principalForProjectVariables returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// env.read is a CapRead action so a developer in the principal's home
// tenant is admitted at the policy boundary; the tests use this to
// focus on downstream wire and persistence behavior, not on the role
// matrix (which is BE-0144's job).
func principalForProjectVariables(principalID, organizationID string) auth.Identity {
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

// seedProjectVariableWire builds a store.ProjectVariable fixture for
// the fakeProjectVariableReader. It is a plain literal helper — no
// database — so the tests stay pure unit tests of the HTTP wire path.
func seedProjectVariableWire(id, orgID, projectID, key, value string, isSecret bool, version int64, created, updated time.Time) store.ProjectVariable {
	return store.ProjectVariable{
		ID:             id,
		OrganizationID: orgID,
		ProjectID:      projectID,
		Key:            key,
		Value:          value,
		IsSecret:       isSecret,
		Version:        version,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
}

// TestListProjectVariablesHappyPath drives the production request path
// against a project the principal's home organization owns. The
// principal is an organization-wide Developer so the policy gate
// admits the read; the reader returns two variables — a non-secret
// REGION and a secret DATABASE_URL — and the assertions pin every
// load-bearing field of the wire shape, including the redaction
// chokepoint: the secret value renders as output.Sentinel, never the
// seeded plaintext.
func TestListProjectVariablesHappyPath(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_backend"
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	updated := created.Add(time.Hour)

	var gotOrg, gotProj string
	callCount := 0
	reader := fakeProjectVariableReader{
		vars: []store.ProjectVariable{
			seedProjectVariableWire("pvar_db", org, proj, "DATABASE_URL", "postgres://user:hunter2@db.internal/yalla", true, 3, created, updated),
			seedProjectVariableWire("pvar_region", org, proj, "REGION", "us-east-1", false, 1, created, created),
		},
		gotOrgID:     &gotOrg,
		gotProjectID: &gotProj,
		callCount:    &callCount,
	}

	handler := listProjectVariablesHandlerFor(
		principalForProjectVariables("usr_dev", org), nil, reader)

	rec := getProjectVariables(handler, proj, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 1 {
		t.Errorf("reader call count = %d, want 1", callCount)
	}
	if gotOrg != org {
		t.Errorf("reader received organization id %q, want the principal's home org %q", gotOrg, org)
	}
	if gotProj != proj {
		t.Errorf("reader received project id %q, want the path parameter %q", gotProj, proj)
	}

	env := decodeListProjectVariables(t, rec)
	if len(env.Data.Variables) != 2 {
		t.Fatalf("variables len = %d, want 2; body %s", len(env.Data.Variables), rec.Body.String())
	}

	db := env.Data.Variables[0]
	if db.ID != "pvar_db" || db.Key != "DATABASE_URL" || !db.IsSecret {
		t.Errorf("[0] = %+v, want (pvar_db, DATABASE_URL, is_secret=true)", db)
	}
	// Wire-level redaction chokepoint: the secret value is the sentinel,
	// never the seeded plaintext.
	if db.Value != output.Sentinel {
		t.Errorf("[0].Value = %q, want output.Sentinel for a secret variable", db.Value)
	}
	if db.OrganizationID != org || db.ProjectID != proj {
		t.Errorf("[0] org/proj = (%q, %q), want (%q, %q)", db.OrganizationID, db.ProjectID, org, proj)
	}
	if db.Version != 3 {
		t.Errorf("[0].Version = %d, want 3", db.Version)
	}

	region := env.Data.Variables[1]
	if region.ID != "pvar_region" || region.Key != "REGION" || region.IsSecret {
		t.Errorf("[1] = %+v, want (pvar_region, REGION, is_secret=false)", region)
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

// TestListProjectVariablesEmptyProject proves a real project with no
// variables yields a deterministic empty array (not null) so agents
// can iterate the field without a nil check.
func TestListProjectVariablesEmptyProject(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_empty"
	reader := fakeProjectVariableReader{vars: nil}

	handler := listProjectVariablesHandlerFor(
		principalForProjectVariables("usr_dev", org), nil, reader)

	rec := getProjectVariables(handler, proj, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListProjectVariables(t, rec)
	if env.Data.Variables == nil {
		t.Errorf("variables = nil; want a non-nil empty slice")
	}
	if len(env.Data.Variables) != 0 {
		t.Errorf("variables len = %d, want 0", len(env.Data.Variables))
	}
	// The JSON literal must carry an explicit `[]`, never `null`, so
	// agents can iterate without a nil check.
	if !strings.Contains(rec.Body.String(), `"variables":[]`) {
		t.Errorf("body does not contain \"variables\":[]; got %s", rec.Body.String())
	}
}

// TestListProjectVariablesNotFoundFromReader proves the store-layer
// apierr.NotFound (a cross-tenant or unknown project_id) reaches the
// HTTP wire as a deterministic 404 yalla.error.v1 envelope — never a
// silent empty success, never a 500 leaking the cause.
func TestListProjectVariablesNotFoundFromReader(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	reader := fakeProjectVariableReader{
		err: apierr.NotFound("project", "proj_unknown"),
	}

	handler := listProjectVariablesHandlerFor(
		principalForProjectVariables("usr_dev", org), nil, reader)

	rec := getProjectVariables(handler, "proj_unknown", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestListProjectVariablesStoreUnavailable proves a datastore outage
// surfaces as the typed 503 — never disguised as a 5xx leaking the
// pgx cause, and never as a misleading empty list.
func TestListProjectVariablesStoreUnavailable(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_backend"
	reader := fakeProjectVariableReader{
		err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused")),
	}

	handler := listProjectVariablesHandlerFor(
		principalForProjectVariables("usr_dev", org), nil, reader)

	rec := getProjectVariables(handler, proj, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	// The raw pgx cause must not leak to the wire.
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestListProjectVariablesUnauthenticated proves a request without a
// valid credential is denied at the auth boundary with a 401 — the
// reader never runs, so no variable id, key, or value can leak.
func TestListProjectVariablesUnauthenticated(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_backend"
	callCount := 0
	reader := fakeProjectVariableReader{
		vars: []store.ProjectVariable{
			seedProjectVariableWire("pvar_db", org, proj, "DATABASE_URL", "leak-me", true, 1, time.Now(), time.Now()),
		},
		callCount: &callCount,
	}

	handler := listProjectVariablesHandlerFor(
		auth.Identity{}, apierr.Unauthenticated("missing token"), reader)

	rec := getProjectVariables(handler, proj, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("reader call count = %d, want 0 (auth must short-circuit)", callCount)
	}
	for _, leak := range []string{"pvar_db", "DATABASE_URL", "leak-me"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("401 body leaks reader-side identifier %q: %s", leak, rec.Body.String())
		}
	}
}

// TestListProjectVariablesMissingReader proves a request that reaches
// a handler with a nil reader (a wiring error) surfaces as the typed
// internal error, never a misleading 200 with an empty list. The
// invariant matches every other reader-port: a missing dependency must
// not silently degrade the response.
func TestListProjectVariablesMissingReader(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_backend"
	handler := listProjectVariablesHandlerFor(
		principalForProjectVariables("usr_dev", org), nil, nil)

	rec := getProjectVariables(handler, proj, "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}

// TestListProjectVariablesOpenAPIRouteIsRegistered proves the OpenAPI
// document carries the GET /v1/projects/{project_id}/variables
// operation with the stable operationId, the env.read required action,
// and the projects + variables tags — every detail an agent reads to
// discover the endpoint.
func TestListProjectVariablesOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/projects/{project_id}/variables" {
			found = true
			if rt.endpoint.OperationID != "listProjectVariables" {
				t.Errorf("operation_id = %q, want listProjectVariables", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionEnvRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionEnvRead)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
			var hasProjects, hasVariables bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagProjects {
					hasProjects = true
				}
				if tag == tagVariables {
					hasVariables = true
				}
			}
			if !hasProjects || !hasVariables {
				t.Errorf("tags = %v, want both %q and %q", rt.endpoint.Tags, tagProjects, tagVariables)
			}
		}
	}
	if !found {
		t.Errorf("GET /v1/projects/{project_id}/variables not in route table")
	}
}
