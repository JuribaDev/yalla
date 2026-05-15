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
)

// Contract and tenant-isolation coverage for GET
// /v1/projects/{project_id}/environments (BE-0148). The endpoint lists
// the environments of the project named by the {project_id} path
// parameter — by reading them through the ProjectEnvironmentReader
// port. The tests drive it through NewHandler with a fake
// Authenticator, the real policy engine, and a fake reader — the same
// wiring a request hits in production, minus the database. The
// store-backed reader has its own isolated-Postgres integration
// coverage in store/environment_test.go — this file exercises the HTTP
// surface in isolation.
//
// This endpoint has a single {project_id} path parameter, no request
// body, and no query parameters. The store-backed reader treats a
// cross-tenant or unknown project_id as a deterministic 404; the
// policy-matrix coverage (BE-0150) drives the engine-level resource
// resolution.

// fakeProjectEnvironmentReader is a canned ProjectEnvironmentReader
// for httpapi tests. The zero value returns an empty slice and no
// error from ListProjectEnvironments, which is all the tests that
// never reach the handler (the public-surface, /v1/me, and other-route
// suites) need. Tests that drive this endpoint set envs/err and read
// gotOrgID + gotProjectID back to prove the (org, project) pair
// forwarded to the store is the principal's home org plus the path
// project_id — never a caller-controlled organization id.
type fakeProjectEnvironmentReader struct {
	envs         []store.Environment
	err          error
	gotOrgID     *string
	gotProjectID *string
	callCount    *int
}

func (f fakeProjectEnvironmentReader) ListProjectEnvironments(_ context.Context, organizationID, projectID string) ([]store.Environment, error) {
	if f.gotOrgID != nil {
		*f.gotOrgID = organizationID
	}
	if f.gotProjectID != nil {
		*f.gotProjectID = projectID
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.envs, f.err
}

// fakeEnvironmentCreator is a canned EnvironmentCreator for httpapi
// tests. The zero value returns a zero Environment and a nil error from
// Create, which is all the tests that never reach the POST endpoint
// (the public-surface, /v1/me, and other-route suites) need. Tests that
// drive POST /v1/projects/{project_id}/environments set env/err and
// read gotInput + callCount back to prove the handler forwarded the
// resolved (principal home org id, path project_id, decoded body
// fields, principal id+kind, actor home org id, request id, correlation
// id) tuple verbatim — the boundary the policy engine and the audit
// record share.
type fakeEnvironmentCreator struct {
	env       store.Environment
	err       error
	gotInput  *store.CreateEnvironmentInput
	callCount *int
}

func (f fakeEnvironmentCreator) Create(_ context.Context, in store.CreateEnvironmentInput) (store.Environment, error) {
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.callCount != nil {
		*f.callCount++
	}
	return f.env, f.err
}

// listProjectEnvironmentsSuccessEnvelope is the decoded shape of the
// GET /v1/projects/{project_id}/environments success envelope.
type listProjectEnvironmentsSuccessEnvelope struct {
	SchemaVersion string                         `json:"schema_version"`
	OK            bool                           `json:"ok"`
	RequestID     string                         `json:"request_id"`
	Data          listProjectEnvironmentsPayload `json:"data"`
}

// listProjectEnvironmentsHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given ProjectEnvironmentReader. It is the production request path:
// the /v1/projects/{project_id}/environments route is wrapped in
// RequireAuth for action environment.read.
func listProjectEnvironmentsHandlerFor(id auth.Identity, authErr error, reader ProjectEnvironmentReader) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, reader, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, nil)
}

// getProjectEnvironments issues GET /v1/projects/{project_id}/environments
// against handler, optionally with a bearer token.
func getProjectEnvironments(handler http.Handler, projectID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/projects/"+projectID+"/environments", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeListProjectEnvironments(t *testing.T, rec *httptest.ResponseRecorder) listProjectEnvironmentsSuccessEnvelope {
	t.Helper()
	var env listProjectEnvironmentsSuccessEnvelope
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

// principalForProjectEnvironments returns an auth.Identity for an
// organization-wide developer principal homed at organizationID.
// environment.read is a CapRead action so a developer in the
// principal's home tenant is admitted at the policy boundary; the
// tests use this to focus on downstream wire and persistence behavior,
// not on the role matrix (which is BE-0150's job).
func principalForProjectEnvironments(principalID, organizationID string) auth.Identity {
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

// seedEnvironmentWire builds a store.Environment fixture for the
// fakeProjectEnvironmentReader. It is a plain literal helper — no
// database — so the tests stay pure unit tests of the HTTP wire path.
func seedEnvironmentWire(id, orgID, projectID, slug, displayName string, version int64, created, updated time.Time) store.Environment {
	return store.Environment{
		ID:             id,
		OrganizationID: orgID,
		ProjectID:      projectID,
		Slug:           slug,
		DisplayName:    displayName,
		Version:        version,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
}

// TestListProjectEnvironmentsHappyPath drives the production request
// path against a project the principal's home organization owns. The
// principal is an organization-wide Developer so the policy gate
// admits the read; the reader returns two environments — production
// and staging — and the assertions pin every load-bearing field of
// the wire shape.
func TestListProjectEnvironmentsHappyPath(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_backend"
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	updated := created.Add(time.Hour)

	var gotOrg, gotProj string
	callCount := 0
	reader := fakeProjectEnvironmentReader{
		envs: []store.Environment{
			seedEnvironmentWire("env_prod", org, proj, "production", "Production", 3, created, updated),
			seedEnvironmentWire("env_stage", org, proj, "staging", "Staging", 1, created, created),
		},
		gotOrgID:     &gotOrg,
		gotProjectID: &gotProj,
		callCount:    &callCount,
	}

	handler := listProjectEnvironmentsHandlerFor(
		principalForProjectEnvironments("usr_dev", org), nil, reader)

	rec := getProjectEnvironments(handler, proj, "a-valid-token")
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

	env := decodeListProjectEnvironments(t, rec)
	if len(env.Data.Environments) != 2 {
		t.Fatalf("environments len = %d, want 2; body %s", len(env.Data.Environments), rec.Body.String())
	}

	prod := env.Data.Environments[0]
	if prod.ID != "env_prod" || prod.Slug != "production" || prod.DisplayName != "Production" {
		t.Errorf("[0] = %+v, want (env_prod, production, Production)", prod)
	}
	if prod.OrganizationID != org || prod.ProjectID != proj {
		t.Errorf("[0] org/proj = (%q, %q), want (%q, %q)", prod.OrganizationID, prod.ProjectID, org, proj)
	}
	if prod.Version != 3 {
		t.Errorf("[0].Version = %d, want 3", prod.Version)
	}
	if !prod.CreatedAt.Equal(created) || !prod.UpdatedAt.Equal(updated) {
		t.Errorf("[0] timestamps = (%s, %s), want (%s, %s)",
			prod.CreatedAt, prod.UpdatedAt, created, updated)
	}

	stage := env.Data.Environments[1]
	if stage.ID != "env_stage" || stage.Slug != "staging" || stage.DisplayName != "Staging" {
		t.Errorf("[1] = %+v, want (env_stage, staging, Staging)", stage)
	}
	if stage.Version != 1 {
		t.Errorf("[1].Version = %d, want 1", stage.Version)
	}
}

// TestListProjectEnvironmentsEmptyProject proves a real project with
// no environments yields a deterministic empty array (not null) so
// agents can iterate the field without a nil check.
func TestListProjectEnvironmentsEmptyProject(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_empty"
	reader := fakeProjectEnvironmentReader{envs: nil}

	handler := listProjectEnvironmentsHandlerFor(
		principalForProjectEnvironments("usr_dev", org), nil, reader)

	rec := getProjectEnvironments(handler, proj, "a-valid-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListProjectEnvironments(t, rec)
	if env.Data.Environments == nil {
		t.Errorf("environments = nil; want a non-nil empty slice")
	}
	if len(env.Data.Environments) != 0 {
		t.Errorf("environments len = %d, want 0", len(env.Data.Environments))
	}
	// The JSON literal must carry an explicit `[]`, never `null`, so
	// agents can iterate without a nil check.
	if !strings.Contains(rec.Body.String(), `"environments":[]`) {
		t.Errorf("body does not contain \"environments\":[]; got %s", rec.Body.String())
	}
}

// TestListProjectEnvironmentsNotFoundFromReader proves the store-layer
// apierr.NotFound (a cross-tenant or unknown project_id) reaches the
// HTTP wire as a deterministic 404 yalla.error.v1 envelope — never a
// silent empty success, never a 500 leaking the cause.
func TestListProjectEnvironmentsNotFoundFromReader(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	reader := fakeProjectEnvironmentReader{
		err: apierr.NotFound("project", "proj_unknown"),
	}

	handler := listProjectEnvironmentsHandlerFor(
		principalForProjectEnvironments("usr_dev", org), nil, reader)

	rec := getProjectEnvironments(handler, "proj_unknown", "a-valid-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeNotFound))
}

// TestListProjectEnvironmentsStoreUnavailable proves a datastore
// outage surfaces as the typed 503 — never disguised as a 5xx leaking
// the pgx cause, and never as a misleading empty list.
func TestListProjectEnvironmentsStoreUnavailable(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_backend"
	reader := fakeProjectEnvironmentReader{
		err: apierr.StoreUnavailable(stderrors.New("pgx: dial tcp: connection refused")),
	}

	handler := listProjectEnvironmentsHandlerFor(
		principalForProjectEnvironments("usr_dev", org), nil, reader)

	rec := getProjectEnvironments(handler, proj, "a-valid-token")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeUnavailable))
	// The raw pgx cause must not leak to the wire.
	if strings.Contains(rec.Body.String(), "dial tcp") || strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("response leaks driver-level cause: %s", rec.Body.String())
	}
}

// TestListProjectEnvironmentsUnauthenticated proves a request without
// a valid credential is denied at the auth boundary with a 401 — the
// reader never runs, so no environment id or slug can leak.
func TestListProjectEnvironmentsUnauthenticated(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_backend"
	callCount := 0
	reader := fakeProjectEnvironmentReader{
		envs: []store.Environment{
			seedEnvironmentWire("env_secret", org, proj, "production", "Production", 1, time.Now(), time.Now()),
		},
		callCount: &callCount,
	}

	handler := listProjectEnvironmentsHandlerFor(
		auth.Identity{}, apierr.Unauthenticated("missing token"), reader)

	rec := getProjectEnvironments(handler, proj, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("reader call count = %d, want 0 (auth must short-circuit)", callCount)
	}
	for _, leak := range []string{"env_secret", "Production"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("401 body leaks reader-side identifier %q: %s", leak, rec.Body.String())
		}
	}
}

// TestListProjectEnvironmentsMissingReader proves a request that
// reaches a handler with a nil reader (a wiring error) surfaces as
// the typed internal error, never a misleading 200 with an empty list.
// The invariant matches every other reader-port: a missing dependency
// must not silently degrade the response.
func TestListProjectEnvironmentsMissingReader(t *testing.T) {
	t.Parallel()

	const org = "org_acme"
	const proj = "proj_backend"
	handler := listProjectEnvironmentsHandlerFor(
		principalForProjectEnvironments("usr_dev", org), nil, nil)

	rec := getProjectEnvironments(handler, proj, "a-valid-token")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, string(yerr.CodeInternal))
}

// TestListProjectEnvironmentsOpenAPIRouteIsRegistered proves the
// OpenAPI document carries the GET /v1/projects/{project_id}/environments
// operation with the stable operationId, the environment.read required
// action, and the projects + environments tags — every detail an
// agent reads to discover the endpoint.
func TestListProjectEnvironmentsOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodGet && rt.endpoint.Path == "/v1/projects/{project_id}/environments" {
			found = true
			if rt.endpoint.OperationID != "listProjectEnvironments" {
				t.Errorf("operation_id = %q, want listProjectEnvironments", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionEnvironmentRead) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionEnvironmentRead)
			}
			if !rt.endpoint.RequiresAuth {
				t.Errorf("requires_auth = false, want true")
			}
			var hasProjects, hasEnvironments bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagProjects {
					hasProjects = true
				}
				if tag == tagEnvironments {
					hasEnvironments = true
				}
			}
			if !hasProjects || !hasEnvironments {
				t.Errorf("tags = %v, want both %q and %q", rt.endpoint.Tags, tagProjects, tagEnvironments)
			}
		}
	}
	if !found {
		t.Errorf("GET /v1/projects/{project_id}/environments not in route table")
	}
}
