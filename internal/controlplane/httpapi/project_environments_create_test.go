package httpapi

import (
	"bytes"
	"encoding/json"
	stderrors "errors"
	"io"
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

// Contract and tenant-isolation coverage for POST
// /v1/projects/{project_id}/environments (BE-0151). The endpoint creates
// an environment under the project named by the {project_id} path
// parameter, through the EnvironmentCreator port. The tests drive the
// handler through NewHandler with a fake Authenticator, the real policy
// engine, and a fake creator — the same wiring a request hits in
// production, minus the database. The store-backed orchestrator has its
// own isolated-Postgres integration coverage in store/environmentservice_test.go
// — this file exercises the HTTP surface in isolation.

// createProjectEnvironmentSuccessEnvelope is the decoded shape of the
// POST /v1/projects/{project_id}/environments success envelope.
type createProjectEnvironmentSuccessEnvelope struct {
	SchemaVersion string                          `json:"schema_version"`
	OK            bool                            `json:"ok"`
	RequestID     string                          `json:"request_id"`
	Data          createProjectEnvironmentPayload `json:"data"`
}

// createProjectEnvironmentErrorEnvelope is the decoded shape of the
// POST /v1/projects/{project_id}/environments error envelope.
type createProjectEnvironmentErrorEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Error         struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// createProjectEnvironmentHandlerFor builds the full NewHandler surface
// with an Authenticator that resolves every credential to id and the
// given EnvironmentCreator. It is the production request path: the POST
// /v1/projects/{project_id}/environments route is wrapped in RequireAuth
// for action environment.create.
func createProjectEnvironmentHandlerFor(id auth.Identity, authErr error, creator EnvironmentCreator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, creator, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeBreakGlassController{}, nil, nil)
}

// postProjectEnvironments issues POST /v1/projects/{project_id}/environments
// against handler, with body and an optional bearer token.
func postProjectEnvironments(handler http.Handler, projectID, token string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/environments", body)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCreateProjectEnvironment(t *testing.T, rec *httptest.ResponseRecorder) createProjectEnvironmentSuccessEnvelope {
	t.Helper()
	var env createProjectEnvironmentSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode success envelope: %v; body %s", err, rec.Body.String())
	}
	return env
}

func decodeCreateProjectEnvironmentError(t *testing.T, rec *httptest.ResponseRecorder) createProjectEnvironmentErrorEnvelope {
	t.Helper()
	var env createProjectEnvironmentErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	return env
}

func createProjectEnvironmentRequestBody(t *testing.T, environmentID, slug, displayName string) io.Reader {
	t.Helper()
	body, err := json.Marshal(createProjectEnvironmentRequest{
		EnvironmentID: environmentID,
		Slug:          slug,
		DisplayName:   displayName,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return bytes.NewReader(body)
}

// TestCreateProjectEnvironmentReturnsCreatedEnvironment is the happy
// path: an authenticated developer principal creates an environment;
// the source-of-truth row returned by the creator is rendered in a
// stable yalla.output.v1 envelope with HTTP 201, and every column is
// projected onto the wire shape.
func TestCreateProjectEnvironmentReturnsCreatedEnvironment(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created
	row := store.Environment{
		ID:             "env_acme_prod",
		OrganizationID: "org_acme",
		ProjectID:      "prj_acme_alpha",
		Slug:           "production",
		DisplayName:    "Production",
		Version:        1,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
	creator := fakeEnvironmentCreator{env: row}

	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-ada",
		createProjectEnvironmentRequestBody(t, "env_acme_prod", "production", "Production"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProjectEnvironment(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK {
		t.Errorf("envelope = %+v, want schema_version=yalla.output.v1 ok=true", env)
	}
	if env.RequestID == "" {
		t.Error("envelope.request_id is empty, want a generated id")
	}
	got := env.Data.Environment
	want := projectEnvironment{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		ProjectID:      row.ProjectID,
		Slug:           row.Slug,
		DisplayName:    row.DisplayName,
		Version:        row.Version,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
	if got.ID != want.ID || got.OrganizationID != want.OrganizationID || got.ProjectID != want.ProjectID ||
		got.Slug != want.Slug || got.DisplayName != want.DisplayName || got.Version != want.Version ||
		!got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf("environment = %+v, want %+v", got, want)
	}
}

// TestCreateProjectEnvironmentForwardsPrincipalScope proves the creator
// is always invoked with the authenticated principal's own home
// organization id (never from the request body) and with the path
// {project_id} (never from the body), plus the principal id, kind, and
// correlation identifiers — so the audit record names the actor verbatim
// and the tenant boundary is structural, not caller-supplied.
func TestCreateProjectEnvironmentForwardsPrincipalScope(t *testing.T) {
	t.Parallel()

	var got store.CreateEnvironmentInput
	creator := fakeEnvironmentCreator{
		env:      store.Environment{ID: "env_acme_prod", OrganizationID: "org_acme", ProjectID: "prj_acme_alpha", Slug: "production", DisplayName: "Production"},
		gotInput: &got,
	}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-ada",
		createProjectEnvironmentRequestBody(t, "env_acme_prod", "production", "Production"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != "org_acme" {
		t.Errorf("creator.OrganizationID = %q, want the principal's home org org_acme", got.OrganizationID)
	}
	if got.ProjectID != "prj_acme_alpha" {
		t.Errorf("creator.ProjectID = %q, want the path project_id prj_acme_alpha", got.ProjectID)
	}
	if got.ActorOrgID != "org_acme" {
		t.Errorf("creator.ActorOrgID = %q, want org_acme", got.ActorOrgID)
	}
	if got.ActorID != "usr_ada" {
		t.Errorf("creator.ActorID = %q, want usr_ada", got.ActorID)
	}
	if got.EnvironmentID != "env_acme_prod" || got.Slug != "production" || got.DisplayName != "Production" {
		t.Errorf("creator caller-supplied fields = %+v, want passthrough of request body", got)
	}
	if got.RequestID == "" {
		t.Error("creator.RequestID is empty, want the request correlation id forwarded")
	}
}

// TestCreateProjectEnvironmentIgnoresOrganizationIDInBody proves an
// organization_id field smuggled into the request body cannot override
// the principal's home organization. The strict decoder rejects unknown
// fields, so the creator must not have been invoked.
func TestCreateProjectEnvironmentIgnoresOrganizationIDInBody(t *testing.T) {
	t.Parallel()

	var callCount int
	creator := fakeEnvironmentCreator{
		err:       stderrors.New("creator must not be called"),
		callCount: &callCount,
	}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)

	body := bytes.NewReader([]byte(`{"organization_id":"org_attacker","environment_id":"env_acme_prod","slug":"production","display_name":"Production"}`))
	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-ada", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unknown field); body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator.Create called %d times after unknown-field reject; want 0", callCount)
	}
}

// TestCreateProjectEnvironmentIgnoresProjectIDInBody proves a project_id
// field smuggled into the request body cannot redirect the write at
// another project. The path parameter is authoritative, not the body.
func TestCreateProjectEnvironmentIgnoresProjectIDInBody(t *testing.T) {
	t.Parallel()

	var callCount int
	creator := fakeEnvironmentCreator{
		err:       stderrors.New("creator must not be called"),
		callCount: &callCount,
	}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)

	body := bytes.NewReader([]byte(`{"project_id":"prj_attacker","environment_id":"env_acme_prod","slug":"production","display_name":"Production"}`))
	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-ada", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unknown field); body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator.Create called %d times after unknown-field reject; want 0", callCount)
	}
}

// TestCreateProjectEnvironmentRejectsMalformedJSON proves the strict
// decoder rejects invalid request bodies with a typed 400 — the creator
// must not have been invoked.
func TestCreateProjectEnvironmentRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	var callCount int
	creator := fakeEnvironmentCreator{
		err:       stderrors.New("creator must not be called"),
		callCount: &callCount,
	}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)

	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-ada", bytes.NewReader([]byte("{not json")))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if callCount != 0 {
		t.Errorf("creator.Create called %d times after decode reject; want 0", callCount)
	}
}

// TestCreateProjectEnvironmentUnauthenticatedReturns401 proves an
// unauthenticated request is rejected at the auth boundary with a typed
// yalla.error.v1 envelope, and the creator is never invoked.
func TestCreateProjectEnvironmentUnauthenticatedReturns401(t *testing.T) {
	t.Parallel()

	var callCount int
	creator := fakeEnvironmentCreator{
		err:       stderrors.New("creator must not be called"),
		callCount: &callCount,
	}
	handler := createProjectEnvironmentHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials, creator)

	rec := postProjectEnvironments(handler, "prj_acme_alpha", "",
		createProjectEnvironmentRequestBody(t, "env_acme_prod", "production", "Production"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProjectEnvironmentError(t, rec)
	if env.SchemaVersion != "yalla.error.v1" || env.OK {
		t.Errorf("envelope = %+v, want schema_version=yalla.error.v1 ok=false", env)
	}
	if callCount != 0 {
		t.Errorf("creator.Create called %d times after 401; want 0", callCount)
	}
}

// TestCreateProjectEnvironmentViewerForbidden proves a viewer principal
// is denied at the policy boundary — environment.create is a CapWrite
// action, which viewer does not hold — and the creator is never invoked.
func TestCreateProjectEnvironmentViewerForbidden(t *testing.T) {
	t.Parallel()

	var callCount int
	creator := fakeEnvironmentCreator{
		err:       stderrors.New("creator must not be called"),
		callCount: &callCount,
	}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_eve", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, creator)

	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-eve",
		createProjectEnvironmentRequestBody(t, "env_acme_prod", "production", "Production"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProjectEnvironmentError(t, rec)
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("envelope schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if callCount != 0 {
		t.Errorf("creator.Create called %d times after viewer 403; want 0", callCount)
	}
}

// TestCreateProjectEnvironmentInvalidInputPropagates proves a validation
// failure from the store layer surfaces as a typed 400 with the field
// violations — never disguised as a 500.
func TestCreateProjectEnvironmentInvalidInputPropagates(t *testing.T) {
	t.Parallel()

	creator := fakeEnvironmentCreator{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "slug",
		Reason: "must be a canonical slug",
	})}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-ada",
		createProjectEnvironmentRequestBody(t, "env_acme_prod", "Not A Slug!", "Production"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProjectEnvironmentError(t, rec)
	if env.Error.Code != string(yerr.CodeInvalidInput) {
		t.Errorf("error code = %q, want %s", env.Error.Code, yerr.CodeInvalidInput)
	}
}

// TestCreateProjectEnvironmentConflictPropagates proves a slug conflict
// from the store layer surfaces as a typed 409, never disguised as a 500.
func TestCreateProjectEnvironmentConflictPropagates(t *testing.T) {
	t.Parallel()

	creator := fakeEnvironmentCreator{err: apierr.Conflict("an environment with this slug already exists in the project")}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-ada",
		createProjectEnvironmentRequestBody(t, "env_acme_prod", "production", "Production"))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProjectEnvironmentError(t, rec)
	if env.Error.Code != string(yerr.CodeConflict) {
		t.Errorf("error code = %q, want %s", env.Error.Code, yerr.CodeConflict)
	}
}

// TestCreateProjectEnvironmentNotFoundPropagates proves a cross-tenant
// or unknown project_id surfaces as a typed 404, never as a 403 that
// would confirm the foreign project's existence and never as a 500.
func TestCreateProjectEnvironmentNotFoundPropagates(t *testing.T) {
	t.Parallel()

	creator := fakeEnvironmentCreator{err: apierr.NotFound("project", "")}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjectEnvironments(handler, "prj_unknown", "tok-ada",
		createProjectEnvironmentRequestBody(t, "env_acme_prod", "production", "Production"))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProjectEnvironmentError(t, rec)
	if env.Error.Code != string(yerr.CodeNotFound) {
		t.Errorf("error code = %q, want %s", env.Error.Code, yerr.CodeNotFound)
	}
}

// TestCreateProjectEnvironmentQuotaExceededPropagates proves an exhausted
// quota surfaces with the typed quota status — never as a 500 — so an
// agent can distinguish a quota condition from an internal error.
func TestCreateProjectEnvironmentQuotaExceededPropagates(t *testing.T) {
	t.Parallel()

	creator := fakeEnvironmentCreator{err: apierr.QuotaExceeded("environments", 3)}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-ada",
		createProjectEnvironmentRequestBody(t, "env_acme_prod", "production", "Production"))

	env := decodeCreateProjectEnvironmentError(t, rec)
	if env.Error.Code != string(yerr.CodeQuotaExceeded) {
		t.Errorf("error code = %q, want %s; status %d body %s",
			env.Error.Code, yerr.CodeQuotaExceeded, rec.Code, rec.Body.String())
	}
}

// TestCreateProjectEnvironmentStoreUnavailablePropagates proves a
// datastore outage surfaces as a typed 5xx with a stable error envelope
// — never as a success or as a leaked driver error string.
func TestCreateProjectEnvironmentStoreUnavailablePropagates(t *testing.T) {
	t.Parallel()

	creator := fakeEnvironmentCreator{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-ada",
		createProjectEnvironmentRequestBody(t, "env_acme_prod", "production", "Production"))

	if rec.Code < 500 {
		t.Fatalf("status = %d, want a 5xx; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("error body leaked driver detail; body %s", rec.Body.String())
	}
}

// TestCreateProjectEnvironmentNilCreatorReturnsInternalError proves the
// wiring error — a nil creator threaded into NewHandler — surfaces as
// the stable internal error envelope rather than panicking or returning
// a misleading success.
func TestCreateProjectEnvironmentNilCreatorReturnsInternalError(t *testing.T) {
	t.Parallel()

	handler := createProjectEnvironmentHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, nil)

	rec := postProjectEnvironments(handler, "prj_acme_alpha", "tok-ada",
		createProjectEnvironmentRequestBody(t, "env_acme_prod", "production", "Production"))

	if rec.Code < 500 {
		t.Fatalf("status = %d, want a 5xx; body %s", rec.Code, rec.Body.String())
	}
}

// TestCreateProjectEnvironmentRouteIsDocumented proves POST
// /v1/projects/{project_id}/environments appears in the OpenAPI document
// with the canonical operation id, the [projects, environments] tags,
// the required action constant, the resolver, the auth requirement, and
// the 201 success status — so a served route is a documented route.
func TestCreateProjectEnvironmentRouteIsDocumented(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeBreakGlassController{})
	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodPost && rt.endpoint.Path == "/v1/projects/{project_id}/environments" {
			found = true
			if rt.endpoint.OperationID != "createProjectEnvironment" {
				t.Errorf("operation_id = %q, want createProjectEnvironment", rt.endpoint.OperationID)
			}
			var sawProjects, sawEnvironments bool
			for _, tag := range rt.endpoint.Tags {
				if tag == tagProjects {
					sawProjects = true
				}
				if tag == tagEnvironments {
					sawEnvironments = true
				}
			}
			if !sawProjects || !sawEnvironments {
				t.Errorf("tags = %v, want both %q and %q", rt.endpoint.Tags, tagProjects, tagEnvironments)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionEnvironmentCreate) {
				t.Errorf("required_action = %q, want %s", rt.endpoint.RequiredAction, policy.ActionEnvironmentCreate)
			}
			if !rt.endpoint.RequiresAuth {
				t.Error("RequiresAuth = false, want true")
			}
			if rt.endpoint.SuccessStatus != http.StatusCreated {
				t.Errorf("SuccessStatus = %d, want 201", rt.endpoint.SuccessStatus)
			}
		}
	}
	if !found {
		t.Fatal("POST /v1/projects/{project_id}/environments not registered in the route table")
	}
}
