package httpapi

import (
	"bytes"
	"context"
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

// fakeProjectCreator is a canned ProjectCreator for httpapi tests. The zero
// value succeeds and returns an empty store.Project; callers can configure
// err to assert error propagation, project to assert the success envelope
// shape, and got to inspect the input forwarded by the handler.
type fakeProjectCreator struct {
	project store.Project
	err     error
	got     *store.CreateProjectInput
}

func (f fakeProjectCreator) Create(_ context.Context, in store.CreateProjectInput) (store.Project, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.project, f.err
}

// createProjectSuccessEnvelope is the decoded shape of the POST /v1/projects
// success envelope.
type createProjectSuccessEnvelope struct {
	SchemaVersion string               `json:"schema_version"`
	OK            bool                 `json:"ok"`
	RequestID     string               `json:"request_id"`
	Data          createProjectPayload `json:"data"`
}

// createProjectErrorEnvelope is the decoded shape of the POST /v1/projects
// error envelope.
type createProjectErrorEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Error         struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// createProjectHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// ProjectCreator. It is the production request path: the POST /v1/projects
// route is wrapped in RequireAuth for action project.create.
func createProjectHandlerFor(id auth.Identity, authErr error, creator ProjectCreator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, creator, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// postProjects issues POST /v1/projects against handler with body and an
// optional bearer token.
func postProjects(handler http.Handler, token string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/projects", body)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCreateProject(t *testing.T, rec *httptest.ResponseRecorder) createProjectSuccessEnvelope {
	t.Helper()
	var env createProjectSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode success envelope: %v; body %s", err, rec.Body.String())
	}
	return env
}

func decodeCreateProjectError(t *testing.T, rec *httptest.ResponseRecorder) createProjectErrorEnvelope {
	t.Helper()
	var env createProjectErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	return env
}

func createProjectRequestBody(t *testing.T, projectID, slug, displayName string) io.Reader {
	t.Helper()
	body, err := json.Marshal(createProjectRequest{
		ProjectID:   projectID,
		Slug:        slug,
		DisplayName: displayName,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return bytes.NewReader(body)
}

// TestCreateProjectReturnsCreatedProject is the happy path: an authenticated
// developer principal creates a project; the source-of-truth row returned by
// the creator is rendered in a stable yalla.output.v1 envelope with HTTP 201,
// and every column is projected onto the wire shape.
func TestCreateProjectReturnsCreatedProject(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := created
	row := store.Project{
		ID:             "prj_acme_alpha",
		OrganizationID: "org_acme",
		Slug:           "alpha",
		DisplayName:    "Alpha service",
		Version:        1,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
	creator := fakeProjectCreator{project: row}

	handler := createProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjects(handler, "tok-ada",
		createProjectRequestBody(t, "prj_acme_alpha", "alpha", "Alpha service"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProject(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK {
		t.Errorf("envelope = %+v, want schema_version=yalla.output.v1 ok=true", env)
	}
	if env.RequestID == "" {
		t.Error("envelope.request_id is empty, want a generated id")
	}
	got := env.Data.Project
	want := projectResource{
		ProjectID:      row.ID,
		OrganizationID: row.OrganizationID,
		Slug:           row.Slug,
		DisplayName:    row.DisplayName,
		Version:        row.Version,
		CreatedAt:      created.UTC().Format(time.RFC3339Nano),
		UpdatedAt:      updated.UTC().Format(time.RFC3339Nano),
	}
	if got != want {
		t.Errorf("project = %+v, want %+v", got, want)
	}
}

// TestCreateProjectForwardsPrincipalScope proves the creator is always
// invoked with the authenticated principal's own home organization id (never
// from the request body) and with the principal id, kind, and correlation
// identifiers — so the audit record names the actor verbatim and the tenant
// boundary is structural, not caller-supplied.
func TestCreateProjectForwardsPrincipalScope(t *testing.T) {
	t.Parallel()

	var got store.CreateProjectInput
	creator := fakeProjectCreator{
		project: store.Project{ID: "prj_acme_alpha", OrganizationID: "org_acme", Slug: "alpha", DisplayName: "Alpha"},
		got:     &got,
	}
	handler := createProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjects(handler, "tok-ada",
		createProjectRequestBody(t, "prj_acme_alpha", "alpha", "Alpha"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	if got.OrganizationID != "org_acme" {
		t.Errorf("creator.OrganizationID = %q, want the principal's home org org_acme", got.OrganizationID)
	}
	if got.ActorOrgID != "org_acme" {
		t.Errorf("creator.ActorOrgID = %q, want org_acme", got.ActorOrgID)
	}
	if got.ActorID != "usr_ada" {
		t.Errorf("creator.ActorID = %q, want usr_ada", got.ActorID)
	}
	if got.ProjectID != "prj_acme_alpha" || got.Slug != "alpha" || got.DisplayName != "Alpha" {
		t.Errorf("creator caller-supplied fields = %+v, want passthrough of request body", got)
	}
	if got.RequestID == "" {
		t.Error("creator.RequestID is empty, want the request correlation id forwarded")
	}
}

// TestCreateProjectIgnoresOrganizationIDInBody proves an organization_id
// field smuggled into the request body cannot override the principal's home
// organization. The handler builds CreateProjectInput.OrganizationID from
// the principal, not the body, so a caller cannot point the write at
// another tenant. The strict decoder also rejects the unknown field.
func TestCreateProjectIgnoresOrganizationIDInBody(t *testing.T) {
	t.Parallel()

	creator := fakeProjectCreator{err: stderrors.New("creator must not be called")}
	handler := createProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)

	body := bytes.NewReader([]byte(`{"organization_id":"org_attacker","project_id":"prj_acme_alpha","slug":"alpha","display_name":"Alpha"}`))
	rec := postProjects(handler, "tok-ada", body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (unknown field); body %s", rec.Code, rec.Body.String())
	}
}

// TestCreateProjectRejectsMalformedJSON proves the strict decoder rejects
// invalid request bodies with a typed 400 — the creator must not have been
// invoked.
func TestCreateProjectRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	creator := fakeProjectCreator{err: stderrors.New("creator must not be called")}
	handler := createProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)

	rec := postProjects(handler, "tok-ada", bytes.NewReader([]byte("{not json")))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
}

// TestCreateProjectUnauthenticatedReturns401 proves an unauthenticated
// request is rejected at the auth boundary with a typed yalla.error.v1
// envelope, and the creator is never invoked.
func TestCreateProjectUnauthenticatedReturns401(t *testing.T) {
	t.Parallel()

	creator := fakeProjectCreator{err: stderrors.New("creator must not be called")}
	handler := createProjectHandlerFor(auth.Identity{}, auth.ErrInvalidCredentials, creator)

	rec := postProjects(handler, "",
		createProjectRequestBody(t, "prj_acme_alpha", "alpha", "Alpha"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProjectError(t, rec)
	if env.SchemaVersion != "yalla.error.v1" || env.OK {
		t.Errorf("envelope = %+v, want schema_version=yalla.error.v1 ok=false", env)
	}
}

// TestCreateProjectViewerForbidden proves a viewer principal is denied at
// the policy boundary — project.create is a CapWrite action, which viewer
// does not hold — and the creator is never invoked.
func TestCreateProjectViewerForbidden(t *testing.T) {
	t.Parallel()

	creator := fakeProjectCreator{err: stderrors.New("creator must not be called")}
	handler := createProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_eve", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, creator)

	rec := postProjects(handler, "tok-eve",
		createProjectRequestBody(t, "prj_acme_alpha", "alpha", "Alpha"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProjectError(t, rec)
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("envelope schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
}

// TestCreateProjectInvalidInputPropagates proves a validation failure from
// the store layer surfaces as a typed 400 with the field violations.
func TestCreateProjectInvalidInputPropagates(t *testing.T) {
	t.Parallel()

	creator := fakeProjectCreator{err: apierr.InvalidInput(apierr.FieldViolation{
		Field:  "slug",
		Reason: "must be a canonical slug",
	})}
	handler := createProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjects(handler, "tok-ada",
		createProjectRequestBody(t, "prj_acme_alpha", "Not A Slug!", "Alpha"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProjectError(t, rec)
	if env.Error.Code != string(yerr.CodeInvalidInput) {
		t.Errorf("error code = %q, want %s", env.Error.Code, yerr.CodeInvalidInput)
	}
}

// TestCreateProjectConflictPropagates proves a slug conflict from the store
// layer surfaces as a typed 409, never disguised as a 500.
func TestCreateProjectConflictPropagates(t *testing.T) {
	t.Parallel()

	creator := fakeProjectCreator{err: apierr.Conflict("a project with this slug already exists in the organization")}
	handler := createProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjects(handler, "tok-ada",
		createProjectRequestBody(t, "prj_acme_alpha", "alpha", "Alpha"))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreateProjectError(t, rec)
	if env.Error.Code != string(yerr.CodeConflict) {
		t.Errorf("error code = %q, want %s", env.Error.Code, yerr.CodeConflict)
	}
}

// TestCreateProjectStoreUnavailablePropagates proves a datastore outage
// surfaces as a typed 5xx with a stable error envelope — never as a
// success or as a leaked driver error string.
func TestCreateProjectStoreUnavailablePropagates(t *testing.T) {
	t.Parallel()

	creator := fakeProjectCreator{err: apierr.StoreUnavailable(stderrors.New("connection refused"))}
	handler := createProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)
	rec := postProjects(handler, "tok-ada",
		createProjectRequestBody(t, "prj_acme_alpha", "alpha", "Alpha"))

	if rec.Code < 500 {
		t.Fatalf("status = %d, want a 5xx; body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "connection refused") {
		t.Errorf("error body leaked driver detail; body %s", rec.Body.String())
	}
}

// TestCreateProjectNilCreatorReturnsInternalError proves the wiring error —
// a nil creator threaded into NewHandler — surfaces as the stable internal
// error envelope rather than panicking or returning a misleading success.
func TestCreateProjectNilCreatorReturnsInternalError(t *testing.T) {
	t.Parallel()

	handler := createProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, nil)

	rec := postProjects(handler, "tok-ada",
		createProjectRequestBody(t, "prj_acme_alpha", "alpha", "Alpha"))

	if rec.Code < 500 {
		t.Fatalf("status = %d, want a 5xx; body %s", rec.Code, rec.Body.String())
	}
}

// TestCreateProjectRouteIsDocumented proves POST /v1/projects appears in the
// OpenAPI document with the canonical operation id and tag, so a served
// route is a documented route.
func TestCreateProjectRouteIsDocumented(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{})
	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodPost && rt.endpoint.Path == "/v1/projects" {
			found = true
			if rt.endpoint.OperationID != "createProject" {
				t.Errorf("operation_id = %q, want createProject", rt.endpoint.OperationID)
			}
			if len(rt.endpoint.Tags) == 0 || rt.endpoint.Tags[0] != tagProjects {
				t.Errorf("tags = %v, want [%s]", rt.endpoint.Tags, tagProjects)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionProjectCreate) {
				t.Errorf("required_action = %q, want %s", rt.endpoint.RequiredAction, policy.ActionProjectCreate)
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
		t.Fatal("POST /v1/projects not registered in the route table")
	}
}
