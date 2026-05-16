package httpapi

import (
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
)

// Contract tests for PATCH /v1/projects/{project_id}. The route is gated by
// RequireAuth on action project.update through projectIDResolver — a CapWrite
// action authorized against the (principal home organization, {project_id})
// resource. These tests drive the real NewHandler with a fake Authenticator,
// the real policy engine, and a fake ProjectUpdater — the same wiring a
// request hits in production, minus the database. The store-backed
// orchestrator (store.ProjectService) has its own isolated-Postgres
// integration coverage in store/projectservice_test.go and white-box
// validation coverage there too.

// fakeProjectUpdater is a canned ProjectUpdater for httpapi tests. The zero
// value returns a zero project and no error, which is all the test helpers
// that never reach the handler need; the PATCH tests set project/err and
// read got back to prove the handler forwards the decoded patch and the
// authenticated actor to the store layer unchanged.
type fakeProjectUpdater struct {
	project store.Project
	err     error
	got     *store.UpdateProjectInput
}

func (f fakeProjectUpdater) Update(_ context.Context, in store.UpdateProjectInput) (store.Project, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.project, f.err
}

// updateProjectSuccessEnvelope is the decoded shape of the PATCH
// /v1/projects/{project_id} success envelope.
type updateProjectSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Project projectResource `json:"project"`
	} `json:"data"`
}

// updateProjectHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// ProjectUpdater. It is the production request path: the PATCH
// /v1/projects/{project_id} route is wrapped in RequireAuth for action
// project.update.
func updateProjectHandlerFor(id auth.Identity, authErr error, updater ProjectUpdater) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, updater, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil)
}

// patchProject issues PATCH /v1/projects/{projectID} against handler with
// body, optionally with a bearer token.
func patchProject(handler http.Handler, projectID, token, body string) *httptest.ResponseRecorder {
	return patchProjectWithIfMatch(handler, projectID, token, "", body)
}

// patchProjectWithIfMatch issues PATCH /v1/projects/{projectID} with an
// optional If-Match header. An empty ifMatch omits the header entirely so
// the optional precondition path remains exercised.
func patchProjectWithIfMatch(handler http.Handler, projectID, token, ifMatch, body string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(http.MethodPatch, "/v1/projects/"+projectID, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeUpdateProject(t *testing.T, rec *httptest.ResponseRecorder) updateProjectSuccessEnvelope {
	t.Helper()
	var env updateProjectSuccessEnvelope
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
		t.Error("request_id is empty")
	}
	return env
}

// TestUpdateProjectHappyPathForwardsBodyAndPrincipal proves the handler
// decodes the request body, threads the principal's home organization and
// the path's project id into the store input, and renders the returned row
// in the stable yalla.output.v1 envelope — including the row's
// authoritative version as the ETag response header so the caller can echo
// it back as the next If-Match precondition.
func TestUpdateProjectHappyPathForwardsBodyAndPrincipal(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	updated := created.Add(time.Minute)
	row := store.Project{
		ID:             "prj_acme_web",
		OrganizationID: "org_acme",
		Slug:           "web-api",
		DisplayName:    "Web API",
		Version:        7,
		CreatedAt:      created,
		UpdatedAt:      updated,
	}
	var captured store.UpdateProjectInput
	updater := fakeProjectUpdater{project: row, got: &captured}
	handler := updateProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchProject(handler, "prj_acme_web", "a-valid-session-token", `{"display_name":"Web API v2","slug":"web"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q, want application/json", got)
	}
	if got := rec.Header().Get("ETag"); got != `"7"` {
		t.Errorf("ETag header = %q, want %q", got, `"7"`)
	}

	env := decodeUpdateProject(t, rec)
	want := projectResource{
		ProjectID:      row.ID,
		OrganizationID: row.OrganizationID,
		Slug:           row.Slug,
		DisplayName:    row.DisplayName,
		Version:        row.Version,
		CreatedAt:      created.Format(time.RFC3339Nano),
		UpdatedAt:      updated.Format(time.RFC3339Nano),
	}
	if env.Data.Project != want {
		t.Errorf("project = %+v, want %+v", env.Data.Project, want)
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("captured.OrganizationID = %q, want org_acme", captured.OrganizationID)
	}
	if captured.ProjectID != "prj_acme_web" {
		t.Errorf("captured.ProjectID = %q, want prj_acme_web", captured.ProjectID)
	}
	if captured.ActorID != "usr_ada" {
		t.Errorf("captured.ActorID = %q, want usr_ada", captured.ActorID)
	}
	if captured.Slug == nil || *captured.Slug != "web" {
		t.Errorf("captured.Slug = %v, want web", captured.Slug)
	}
	if captured.DisplayName == nil || *captured.DisplayName != "Web API v2" {
		t.Errorf("captured.DisplayName = %v, want Web API v2", captured.DisplayName)
	}
	if captured.IfMatchVersion != nil {
		t.Errorf("captured.IfMatchVersion = %v, want nil", *captured.IfMatchVersion)
	}
}

// TestUpdateProjectIfMatchHeader proves the handler parses the If-Match
// header in canonical strong-ETag form and forwards the version to the
// store layer. An absent header still succeeds: the precondition is
// optional.
func TestUpdateProjectIfMatchHeader(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		ifMatch string
		want    *int64
	}{
		{"absent", "", nil},
		{"strong etag", `"5"`, ptrInt64(5)},
		{"unquoted integer (lenient)", "5", ptrInt64(5)},
		{"whitespace stripped", `   "12"   `, ptrInt64(12)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var captured store.UpdateProjectInput
			updater := fakeProjectUpdater{
				project: store.Project{ID: "prj_acme_web", Slug: "web", DisplayName: "Web", Version: 99},
				got:     &captured,
			}
			handler := updateProjectHandlerFor(
				auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleAdmin), Method: auth.MethodSession},
				nil, updater)

			rec := patchProjectWithIfMatch(handler, "prj_acme_web", "a-valid-session-token", tc.ifMatch, `{"display_name":"Web"}`)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
			}
			if !int64PtrEqual(captured.IfMatchVersion, tc.want) {
				t.Errorf("captured.IfMatchVersion = %v, want %v", deref(captured.IfMatchVersion), deref(tc.want))
			}
		})
	}
}

// decodedProjectErrorEnvelope mirrors yalla.error.v1 including the optional
// structured details map (carrying current_version on a stale-write conflict)
// and hint. The package-level errorEnvelope in middleware_test.go is the
// minimal shape; this is the richer shape the concurrency-aware tests need.
type decodedProjectErrorEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Error         struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Hint    string            `json:"hint"`
		Details map[string]string `json:"details"`
	} `json:"error"`
	RequestID string `json:"request_id"`
}

func decodeProjectError(t *testing.T, rec *httptest.ResponseRecorder) decodedProjectErrorEnvelope {
	t.Helper()
	var env decodedProjectErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if env.OK {
		t.Errorf("ok = true, want false")
	}
	if env.RequestID == "" {
		t.Errorf("request_id is empty, want a generated id")
	}
	return env
}

// TestUpdateProjectStaleIfMatchReturnsConflict proves a stale If-Match
// precondition surfaces as a deterministic 409 with the row's
// authoritative version under details.current_version — never disguised as
// a 200 or a generic 500 — so an agent can recover by re-reading the row.
func TestUpdateProjectStaleIfMatchReturnsConflict(t *testing.T) {
	t.Parallel()

	updater := fakeProjectUpdater{err: apierr.ConflictStale(42)}
	handler := updateProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchProjectWithIfMatch(handler, "prj_acme_web", "a-valid-session-token", `"3"`, `{"display_name":"Web"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	env := decodeProjectError(t, rec)
	if env.Error.Code != "E_CONFLICT" {
		t.Errorf("error.code = %q, want E_CONFLICT", env.Error.Code)
	}
	if got := env.Error.Details["current_version"]; got != "42" {
		t.Errorf("details.current_version = %q, want 42", got)
	}
}

// TestUpdateProjectRejectsBodyOrgID proves the strict JSON decoder rejects
// an organization_id field in the body: tenant isolation on this endpoint
// is structural — the handler always builds the store input from the
// authenticated principal's home organization and the path project_id —
// and an unknown field is a stable 400 E_INVALID_INPUT so a stale schema
// or typo cannot be silently dropped.
func TestUpdateProjectRejectsBodyOrgID(t *testing.T) {
	t.Parallel()

	updater := fakeProjectUpdater{err: stderrors.New("updater must not be called")}
	handler := updateProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchProject(handler, "prj_acme_web", "a-valid-session-token", `{"organization_id":"org_evil","display_name":"Web"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestUpdateProjectMalformedBodyIsValidationError proves a malformed JSON
// body is a stable 400 E_INVALID_INPUT and never reaches the updater.
func TestUpdateProjectMalformedBodyIsValidationError(t *testing.T) {
	t.Parallel()

	updater := fakeProjectUpdater{err: stderrors.New("updater must not be called")}
	handler := updateProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchProject(handler, "prj_acme_web", "a-valid-session-token", `{"slug":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
}

// TestUpdateProjectNotFoundIsTyped404 proves a NotFound from the store
// surfaces as a deterministic 404 E_NOT_FOUND — a cross-tenant project_id
// surfaces here too (tenant-scoped repository), never as another tenant's
// row.
func TestUpdateProjectNotFoundIsTyped404(t *testing.T) {
	t.Parallel()

	updater := fakeProjectUpdater{err: apierr.NotFound("project", "prj_ghost")}
	handler := updateProjectHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
		nil, updater)

	rec := patchProject(handler, "prj_ghost", "a-valid-session-token", `{"display_name":"Ghost"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

// TestUpdateProjectMissingCredentialsIs401 proves the route requires
// authentication: a request with no bearer is a deterministic 401 E_AUTH
// at the RequireAuth boundary, never reaching the updater.
func TestUpdateProjectMissingCredentialsIs401(t *testing.T) {
	t.Parallel()

	updater := fakeProjectUpdater{err: stderrors.New("updater must not be called")}
	handler := updateProjectHandlerFor(
		auth.Identity{},
		auth.ErrNoCredentials, updater)

	rec := patchProject(handler, "prj_acme_web", "", `{"display_name":"Web"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTH")
}

// TestUpdateProjectInvalidIfMatchHeader proves a weak ETag, a "*", a
// multi-value list, or a non-numeric token in If-Match is a stable 400
// E_INVALID_INPUT — never reaches the updater — so a client cannot smuggle
// a malformed precondition past the parser.
func TestUpdateProjectInvalidIfMatchHeader(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		ifMatch string
	}{
		{"weak etag", `W/"5"`},
		{"wildcard", "*"},
		{"multi-value list", `"3", "5"`},
		{"non-numeric", `"abc"`},
		{"zero", `"0"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			updater := fakeProjectUpdater{err: stderrors.New("updater must not be called")}
			handler := updateProjectHandlerFor(
				auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleOwner), Method: auth.MethodSession},
				nil, updater)

			rec := patchProjectWithIfMatch(handler, "prj_acme_web", "a-valid-session-token", tc.ifMatch, `{"display_name":"Web"}`)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			decodeError(t, rec, "E_INVALID_INPUT")
		})
	}
}
