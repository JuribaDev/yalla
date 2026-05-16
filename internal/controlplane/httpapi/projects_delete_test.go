package httpapi

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Contract tests for DELETE /v1/projects/{project_id}. The route is gated by
// RequireAuth on action project.delete through projectIDResolver — a CapWrite
// action authorized against the (principal home organization, {project_id})
// resource. These tests drive the real NewHandler with a fake Authenticator,
// the real policy engine, and a fake ProjectDeleter — the same wiring a
// request hits in production, minus the database. The store-backed
// orchestrator (store.ProjectService.ScheduleDeletion) has its own
// isolated-Postgres integration coverage in store/projectservice_test.go and
// store/project_test.go.
//
// The fuller "every principal class × every authorization edge" matrix lives
// in projects_delete_policy_test.go (BE-0132).

// fakeProjectDeleter is a canned ProjectDeleter for httpapi tests. The zero
// value returns a zero project and no error, which is all the test helpers
// that never reach the handler need; the DELETE tests set project/err and
// read got back to prove the handler forwards the principal's home
// organization, the path project id, and the optional If-Match precondition
// to the store layer unchanged.
type fakeProjectDeleter struct {
	project store.Project
	err     error
	got     *store.DeleteProjectInput
}

func (f fakeProjectDeleter) ScheduleDeletion(_ context.Context, in store.DeleteProjectInput) (store.Project, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.project, f.err
}

// deleteProjectSuccessEnvelope is the decoded shape of the DELETE
// /v1/projects/{project_id} success envelope.
type deleteProjectSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Project projectResource `json:"project"`
	} `json:"data"`
}

// deleteProjectHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// ProjectDeleter. It is the production request path: the DELETE
// /v1/projects/{project_id} route is wrapped in RequireAuth for action
// project.delete.
func deleteProjectHandlerFor(id auth.Identity, authErr error, deleter ProjectDeleter) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, deleter, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeBreakGlassController{}, nil, nil)
}

// deleteProject issues DELETE /v1/projects/{projectID} against handler,
// optionally with a bearer token.
func deleteProject(handler http.Handler, projectID, token string) *httptest.ResponseRecorder {
	return deleteProjectWithIfMatch(handler, projectID, token, "")
}

// deleteProjectWithIfMatch issues DELETE /v1/projects/{projectID} with an
// optional If-Match header. An empty ifMatch omits the header entirely so
// the optional precondition path remains exercised.
func deleteProjectWithIfMatch(handler http.Handler, projectID, token, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/projects/"+projectID, nil)
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

func decodeDeleteProject(t *testing.T, rec *httptest.ResponseRecorder) deleteProjectSuccessEnvelope {
	t.Helper()
	var env deleteProjectSuccessEnvelope
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

// TestDeleteProjectHappyPathForwardsPrincipalAndScheduling proves the
// handler threads the principal's home organization and the path's project
// id into the store input, renders the returned row — with its
// deletion_scheduled_at stamp — in the stable yalla.output.v1 envelope,
// returns 202 Accepted because the destructive teardown is scheduled rather
// than immediate, and mirrors the row's authoritative version into the ETag
// response header so the caller can echo it back as the next If-Match
// precondition.
func TestDeleteProjectHappyPathForwardsPrincipalAndScheduling(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	updated := created.Add(time.Minute)
	scheduled := updated.Add(time.Minute)
	row := store.Project{
		ID:                  "prj_acme_web",
		OrganizationID:      "org_acme",
		Slug:                "web-api",
		DisplayName:         "Web API",
		Version:             4,
		CreatedAt:           created,
		UpdatedAt:           updated,
		DeletionScheduledAt: &scheduled,
	}
	var captured store.DeleteProjectInput
	deleter := fakeProjectDeleter{project: row, got: &captured}
	handler := deleteProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteProject(handler, "prj_acme_web", "valid-key")

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	env := decodeDeleteProject(t, rec)
	if env.Data.Project.ProjectID != row.ID {
		t.Errorf("project_id = %q, want %q", env.Data.Project.ProjectID, row.ID)
	}
	if env.Data.Project.OrganizationID != row.OrganizationID {
		t.Errorf("organization_id = %q, want %q", env.Data.Project.OrganizationID, row.OrganizationID)
	}
	if env.Data.Project.Version != row.Version {
		t.Errorf("version = %d, want %d", env.Data.Project.Version, row.Version)
	}
	if env.Data.Project.DeletionScheduledAt == nil {
		t.Fatal("deletion_scheduled_at is nil, want a stamp")
	}
	if *env.Data.Project.DeletionScheduledAt != scheduled.Format(time.RFC3339Nano) {
		t.Errorf("deletion_scheduled_at = %q, want %q", *env.Data.Project.DeletionScheduledAt, scheduled.Format(time.RFC3339Nano))
	}
	if got, want := rec.Header().Get("ETag"), `"4"`; got != want {
		t.Errorf("ETag header = %q, want %q", got, want)
	}
	if captured.OrganizationID != "org_acme" {
		t.Errorf("forwarded organization_id = %q, want org_acme (principal home)", captured.OrganizationID)
	}
	if captured.ProjectID != "prj_acme_web" {
		t.Errorf("forwarded project_id = %q, want prj_acme_web", captured.ProjectID)
	}
	if captured.ActorID != "usr_acme_owner" {
		t.Errorf("forwarded actor_id = %q, want the resolved principal", captured.ActorID)
	}
	if captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor_org_id = %q, want the principal's home org", captured.ActorOrgID)
	}
	if captured.IfMatchVersion != nil {
		t.Errorf("forwarded if_match_version = %v, want nil (no header)", *captured.IfMatchVersion)
	}
}

// TestDeleteProjectForwardsIfMatchVersion proves a strong-ETag If-Match
// header is parsed and forwarded as the optimistic-concurrency precondition.
func TestDeleteProjectForwardsIfMatchVersion(t *testing.T) {
	t.Parallel()

	row := store.Project{
		ID:             "prj_acme_web",
		OrganizationID: "org_acme",
		Slug:           "web-api",
		DisplayName:    "Web API",
		Version:        5,
	}
	stamp := time.Now().UTC()
	row.DeletionScheduledAt = &stamp
	var captured store.DeleteProjectInput
	deleter := fakeProjectDeleter{project: row, got: &captured}
	handler := deleteProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteProjectWithIfMatch(handler, "prj_acme_web", "valid-key", `"4"`)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusAccepted, rec.Body.String())
	}
	if captured.IfMatchVersion == nil {
		t.Fatal("forwarded if_match_version is nil, want 4")
	}
	if *captured.IfMatchVersion != 4 {
		t.Errorf("forwarded if_match_version = %d, want 4", *captured.IfMatchVersion)
	}
}

// TestDeleteProjectRejectsMalformedIfMatch proves a weak/wildcard/multi
// If-Match value is a stable 400 E_INVALID_INPUT before the deleter runs —
// the malformed precondition is a client error, not a silent next-write-wins
// pass-through.
func TestDeleteProjectRejectsMalformedIfMatch(t *testing.T) {
	t.Parallel()

	deleter := fakeProjectDeleter{err: stderrors.New("deleter must not be called")}
	handler := deleteProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteProjectWithIfMatch(handler, "prj_acme_web", "valid-key", `W/"4"`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestDeleteProjectSurfacesNotFound proves a NotFound from the store is
// rendered as a 404 error envelope — never disguised as an empty success.
func TestDeleteProjectSurfacesNotFound(t *testing.T) {
	t.Parallel()

	deleter := fakeProjectDeleter{err: apierr.NotFound("project", "prj_ghost")}
	handler := deleteProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteProject(handler, "prj_ghost", "valid-key")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestDeleteProjectSurfacesAlreadyScheduledConflict proves the
// already-scheduled Conflict from the store is rendered as a 409 — the
// caller's view of the resource lifecycle is stale, so a silent success
// would write a misleading audit record.
func TestDeleteProjectSurfacesAlreadyScheduledConflict(t *testing.T) {
	t.Parallel()

	deleter := fakeProjectDeleter{err: apierr.Conflict("project deletion is already scheduled")}
	handler := deleteProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteProject(handler, "prj_acme_web", "valid-key")

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestDeleteProjectSurfacesStaleIfMatchConflict proves the ConflictStale
// from the store is rendered as a 409 carrying the row's current version
// under details.current_version, so an agent can retry with the
// authoritative If-Match without re-reading the row.
func TestDeleteProjectSurfacesStaleIfMatchConflict(t *testing.T) {
	t.Parallel()

	deleter := fakeProjectDeleter{err: apierr.ConflictStale(7)}
	handler := deleteProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, deleter)

	rec := deleteProjectWithIfMatch(handler, "prj_acme_web", "valid-key", `"4"`)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestDeleteProjectMissingDeleterIsInternalError proves the handler reports a
// nil ProjectDeleter as a typed internal error rather than serving a
// misleading success. The wiring goes through NewHandler so the request
// reaches the typed-internal guard inside deleteProjectHandler.
func TestDeleteProjectMissingDeleterIsInternalError(t *testing.T) {
	t.Parallel()

	a := fakeAuthenticator{identity: auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, nil, nil, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeBreakGlassController{}, nil, nil)

	rec := deleteProject(handler, "prj_acme_web", "valid-key")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestDeleteProjectUnauthenticatedReturns401 proves a request without
// credentials is rejected by RequireAuth before the deleter runs.
func TestDeleteProjectUnauthenticatedReturns401(t *testing.T) {
	t.Parallel()

	deleter := fakeProjectDeleter{err: stderrors.New("deleter must not be called")}
	handler := deleteProjectHandlerFor(auth.Identity{}, auth.ErrNoCredentials, deleter)

	rec := deleteProject(handler, "prj_acme_web", "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestDeleteProjectOpenAPIRouteIsRegistered proves the route table publishes
// the operation — agents must be able to discover the public surface
// through /openapi.json.
func TestDeleteProjectOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeBreakGlassController{})

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodDelete && rt.endpoint.Path == "/v1/projects/{project_id}" {
			found = true
			if rt.endpoint.OperationID != "deleteProject" {
				t.Errorf("operation_id = %q, want deleteProject", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionProjectDelete) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionProjectDelete)
			}
			if !rt.endpoint.RequiresAuth {
				t.Error("requires_auth = false, want true")
			}
			if rt.endpoint.SuccessStatus != http.StatusAccepted {
				t.Errorf("success_status = %d, want %d", rt.endpoint.SuccessStatus, http.StatusAccepted)
			}
			break
		}
	}
	if !found {
		t.Fatalf("route DELETE /v1/projects/{project_id} not registered in route table")
	}
}
