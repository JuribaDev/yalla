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

// Contract tests for POST /v1/projects/{project_id}/restore. The route is
// gated by RequireAuth on action project.restore through projectIDResolver —
// a CapWrite action authorized against the (principal home organization,
// {project_id}) resource. These tests drive the real NewHandler with a fake
// Authenticator, the real policy engine, and a fake ProjectRestorer — the
// same wiring a request hits in production, minus the database. The
// store-backed orchestrator (store.ProjectService.Restore) has its own
// isolated-Postgres integration coverage in store/project_restore_test.go.
//
// The fuller "every principal class × every authorization edge" matrix lives
// in projects_restore_policy_test.go (BE-0135).

// fakeProjectRestorer is a canned ProjectRestorer for httpapi tests. The
// zero value returns a zero project and no error, which is all the test
// helpers that never reach the handler need; the restore tests set
// project/err and read got back to prove the handler forwards the
// principal's home organization, the path project id, and the optional
// If-Match precondition to the store layer unchanged.
type fakeProjectRestorer struct {
	project store.Project
	err     error
	got     *store.RestoreProjectInput
}

func (f fakeProjectRestorer) Restore(_ context.Context, in store.RestoreProjectInput) (store.Project, error) {
	if f.got != nil {
		*f.got = in
	}
	return f.project, f.err
}

// restoreProjectSuccessEnvelope is the decoded shape of the POST
// /v1/projects/{project_id}/restore success envelope.
type restoreProjectSuccessEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Data          struct {
		Project projectResource `json:"project"`
	} `json:"data"`
}

// restoreProjectHandlerFor builds the full NewHandler surface with an
// Authenticator that resolves every credential to id and the given
// ProjectRestorer. It is the production request path: the POST
// /v1/projects/{project_id}/restore route is wrapped in RequireAuth for
// action project.restore.
func restoreProjectHandlerFor(id auth.Identity, authErr error, restorer ProjectRestorer) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, restorer, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, nil)
}

// restoreProject issues POST /v1/projects/{projectID}/restore against
// handler, optionally with a bearer token.
func restoreProject(handler http.Handler, projectID, token string) *httptest.ResponseRecorder {
	return restoreProjectWithIfMatch(handler, projectID, token, "")
}

// restoreProjectWithIfMatch issues POST /v1/projects/{projectID}/restore
// with an optional If-Match header. An empty ifMatch omits the header
// entirely so the optional precondition path remains exercised.
func restoreProjectWithIfMatch(handler http.Handler, projectID, token, ifMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/restore", nil)
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

func decodeRestoreProject(t *testing.T, rec *httptest.ResponseRecorder) restoreProjectSuccessEnvelope {
	t.Helper()
	var env restoreProjectSuccessEnvelope
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

// TestRestoreProjectHappyPathForwardsPrincipalAndClearsStamp proves the
// handler threads the principal's home organization and the path's project
// id into the store input, renders the returned live row — with its
// deletion_scheduled_at stamp absent — in the stable yalla.output.v1
// envelope, returns 200 OK because the restore is immediate, and mirrors
// the row's authoritative version into the ETag response header so the
// caller can echo it back as the next If-Match precondition.
func TestRestoreProjectHappyPathForwardsPrincipalAndClearsStamp(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	updated := created.Add(2 * time.Minute)
	row := store.Project{
		ID:             "prj_acme_web",
		OrganizationID: "org_acme",
		Slug:           "web-api",
		DisplayName:    "Web API",
		Version:        5,
		CreatedAt:      created,
		UpdatedAt:      updated,
		// DeletionScheduledAt nil — the restore cleared it.
	}
	var captured store.RestoreProjectInput
	restorer := fakeProjectRestorer{project: row, got: &captured}
	handler := restoreProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, restorer)

	rec := restoreProject(handler, "prj_acme_web", "valid-key")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	env := decodeRestoreProject(t, rec)
	if env.Data.Project.ProjectID != row.ID {
		t.Errorf("project_id = %q, want %q", env.Data.Project.ProjectID, row.ID)
	}
	if env.Data.Project.OrganizationID != row.OrganizationID {
		t.Errorf("organization_id = %q, want %q", env.Data.Project.OrganizationID, row.OrganizationID)
	}
	if env.Data.Project.Version != row.Version {
		t.Errorf("version = %d, want %d", env.Data.Project.Version, row.Version)
	}
	if env.Data.Project.DeletionScheduledAt != nil {
		t.Errorf("deletion_scheduled_at = %v, want nil (restored)", *env.Data.Project.DeletionScheduledAt)
	}
	if got, want := rec.Header().Get("ETag"), `"5"`; got != want {
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

// TestRestoreProjectForwardsIfMatchVersion proves a strong-ETag If-Match
// header is parsed and forwarded as the optimistic-concurrency precondition.
func TestRestoreProjectForwardsIfMatchVersion(t *testing.T) {
	t.Parallel()

	row := store.Project{
		ID:             "prj_acme_web",
		OrganizationID: "org_acme",
		Slug:           "web-api",
		DisplayName:    "Web API",
		Version:        6,
	}
	var captured store.RestoreProjectInput
	restorer := fakeProjectRestorer{project: row, got: &captured}
	handler := restoreProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, restorer)

	rec := restoreProjectWithIfMatch(handler, "prj_acme_web", "valid-key", `"5"`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if captured.IfMatchVersion == nil {
		t.Fatal("forwarded if_match_version is nil, want 5")
	}
	if *captured.IfMatchVersion != 5 {
		t.Errorf("forwarded if_match_version = %d, want 5", *captured.IfMatchVersion)
	}
}

// TestRestoreProjectRejectsMalformedIfMatch proves a weak/wildcard/multi
// If-Match value is a stable 400 E_INVALID_INPUT before the restorer runs —
// the malformed precondition is a client error, not a silent
// next-write-wins pass-through.
func TestRestoreProjectRejectsMalformedIfMatch(t *testing.T) {
	t.Parallel()

	restorer := fakeProjectRestorer{err: stderrors.New("restorer must not be called")}
	handler := restoreProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, restorer)

	rec := restoreProjectWithIfMatch(handler, "prj_acme_web", "valid-key", `W/"5"`)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestRestoreProjectSurfacesNotFound proves a NotFound from the store is
// rendered as a 404 error envelope — never disguised as an empty success.
func TestRestoreProjectSurfacesNotFound(t *testing.T) {
	t.Parallel()

	restorer := fakeProjectRestorer{err: apierr.NotFound("project", "prj_ghost")}
	handler := restoreProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, restorer)

	rec := restoreProject(handler, "prj_ghost", "valid-key")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestRestoreProjectSurfacesNotScheduledConflict proves the
// not-scheduled-for-deletion Conflict from the store is rendered as a 409 —
// the caller's view of the resource lifecycle is stale, so a silent
// success would write a misleading audit record.
func TestRestoreProjectSurfacesNotScheduledConflict(t *testing.T) {
	t.Parallel()

	restorer := fakeProjectRestorer{err: apierr.Conflict("project is not scheduled for deletion")}
	handler := restoreProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, restorer)

	rec := restoreProject(handler, "prj_acme_web", "valid-key")

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestRestoreProjectSurfacesStaleIfMatchConflict proves the ConflictStale
// from the store is rendered as a 409 carrying the row's current version
// under details.current_version, so an agent can retry with the
// authoritative If-Match without re-reading the row.
func TestRestoreProjectSurfacesStaleIfMatchConflict(t *testing.T) {
	t.Parallel()

	restorer := fakeProjectRestorer{err: apierr.ConflictStale(9)}
	handler := restoreProjectHandlerFor(auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}, nil, restorer)

	rec := restoreProjectWithIfMatch(handler, "prj_acme_web", "valid-key", `"5"`)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// TestRestoreProjectMissingRestorerIsInternalError proves the handler
// reports a nil ProjectRestorer as a typed internal error rather than
// serving a misleading success. The wiring goes through NewHandler so the
// request reaches the typed-internal guard inside restoreProjectHandler.
func TestRestoreProjectMissingRestorerIsInternalError(t *testing.T) {
	t.Parallel()

	a := fakeAuthenticator{identity: auth.Identity{Principal: orgPrincipal("usr_acme_owner", "org_acme", policy.RoleOwner), Method: auth.MethodSession}}
	handler := NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, nil, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, nil)

	rec := restoreProject(handler, "prj_acme_web", "valid-key")

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// TestRestoreProjectUnauthenticatedReturns401 proves a request without
// credentials is rejected by RequireAuth before the restorer runs.
func TestRestoreProjectUnauthenticatedReturns401(t *testing.T) {
	t.Parallel()

	restorer := fakeProjectRestorer{err: stderrors.New("restorer must not be called")}
	handler := restoreProjectHandlerFor(auth.Identity{}, auth.ErrNoCredentials, restorer)

	rec := restoreProject(handler, "prj_acme_web", "")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestRestoreProjectOpenAPIRouteIsRegistered proves the route table
// publishes the operation — agents must be able to discover the public
// surface through /openapi.json.
func TestRestoreProjectOpenAPIRouteIsRegistered(t *testing.T) {
	t.Parallel()

	table := newRouteTable(runtime.BuildInfo{Version: "1.0.0"}, nil, nil,
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, nil)

	var found bool
	for _, rt := range table {
		if rt.endpoint.Method == http.MethodPost && rt.endpoint.Path == "/v1/projects/{project_id}/restore" {
			found = true
			if rt.endpoint.OperationID != "restoreProject" {
				t.Errorf("operation_id = %q, want restoreProject", rt.endpoint.OperationID)
			}
			if rt.endpoint.RequiredAction != string(policy.ActionProjectRestore) {
				t.Errorf("required_action = %q, want %q", rt.endpoint.RequiredAction, policy.ActionProjectRestore)
			}
			if !rt.endpoint.RequiresAuth {
				t.Error("requires_auth = false, want true")
			}
			if rt.endpoint.SuccessStatus != 0 && rt.endpoint.SuccessStatus != http.StatusOK {
				t.Errorf("success_status = %d, want 0 (default 200) or %d", rt.endpoint.SuccessStatus, http.StatusOK)
			}
			break
		}
	}
	if !found {
		t.Fatalf("route POST /v1/projects/{project_id}/restore not registered in route table")
	}
}
