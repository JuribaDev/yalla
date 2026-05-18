package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/auth"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type deletePreviewSuccessEnvelope struct {
	SchemaVersion string               `json:"schema_version"`
	OK            bool                 `json:"ok"`
	RequestID     string               `json:"request_id"`
	Data          deletePreviewPayload `json:"data"`
}

func deletePreviewHandlerFor(id auth.Identity, authErr error, previews PreviewCreator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, previews)
}

func deleteProjectPreview(handler http.Handler, projectID, previewID, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/projects/"+projectID+"/previews/"+previewID, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeDeletePreview(t *testing.T, rec *httptest.ResponseRecorder) deletePreviewSuccessEnvelope {
	t.Helper()
	var env deletePreviewSuccessEnvelope
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

func TestDeleteProjectPreviewHappyPathForwardsPrincipalAndPath(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	scheduledAt := now.Add(time.Minute)
	row := store.PreviewEnvironment{
		ID:                  "penv_acme_pr_42",
		OrganizationID:      "org_acme",
		ProjectID:           "proj_acme_web",
		EnvironmentID:       "env_acme_pr_42",
		SourceEnvironmentID: "env_acme_prod",
		DisplayName:         "PR 42",
		ChangeRef:           "refs/pull/42/head",
		Status:              store.PreviewEnvironmentStatusDeleting,
		DeletionScheduledAt: &scheduledAt,
		Version:             7,
		CreatedAt:           now,
		UpdatedAt:           scheduledAt,
	}
	var captured store.DeletePreviewEnvironmentInput
	previews := fakePreviewCreator{deleted: row, gotDeleteInput: &captured}
	handler := deletePreviewHandlerFor(
		auth.Identity{Principal: previewPrincipal("usr_ada", "org_acme", policy.RoleDeveloper).Principal, Method: auth.MethodSession},
		nil, previews)

	rec := deleteProjectPreview(handler, "proj_acme_web", "penv_acme_pr_42", "tok-ada")

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	env := decodeDeletePreview(t, rec)
	if env.Data.Preview.ID != row.ID || env.Data.Preview.Status != store.PreviewEnvironmentStatusDeleting {
		t.Fatalf("preview payload = %+v, want scheduled row", env.Data.Preview)
	}
	if env.Data.Preview.DeletionScheduledAt == nil {
		t.Fatal("deletion_scheduled_at missing from response")
	}
	if captured.OrganizationID != "org_acme" || captured.ProjectID != "proj_acme_web" || captured.PreviewID != "penv_acme_pr_42" {
		t.Errorf("forwarded scope = %+v, want principal org and path project/preview", captured)
	}
	if captured.ActorID != "usr_ada" || captured.ActorOrgID != "org_acme" {
		t.Errorf("forwarded actor = %+v, want authenticated principal", captured)
	}
}

func TestDeleteProjectPreviewUnauthenticatedDoesNotCallDeleter(t *testing.T) {
	t.Parallel()

	calls := 0
	handler := deletePreviewHandlerFor(auth.Identity{}, auth.ErrNoCredentials, fakePreviewCreator{deleteCallCount: &calls})

	rec := deleteProjectPreview(handler, "proj_acme_web", "penv_acme_pr_42", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("delete calls = %d, want 0", calls)
	}
}

func TestDeleteProjectPreviewAuthorizationFailureDoesNotCallDeleter(t *testing.T) {
	t.Parallel()

	calls := 0
	handler := deletePreviewHandlerFor(
		auth.Identity{Principal: previewPrincipal("usr_view", "org_acme", policy.RoleViewer).Principal, Method: auth.MethodSession},
		nil, fakePreviewCreator{deleteCallCount: &calls})

	rec := deleteProjectPreview(handler, "proj_acme_web", "penv_acme_pr_42", "tok-view")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("delete calls = %d, want 0", calls)
	}
}

func TestDeleteProjectPreviewMalformedIfMatchIsValidationFailure(t *testing.T) {
	t.Parallel()

	calls := 0
	handler := deletePreviewHandlerFor(
		auth.Identity{Principal: previewPrincipal("usr_ada", "org_acme", policy.RoleDeveloper).Principal, Method: auth.MethodSession},
		nil, fakePreviewCreator{deleteCallCount: &calls})

	req := httptest.NewRequest(http.MethodDelete, "/v1/projects/proj_acme_web/previews/penv_acme_pr_42", nil)
	req.Header.Set("Authorization", "Bearer tok-ada")
	req.Header.Set("If-Match", "not-a-strong-etag")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("delete calls = %d, want 0", calls)
	}
	var env createPreviewErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	if env.Error.Code != string(yerr.CodeInvalidInput) {
		t.Fatalf("error code = %s, want E_INVALID_INPUT", env.Error.Code)
	}
}

func TestDeleteProjectPreviewNotFound(t *testing.T) {
	t.Parallel()

	handler := deletePreviewHandlerFor(
		auth.Identity{Principal: previewPrincipal("usr_ada", "org_acme", policy.RoleDeveloper).Principal, Method: auth.MethodSession},
		nil, fakePreviewCreator{deleteErr: apierr.NotFound("preview environment", "penv_missing")})

	rec := deleteProjectPreview(handler, "proj_acme_web", "penv_missing", "tok-ada")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	var env createPreviewErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	if env.Error.Code != string(yerr.CodeNotFound) {
		t.Fatalf("error code = %s, want E_NOT_FOUND", env.Error.Code)
	}
}

func TestDeleteProjectPreviewOpenAPI(t *testing.T) {
	t.Parallel()

	handler := deletePreviewHandlerFor(
		auth.Identity{Principal: previewPrincipal("usr_ada", "org_acme", policy.RoleDeveloper).Principal, Method: auth.MethodSession},
		nil, fakePreviewCreator{})

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string `json:"operationId"`
			RequiredAction string `json:"x-required-action"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	op, ok := doc.Paths["/v1/projects/{project_id}/previews/{preview_id}"]["delete"]
	if !ok {
		t.Fatalf("DELETE /v1/projects/{project_id}/previews/{preview_id} missing from openapi.json: %s", rec.Body.String())
	}
	if op.OperationID != "deletePreview" {
		t.Errorf("operationId = %q, want deletePreview", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionPreviewDelete) {
		t.Errorf("x-required-action = %q, want %s", op.RequiredAction, policy.ActionPreviewDelete)
	}
}

var _ PreviewCreator = fakePreviewCreator{}

func (f fakePreviewCreator) ScheduleDeletion(_ context.Context, in store.DeletePreviewEnvironmentInput) (store.PreviewEnvironment, error) {
	if f.gotDeleteInput != nil {
		*f.gotDeleteInput = in
	}
	if f.deleteCallCount != nil {
		*f.deleteCallCount++
	}
	if f.deleteErr != nil {
		return store.PreviewEnvironment{}, f.deleteErr
	}
	return f.deleted, nil
}
