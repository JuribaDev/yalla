package httpapi

import (
	"bytes"
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

type createPreviewSuccessEnvelope struct {
	SchemaVersion string               `json:"schema_version"`
	OK            bool                 `json:"ok"`
	RequestID     string               `json:"request_id"`
	Data          createPreviewPayload `json:"data"`
}

type createPreviewErrorEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	RequestID     string `json:"request_id"`
	Error         struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func createPreviewHandlerFor(id auth.Identity, authErr error, creator PreviewCreator) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, creator)
}

func postProjectPreviews(handler http.Handler, projectID, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/"+projectID+"/previews", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeCreatePreview(t *testing.T, rec *httptest.ResponseRecorder) createPreviewSuccessEnvelope {
	t.Helper()
	var env createPreviewSuccessEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode success envelope: %v; body %s", err, rec.Body.String())
	}
	return env
}

func decodeCreatePreviewError(t *testing.T, rec *httptest.ResponseRecorder) createPreviewErrorEnvelope {
	t.Helper()
	var env createPreviewErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v; body %s", err, rec.Body.String())
	}
	return env
}

func TestCreatePreviewReturnsCreatedPreview(t *testing.T) {
	t.Parallel()

	expires := time.Date(2035, 6, 1, 12, 0, 0, 0, time.UTC)
	created := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	row := store.PreviewEnvironment{
		ID:                  "penv_acme_pr_42",
		OrganizationID:      "org_acme",
		ProjectID:           "proj_acme_web",
		EnvironmentID:       "env_acme_pr_42",
		SourceEnvironmentID: "env_acme_prod",
		DisplayName:         "PR 42",
		ChangeRef:           "refs/pull/42/head",
		Status:              store.PreviewEnvironmentStatusPending,
		ExpiresAt:           &expires,
		Version:             1,
		CreatedAt:           created,
		UpdatedAt:           created,
	}
	var captured store.CreatePreviewEnvironmentInput
	creator := fakePreviewCreator{preview: row, gotInput: &captured}
	handler := createPreviewHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)

	body := `{"preview_id":"penv_acme_pr_42","environment_id":"env_acme_pr_42","source_environment_id":"env_acme_prod","slug":"pr-42","display_name":"PR 42","change_ref":"refs/pull/42/head","expires_at":"2035-06-01T12:00:00Z"}`
	rec := postProjectPreviews(handler, "proj_acme_web", "tok-ada", body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreatePreview(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID == "" {
		t.Fatalf("envelope = %+v, want yalla.output.v1 ok=true with request_id", env)
	}
	got := env.Data.Preview
	if got.ID != row.ID || got.OrganizationID != row.OrganizationID || got.ProjectID != row.ProjectID ||
		got.EnvironmentID != row.EnvironmentID || got.SourceEnvironmentID != row.SourceEnvironmentID ||
		got.DisplayName != row.DisplayName || got.ChangeRef != row.ChangeRef || got.Status != row.Status ||
		got.Version != row.Version || !got.CreatedAt.Equal(created) || !got.UpdatedAt.Equal(created) {
		t.Errorf("preview = %+v, want row projection %+v", got, row)
	}
	if got.ExpiresAt == nil || *got.ExpiresAt != "2035-06-01T12:00:00Z" {
		t.Errorf("expires_at = %v, want 2035-06-01T12:00:00Z", got.ExpiresAt)
	}
	if captured.OrganizationID != "org_acme" || captured.ProjectID != "proj_acme_web" {
		t.Errorf("scope = (%q,%q), want principal org and path project", captured.OrganizationID, captured.ProjectID)
	}
	if captured.PreviewID != "penv_acme_pr_42" || captured.EnvironmentID != "env_acme_pr_42" ||
		captured.SourceEnvironmentID != "env_acme_prod" || captured.Slug != "pr-42" ||
		captured.DisplayName != "PR 42" || captured.ChangeRef != "refs/pull/42/head" {
		t.Errorf("captured input = %+v, want request fields forwarded", captured)
	}
	if captured.ActorID != "usr_ada" || captured.ActorOrgID != "org_acme" || captured.RequestID == "" {
		t.Errorf("actor/correlation = %+v, want resolved principal and request id", captured)
	}
}

func TestCreatePreviewRejectsUnknownFieldBeforeCreator(t *testing.T) {
	t.Parallel()

	var calls int
	creator := fakePreviewCreator{err: stderrors.New("creator must not be called"), callCount: &calls}
	handler := createPreviewHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)

	rec := postProjectPreviews(handler, "proj_acme_web", "tok-ada",
		`{"organization_id":"org_attacker","preview_id":"penv_x","environment_id":"env_x","source_environment_id":"env_src","slug":"x","display_name":"X","change_ref":"pr-1"}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Errorf("creator called %d times after strict decode rejection; want 0", calls)
	}
}

func TestCreatePreviewRequiresAuthorization(t *testing.T) {
	t.Parallel()

	var calls int
	creator := fakePreviewCreator{err: stderrors.New("creator must not be called"), callCount: &calls}
	handler := createPreviewHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_viewer", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
		nil, creator)

	rec := postProjectPreviews(handler, "proj_acme_web", "tok-viewer",
		`{"preview_id":"penv_acme_pr_42","environment_id":"env_acme_pr_42","source_environment_id":"env_acme_prod","slug":"pr-42","display_name":"PR 42","change_ref":"refs/pull/42/head"}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreatePreviewError(t, rec)
	if env.SchemaVersion != "yalla.error.v1" || env.OK || env.Error.Code != "E_FORBIDDEN" {
		t.Errorf("error envelope = %+v, want E_FORBIDDEN", env)
	}
	if calls != 0 {
		t.Errorf("creator called %d times after authorization denial; want 0", calls)
	}
}

func TestCreatePreviewSurfacesProjectNotFound(t *testing.T) {
	t.Parallel()

	creator := fakePreviewCreator{err: apierr.NotFound("project", "proj_ghost")}
	handler := createPreviewHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, creator)

	rec := postProjectPreviews(handler, "proj_ghost", "tok-ada",
		`{"preview_id":"penv_acme_pr_42","environment_id":"env_acme_pr_42","source_environment_id":"env_acme_prod","slug":"pr-42","display_name":"PR 42","change_ref":"refs/pull/42/head"}`)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreatePreviewError(t, rec)
	if env.SchemaVersion != "yalla.error.v1" || env.OK || env.Error.Code != "E_NOT_FOUND" {
		t.Errorf("error envelope = %+v, want E_NOT_FOUND", env)
	}
}

type fakePreviewCreator struct {
	preview   store.PreviewEnvironment
	err       error
	gotInput  *store.CreatePreviewEnvironmentInput
	callCount *int
}

func (f fakePreviewCreator) Create(ctx context.Context, in store.CreatePreviewEnvironmentInput) (store.PreviewEnvironment, error) {
	_ = ctx
	if f.callCount != nil {
		*f.callCount++
	}
	if f.gotInput != nil {
		*f.gotInput = in
	}
	if f.err != nil {
		return store.PreviewEnvironment{}, f.err
	}
	return f.preview, nil
}
