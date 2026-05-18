package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	stderrors "errors"
	"log/slog"
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

const createPreviewContractSecret = "yk_live_supersecret_previews_create_DEADBEEF0123456789"

func createPreviewHandlerFor(id auth.Identity, authErr error, creator PreviewCreator) http.Handler {
	return createPreviewHandlerForWithLogger(id, authErr, creator, nil)
}

func createPreviewHandlerForWithLogger(id auth.Identity, authErr error, creator PreviewCreator, logger *slog.Logger) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil, creator)
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

func TestCreatePreviewPropagatesInboundRequestID(t *testing.T) {
	t.Parallel()

	row := store.PreviewEnvironment{
		ID:                  "penv_acme_pr_42",
		OrganizationID:      "org_acme",
		ProjectID:           "proj_acme_web",
		EnvironmentID:       "env_acme_pr_42",
		SourceEnvironmentID: "env_acme_prod",
		DisplayName:         "PR 42",
		ChangeRef:           "refs/pull/42/head",
		Status:              store.PreviewEnvironmentStatusPending,
		Version:             1,
		CreatedAt:           time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
		UpdatedAt:           time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC),
	}
	var captured store.CreatePreviewEnvironmentInput
	handler := createPreviewHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, fakePreviewCreator{preview: row, gotInput: &captured})

	req := httptest.NewRequest(http.MethodPost, "/v1/projects/proj_acme_web/previews",
		bytes.NewReader([]byte(`{"preview_id":"penv_acme_pr_42","environment_id":"env_acme_pr_42","source_environment_id":"env_acme_prod","slug":"pr-42","display_name":"PR 42","change_ref":"refs/pull/42/head"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer tok-ada")
	req.Header.Set("X-Request-Id", "req-preview-contract-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreatePreview(t, rec)
	if env.RequestID != "req-preview-contract-123" {
		t.Errorf("envelope request_id = %q, want inbound request id", env.RequestID)
	}
	if got := rec.Header().Get("X-Request-Id"); got != "req-preview-contract-123" {
		t.Errorf("X-Request-Id header = %q, want inbound request id", got)
	}
	if captured.RequestID != "req-preview-contract-123" {
		t.Errorf("captured request id = %q, want inbound request id", captured.RequestID)
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

func TestCreatePreviewRequiresAuthentication(t *testing.T) {
	t.Parallel()

	var calls int
	creator := fakePreviewCreator{err: stderrors.New("creator must not be called"), callCount: &calls}
	handler := createPreviewHandlerFor(auth.Identity{}, apierr.AuthenticationRequired(), creator)

	rec := postProjectPreviews(handler, "proj_acme_web", "",
		`{"preview_id":"penv_acme_pr_42","environment_id":"env_acme_pr_42","source_environment_id":"env_acme_prod","slug":"pr-42","display_name":"PR 42","change_ref":"refs/pull/42/head"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreatePreviewError(t, rec)
	if env.SchemaVersion != "yalla.error.v1" || env.OK || env.Error.Code != "E_AUTHENTICATION_REQUIRED" || env.RequestID == "" {
		t.Errorf("error envelope = %+v, want E_AUTH with request_id", env)
	}
	if calls != 0 {
		t.Errorf("creator called %d times after authentication failure; want 0", calls)
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

func TestCreatePreviewServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

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
		Version:             1,
		CreatedAt:           created,
		UpdatedAt:           created,
	}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	handler := createPreviewHandlerForWithLogger(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, fakePreviewCreator{preview: row}, logger)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = postProjectPreviews(handler, "proj_acme_web", createPreviewContractSecret,
			`{"preview_id":"penv_acme_pr_42","environment_id":"env_acme_pr_42","source_environment_id":"env_acme_prod","slug":"pr-42","display_name":"PR 42","change_ref":"refs/pull/42/head"}`)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing", stderr)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreatePreview(t, rec)
	if env.Data.Preview.ID != "penv_acme_pr_42" {
		t.Errorf("preview.id = %q, want response data in body", env.Data.Preview.ID)
	}
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

func TestCreatePreviewRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	created := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	successCreator := fakePreviewCreator{preview: store.PreviewEnvironment{
		ID:                  "penv_acme_pr_42",
		OrganizationID:      "org_acme",
		ProjectID:           "proj_acme_web",
		EnvironmentID:       "env_acme_pr_42",
		SourceEnvironmentID: "env_acme_prod",
		DisplayName:         "PR 42",
		ChangeRef:           "refs/pull/42/head",
		Status:              store.PreviewEnvironmentStatusPending,
		Version:             1,
		CreatedAt:           created,
		UpdatedAt:           created,
	}}
	denyCreator := fakePreviewCreator{err: stderrors.New("creator must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		creator    PreviewCreator
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
			creator:    successCreator,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: orgPrincipal("usr_eve", "org_acme", policy.RoleViewer), Method: auth.MethodSession},
			creator:    denyCreator,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := createPreviewHandlerForWithLogger(tc.identity, nil, tc.creator, logger)

			rec := postProjectPreviews(handler, "proj_acme_web", createPreviewContractSecret,
				`{"preview_id":"penv_acme_pr_42","environment_id":"env_acme_pr_42","source_environment_id":"env_acme_prod","slug":"pr-42","display_name":"PR 42","change_ref":"refs/pull/42/head"}`)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), createPreviewContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), createPreviewContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

func TestCreatePreviewErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	handler := createPreviewHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, fakePreviewCreator{err: apierr.StoreUnavailable(stderrors.New(cause))})

	rec := postProjectPreviews(handler, "proj_acme_web", createPreviewContractSecret,
		`{"preview_id":"penv_acme_pr_42","environment_id":"env_acme_pr_42","source_environment_id":"env_acme_prod","slug":"pr-42","display_name":"PR 42","change_ref":"refs/pull/42/head"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeCreatePreviewError(t, rec)
	if env.SchemaVersion != "yalla.error.v1" || env.OK || env.Error.Code != "E_UNAVAILABLE" {
		t.Errorf("error envelope = %+v, want E_UNAVAILABLE", env)
	}
	if strings.Contains(rec.Body.String(), cause) {
		t.Errorf("error envelope leaked the wrapped dependency cause %q: %s", cause, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("error envelope leaked the datastore address: %s", rec.Body.String())
	}
}

func TestCreatePreviewRouteIsDocumented(t *testing.T) {
	t.Parallel()

	handler := createPreviewHandlerFor(
		auth.Identity{Principal: orgPrincipal("usr_ada", "org_acme", policy.RoleDeveloper), Method: auth.MethodSession},
		nil, fakePreviewCreator{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string                `json:"operationId"`
			Summary        string                `json:"summary"`
			RequiredAction string                `json:"x-required-action"`
			Security       []map[string][]string `json:"security"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi.json: %v", err)
	}
	op, ok := doc.Paths["/v1/projects/{project_id}/previews"]["post"]
	if !ok {
		t.Fatalf("POST /v1/projects/{project_id}/previews missing from openapi.json: %s", rec.Body.String())
	}
	if op.OperationID != "createPreview" {
		t.Errorf("operationId = %q, want createPreview", op.OperationID)
	}
	if op.Summary != "Create preview environment" {
		t.Errorf("summary = %q, want Create preview environment", op.Summary)
	}
	if op.RequiredAction != string(policy.ActionPreviewCreate) {
		t.Errorf("x-required-action = %q, want %s", op.RequiredAction, policy.ActionPreviewCreate)
	}
	if len(op.Security) == 0 {
		t.Error("security is empty, want ApiKeyAuth requirement for authenticated route")
	}
}

type fakePreviewCreator struct {
	preview          store.PreviewEnvironment
	previews         []store.PreviewEnvironment
	deleted          store.PreviewEnvironment
	err              error
	listErr          error
	deleteErr        error
	gotInput         *store.CreatePreviewEnvironmentInput
	gotDeleteInput   *store.DeletePreviewEnvironmentInput
	gotListOrgID     *string
	gotListProjectID *string
	callCount        *int
	listCallCount    *int
	deleteCallCount  *int
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

func (f fakePreviewCreator) ListProjectPreviews(ctx context.Context, organizationID, projectID string) ([]store.PreviewEnvironment, error) {
	_ = ctx
	if f.listCallCount != nil {
		*f.listCallCount++
	}
	if f.gotListOrgID != nil {
		*f.gotListOrgID = organizationID
	}
	if f.gotListProjectID != nil {
		*f.gotListProjectID = projectID
	}
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.previews == nil {
		return []store.PreviewEnvironment{}, nil
	}
	return f.previews, nil
}
