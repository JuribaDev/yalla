package httpapi

import (
	"bytes"
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

// Public-API contract coverage for DELETE
// /v1/projects/{project_id}/previews/{preview_id} (BE-0269).
//
// project_previews_delete_test.go already proves the 202 success envelope,
// generated request_id, authenticated/unauthenticated/unauthorized/not-found
// status space, OpenAPI operation registration, ETag emission, and principal +
// path forwarding into the store service.
// This file closes the remaining dedicated contract-test criteria:
//
//   - inbound request_id propagation to the response and store input;
//   - stable invalid-input error envelope with no submitted value echo;
//   - response data is written only through http.ResponseWriter;
//   - structured request logs redact bearer tokens on success and denial;
//   - wrapped dependency causes stay out of public error envelopes.

const deleteProjectPreviewContractSecret = "yk_live_supersecret_project_preview_delete_DEADBEEF0123456789"

func deletePreviewHandlerForWithLogger(id auth.Identity, authErr error, previews PreviewCreator, logger *slog.Logger) http.Handler {
	a := fakeAuthenticator{identity: id, err: authErr}
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, a, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{},
		fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{},
		fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{},
		fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{},
		fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{},
		fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{},
		fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{},
		fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{},
		fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{},
		fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{},
		fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{},
		fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{},
		fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil, previews)
}

func TestDeleteProjectPreviewPropagatesInboundRequestID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	scheduledAt := now.Add(time.Minute)
	row := seedDeletePreviewWire("penv_acme_pr_42", "org_acme", "proj_acme_web", scheduledAt, now)
	var captured store.DeletePreviewEnvironmentInput
	handler := deletePreviewHandlerFor(
		auth.Identity{Principal: previewPrincipal("usr_ada", "org_acme", policy.RoleDeveloper).Principal, Method: auth.MethodSession},
		nil,
		fakePreviewCreator{deleted: row, gotDeleteInput: &captured},
	)

	req := httptest.NewRequest(http.MethodDelete, "/v1/projects/proj_acme_web/previews/penv_acme_pr_42", nil)
	req.Header.Set("Authorization", "Bearer "+deleteProjectPreviewContractSecret)
	req.Header.Set("X-Request-Id", "req-preview-delete-42")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	env := decodeDeletePreview(t, rec)
	if env.RequestID != "req-preview-delete-42" {
		t.Errorf("envelope request_id = %q, want inbound request id", env.RequestID)
	}
	if got := rec.Header().Get("X-Request-Id"); got != "req-preview-delete-42" {
		t.Errorf("X-Request-Id header = %q, want inbound request id", got)
	}
	if captured.RequestID != "req-preview-delete-42" {
		t.Errorf("captured request id = %q, want inbound request id", captured.RequestID)
	}
}

func TestDeleteProjectPreviewInvalidInputEnvelopeDoesNotEchoIfMatch(t *testing.T) {
	t.Parallel()

	const badIfMatch = "not-a-strong-etag-with-secret-" + deleteProjectPreviewContractSecret
	var calls int
	handler := deletePreviewHandlerFor(
		auth.Identity{Principal: previewPrincipal("usr_ada", "org_acme", policy.RoleDeveloper).Principal, Method: auth.MethodSession},
		nil,
		fakePreviewCreator{deleteCallCount: &calls},
	)

	req := httptest.NewRequest(http.MethodDelete, "/v1/projects/proj_acme_web/previews/penv_acme_pr_42", nil)
	req.Header.Set("Authorization", "Bearer "+deleteProjectPreviewContractSecret)
	req.Header.Set("If-Match", badIfMatch)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_VALIDATION")
	if env.SchemaVersion != "yalla.error.v1" {
		t.Errorf("schema_version = %q, want yalla.error.v1", env.SchemaVersion)
	}
	if env.RequestID == "" {
		t.Error("request_id is empty, want generated request id")
	}
	if calls != 0 {
		t.Fatalf("delete calls = %d, want 0 after validation failure", calls)
	}
	if strings.Contains(rec.Body.String(), badIfMatch) || strings.Contains(rec.Body.String(), deleteProjectPreviewContractSecret) {
		t.Errorf("invalid-input envelope echoed caller-controlled header bytes: %s", rec.Body.String())
	}
}

func TestDeleteProjectPreviewServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	scheduledAt := now.Add(time.Minute)
	row := seedDeletePreviewWire("penv_acme_pr_42", "org_acme", "proj_acme_web", scheduledAt, now)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	handler := deletePreviewHandlerForWithLogger(
		auth.Identity{Principal: previewPrincipal("usr_ada", "org_acme", policy.RoleDeveloper).Principal, Method: auth.MethodSession},
		nil,
		fakePreviewCreator{deleted: row},
		logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = deleteProjectPreview(handler, "proj_acme_web", "penv_acme_pr_42", deleteProjectPreviewContractSecret)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing; response data must go through the ResponseWriter", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing; response data must go through the ResponseWriter", stderr)
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body.String())
	}
	env := decodeDeletePreview(t, rec)
	if env.Data.Preview.ID != "penv_acme_pr_42" {
		t.Errorf("preview.id = %q, want response data in body", env.Data.Preview.ID)
	}
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

func TestDeleteProjectPreviewRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	scheduledAt := now.Add(time.Minute)
	successDeleter := fakePreviewCreator{
		deleted: seedDeletePreviewWire("penv_acme_pr_42", "org_acme", "proj_acme_web", scheduledAt, now),
	}
	denyDeleter := fakePreviewCreator{deleteErr: stderrors.New("deleter must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		deleter    PreviewCreator
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   auth.Identity{Principal: previewPrincipal("usr_ada", "org_acme", policy.RoleDeveloper).Principal, Method: auth.MethodSession},
			deleter:    successDeleter,
			wantStatus: http.StatusAccepted,
		},
		{
			name:       "authorization failure path",
			identity:   auth.Identity{Principal: previewPrincipal("usr_viewer", "org_acme", policy.RoleViewer).Principal, Method: auth.MethodSession},
			deleter:    denyDeleter,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := deletePreviewHandlerForWithLogger(tc.identity, nil, tc.deleter, logger)

			rec := deleteProjectPreview(handler, "proj_acme_web", "penv_acme_pr_42", deleteProjectPreviewContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), deleteProjectPreviewContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), deleteProjectPreviewContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

func TestDeleteProjectPreviewErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing 10.0.0.5:5432"
	handler := deletePreviewHandlerFor(
		auth.Identity{Principal: previewPrincipal("usr_ada", "org_acme", policy.RoleDeveloper).Principal, Method: auth.MethodSession},
		nil,
		fakePreviewCreator{deleteErr: apierr.StoreUnavailable(stderrors.New(cause))},
	)

	rec := deleteProjectPreview(handler, "proj_acme_web", "penv_acme_pr_42", deleteProjectPreviewContractSecret)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_UNAVAILABLE")
	if env.Error.Message == "" {
		t.Error("error.message is empty, want a stable generic message")
	}
	if strings.Contains(rec.Body.String(), cause) {
		t.Errorf("error envelope leaked the wrapped dependency cause %q: %s", cause, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Errorf("error envelope leaked the datastore address: %s", rec.Body.String())
	}
}

func seedDeletePreviewWire(id, orgID, projectID string, scheduledAt, now time.Time) store.PreviewEnvironment {
	return store.PreviewEnvironment{
		ID:                  id,
		OrganizationID:      orgID,
		ProjectID:           projectID,
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
}
