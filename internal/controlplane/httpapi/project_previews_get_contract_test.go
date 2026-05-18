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

// Public-API contract coverage for GET
// /v1/projects/{project_id}/previews (BE-0266).
//
// project_previews_get_test.go already proves the 200 success envelope,
// stable yalla.output.v1 schema version, generated request_id, OpenAPI
// operation registration, unauthenticated / unauthorized / not-found /
// dependency-failure rejection space, the "empty project is a stable [] shape"
// invariant, and the "reader receives the principal's home org plus the path
// {project_id}" wiring invariant.
// This file closes the remaining contract-test criteria those tests do not
// assert directly:
//
//   - inbound request_id propagation on the success path;
//   - an invalid-input error envelope remains stable when the reader rejects
//     the opaque project id;
//   - the HTTP server writes response data only through the
//     http.ResponseWriter, never stdout/stderr;
//   - the structured request log stays redacted on success and authorization
//     failure paths;
//   - wrapped dependency causes stay out of public error envelopes.
//
// GET /v1/projects/{project_id}/previews accepts a single opaque path
// parameter and no request body or query parameters. Real syntactic validation
// happens at the tenant-scoped store/service boundary, so invalid-input
// contract coverage is driven by a typed reader rejection rather than a request
// body decoder.

const listProjectPreviewsContractSecret = "yk_live_supersecret_project_previews_get_DEADBEEF0123456789"

func listProjectPreviewsHandlerForWithLogger(
	id auth.Identity, authErr error, previews PreviewCreator, logger *slog.Logger,
) http.Handler {
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

func TestListProjectPreviewsPropagatesInboundRequestID(t *testing.T) {
	t.Parallel()

	handler := listProjectPreviewsHandlerFor(
		previewPrincipal("usr_dev", "org_acme", policy.RoleDeveloper),
		nil,
		fakePreviewCreator{},
	)
	req := httptest.NewRequest(http.MethodGet, "/v1/projects/proj_web/previews", nil)
	req.Header.Set("Authorization", "Bearer a-valid-token")
	req.Header.Set("X-Request-Id", "req-preview-list-42")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListProjectPreviews(t, rec)
	if env.RequestID != "req-preview-list-42" {
		t.Errorf("request_id = %q, want inbound request id", env.RequestID)
	}
	if rec.Header().Get("X-Request-Id") != "req-preview-list-42" {
		t.Errorf("X-Request-Id header = %q, want inbound request id", rec.Header().Get("X-Request-Id"))
	}
}

func TestListProjectPreviewsInvalidInputEnvelope(t *testing.T) {
	t.Parallel()

	handler := listProjectPreviewsHandlerFor(
		previewPrincipal("usr_dev", "org_acme", policy.RoleDeveloper),
		nil,
		fakePreviewCreator{listErr: apierr.InvalidInput(apierr.FieldViolation{
			Field:  "project_id",
			Reason: "must be a valid project id",
		})},
	)
	rec := getProjectPreviews(handler, "not-a-project-id", "a-valid-token")
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
	if strings.Contains(rec.Body.String(), "not-a-project-id") {
		t.Errorf("invalid-input envelope echoed the submitted project id: %s", rec.Body.String())
	}
}

func TestListProjectPreviewsServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps the global os.Stdout/os.Stderr.

	const (
		orgID     = "org_acme"
		projectID = "proj_widgets"
	)
	created := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	previews := fakePreviewCreator{
		previews: []store.PreviewEnvironment{
			seedPreviewWire(
				"penv_pr_42", orgID, projectID,
				"env_pr_42", "env_prod", "PR 42",
				"refs/pull/42/head", store.PreviewEnvironmentStatusReady,
				1, created, created,
			),
		},
	}
	handler := listProjectPreviewsHandlerForWithLogger(
		previewPrincipal("usr_owner", orgID, policy.RoleOwner), nil, previews, logger,
	)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		rec = getProjectPreviews(handler, projectID, listProjectPreviewsContractSecret)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing; response data must go through the ResponseWriter", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing; response data must go through the ResponseWriter", stderr)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeListProjectPreviews(t, rec)
	if len(env.Data.Previews) != 1 {
		t.Fatalf("previews = %+v, want exactly the seeded entry", env.Data.Previews)
	}
	if env.Data.Previews[0].ID != "penv_pr_42" {
		t.Errorf("previews[0].id = %q, want penv_pr_42; data must be carried by the response body", env.Data.Previews[0].ID)
	}
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

func TestListProjectPreviewsRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "proj_widgets"
	)
	created := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	allowed := previewPrincipal("usr_ada", orgID, policy.RoleDeveloper)
	denied := previewPrincipal("usr_revoked", orgID, policy.RoleOwner)
	denied.Principal.Disabled = true

	successReader := fakePreviewCreator{
		previews: []store.PreviewEnvironment{
			seedPreviewWire(
				"penv_pr_42", orgID, projectID,
				"env_pr_42", "env_prod", "PR 42",
				"refs/pull/42/head", store.PreviewEnvironmentStatusReady,
				1, created, created,
			),
		},
	}
	denyReader := fakePreviewCreator{listErr: stderrors.New("reader must not be called")}

	tests := []struct {
		name       string
		identity   auth.Identity
		reader     PreviewCreator
		wantStatus int
	}{
		{
			name:       "success path",
			identity:   allowed,
			reader:     successReader,
			wantStatus: http.StatusOK,
		},
		{
			name:       "authorization failure path",
			identity:   denied,
			reader:     denyReader,
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			handler := listProjectPreviewsHandlerForWithLogger(tc.identity, nil, tc.reader, logger)

			rec := getProjectPreviews(handler, projectID, listProjectPreviewsContractSecret)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), listProjectPreviewsContractSecret) {
				t.Errorf("request log leaked the bearer credential: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), listProjectPreviewsContractSecret) {
				t.Errorf("response body echoed the bearer credential: %s", rec.Body.String())
			}
		})
	}
}

func TestListProjectPreviewsErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const (
		orgID     = "org_acme"
		projectID = "proj_widgets"
		cause     = "connection refused dialing 10.0.0.5:5432"
	)
	handler := listProjectPreviewsHandlerFor(
		previewPrincipal("usr_owner", orgID, policy.RoleOwner),
		nil,
		fakePreviewCreator{listErr: apierr.StoreUnavailable(stderrors.New(cause))},
	)

	rec := getProjectPreviews(handler, projectID, listProjectPreviewsContractSecret)
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
