package httpapi

import (
	"bytes"
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
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

// Public-API contract coverage for GET /v1/jobs/{job_id} (BE-0275).
//
// jobs_test.go already proves the thin handler and resolver behavior for this
// endpoint: success envelope, yalla.output.v1 / yalla.error.v1 schema versions,
// request_id propagation, invalid-input rejection, unauthenticated rejection,
// unauthorized scoped-grant rejection, not-found propagation, and OpenAPI route
// registration. This file closes the remaining public-contract criteria:
//
//   - response data is written only through http.ResponseWriter, never stdout or
//     stderr;
//   - the request log stays credential-free on success, authn failure, and
//     authz failure paths;
//   - wrapped dependency causes stay server-side and never reach error
//     envelopes;
//   - OpenAPI metadata includes the authenticated security requirement and the
//     documented {job_id} path parameter.

const getJobContractSecret = "yk_live_supersecret_jobs_get_DEADBEEF0123456789"

func contractJobForGet(now time.Time) store.ProvisioningJob {
	return store.ProvisioningJob{
		ID:             "job_0123456789abcdefghjkmnpqrs",
		OrganizationID: "org_jobs",
		JobType:        "ensure_application_service",
		ProjectID:      "proj_jobs",
		EnvironmentID:  "env_jobs",
		ServiceID:      "svc_jobs",
		DesiredVersion: 7,
		Status:         store.JobStatusQueued,
		MaxAttempts:    20,
		NextRunAt:      now,
		Payload:        map[string]string{"service_id": "svc_jobs"},
		RequestID:      "req_seeded_job",
		CorrelationID:  "corr_seeded_job",
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func getJobContractPrincipal() policy.Principal {
	return policy.Principal{
		ID:             "usr_jobs",
		Kind:           domain.KindUser,
		OrganizationID: "org_jobs",
		Role:           policy.RoleViewer,
	}
}

func TestGetJobServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps global os.Stdout/os.Stderr.
	now := time.Date(2026, 5, 18, 13, 0, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := fakeJobReader{job: contractJobForGet(now)}
	h := newJobsTestHandlerWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: getJobContractPrincipal(),
		Method:    auth.MethodAPIKey,
	}}, reader, logger)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		req := httptest.NewRequest(http.MethodGet, "/v1/jobs/job_0123456789abcdefghjkmnpqrs", nil)
		req.Header.Set("Authorization", "Bearer "+getJobContractSecret)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing", stderr)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "job_0123456789abcdefghjkmnpqrs") {
		t.Fatalf("response body does not carry the job payload: %s", rec.Body.String())
	}
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

func TestGetJobRequestLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 18, 14, 0, 0, 0, time.UTC)
	enabled := getJobContractPrincipal()
	disabled := enabled
	disabled.ID = "usr_jobs_disabled"
	disabled.Disabled = true

	tests := []struct {
		name       string
		authn      Authenticator
		wantStatus int
	}{
		{
			name: "success path",
			authn: fakeAuthenticator{identity: auth.Identity{
				Principal: enabled,
				Method:    auth.MethodAPIKey,
			}},
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid credentials path",
			authn:      fakeAuthenticator{err: auth.ErrInvalidCredentials},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "authorization failure path",
			authn: fakeAuthenticator{identity: auth.Identity{
				Principal: disabled,
				Method:    auth.MethodAPIKey,
			}},
			wantStatus: http.StatusForbidden,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			h := newJobsTestHandlerWithLogger(tc.authn, fakeJobReader{job: contractJobForGet(now)}, logger)
			req := httptest.NewRequest(http.MethodGet, "/v1/jobs/job_0123456789abcdefghjkmnpqrs", nil)
			req.Header.Set("Authorization", "Bearer "+getJobContractSecret)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if logBuf.Len() == 0 {
				t.Fatal("structured request log is empty, want one record for the served request")
			}
			if strings.Contains(logBuf.String(), getJobContractSecret) {
				t.Errorf("request log leaked bearer token: %s", logBuf.String())
			}
			if strings.Contains(rec.Body.String(), getJobContractSecret) {
				t.Errorf("response body leaked bearer token: %s", rec.Body.String())
			}
		})
	}
}

func TestGetJobErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "connection refused dialing postgres://admin:secret@10.0.0.5:5432/yalla"
	h := newJobsTestHandler(fakeAuthenticator{identity: auth.Identity{
		Principal: getJobContractPrincipal(),
		Method:    auth.MethodAPIKey,
	}}, fakeJobReader{err: apierr.StoreUnavailable(stderrors.New(cause))})

	req := httptest.NewRequest(http.MethodGet, "/v1/jobs/job_0123456789abcdefghjkmnpqrs", nil)
	req.Header.Set("Authorization", "Bearer "+getJobContractSecret)
	req.Header.Set("X-Request-Id", "req_jobs_get_store_outage")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, string(yerr.CodeDBUnavailable))
	if env.RequestID != "req_jobs_get_store_outage" {
		t.Errorf("request_id = %q, want req_jobs_get_store_outage", env.RequestID)
	}
	if env.Error.Message == "" {
		t.Error("error.message is empty, want a stable generic message")
	}
	for _, needle := range []string{cause, "10.0.0.5", "admin:secret", getJobContractSecret} {
		if strings.Contains(rec.Body.String(), needle) {
			t.Errorf("error envelope leaked %q: %s", needle, rec.Body.String())
		}
	}
}

func TestGetJobOpenAPIContractMetadata(t *testing.T) {
	t.Parallel()

	h := newJobsTestHandler(fakeAuthenticator{}, fakeJobReader{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string                  `json:"operationId"`
			Security       []map[string]any        `json:"security"`
			RequiredAction string                  `json:"x-required-action"`
			Parameters     []struct{ Name string } `json:"parameters"`
			Responses      map[string]struct{}     `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi.json: %v; body %s", err, rec.Body.String())
	}
	get, ok := doc.Paths["/v1/jobs/{job_id}"]["get"]
	if !ok {
		t.Fatalf("GET /v1/jobs/{job_id} missing from openapi.json: %s", rec.Body.String())
	}
	if get.OperationID != "getJob" {
		t.Errorf("operationId = %q, want getJob", get.OperationID)
	}
	if get.RequiredAction != string(policy.ActionJobRead) {
		t.Errorf("x-required-action = %q, want %q", get.RequiredAction, policy.ActionJobRead)
	}
	if len(get.Security) == 0 {
		t.Fatal("security is empty, want ApiKeyAuth requirement for authenticated route")
	}
	if _, ok := get.Responses["200"]; !ok {
		t.Error("responses[200] missing")
	}
	foundJobID := false
	for _, p := range get.Parameters {
		if p.Name == "job_id" {
			foundJobID = true
			break
		}
	}
	if !foundJobID {
		t.Fatalf("OpenAPI parameters = %+v, want job_id path parameter", get.Parameters)
	}
}
