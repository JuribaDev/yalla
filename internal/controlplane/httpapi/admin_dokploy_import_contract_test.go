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
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Public-API contract coverage for POST /v1/admin/dokploy/import (BE-0290).
//
// admin_dokploy_import_test.go proves the main route behavior: 202 success
// envelope, validation, unauthenticated, unauthorized, not-found, request
// correlation forwarding, request-log redaction on the happy path, and OpenAPI
// registration. This file closes the remaining public-contract criteria:
//
//   - response data is written only through http.ResponseWriter, never process
//     stdout/stderr;
//   - error envelopes preserve the correlated request_id on validation and
//     authentication failures;
//   - request logs stay redacted on authorization failures as well as success;
//   - wrapped dependency causes never leak into client-facing error envelopes.

const importAdminDokployContractSecret = "yk_live_admin_import_contract_secret_DEADBEEF0123456789"

func TestImportAdminDokployServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps global os.Stdout/os.Stderr.

	orgID := string(domain.MustNewID(domain.KindOrganization))
	now := time.Date(2026, 5, 19, 9, 30, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	importer := &fakeAdminDokployImporter{job: store.ProvisioningJob{
		ID:             string(domain.MustNewID(domain.KindJob)),
		OrganizationID: orgID,
		JobType:        "import_dokploy_resource",
		IdempotencyKey: "contract-import-once",
		Status:         store.JobStatusQueued,
		MaxAttempts:    20,
		Payload: map[string]string{
			"organization_id":         orgID,
			"yalla_organization_id":   orgID,
			"dokploy_organization_id": "dkp-org-contract",
		},
		RequestID:     "req_admin_import_contract_streams",
		CorrelationID: "corr_admin_import_contract_streams",
		NextRunAt:     now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}}
	handler := adminImportHandlerForWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, importer, logger)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import?organization_id="+orgID, strings.NewReader(`{"dokploy_organization_id":"dkp-org-contract","idempotency_key":"contract-import-once"}`))
		req.Header.Set("Authorization", "Bearer "+importAdminDokployContractSecret)
		req.Header.Set("X-Request-Id", "req_admin_import_contract_streams")
		req.Header.Set("X-Correlation-Id", "corr_admin_import_contract_streams")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
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
	if !strings.Contains(rec.Body.String(), `"schema_version":"yalla.output.v1"`) {
		t.Fatalf("response body is not a success envelope: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"request_id":"req_admin_import_contract_streams"`) {
		t.Fatalf("response body did not carry request_id: %s", rec.Body.String())
	}
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

func TestImportAdminDokployErrorEnvelopesPreserveRequestID(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	handler := adminImportHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, &fakeAdminDokployImporter{})

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import?organization_id="+orgID, strings.NewReader(`{"dokploy_organization_id":"","idempotency_key":"contract-import-once"}`))
	req.Header.Set("Authorization", "Bearer "+importAdminDokployContractSecret)
	req.Header.Set("X-Request-Id", "req_admin_import_contract_invalid")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	invalidEnv := decodeError(t, rec, "E_VALIDATION")
	if invalidEnv.RequestID != "req_admin_import_contract_invalid" {
		t.Errorf("validation request_id = %q, want req_admin_import_contract_invalid", invalidEnv.RequestID)
	}

	handler = adminImportHandlerFor(fakeAuthenticator{err: auth.ErrNoCredentials}, &fakeAdminDokployImporter{})
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import?organization_id="+orgID, strings.NewReader(`{"dokploy_organization_id":"dkp-org-contract","idempotency_key":"contract-import-once"}`))
	req.Header.Set("X-Request-Id", "req_admin_import_contract_auth")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("auth status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	authEnv := decodeError(t, rec, "E_AUTHENTICATION_REQUIRED")
	if authEnv.RequestID != "req_admin_import_contract_auth" {
		t.Errorf("auth request_id = %q, want req_admin_import_contract_auth", authEnv.RequestID)
	}
}

func TestImportAdminDokployAuthorizationFailureLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	importer := &fakeAdminDokployImporter{err: stderrors.New("importer must not be called")}
	handler := adminImportHandlerForWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleOwner),
		Method:    auth.MethodAPIKey,
	}}, importer, logger)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import?organization_id="+orgID, strings.NewReader(`{"dokploy_organization_id":"dkp-org-contract","idempotency_key":"contract-import-once"}`))
	req.Header.Set("Authorization", "Bearer "+importAdminDokployContractSecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if importer.calls != 0 {
		t.Fatalf("importer calls = %d, want 0 when policy denies", importer.calls)
	}
	if logBuf.Len() == 0 {
		t.Fatal("structured request log is empty, want one record for the denied request")
	}
	if strings.Contains(logBuf.String(), importAdminDokployContractSecret) {
		t.Errorf("request log leaked bearer credential: %s", logBuf.String())
	}
	if strings.Contains(rec.Body.String(), importAdminDokployContractSecret) {
		t.Errorf("response body echoed bearer credential: %s", rec.Body.String())
	}
}

func TestImportAdminDokployErrorEnvelopeDoesNotLeakDependencyCause(t *testing.T) {
	t.Parallel()

	const cause = "dial tcp 10.0.0.9:5432: connection refused"
	orgID := string(domain.MustNewID(domain.KindOrganization))
	importer := &fakeAdminDokployImporter{err: apierr.StoreUnavailable(stderrors.New(cause))}
	handler := adminImportHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, importer)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/dokploy/import?organization_id="+orgID, strings.NewReader(`{"dokploy_organization_id":"dkp-org-contract","idempotency_key":"contract-import-once"}`))
	req.Header.Set("Authorization", "Bearer "+importAdminDokployContractSecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec, "E_DB_UNAVAILABLE")
	if env.Error.Message == "" {
		t.Error("error.message is empty, want stable generic message")
	}
	for _, needle := range []string{cause, "10.0.0.9", "5432", "connection refused"} {
		if strings.Contains(rec.Body.String(), needle) {
			t.Errorf("error envelope leaked dependency cause fragment %q: %s", needle, rec.Body.String())
		}
	}
}
