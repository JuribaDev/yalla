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
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// Public-API contract coverage for POST /v1/admin/break-glass (BE-0296)
// and DELETE /v1/admin/break-glass/{session_id} (BE-0298).
//
// break_glass_test.go covers the primary behavior for both the organization
// path and admin query-scoped route. This file pins the remaining public
// contract details for the admin route: response data only through the
// ResponseWriter, request-id propagation on success and error envelopes,
// OpenAPI registration, and log/error redaction.

const adminBreakGlassContractSecret = "yka_admin_break_glass_contract_secret_DEADBEEF0123456789"

func adminBreakGlassHandlerForWithLogger(authn Authenticator, ctl BreakGlassController, logger *slog.Logger) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, ctl, logger, nil)
}

func TestPostAdminBreakGlassServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps global os.Stdout/os.Stderr.

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	now := time.Date(2026, 5, 19, 13, 0, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	session := fakeBreakGlassSession(targetOrg, "bgs_admin_contract", now, 10*time.Minute)
	session.RequestID = "req_admin_break_glass_contract_streams"
	session.CorrelationID = "corr_admin_break_glass_contract_streams"
	handler := adminBreakGlassHandlerForWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: orgPrincipal("usr_support", homeOrg, policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, fakeBreakGlassController{startResult: session}, logger)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass?organization_id="+targetOrg, strings.NewReader(`{"organization_id":"`+targetOrg+`","reason":"INC-42 support escalation","ttl_seconds":600}`))
		req.Header.Set("Authorization", "Bearer "+adminBreakGlassContractSecret)
		req.Header.Set("X-Request-Id", "req_admin_break_glass_contract_streams")
		req.Header.Set("X-Correlation-Id", "corr_admin_break_glass_contract_streams")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	})

	if stdout != "" {
		t.Errorf("HTTP server wrote %q to stdout, want nothing; response data must go through the ResponseWriter", stdout)
	}
	if stderr != "" {
		t.Errorf("HTTP server wrote %q to stderr, want nothing; response data must go through the ResponseWriter", stderr)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body %s", rec.Code, rec.Body.String())
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		RequestID     string `json:"request_id"`
		Data          struct {
			Session struct {
				ID             string `json:"id"`
				OrganizationID string `json:"organization_id"`
				ElevatedAccess bool   `json:"elevated_access"`
				RequestID      string `json:"request_id"`
				CorrelationID  string `json:"correlation_id"`
			} `json:"session"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode success envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK {
		t.Fatalf("success envelope = %+v, want yalla.output.v1 ok=true", env)
	}
	if env.RequestID != "req_admin_break_glass_contract_streams" {
		t.Errorf("envelope request_id = %q, want req_admin_break_glass_contract_streams", env.RequestID)
	}
	if env.Data.Session.ID != "bgs_admin_contract" || env.Data.Session.OrganizationID != targetOrg || !env.Data.Session.ElevatedAccess {
		t.Errorf("session projection = %+v, want target break-glass session with elevated_access=true", env.Data.Session)
	}
	if env.Data.Session.RequestID != "req_admin_break_glass_contract_streams" || env.Data.Session.CorrelationID != "corr_admin_break_glass_contract_streams" {
		t.Errorf("session correlation = request_id %q correlation_id %q", env.Data.Session.RequestID, env.Data.Session.CorrelationID)
	}
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
	if strings.Contains(logBuf.String(), adminBreakGlassContractSecret) {
		t.Errorf("request log leaked bearer credential: %s", logBuf.String())
	}
}

func TestPostAdminBreakGlassErrorEnvelopesPreserveRequestID(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, fakeBreakGlassController{})

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass?organization_id="+targetOrg, strings.NewReader(`{"organization_id":"`+targetOrg+`","reason":"missing ttl"}`))
	req.Header.Set("Authorization", "Bearer "+adminBreakGlassContractSecret)
	req.Header.Set("X-Request-Id", "req_admin_break_glass_contract_invalid")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	invalidEnv := decodeError(t, rec, "E_VALIDATION")
	if invalidEnv.RequestID != "req_admin_break_glass_contract_invalid" {
		t.Errorf("validation request_id = %q, want req_admin_break_glass_contract_invalid", invalidEnv.RequestID)
	}

	handler = breakGlassHandlerFor(auth.Identity{}, auth.ErrNoCredentials, fakeBreakGlassController{})
	req = httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass?organization_id="+targetOrg, strings.NewReader(`{"organization_id":"`+targetOrg+`","reason":"auth","ttl_seconds":60}`))
	req.Header.Set("X-Request-Id", "req_admin_break_glass_contract_auth")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("auth status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	authEnv := decodeError(t, rec, "E_AUTHENTICATION_REQUIRED")
	if authEnv.RequestID != "req_admin_break_glass_contract_auth" {
		t.Errorf("auth request_id = %q, want req_admin_break_glass_contract_auth", authEnv.RequestID)
	}
}

func TestPostAdminBreakGlassContractErrorPaths(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	targetOrg := string(domain.MustNewID(domain.KindOrganization))

	t.Run("unauthorized", func(t *testing.T) {
		t.Parallel()
		var got store.StartBreakGlassInput
		handler := breakGlassHandlerFor(ownerIdentity(targetOrg, "usr_owner"), nil, fakeBreakGlassController{startGot: &got})
		rec := postAdminBreakGlass(handler, targetOrg, `{"organization_id":"`+targetOrg+`","reason":"owner denied","ttl_seconds":60}`, adminBreakGlassContractSecret)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
		}
		decodeError(t, rec, "E_FORBIDDEN")
		if got.OrganizationID != "" {
			t.Fatalf("StartSession called on authorization failure: %+v", got)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		t.Parallel()
		handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, fakeBreakGlassController{
			startErr: apierr.NotFound("organization", targetOrg),
		})
		rec := postAdminBreakGlass(handler, targetOrg, `{"organization_id":"`+targetOrg+`","reason":"missing org","ttl_seconds":60}`, adminBreakGlassContractSecret)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
		}
		env := decodeError(t, rec, "E_NOT_FOUND")
		if env.SchemaVersion != "yalla.error.v1" || env.OK {
			t.Fatalf("error envelope = %+v, want yalla.error.v1 ok=false", env)
		}
	})
}

func TestPostAdminBreakGlassAuthorizationFailureLogRedactsBearerToken(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctl := fakeBreakGlassController{startErr: stderrors.New("controller must not be called")}
	handler := adminBreakGlassHandlerForWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: orgPrincipal("usr_owner", orgID, policy.RoleOwner),
		Method:    auth.MethodAPIKey,
	}}, ctl, logger)

	req := httptest.NewRequest(http.MethodPost, "/v1/admin/break-glass?organization_id="+orgID, strings.NewReader(`{"organization_id":"`+orgID+`","reason":"owner denied","ttl_seconds":60}`))
	req.Header.Set("Authorization", "Bearer "+adminBreakGlassContractSecret)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if logBuf.Len() == 0 {
		t.Fatal("structured request log is empty, want one record for the denied request")
	}
	if strings.Contains(logBuf.String(), adminBreakGlassContractSecret) {
		t.Errorf("request log leaked bearer credential: %s", logBuf.String())
	}
	if strings.Contains(rec.Body.String(), adminBreakGlassContractSecret) {
		t.Errorf("response body echoed bearer credential: %s", rec.Body.String())
	}
}

func TestPostAdminBreakGlassOpenAPIContract(t *testing.T) {
	t.Parallel()

	handler := breakGlassHandlerFor(auth.Identity{}, nil, fakeBreakGlassController{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string         `json:"operationId"`
			Extensions  map[string]any `json:"-"`
		} `json:"paths"`
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode openapi document: %v; body %s", err, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi paths: %v; body %s", err, rec.Body.String())
	}
	post, ok := doc.Paths["/v1/admin/break-glass"]["post"]
	if !ok {
		t.Fatalf("openapi document does not describe POST /v1/admin/break-glass")
	}
	if post.OperationID != "startAdminBreakGlassSession" {
		t.Errorf("operationId = %q, want startAdminBreakGlassSession", post.OperationID)
	}
	paths, ok := raw["paths"].(map[string]any)
	if !ok {
		t.Fatalf("openapi paths missing or wrong type: %T", raw["paths"])
	}
	pathItem, ok := paths["/v1/admin/break-glass"].(map[string]any)
	if !ok {
		t.Fatalf("openapi path item missing or wrong type: %T", paths["/v1/admin/break-glass"])
	}
	op, ok := pathItem["post"].(map[string]any)
	if !ok {
		t.Fatalf("openapi post operation missing or wrong type: %T", pathItem["post"])
	}
	if got := op["x-required-action"]; got != string(policy.ActionAdminBreakGlass) {
		t.Errorf("x-required-action = %v, want %s", got, policy.ActionAdminBreakGlass)
	}
	if got := op["security"]; got == nil {
		t.Errorf("security requirement missing from POST /v1/admin/break-glass operation")
	}
}

func TestDeleteAdminBreakGlassResponseAndErrorEnvelopesPreserveRequestID(t *testing.T) {
	t.Parallel()

	homeOrg := string(domain.MustNewID(domain.KindOrganization))
	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	const sessionID = "bgs_admin_delete_contract"
	now := time.Date(2026, 5, 19, 14, 30, 0, 0, time.UTC)
	revoked := fakeBreakGlassSession(targetOrg, sessionID, now, time.Hour)
	revoked.RequestID = "req_admin_break_glass_delete_contract"
	revoked.CorrelationID = "corr_admin_break_glass_delete_contract"
	revoked.Status = store.BreakGlassSessionStatusRevoked
	revokedAt := now.Add(2 * time.Minute)
	revoked.RevokedAt = &revokedAt
	revoked.RevokedByID = "usr_support"
	revoked.RevokedByKind = "usr"
	handler := breakGlassHandlerFor(supportIdentity(homeOrg, "usr_support"), nil, fakeBreakGlassController{
		revokeResult: revoked,
	})

	req := httptest.NewRequest(http.MethodDelete, "/v1/admin/break-glass/"+sessionID+"?organization_id="+targetOrg, nil)
	req.Header.Set("Authorization", "Bearer "+adminBreakGlassContractSecret)
	req.Header.Set("X-Request-Id", "req_admin_break_glass_delete_contract")
	req.Header.Set("X-Correlation-Id", "corr_admin_break_glass_delete_contract")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		RequestID     string `json:"request_id"`
		Data          struct {
			Session struct {
				ID             string `json:"id"`
				OrganizationID string `json:"organization_id"`
				Status         string `json:"status"`
				ElevatedAccess bool   `json:"elevated_access"`
				RequestID      string `json:"request_id"`
				CorrelationID  string `json:"correlation_id"`
			} `json:"session"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode success envelope: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID != "req_admin_break_glass_delete_contract" {
		t.Fatalf("success envelope = %+v, want yalla.output.v1 ok=true with request id", env)
	}
	if env.Data.Session.ID != sessionID || env.Data.Session.OrganizationID != targetOrg || env.Data.Session.Status != "revoked" || !env.Data.Session.ElevatedAccess {
		t.Fatalf("session projection = %+v, want revoked admin break-glass session", env.Data.Session)
	}
	if env.Data.Session.RequestID != "req_admin_break_glass_delete_contract" || env.Data.Session.CorrelationID != "corr_admin_break_glass_delete_contract" {
		t.Errorf("session correlation = request_id %q correlation_id %q", env.Data.Session.RequestID, env.Data.Session.CorrelationID)
	}

	req = httptest.NewRequest(http.MethodDelete, "/v1/admin/break-glass/"+sessionID+"?organization_id=not-an-org-id", nil)
	req.Header.Set("Authorization", "Bearer "+adminBreakGlassContractSecret)
	req.Header.Set("X-Request-Id", "req_admin_break_glass_delete_invalid")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	invalidEnv := decodeError(t, rec, "E_VALIDATION")
	if invalidEnv.RequestID != "req_admin_break_glass_delete_invalid" {
		t.Errorf("validation request_id = %q, want req_admin_break_glass_delete_invalid", invalidEnv.RequestID)
	}
	if strings.Contains(rec.Body.String(), "not-an-org-id") {
		t.Fatalf("validation body leaked invalid organization id: %s", rec.Body.String())
	}
}

func TestDeleteAdminBreakGlassOpenAPIContract(t *testing.T) {
	t.Parallel()

	handler := breakGlassHandlerFor(auth.Identity{}, nil, fakeBreakGlassController{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("openapi.json status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode openapi document: %v; body %s", err, rec.Body.String())
	}
	paths, ok := raw["paths"].(map[string]any)
	if !ok {
		t.Fatalf("openapi paths missing or wrong type: %T", raw["paths"])
	}
	pathItem, ok := paths["/v1/admin/break-glass/{session_id}"].(map[string]any)
	if !ok {
		t.Fatalf("openapi path item missing or wrong type: %T", paths["/v1/admin/break-glass/{session_id}"])
	}
	op, ok := pathItem["delete"].(map[string]any)
	if !ok {
		t.Fatalf("openapi delete operation missing or wrong type: %T", pathItem["delete"])
	}
	if got := op["operationId"]; got != "revokeAdminBreakGlassSession" {
		t.Errorf("operationId = %v, want revokeAdminBreakGlassSession", got)
	}
	if got := op["x-required-action"]; got != string(policy.ActionAdminBreakGlass) {
		t.Errorf("x-required-action = %v, want %s", got, policy.ActionAdminBreakGlass)
	}
	if got := op["security"]; got == nil {
		t.Errorf("security requirement missing from DELETE /v1/admin/break-glass/{session_id} operation")
	}
}
