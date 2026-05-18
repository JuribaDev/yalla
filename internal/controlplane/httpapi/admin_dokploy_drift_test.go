package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/JuribaDev/yalla/internal/output"
)

type fakeDriftFindingReader struct {
	findings []store.DriftFinding
	err      error

	gotOrgID string
	gotQuery store.DriftFindingListQuery
	calls    int
}

func (f *fakeDriftFindingReader) ListDriftFindings(ctx context.Context, organizationID string, query store.DriftFindingListQuery) ([]store.DriftFinding, error) {
	f.calls++
	f.gotOrgID = organizationID
	f.gotQuery = query
	if f.err != nil {
		return nil, f.err
	}
	return f.findings, nil
}

func adminDriftHandlerFor(authn Authenticator, reader DriftFindingReader) http.Handler {
	return adminDriftHandlerForWithLogger(authn, reader, nil)
}

func adminDriftHandlerForWithLogger(authn Authenticator, reader DriftFindingReader, logger *slog.Logger) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil, reader)
}

func adminDriftPrincipal(orgID string, role policy.Role) policy.Principal {
	p := orgPrincipal("usr_admin_drift", orgID, role)
	return p
}

func TestListAdminDokployDriftReturnsFilteredFindings(t *testing.T) {
	t.Parallel()

	detected := time.Date(2026, 5, 18, 10, 20, 30, 0, time.UTC)
	reader := &fakeDriftFindingReader{findings: []store.DriftFinding{{
		ID:                "drft_001",
		OrganizationID:    "org_target",
		Status:            store.DriftFindingStatusOpen,
		Kind:              store.DriftKindDangerous,
		Reason:            store.DriftReasonServiceMissing,
		Level:             store.DriftLevelService,
		ProjectID:         "proj_alpha",
		EnvironmentID:     "env_alpha",
		ServiceID:         "svc_alpha",
		DokployResourceID: "app_123",
		RequestID:         "req_reconcile",
		CorrelationID:     "corr_reconcile",
		DetectedAt:        detected,
		CreatedAt:         detected,
		UpdatedAt:         detected,
	}}}
	h := adminDriftHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/dokploy/drift?organization_id=org_target&project_id=proj_alpha&environment_id=env_alpha&service_id=svc_alpha&status=open&limit=25", nil)
	req.Header.Set("Authorization", "Bearer yk_test_admin_drift")
	req.Header.Set("X-Request-Id", "req_admin_drift")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if reader.gotOrgID != "org_target" {
		t.Fatalf("reader org = %q, want org_target", reader.gotOrgID)
	}
	if reader.gotQuery.ProjectID != "proj_alpha" || reader.gotQuery.EnvironmentID != "env_alpha" || reader.gotQuery.ServiceID != "svc_alpha" {
		t.Fatalf("reader query = %+v, want scoped filters", reader.gotQuery)
	}
	if reader.gotQuery.Status != store.DriftFindingStatusOpen || reader.gotQuery.Limit != 25 {
		t.Fatalf("reader query = %+v, want status=open limit=25", reader.gotQuery)
	}

	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		RequestID     string `json:"request_id"`
		Data          struct {
			Findings []struct {
				ID             string `json:"id"`
				OrganizationID string `json:"organization_id"`
				Status         string `json:"status"`
				Kind           string `json:"kind"`
				Reason         string `json:"reason"`
				Level          string `json:"level"`
				ServiceID      string `json:"service_id"`
			} `json:"findings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID != "req_admin_drift" {
		t.Fatalf("bad envelope: %+v", env)
	}
	if len(env.Data.Findings) != 1 || env.Data.Findings[0].ID != "drft_001" || env.Data.Findings[0].ServiceID != "svc_alpha" {
		t.Fatalf("findings = %+v, want seeded finding", env.Data.Findings)
	}
}

func TestListAdminDokployDriftContractRedactsRequestLogs(t *testing.T) {
	t.Parallel()

	const queryToken = "dokploy-query-token-secret"
	const queryAPIKey = "dokploy-query-api-key-secret"
	const bearerSecret = "yk_live_admin_drift_secret"

	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := &fakeDriftFindingReader{}
	h := adminDriftHandlerForWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader, logger)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/dokploy/drift?organization_id=org_target&token="+queryToken+"&api_key="+queryAPIKey, nil)
	req.Header.Set("Authorization", "Bearer "+bearerSecret)
	req.Header.Set("X-Request-Id", "req_admin_drift_redaction")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{queryToken, queryAPIKey, bearerSecret} {
		if strings.Contains(body, secret) {
			t.Fatalf("response body leaked secret %q: %s", secret, body)
		}
	}
	rawLogs := logs.String()
	for _, secret := range []string{queryToken, queryAPIKey, bearerSecret} {
		if strings.Contains(rawLogs, secret) {
			t.Fatalf("request logs leaked secret %q: %s", secret, rawLogs)
		}
	}
	if !strings.Contains(rawLogs, output.Sentinel) {
		t.Fatalf("request logs = %s, want at least one redaction sentinel", rawLogs)
	}
}

func TestListAdminDokployDriftRejectsInvalidQuery(t *testing.T) {
	t.Parallel()

	reader := &fakeDriftFindingReader{}
	h := adminDriftHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/dokploy/drift?environment_id=env_alpha", nil)
	req.Header.Set("Authorization", "Bearer yk_test_admin_drift")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_INVALID_INPUT")
	if reader.calls != 0 {
		t.Fatalf("reader calls = %d, want 0 on validation failure", reader.calls)
	}
}

func TestListAdminDokployDriftAuthFailures(t *testing.T) {
	t.Parallel()

	reader := &fakeDriftFindingReader{}
	h := adminDriftHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_acme", policy.RoleOwner),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/dokploy/drift?organization_id=org_acme", nil)
	req.Header.Set("Authorization", "Bearer yk_owner_not_support")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")

	h = adminDriftHandlerFor(fakeAuthenticator{err: auth.ErrNoCredentials}, reader)
	req = httptest.NewRequest(http.MethodGet, "/v1/admin/dokploy/drift?organization_id=org_acme", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_AUTHENTICATION_REQUIRED")
	if reader.calls != 0 {
		t.Fatalf("reader calls = %d, want 0 when auth fails", reader.calls)
	}
}

func TestListAdminDokployDriftPropagatesNotFound(t *testing.T) {
	t.Parallel()

	reader := &fakeDriftFindingReader{err: apierr.NotFound("organization", "org_missing")}
	h := adminDriftHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/dokploy/drift?organization_id=org_missing", nil)
	req.Header.Set("Authorization", "Bearer yk_test_admin_drift")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

func TestListAdminDokployDriftOpenAPIRegistration(t *testing.T) {
	t.Parallel()

	h := adminDriftHandlerFor(fakeAuthenticator{}, &fakeDriftFindingReader{})
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID    string           `json:"operationId"`
			RequiredAction string           `json:"x-required-action"`
			Security       []map[string]any `json:"security"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	op, ok := doc.Paths["/v1/admin/dokploy/drift"]["get"]
	if !ok {
		t.Fatalf("GET /v1/admin/dokploy/drift is missing from OpenAPI")
	}
	if op.OperationID != "listAdminDokployDrift" {
		t.Errorf("operationId = %q, want listAdminDokployDrift", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionAdminReconcile) {
		t.Errorf("required action = %q, want %q", op.RequiredAction, policy.ActionAdminReconcile)
	}
	if len(op.Security) == 0 {
		t.Error("security is empty, want ApiKeyAuth requirement")
	}
}
