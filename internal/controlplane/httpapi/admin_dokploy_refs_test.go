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
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/output"
)

const adminDokployRefsContractSecret = "yk_live_admin_refs_contract_secret_DEADBEEF0123456789"

type fakeDokployRefReader struct {
	refs []store.DokployRef
	err  error

	gotOrgID string
	calls    int
}

func (f *fakeDokployRefReader) ListDokployRefs(ctx context.Context, organizationID string) ([]store.DokployRef, error) {
	f.calls++
	f.gotOrgID = organizationID
	if f.err != nil {
		return nil, f.err
	}
	return f.refs, nil
}

func adminDokployRefsHandlerFor(authn Authenticator, reader *fakeDokployRefReader) http.Handler {
	return adminDokployRefsHandlerForWithLogger(authn, reader, nil)
}

func adminDokployRefsHandlerForWithLogger(authn Authenticator, reader *fakeDokployRefReader, logger *slog.Logger) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, logger, nil, reader)
}

func TestListAdminDokployRefsReturnsOrganizationRefs(t *testing.T) {
	t.Parallel()

	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	created := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	reader := &fakeDokployRefReader{refs: []store.DokployRef{{
		ID:              42,
		OrganizationID:  targetOrg,
		YallaKind:       store.YallaKindProject,
		YallaID:         "proj_alpha",
		DokployResource: store.DokployResourceProject,
		DokployID:       "dkp-project-42",
		CreatedAt:       created,
		UpdatedAt:       created,
	}}}
	h := adminDokployRefsHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+targetOrg+"/dokploy-refs", nil)
	req.Header.Set("Authorization", "Bearer yk_test_admin_refs")
	req.Header.Set("X-Request-Id", "req_admin_refs")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if reader.calls != 1 || reader.gotOrgID != targetOrg {
		t.Fatalf("reader calls/org = %d/%q, want 1/%q", reader.calls, reader.gotOrgID, targetOrg)
	}

	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		RequestID     string `json:"request_id"`
		Data          struct {
			OrganizationID string `json:"organization_id"`
			Refs           []struct {
				ID              int64  `json:"id"`
				OrganizationID  string `json:"organization_id"`
				YallaKind       string `json:"yalla_kind"`
				YallaID         string `json:"yalla_id"`
				DokployResource string `json:"dokploy_resource"`
				DokployID       string `json:"dokploy_id"`
			} `json:"refs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID != "req_admin_refs" {
		t.Fatalf("bad envelope: %+v", env)
	}
	if env.Data.OrganizationID != targetOrg {
		t.Fatalf("organization_id = %q, want %q", env.Data.OrganizationID, targetOrg)
	}
	if len(env.Data.Refs) != 1 || env.Data.Refs[0].ID != 42 || env.Data.Refs[0].DokployID != "dkp-project-42" {
		t.Fatalf("refs = %+v, want seeded ref", env.Data.Refs)
	}
}

func TestListAdminDokployRefsServerWritesResponseDataOnlyToResponseWriter(t *testing.T) {
	// Not parallel: captureProcessOutput swaps global os.Stdout/os.Stderr.

	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	created := time.Date(2026, 5, 19, 9, 10, 0, 0, time.UTC)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reader := &fakeDokployRefReader{refs: []store.DokployRef{{
		ID:              7,
		OrganizationID:  targetOrg,
		YallaKind:       store.YallaKindProject,
		YallaID:         "proj_contract",
		DokployResource: store.DokployResourceProject,
		DokployID:       "dkp-project-contract",
		CreatedAt:       created,
		UpdatedAt:       created,
	}}}
	h := adminDokployRefsHandlerForWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader, logger)

	var rec *httptest.ResponseRecorder
	stdout, stderr := captureProcessOutput(t, func() {
		req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+targetOrg+"/dokploy-refs", nil)
		req.Header.Set("Authorization", "Bearer "+adminDokployRefsContractSecret)
		req.Header.Set("X-Request-Id", "req_admin_refs_contract_streams")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
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
	if !strings.Contains(rec.Body.String(), `"schema_version":"yalla.output.v1"`) {
		t.Fatalf("response body is not a success envelope: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"request_id":"req_admin_refs_contract_streams"`) {
		t.Fatalf("response body did not carry request_id: %s", rec.Body.String())
	}
	if logBuf.Len() == 0 {
		t.Error("structured request log is empty, want one record for the served request")
	}
}

func TestListAdminDokployRefsRejectsInvalidOrganizationID(t *testing.T) {
	t.Parallel()

	reader := &fakeDokployRefReader{}
	h := adminDokployRefsHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/not-an-org/dokploy-refs", nil)
	req.Header.Set("Authorization", "Bearer yk_test_admin_refs")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_VALIDATION")
	if reader.calls != 0 {
		t.Fatalf("reader calls = %d, want 0 on validation failure", reader.calls)
	}
}

func TestListAdminDokployRefsErrorEnvelopesPreserveRequestID(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	reader := &fakeDokployRefReader{}
	h := adminDokployRefsHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/not-an-org/dokploy-refs", nil)
	req.Header.Set("Authorization", "Bearer "+adminDokployRefsContractSecret)
	req.Header.Set("X-Request-Id", "req_admin_refs_contract_invalid")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	invalidEnv := decodeError(t, rec, "E_VALIDATION")
	if invalidEnv.RequestID != "req_admin_refs_contract_invalid" {
		t.Errorf("validation request_id = %q, want req_admin_refs_contract_invalid", invalidEnv.RequestID)
	}

	h = adminDokployRefsHandlerFor(fakeAuthenticator{err: auth.ErrNoCredentials}, reader)
	req = httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+orgID+"/dokploy-refs", nil)
	req.Header.Set("X-Request-Id", "req_admin_refs_contract_auth")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("auth status = %d, want 401; body %s", rec.Code, rec.Body.String())
	}
	authEnv := decodeError(t, rec, "E_AUTHENTICATION_REQUIRED")
	if authEnv.RequestID != "req_admin_refs_contract_auth" {
		t.Errorf("auth request_id = %q, want req_admin_refs_contract_auth", authEnv.RequestID)
	}
}

func TestListAdminDokployRefsAuthFailures(t *testing.T) {
	t.Parallel()

	orgID := string(domain.MustNewID(domain.KindOrganization))
	reader := &fakeDokployRefReader{}
	h := adminDokployRefsHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, policy.RoleOwner),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+orgID+"/dokploy-refs", nil)
	req.Header.Set("Authorization", "Bearer yk_owner_not_support")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")

	h = adminDokployRefsHandlerFor(fakeAuthenticator{err: auth.ErrNoCredentials}, reader)
	req = httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+orgID+"/dokploy-refs", nil)
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

func TestListAdminDokployRefsPropagatesNotFound(t *testing.T) {
	t.Parallel()

	missingOrg := string(domain.MustNewID(domain.KindOrganization))
	reader := &fakeDokployRefReader{err: apierr.NotFound("organization", missingOrg)}
	h := adminDokployRefsHandlerFor(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+missingOrg+"/dokploy-refs", nil)
	req.Header.Set("Authorization", "Bearer yk_test_admin_refs")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_NOT_FOUND")
}

func TestListAdminDokployRefsContractRedactsRequestLogs(t *testing.T) {
	t.Parallel()

	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	const queryToken = "dokploy-refs-query-token-secret"
	const queryAPIKey = "dokploy-refs-query-api-key-secret"

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reader := &fakeDokployRefReader{}
	h := adminDokployRefsHandlerForWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal("org_support", policy.RoleSupport),
		Method:    auth.MethodAPIKey,
	}}, reader, logger)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+targetOrg+"/dokploy-refs?token="+queryToken+"&api_key="+queryAPIKey, nil)
	req.Header.Set("Authorization", "Bearer "+adminDokployRefsContractSecret)
	req.Header.Set("X-Request-Id", "req_admin_refs_contract_redaction")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	rawLogs := logBuf.String()
	if rawLogs == "" {
		t.Fatal("structured request log is empty, want one record for the served request")
	}
	for _, secret := range []string{queryToken, queryAPIKey, adminDokployRefsContractSecret} {
		if strings.Contains(body, secret) {
			t.Fatalf("response body leaked secret %q: %s", secret, body)
		}
		if strings.Contains(rawLogs, secret) {
			t.Fatalf("request logs leaked secret %q: %s", secret, rawLogs)
		}
	}
	if !strings.Contains(rawLogs, output.Sentinel) {
		t.Fatalf("request logs = %s, want at least one redaction sentinel", rawLogs)
	}
}

func TestListAdminDokployRefsAuthorizationFailureRedactsBearerToken(t *testing.T) {
	t.Parallel()

	targetOrg := string(domain.MustNewID(domain.KindOrganization))
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reader := &fakeDokployRefReader{}
	h := adminDokployRefsHandlerForWithLogger(fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(targetOrg, policy.RoleOwner),
		Method:    auth.MethodAPIKey,
	}}, reader, logger)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/organizations/"+targetOrg+"/dokploy-refs", nil)
	req.Header.Set("Authorization", "Bearer "+adminDokployRefsContractSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	decodeError(t, rec, "E_FORBIDDEN")
	if reader.calls != 0 {
		t.Fatalf("reader calls = %d, want 0 when policy denies", reader.calls)
	}
	if logBuf.Len() == 0 {
		t.Fatal("structured request log is empty, want one record for the denied request")
	}
	if strings.Contains(logBuf.String(), adminDokployRefsContractSecret) {
		t.Errorf("request log leaked bearer credential: %s", logBuf.String())
	}
	if strings.Contains(rec.Body.String(), adminDokployRefsContractSecret) {
		t.Errorf("response body echoed bearer credential: %s", rec.Body.String())
	}
}

func TestListAdminDokployRefsOpenAPIRegistration(t *testing.T) {
	t.Parallel()

	h := adminDokployRefsHandlerFor(fakeAuthenticator{}, &fakeDokployRefReader{})
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
	op, ok := doc.Paths["/v1/admin/organizations/{org_id}/dokploy-refs"]["get"]
	if !ok {
		t.Fatalf("GET /v1/admin/organizations/{org_id}/dokploy-refs is missing from OpenAPI")
	}
	if op.OperationID != "listAdminOrganizationDokployRefs" {
		t.Errorf("operationId = %q, want listAdminOrganizationDokployRefs", op.OperationID)
	}
	if op.RequiredAction != string(policy.ActionAdminRead) {
		t.Errorf("required action = %q, want %q", op.RequiredAction, policy.ActionAdminRead)
	}
	if len(op.Security) == 0 {
		t.Error("security is empty, want ApiKeyAuth requirement")
	}
}
