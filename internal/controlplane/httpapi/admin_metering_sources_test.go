package httpapi

import (
	"context"
	"encoding/json"
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
	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

type fakeAdminMeteringSourceManager struct {
	source     store.MeteringSource
	testResult AdminMeteringSourceTestResult
	err        error
	calls      []string
	got        AdminMeteringSourceUpsertInput
}

func (f *fakeAdminMeteringSourceManager) UpsertMeteringSource(_ context.Context, key string, in AdminMeteringSourceUpsertInput, _ store.AdminMeteringSourceAuditContext) (store.MeteringSource, error) {
	f.calls = append(f.calls, "upsert:"+key)
	f.got = in
	if f.err != nil {
		return store.MeteringSource{}, f.err
	}
	if f.source.ID == "" {
		f.source = adminMeteringSourceFixture(key)
	}
	return f.source, nil
}

func (f *fakeAdminMeteringSourceManager) TestMeteringSource(_ context.Context, key string, in AdminMeteringSourceTestInput, _ store.AdminMeteringSourceAuditContext) (AdminMeteringSourceTestResult, error) {
	f.calls = append(f.calls, "test:"+key)
	if f.err != nil {
		return AdminMeteringSourceTestResult{}, f.err
	}
	if f.testResult.Status == "" {
		f.testResult = AdminMeteringSourceTestResult{
			SourceKey:     key,
			Status:        "ok",
			CheckedAt:     time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC),
			LatencyMillis: 12,
		}
	}
	return f.testResult, nil
}

func adminMeteringSourceHandlerFor(authn Authenticator, manager AdminMeteringSourceManager) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, manager)
}

func TestAdminMeteringSourcesUpsertRedactsCredential(t *testing.T) {
	t.Parallel()

	manager := &fakeAdminMeteringSourceManager{source: adminMeteringSourceFixture("prometheus-main")}
	h := adminMeteringSourceHandlerFor(adminMeteringSourceAuth(t, policy.RoleMeteringAdmin), manager)
	req := adminMeteringSourceRequest(http.MethodPut, "/v1/admin/metering/sources/prometheus-main", `{"source_type":"prometheus","endpoint_url":"https://metrics.internal.example","auth_scheme":"bearer","auth_reference":"vault/prometheus/main","credential_value":"super-secret-token","scrape_interval_seconds":60,"query_interval_seconds":300,"timeout_seconds":10,"labels":{"cluster":"prod"},"enabled":true}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(manager.calls) != 1 || manager.calls[0] != "upsert:prometheus-main" {
		t.Fatalf("calls = %#v", manager.calls)
	}
	if manager.got.CredentialValue == nil || *manager.got.CredentialValue != "super-secret-token" {
		t.Fatalf("manager credential was not passed as write-only input: %+v", manager.got)
	}
	body := rec.Body.String()
	if strings.Contains(body, "super-secret-token") {
		t.Fatalf("response leaked submitted credential: %s", body)
	}
	env := decodeAdminMeteringSourceEnvelope(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.Data.SourceKey != "prometheus-main" || !env.Data.CredentialSet {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestAdminMeteringSourcesTestConnection(t *testing.T) {
	t.Parallel()

	h := adminMeteringSourceHandlerFor(adminMeteringSourceAuth(t, policy.RoleMeteringAdmin), &fakeAdminMeteringSourceManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminMeteringSourceRequest(http.MethodPost, "/v1/admin/metering/sources/prometheus-main/test", `{}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			SourceKey     string `json:"source_key"`
			Status        string `json:"status"`
			LatencyMillis int64  `json:"latency_millis"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	if env.Data.SourceKey != "prometheus-main" || env.Data.Status != "ok" || env.Data.LatencyMillis != 12 {
		t.Fatalf("test result = %+v", env.Data)
	}
}

func TestAdminMeteringSourcesRequireAuthenticationAndMeteringRole(t *testing.T) {
	t.Parallel()

	h := adminMeteringSourceHandlerFor(fakeAuthenticator{}, &fakeAdminMeteringSourceManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/admin/metering/sources/prometheus-main", strings.NewReader(`{"source_type":"prometheus","endpoint_url":"https://metrics.example","enabled":true}`)))
	assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)

	h = adminMeteringSourceHandlerFor(adminMeteringSourceAuth(t, policy.RoleAdmin), &fakeAdminMeteringSourceManager{})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminMeteringSourceRequest(http.MethodPut, "/v1/admin/metering/sources/prometheus-main", `{"source_type":"prometheus","endpoint_url":"https://metrics.example","enabled":true}`))
	assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)
}

func TestAdminMeteringSourcesRejectInvalidAndPropagateFailures(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name   string
		method string
		path   string
		body   string
		err    error
		status int
		code   yerr.Code
	}{
		{"invalid", http.MethodPut, "/v1/admin/metering/sources/bad-key", `{"source_type":"prometheus","endpoint_url":"not-url","enabled":true}`, apierr.InvalidInput(apierr.FieldViolation{Field: "endpoint_url", Reason: "must be valid"}), http.StatusBadRequest, yerr.CodeValidation},
		{"not-found", http.MethodPost, "/v1/admin/metering/sources/missing/test", `{}`, apierr.NotFound("metering_source", "missing"), http.StatusNotFound, yerr.CodeNotFound},
		{"conflict", http.MethodPut, "/v1/admin/metering/sources/prometheus-main", `{"source_type":"prometheus","endpoint_url":"https://metrics.example","enabled":true}`, apierr.Conflict("metering source conflict"), http.StatusConflict, yerr.CodeConflict},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			h := adminMeteringSourceHandlerFor(adminMeteringSourceAuth(t, policy.RoleMeteringAdmin), &fakeAdminMeteringSourceManager{err: row.err})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, adminMeteringSourceRequest(row.method, row.path, row.body))
			assertErrorCode(t, rec, row.status, row.code)
		})
	}
}

func adminMeteringSourceAuth(t *testing.T, role policy.Role) fakeAuthenticator {
	t.Helper()
	orgID := string(domain.MustNewID(domain.KindOrganization))
	return fakeAuthenticator{identity: auth.Identity{
		Principal: adminDriftPrincipal(orgID, role),
		Method:    auth.MethodAPIKey,
	}}
}

func adminMeteringSourceRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer yk_test_admin_metering")
	req.Header.Set("X-Request-Id", "req_admin_metering")
	return req
}

func adminMeteringSourceFixture(key string) store.MeteringSource {
	return store.MeteringSource{
		ID:                    "msrc_test",
		SourceKey:             key,
		SourceType:            store.MeteringSourceTypePrometheus,
		EndpointURL:           "https://metrics.internal.example",
		AuthScheme:            "bearer",
		AuthReference:         "vault/prometheus/main",
		CredentialSet:         true,
		ScrapeIntervalSeconds: 60,
		QueryIntervalSeconds:  300,
		TimeoutSeconds:        10,
		Labels:                map[string]string{"cluster": "prod"},
		Enabled:               true,
		Revision:              2,
	}
}

func decodeAdminMeteringSourceEnvelope(t *testing.T, rec *httptest.ResponseRecorder) struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Data          struct {
		ID                    string            `json:"id"`
		SourceKey             string            `json:"source_key"`
		SourceType            string            `json:"source_type"`
		EndpointURL           string            `json:"endpoint_url"`
		AuthScheme            string            `json:"auth_scheme"`
		AuthReference         string            `json:"auth_reference,omitempty"`
		CredentialSet         bool              `json:"credential_set"`
		CredentialValue       string            `json:"credential_value,omitempty"`
		ScrapeIntervalSeconds int               `json:"scrape_interval_seconds"`
		QueryIntervalSeconds  int               `json:"query_interval_seconds"`
		TimeoutSeconds        int               `json:"timeout_seconds"`
		Labels                map[string]string `json:"labels"`
		Enabled               bool              `json:"enabled"`
		Revision              int64             `json:"revision"`
	} `json:"data"`
} {
	t.Helper()
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			ID                    string            `json:"id"`
			SourceKey             string            `json:"source_key"`
			SourceType            string            `json:"source_type"`
			EndpointURL           string            `json:"endpoint_url"`
			AuthScheme            string            `json:"auth_scheme"`
			AuthReference         string            `json:"auth_reference,omitempty"`
			CredentialSet         bool              `json:"credential_set"`
			CredentialValue       string            `json:"credential_value,omitempty"`
			ScrapeIntervalSeconds int               `json:"scrape_interval_seconds"`
			QueryIntervalSeconds  int               `json:"query_interval_seconds"`
			TimeoutSeconds        int               `json:"timeout_seconds"`
			Labels                map[string]string `json:"labels"`
			Enabled               bool              `json:"enabled"`
			Revision              int64             `json:"revision"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	if env.Data.CredentialValue != "" && env.Data.CredentialValue != output.Sentinel {
		t.Fatalf("credential_value must be omitted or redacted, got %q", env.Data.CredentialValue)
	}
	return env
}
