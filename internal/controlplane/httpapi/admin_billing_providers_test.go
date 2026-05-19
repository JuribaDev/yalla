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
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

type fakeAdminBillingProviderManager struct {
	provider   store.BillingProviderConfig
	testResult AdminBillingProviderTestResult
	err        error
	calls      []string
	got        AdminBillingProviderUpsertInput
}

func (f *fakeAdminBillingProviderManager) UpsertBillingProvider(_ context.Context, key string, in AdminBillingProviderUpsertInput, _ store.AdminBillingProviderAuditContext) (store.BillingProviderConfig, error) {
	f.calls = append(f.calls, "upsert:"+key)
	f.got = in
	if f.err != nil {
		return store.BillingProviderConfig{}, f.err
	}
	if f.provider.ID == "" {
		f.provider = adminBillingProviderFixture(key)
	}
	return f.provider, nil
}

func (f *fakeAdminBillingProviderManager) GetBillingProvider(_ context.Context, key string) (store.BillingProviderConfig, error) {
	f.calls = append(f.calls, "get:"+key)
	if f.err != nil {
		return store.BillingProviderConfig{}, f.err
	}
	if f.provider.ID == "" {
		f.provider = adminBillingProviderFixture(key)
	}
	return f.provider, nil
}

func (f *fakeAdminBillingProviderManager) TestBillingProvider(_ context.Context, key string, in AdminBillingProviderTestInput, _ store.AdminBillingProviderAuditContext) (AdminBillingProviderTestResult, error) {
	f.calls = append(f.calls, "test:"+key)
	if f.err != nil {
		return AdminBillingProviderTestResult{}, f.err
	}
	if f.testResult.Status == "" {
		f.testResult = AdminBillingProviderTestResult{
			ProviderKey:      key,
			Status:           "ok",
			CheckedAt:        time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC),
			FakeCounterCount: in.FakeCounterCount,
			Message:          "manual export mapping accepted",
		}
	}
	return f.testResult, nil
}

func adminBillingProviderHandlerFor(authn Authenticator, manager AdminBillingProviderManager) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, manager)
}

func TestAdminBillingProvidersUpsertGetAndTestRedactsSecret(t *testing.T) {
	t.Parallel()

	manager := &fakeAdminBillingProviderManager{provider: adminBillingProviderFixture("manual-main")}
	h := adminBillingProviderHandlerFor(adminMeteringSourceAuth(t, policy.RoleBillingAdmin), manager)
	req := adminBillingProviderRequest(http.MethodPut, "/v1/admin/billing/providers/manual-main", `{"provider_type":"manual","display_name":"Manual exports","secret_reference":"vault/billing/manual","credential_value":"manual-secret-token","export_cadence_seconds":86400,"retry_max_attempts":5,"retry_initial_backoff_seconds":60,"dry_run":true,"metadata":{"owner":"finance"},"enabled":true}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(manager.calls) != 1 || manager.calls[0] != "upsert:manual-main" {
		t.Fatalf("calls = %#v", manager.calls)
	}
	if manager.got.CredentialValue == nil || *manager.got.CredentialValue != "manual-secret-token" {
		t.Fatalf("manager credential was not passed as write-only input: %+v", manager.got)
	}
	if strings.Contains(rec.Body.String(), "manual-secret-token") {
		t.Fatalf("response leaked submitted credential: %s", rec.Body.String())
	}
	env := decodeAdminBillingProviderEnvelope(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.Data.ProviderKey != "manual-main" || !env.Data.CredentialSet || env.Data.CredentialValue != "" {
		t.Fatalf("envelope = %+v", env)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminBillingProviderRequest(http.MethodGet, "/v1/admin/billing/providers/manual-main", ``))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminBillingProviderRequest(http.MethodPost, "/v1/admin/billing/providers/manual-main/test", `{"fake_counter_count":3}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("test status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var testEnv struct {
		Data struct {
			ProviderKey      string `json:"provider_key"`
			Status           string `json:"status"`
			FakeCounterCount int    `json:"fake_counter_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &testEnv); err != nil {
		t.Fatalf("decode test response: %v", err)
	}
	if testEnv.Data.ProviderKey != "manual-main" || testEnv.Data.Status != "ok" || testEnv.Data.FakeCounterCount != 3 {
		t.Fatalf("test result = %+v", testEnv.Data)
	}
}

func TestAdminBillingProvidersRequireAuthenticationAndBillingRole(t *testing.T) {
	t.Parallel()

	h := adminBillingProviderHandlerFor(fakeAuthenticator{}, &fakeAdminBillingProviderManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/admin/billing/providers/manual-main", strings.NewReader(`{"provider_type":"manual","enabled":true}`)))
	assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)

	h = adminBillingProviderHandlerFor(adminMeteringSourceAuth(t, policy.RoleMeteringAdmin), &fakeAdminBillingProviderManager{})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminBillingProviderRequest(http.MethodPut, "/v1/admin/billing/providers/manual-main", `{"provider_type":"manual","enabled":true}`))
	assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)
}

func TestAdminBillingProvidersRejectInvalidAndPropagateFailures(t *testing.T) {
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
		{"invalid", http.MethodPut, "/v1/admin/billing/providers/bad-key", `{"provider_type":"bogus","enabled":true}`, apierr.InvalidInput(apierr.FieldViolation{Field: "provider_type", Reason: "must be valid"}), http.StatusBadRequest, yerr.CodeValidation},
		{"not-found", http.MethodGet, "/v1/admin/billing/providers/missing", ``, apierr.NotFound("billing_provider", "missing"), http.StatusNotFound, yerr.CodeNotFound},
		{"conflict", http.MethodPut, "/v1/admin/billing/providers/manual-main", `{"provider_type":"manual","enabled":true}`, apierr.Conflict("billing provider conflict"), http.StatusConflict, yerr.CodeConflict},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			h := adminBillingProviderHandlerFor(adminMeteringSourceAuth(t, policy.RoleBillingAdmin), &fakeAdminBillingProviderManager{err: row.err})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, adminBillingProviderRequest(row.method, row.path, row.body))
			assertErrorCode(t, rec, row.status, row.code)
		})
	}
}

func adminBillingProviderRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer yk_test_admin_billing")
	req.Header.Set("X-Request-Id", "req_admin_billing")
	return req
}

func adminBillingProviderFixture(key string) store.BillingProviderConfig {
	return store.BillingProviderConfig{
		ID:                         "bprov_test",
		ProviderKey:                key,
		ProviderType:               store.BillingProviderTypeManual,
		DisplayName:                "Manual exports",
		SecretReference:            "vault/billing/manual",
		CredentialSet:              true,
		ExportCadenceSeconds:       86400,
		RetryMaxAttempts:           5,
		RetryInitialBackoffSeconds: 60,
		DryRun:                     true,
		Metadata:                   map[string]string{"owner": "finance"},
		Enabled:                    true,
		Revision:                   2,
	}
}

func decodeAdminBillingProviderEnvelope(t *testing.T, rec *httptest.ResponseRecorder) struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Data          struct {
		ProviderKey                string            `json:"provider_key"`
		ProviderType               string            `json:"provider_type"`
		CredentialSet              bool              `json:"credential_set"`
		CredentialValue            string            `json:"credential_value,omitempty"`
		ExportCadenceSeconds       int               `json:"export_cadence_seconds"`
		RetryMaxAttempts           int               `json:"retry_max_attempts"`
		RetryInitialBackoffSeconds int               `json:"retry_initial_backoff_seconds"`
		Metadata                   map[string]string `json:"metadata"`
	} `json:"data"`
} {
	t.Helper()
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			ProviderKey                string            `json:"provider_key"`
			ProviderType               string            `json:"provider_type"`
			CredentialSet              bool              `json:"credential_set"`
			CredentialValue            string            `json:"credential_value,omitempty"`
			ExportCadenceSeconds       int               `json:"export_cadence_seconds"`
			RetryMaxAttempts           int               `json:"retry_max_attempts"`
			RetryInitialBackoffSeconds int               `json:"retry_initial_backoff_seconds"`
			Metadata                   map[string]string `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	return env
}
