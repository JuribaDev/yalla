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

type fakeAdminMetricDefinitionManager struct {
	def   store.MetricDefinition
	err   error
	calls []string
	got   AdminMetricDefinitionUpsertInput
}

func (f *fakeAdminMetricDefinitionManager) UpsertMetricDefinition(_ context.Context, key string, in AdminMetricDefinitionUpsertInput, _ store.AdminMetricDefinitionAuditContext) (store.MetricDefinition, error) {
	f.calls = append(f.calls, "upsert:"+key)
	f.got = in
	if f.err != nil {
		return store.MetricDefinition{}, f.err
	}
	if f.def.ID == "" {
		f.def = adminMetricDefinitionFixture(key)
	}
	return f.def, nil
}

func (f *fakeAdminMetricDefinitionManager) GetMetricDefinition(_ context.Context, key string) (store.MetricDefinition, error) {
	f.calls = append(f.calls, "get:"+key)
	if f.err != nil {
		return store.MetricDefinition{}, f.err
	}
	if f.def.ID == "" {
		f.def = adminMetricDefinitionFixture(key)
	}
	return f.def, nil
}

func (f *fakeAdminMetricDefinitionManager) DisableMetricDefinition(_ context.Context, key string, _ store.AdminMetricDefinitionAuditContext) (store.MetricDefinition, error) {
	f.calls = append(f.calls, "disable:"+key)
	if f.err != nil {
		return store.MetricDefinition{}, f.err
	}
	if f.def.ID == "" {
		f.def = adminMetricDefinitionFixture(key)
	}
	f.def.Enabled = false
	return f.def, nil
}

func adminMetricDefinitionHandlerFor(authn Authenticator, manager AdminMetricDefinitionManager) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, manager)
}

func TestAdminMetricDefinitionsUpsertAndGet(t *testing.T) {
	t.Parallel()

	manager := &fakeAdminMetricDefinitionManager{}
	h := adminMetricDefinitionHandlerFor(adminMeteringSourceAuth(t, policy.RoleSupport), manager)
	req := adminMetricDefinitionRequest(http.MethodPut, "/v1/admin/metering/definitions/http_rps_peak_1m", `{"unit":"request_per_second","source":"traefik","aggregation_function":"max","aggregation_window_seconds":60,"billing_grade":true,"retention_days":400,"enforcement_link":"http_rps_peak_1m","enabled":true}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(manager.calls) != 1 || manager.calls[0] != "upsert:http_rps_peak_1m" {
		t.Fatalf("calls = %#v", manager.calls)
	}
	if manager.got.AggregationFunction != store.MetricAggregationMax || manager.got.AggregationWindowSeconds != 60 || !manager.got.BillingGrade {
		t.Fatalf("manager input = %+v", manager.got)
	}
	env := decodeAdminMetricDefinitionEnvelope(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.Data.Key != "http_rps_peak_1m" || env.Data.AggregationFunction != "max" {
		t.Fatalf("envelope = %+v", env)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminMetricDefinitionRequest(http.MethodGet, "/v1/admin/metering/definitions/http_rps_peak_1m", ``))
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

func TestAdminMetricDefinitionsDisable(t *testing.T) {
	t.Parallel()

	h := adminMetricDefinitionHandlerFor(adminMeteringSourceAuth(t, policy.RoleSupport), &fakeAdminMetricDefinitionManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, adminMetricDefinitionRequest(http.MethodDelete, "/v1/admin/metering/definitions/http_rps_peak_1m", ``))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	env := decodeAdminMetricDefinitionEnvelope(t, rec)
	if env.Data.Enabled {
		t.Fatalf("disabled response still enabled: %+v", env.Data)
	}
}

func TestAdminMetricDefinitionsRequireAuthenticationAndSupport(t *testing.T) {
	t.Parallel()

	h := adminMetricDefinitionHandlerFor(fakeAuthenticator{}, &fakeAdminMetricDefinitionManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/admin/metering/definitions/http_rps_peak_1m", strings.NewReader(`{"unit":"request_per_second","source":"traefik","aggregation_function":"max","enabled":true}`)))
	assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)

	h = adminMetricDefinitionHandlerFor(adminMeteringSourceAuth(t, policy.RoleAdmin), &fakeAdminMetricDefinitionManager{})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminMetricDefinitionRequest(http.MethodPut, "/v1/admin/metering/definitions/http_rps_peak_1m", `{"unit":"request_per_second","source":"traefik","aggregation_function":"max","enabled":true}`))
	assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)
}

func TestAdminMetricDefinitionsRejectInvalidAndPropagateFailures(t *testing.T) {
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
		{"invalid", http.MethodPut, "/v1/admin/metering/definitions/bad-key", `{"unit":"","source":"traefik","aggregation_function":"max","enabled":true}`, apierr.InvalidInput(apierr.FieldViolation{Field: "unit", Reason: "must be valid"}), http.StatusBadRequest, yerr.CodeValidation},
		{"not-found", http.MethodGet, "/v1/admin/metering/definitions/missing", ``, apierr.NotFound("metric_definition", "missing"), http.StatusNotFound, yerr.CodeNotFound},
		{"unit-change-conflict", http.MethodPut, "/v1/admin/metering/definitions/http_requests", `{"unit":"byte","source":"traefik","aggregation_function":"sum","billing_grade":true,"enabled":true}`, apierr.Conflict("billing-grade metric unit changes require a new version"), http.StatusConflict, yerr.CodeConflict},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			h := adminMetricDefinitionHandlerFor(adminMeteringSourceAuth(t, policy.RoleSupport), &fakeAdminMetricDefinitionManager{err: row.err})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, adminMetricDefinitionRequest(row.method, row.path, row.body))
			assertErrorCode(t, rec, row.status, row.code)
		})
	}
}

func adminMetricDefinitionRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer yk_test_admin_metric_definition")
	req.Header.Set("X-Request-Id", "req_admin_metric_definition")
	req.Header.Set("X-Yalla-Reason", "configure metering")
	return req
}

func adminMetricDefinitionFixture(key string) store.MetricDefinition {
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	return store.MetricDefinition{
		ID:                       "mdef_test",
		Key:                      key,
		Version:                  1,
		Unit:                     "request_per_second",
		Source:                   "traefik",
		AggregationFunction:      store.MetricAggregationMax,
		AggregationWindowSeconds: 60,
		BillingGrade:             true,
		RetentionDays:            400,
		EnforcementLink:          key,
		Enabled:                  true,
		Revision:                 1,
		PublishedAt:              now,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
}

func decodeAdminMetricDefinitionEnvelope(t *testing.T, rec *httptest.ResponseRecorder) struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Data          struct {
		Key                 string `json:"key"`
		Version             int    `json:"version"`
		Unit                string `json:"unit"`
		Source              string `json:"source"`
		AggregationFunction string `json:"aggregation_function"`
		BillingGrade        bool   `json:"billing_grade"`
		Enabled             bool   `json:"enabled"`
	} `json:"data"`
} {
	t.Helper()
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			Key                 string `json:"key"`
			Version             int    `json:"version"`
			Unit                string `json:"unit"`
			Source              string `json:"source"`
			AggregationFunction string `json:"aggregation_function"`
			BillingGrade        bool   `json:"billing_grade"`
			Enabled             bool   `json:"enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	return env
}
