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

type fakeAdminUsageScheduleManager struct {
	schedule store.UsageAggregationSchedule
	err      error
	calls    []string
	got      AdminUsageAggregationScheduleUpsertInput
}

func (f *fakeAdminUsageScheduleManager) UpsertUsageAggregationSchedule(_ context.Context, key string, in AdminUsageAggregationScheduleUpsertInput, _ store.AdminUsageAggregationScheduleAuditContext) (store.UsageAggregationSchedule, error) {
	f.calls = append(f.calls, "upsert:"+key)
	f.got = in
	if f.err != nil {
		return store.UsageAggregationSchedule{}, f.err
	}
	if f.schedule.ID == "" {
		f.schedule = adminUsageScheduleFixture(key)
	}
	return f.schedule, nil
}

func (f *fakeAdminUsageScheduleManager) GetUsageAggregationSchedule(_ context.Context, key string) (store.UsageAggregationSchedule, error) {
	f.calls = append(f.calls, "get:"+key)
	if f.err != nil {
		return store.UsageAggregationSchedule{}, f.err
	}
	if f.schedule.ID == "" {
		f.schedule = adminUsageScheduleFixture(key)
	}
	return f.schedule, nil
}

func (f *fakeAdminUsageScheduleManager) DisableUsageAggregationSchedule(_ context.Context, key string, _ store.AdminUsageAggregationScheduleAuditContext) (store.UsageAggregationSchedule, error) {
	f.calls = append(f.calls, "disable:"+key)
	if f.err != nil {
		return store.UsageAggregationSchedule{}, f.err
	}
	if f.schedule.ID == "" {
		f.schedule = adminUsageScheduleFixture(key)
	}
	f.schedule.Enabled = false
	return f.schedule, nil
}

func adminUsageScheduleHandlerFor(authn Authenticator, manager AdminUsageAggregationScheduleManager) http.Handler {
	return NewHandler(runtime.BuildInfo{Version: "1.0.0"}, nil, nil, nil, authn, policy.NewEngine(),
		fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{},
		fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{},
		fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{},
		fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{},
		fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, manager)
}

func TestAdminUsageAggregationSchedulesUpsertGetAndDisable(t *testing.T) {
	t.Parallel()

	manager := &fakeAdminUsageScheduleManager{}
	h := adminUsageScheduleHandlerFor(adminMeteringSourceAuth(t, policy.RoleMeteringAdmin), manager)
	req := adminUsageScheduleRequest(http.MethodPut, "/v1/admin/metering/schedules/http_requests_hourly", `{"source":"traefik","metric_key":"http_requests_total","aggregation_interval_seconds":3600,"replay_lookback_seconds":86400,"close_delay_seconds":7200,"late_event_mode":"adjust","enabled":true}`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if len(manager.calls) != 1 || manager.calls[0] != "upsert:http_requests_hourly" {
		t.Fatalf("calls = %#v", manager.calls)
	}
	if manager.got.AggregationIntervalSeconds != 3600 || manager.got.ReplayLookbackSeconds != 86400 || manager.got.LateEventMode != store.LateEventModeAdjust {
		t.Fatalf("manager input = %+v", manager.got)
	}
	env := decodeAdminUsageScheduleEnvelope(t, rec)
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.Data.ScheduleKey != "http_requests_hourly" || env.Data.LateEventMode != "adjust" {
		t.Fatalf("envelope = %+v", env)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminUsageScheduleRequest(http.MethodGet, "/v1/admin/metering/schedules/http_requests_hourly", ``))
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminUsageScheduleRequest(http.MethodDelete, "/v1/admin/metering/schedules/http_requests_hourly", ``))
	if rec.Code != http.StatusOK {
		t.Fatalf("disable status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if decodeAdminUsageScheduleEnvelope(t, rec).Data.Enabled {
		t.Fatal("disabled schedule response remained enabled")
	}
}

func TestAdminUsageAggregationSchedulesRequireAuthenticationAndMeteringRole(t *testing.T) {
	t.Parallel()

	h := adminUsageScheduleHandlerFor(fakeAuthenticator{}, &fakeAdminUsageScheduleManager{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/admin/metering/schedules/http_requests_hourly", strings.NewReader(`{"source":"traefik","metric_key":"http_requests_total","aggregation_interval_seconds":3600,"late_event_mode":"adjust","enabled":true}`)))
	assertErrorCode(t, rec, http.StatusUnauthorized, yerr.CodeAuthenticationRequired)

	h = adminUsageScheduleHandlerFor(adminMeteringSourceAuth(t, policy.RoleAdmin), &fakeAdminUsageScheduleManager{})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, adminUsageScheduleRequest(http.MethodPut, "/v1/admin/metering/schedules/http_requests_hourly", `{"source":"traefik","metric_key":"http_requests_total","aggregation_interval_seconds":3600,"late_event_mode":"adjust","enabled":true}`))
	assertErrorCode(t, rec, http.StatusForbidden, yerr.CodeForbidden)
}

func TestAdminUsageAggregationSchedulesRejectInvalidAndPropagateFailures(t *testing.T) {
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
		{"invalid", http.MethodPut, "/v1/admin/metering/schedules/bad-key", `{"source":"","metric_key":"http_requests_total","aggregation_interval_seconds":0,"late_event_mode":"adjust","enabled":true}`, apierr.InvalidInput(apierr.FieldViolation{Field: "source", Reason: "must be valid"}), http.StatusBadRequest, yerr.CodeValidation},
		{"not-found", http.MethodGet, "/v1/admin/metering/schedules/missing", ``, apierr.NotFound("usage_aggregation_schedule", "missing"), http.StatusNotFound, yerr.CodeNotFound},
		{"conflict", http.MethodPut, "/v1/admin/metering/schedules/http_requests_hourly", `{"source":"traefik","metric_key":"http_requests_total","aggregation_interval_seconds":3600,"late_event_mode":"adjust","enabled":true}`, apierr.Conflict("aggregation schedule key is already used by another source metric"), http.StatusConflict, yerr.CodeConflict},
	}
	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			h := adminUsageScheduleHandlerFor(adminMeteringSourceAuth(t, policy.RoleMeteringAdmin), &fakeAdminUsageScheduleManager{err: row.err})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, adminUsageScheduleRequest(row.method, row.path, row.body))
			assertErrorCode(t, rec, row.status, row.code)
		})
	}
}

func adminUsageScheduleRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer yk_test_admin_usage_schedule")
	req.Header.Set("X-Request-Id", "req_admin_usage_schedule")
	req.Header.Set("X-Yalla-Reason", "configure usage aggregation")
	return req
}

func adminUsageScheduleFixture(key string) store.UsageAggregationSchedule {
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	return store.UsageAggregationSchedule{
		ID:                         "usched_test",
		ScheduleKey:                key,
		Version:                    1,
		Source:                     "traefik",
		MetricKey:                  "http_requests_total",
		AggregationIntervalSeconds: 3600,
		ReplayLookbackSeconds:      86400,
		CloseDelaySeconds:          7200,
		LateEventMode:              store.LateEventModeAdjust,
		Enabled:                    true,
		Revision:                   1,
		PublishedAt:                now,
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}
}

func decodeAdminUsageScheduleEnvelope(t *testing.T, rec *httptest.ResponseRecorder) struct {
	SchemaVersion string `json:"schema_version"`
	OK            bool   `json:"ok"`
	Data          struct {
		ScheduleKey                string `json:"schedule_key"`
		Version                    int    `json:"version"`
		Source                     string `json:"source"`
		MetricKey                  string `json:"metric_key"`
		AggregationIntervalSeconds int    `json:"aggregation_interval_seconds"`
		ReplayLookbackSeconds      int    `json:"replay_lookback_seconds"`
		CloseDelaySeconds          int    `json:"close_delay_seconds"`
		LateEventMode              string `json:"late_event_mode"`
		Enabled                    bool   `json:"enabled"`
	} `json:"data"`
} {
	t.Helper()
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		Data          struct {
			ScheduleKey                string `json:"schedule_key"`
			Version                    int    `json:"version"`
			Source                     string `json:"source"`
			MetricKey                  string `json:"metric_key"`
			AggregationIntervalSeconds int    `json:"aggregation_interval_seconds"`
			ReplayLookbackSeconds      int    `json:"replay_lookback_seconds"`
			CloseDelaySeconds          int    `json:"close_delay_seconds"`
			LateEventMode              string `json:"late_event_mode"`
			Enabled                    bool   `json:"enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v; body %s", err, rec.Body.String())
	}
	return env
}
