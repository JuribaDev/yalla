package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

func TestMetricsEndpointReturnsEnvelopeSnapshot(t *testing.T) {
	t.Parallel()

	metrics := telemetry.NewHTTPMetrics()
	dokployMetrics := telemetry.NewDokployDependencyMetrics()
	dokployMetrics.RecordDokployDependencyCall(context.Background(), telemetry.DokployDependencyEvent{
		Method:     http.MethodGet,
		Path:       "/api/projects/proj_metrics_probe",
		StatusCode: http.StatusOK,
	})
	handler := NewHandler(
		runtime.BuildInfo{Version: "test"}, nil, nil, nil,
		fakeAuthenticator{}, policy.NewEngine(), fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, metrics, dokployMetrics,
	)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodGet, "/missing", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("X-Request-Id", "req-metrics-endpoint")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var env struct {
		SchemaVersion string `json:"schema_version"`
		OK            bool   `json:"ok"`
		RequestID     string `json:"request_id"`
		Data          struct {
			TotalRequests       int64                                      `json:"total_requests"`
			Requests            []telemetry.HTTPRequestMetric              `json:"requests"`
			DokployDependencies telemetry.DokployDependencyMetricsSnapshot `json:"dokploy_dependencies"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode metrics envelope: %v", err)
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID != "req-metrics-endpoint" {
		t.Fatalf("envelope = %+v, want yalla.output.v1 ok with request id", env)
	}
	if env.Data.TotalRequests < 2 {
		t.Fatalf("total_requests = %d, want at least healthz and missing requests", env.Data.TotalRequests)
	}
	if len(env.Data.Requests) == 0 {
		t.Fatal("metrics response has no request series")
	}
	if env.Data.DokployDependencies.TotalCalls != 1 {
		t.Fatalf("dokploy total_calls = %d, want 1", env.Data.DokployDependencies.TotalCalls)
	}
	if len(env.Data.DokployDependencies.Series) != 1 || env.Data.DokployDependencies.Series[0].Endpoint != "/api/projects/{id}" {
		t.Fatalf("dokploy dependency series = %+v, want normalized project endpoint", env.Data.DokployDependencies.Series)
	}
	for _, metric := range env.Data.Requests {
		if metric.Route == "unmatched" {
			return
		}
	}
	t.Fatalf("metrics response did not include unmatched route series: %+v", env.Data.Requests)
}
