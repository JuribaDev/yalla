package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/runtime"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

func TestDashboardExportEndpointReturnsEnvelope(t *testing.T) {
	t.Parallel()

	handler := NewHandler(
		runtime.BuildInfo{Version: "test"}, nil, nil, nil,
		fakeAuthenticator{}, policy.NewEngine(), fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil,
	)

	req := httptest.NewRequest(http.MethodGet, "/dashboards/control-plane.json", nil)
	req.Header.Set("X-Request-Id", "req-dashboard-export")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var env struct {
		SchemaVersion string                    `json:"schema_version"`
		OK            bool                      `json:"ok"`
		RequestID     string                    `json:"request_id"`
		Data          telemetry.DashboardExport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode dashboard envelope: %v", err)
	}
	if env.SchemaVersion != "yalla.output.v1" || !env.OK || env.RequestID != "req-dashboard-export" {
		t.Fatalf("envelope = %+v, want yalla.output.v1 ok with request id", env)
	}
	if env.Data.SchemaVersion != telemetry.DashboardExportSchemaVersion {
		t.Fatalf("dashboard schema_version = %q, want %q", env.Data.SchemaVersion, telemetry.DashboardExportSchemaVersion)
	}
	if env.Data.Source.Endpoint != "/metrics" || len(env.Data.Panels) == 0 {
		t.Fatalf("dashboard data = %+v, want /metrics source and panels", env.Data)
	}
	for _, panel := range env.Data.Panels {
		for _, group := range panel.GroupBy {
			if dashboardEndpointHighCardinalityGroup(group) {
				t.Fatalf("panel %s groups by high-cardinality hint %q", panel.ID, group)
			}
		}
	}
	body := strings.ToLower(rec.Body.String())
	for _, secretNeedle := range []string{"api_key", "bearer ", "password", "secret-query-value", "correcthorsebatterystaple"} {
		if strings.Contains(body, secretNeedle) {
			t.Fatalf("dashboard response contains secret-shaped needle %q: %s", secretNeedle, rec.Body.String())
		}
	}
}

func TestDashboardExportRouteIsDocumented(t *testing.T) {
	t.Parallel()

	handler := NewHandler(
		runtime.BuildInfo{Version: "test"}, nil, nil, nil,
		fakeAuthenticator{}, policy.NewEngine(), fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil,
	)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode openapi document: %v", err)
	}
	if _, ok := doc.Paths["/dashboards/control-plane.json"]["get"]; !ok {
		t.Fatalf("openapi document is missing GET /dashboards/control-plane.json: %v", doc.Paths["/dashboards/control-plane.json"])
	}
}

func dashboardEndpointHighCardinalityGroup(field string) bool {
	switch field {
	case "request_id", "correlation_id", "organization_id", "principal_id", "resource_id", "project_id", "environment_id", "service_id", "job_id":
		return true
	default:
		return false
	}
}
