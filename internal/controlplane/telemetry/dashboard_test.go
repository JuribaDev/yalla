package telemetry

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOperationalDashboardExportUsesLowCardinalityDimensions(t *testing.T) {
	t.Parallel()

	dashboard := OperationalDashboardExport()
	if dashboard.SchemaVersion != DashboardExportSchemaVersion {
		t.Fatalf("schema_version = %q, want %q", dashboard.SchemaVersion, DashboardExportSchemaVersion)
	}
	if dashboard.Source.Endpoint != "/metrics" || dashboard.Source.Envelope != "yalla.output.v1" || dashboard.Source.DataRoot != "data" {
		t.Fatalf("source = %+v, want /metrics yalla.output.v1 data", dashboard.Source)
	}
	if dashboard.RefreshSeconds <= 0 {
		t.Fatalf("refresh_seconds = %d, want positive", dashboard.RefreshSeconds)
	}
	if len(dashboard.Panels) < 8 {
		t.Fatalf("panels len = %d, want the full operational dashboard", len(dashboard.Panels))
	}

	for _, panel := range dashboard.Panels {
		if panel.ID == "" || panel.Source == "" || panel.Metric == "" {
			t.Fatalf("panel has missing stable identity fields: %+v", panel)
		}
		for _, field := range panel.GroupBy {
			if isHighCardinalityDashboardField(field) {
				t.Fatalf("panel %s groups by high-cardinality field %q: %+v", panel.ID, field, panel.GroupBy)
			}
		}
		if len(panel.JoinHints) == 0 {
			t.Fatalf("panel %s has no correlation join hints", panel.ID)
		}
	}

	encoded, err := json.Marshal(dashboard)
	if err != nil {
		t.Fatalf("marshal dashboard: %v", err)
	}
	body := string(encoded)
	for _, secretNeedle := range []string{"token", "cookie", "api_key", "password", "secret-query-value", "correcthorsebatterystaple"} {
		if strings.Contains(strings.ToLower(body), secretNeedle) {
			t.Fatalf("dashboard export contains secret-shaped needle %q: %s", secretNeedle, body)
		}
	}
}

func TestOperationalDashboardExportDocumentsIncidentFlows(t *testing.T) {
	t.Parallel()

	dashboard := OperationalDashboardExport()
	want := map[string]bool{
		"api-error-spike":             false,
		"provisioning-stall":          false,
		"secret-redaction-regression": false,
	}
	for _, flow := range dashboard.IncidentFlows {
		if _, ok := want[flow.ID]; ok {
			want[flow.ID] = true
		}
		if len(flow.StartPanels) == 0 || len(flow.JoinHints) == 0 || len(flow.Steps) == 0 {
			t.Fatalf("incident flow is incomplete: %+v", flow)
		}
		for _, hint := range flow.JoinHints {
			if !dashboardJoinHintAllowed(dashboard.JoinHints, hint) {
				t.Fatalf("incident flow %s uses undeclared join hint %q", flow.ID, hint)
			}
		}
	}
	for id, found := range want {
		if !found {
			t.Fatalf("missing incident flow %s: %+v", id, dashboard.IncidentFlows)
		}
	}
}

func isHighCardinalityDashboardField(field string) bool {
	switch field {
	case "request_id", "correlation_id", "organization_id", "principal_id", "resource_id", "project_id", "environment_id", "service_id", "job_id":
		return true
	default:
		return false
	}
}

func dashboardJoinHintAllowed(allowed []string, hint string) bool {
	for _, candidate := range allowed {
		if candidate == hint {
			return true
		}
	}
	return false
}
