package telemetry

// DashboardExportSchemaVersion is the stable schema version for the
// operational dashboard JSON exported by the API.
const DashboardExportSchemaVersion = "yalla.dashboard.v1"

// DashboardExport is a deterministic, JSON-serializable dashboard definition
// for operators. It describes how to render the low-cardinality operational
// signals that GET /metrics exposes; tenant, resource, and job identifiers are
// modeled as latest-sample join hints, not dashboard grouping labels.
type DashboardExport struct {
	SchemaVersion  string                 `json:"schema_version"`
	Title          string                 `json:"title"`
	Description    string                 `json:"description"`
	Source         DashboardSource        `json:"source"`
	RefreshSeconds int                    `json:"refresh_seconds"`
	Variables      []DashboardVariable    `json:"variables"`
	JoinHints      []string               `json:"join_hints"`
	Panels         []DashboardPanel       `json:"panels"`
	IncidentFlows  []DashboardIncidentRun `json:"incident_flows"`
}

// DashboardSource identifies the API endpoint that supplies dashboard data.
type DashboardSource struct {
	Endpoint      string `json:"endpoint"`
	Envelope      string `json:"envelope"`
	DataRoot      string `json:"data_root"`
	Authenticated bool   `json:"authenticated"`
}

// DashboardVariable is a low-cardinality dashboard filter.
type DashboardVariable struct {
	Name        string   `json:"name"`
	Source      string   `json:"source"`
	Field       string   `json:"field"`
	Description string   `json:"description"`
	Examples    []string `json:"examples,omitempty"`
}

// DashboardPanel is one dashboard panel definition.
type DashboardPanel struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Source        string   `json:"source"`
	Metric        string   `json:"metric"`
	Visualization string   `json:"visualization"`
	GroupBy       []string `json:"group_by"`
	JoinHints     []string `json:"join_hints"`
	Thresholds    []string `json:"thresholds,omitempty"`
	Description   string   `json:"description"`
}

// DashboardIncidentRun names an operator workflow backed by the exported
// panels and latest-sample join hints.
type DashboardIncidentRun struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	StartPanels []string `json:"start_panels"`
	JoinHints   []string `json:"join_hints"`
	Steps       []string `json:"steps"`
}

// OperationalDashboardExport returns the canonical Yalla control-plane
// dashboard export. Keep this function free of runtime state so the response
// stays byte-stable for agents, review diffs, and dashboard import tooling.
func OperationalDashboardExport() DashboardExport {
	joinHints := []string{
		"request_id",
		"correlation_id",
		"organization_id",
		"principal_id",
		"resource_id",
		"project_id",
		"environment_id",
		"service_id",
		"job_id",
	}
	return DashboardExport{
		SchemaVersion:  DashboardExportSchemaVersion,
		Title:          "Yalla Control Plane Operations",
		Description:    "Dashboard definition for the low-cardinality operational signals exposed by GET /metrics.",
		RefreshSeconds: 30,
		Source: DashboardSource{
			Endpoint:      "/metrics",
			Envelope:      "yalla.output.v1",
			DataRoot:      "data",
			Authenticated: false,
		},
		Variables: []DashboardVariable{
			{Name: "route", Source: "requests", Field: "route", Description: "Matched HTTP route pattern or unmatched.", Examples: []string{"/v1/projects", "unmatched"}},
			{Name: "status_class", Source: "requests", Field: "status_class", Description: "HTTP status family.", Examples: []string{"2xx", "4xx", "5xx"}},
			{Name: "outcome", Source: "trace_spans", Field: "outcome", Description: "Success or error outcome for spans and dependencies.", Examples: []string{"success", "error"}},
			{Name: "component", Source: "trace_spans", Field: "component", Description: "Bounded component name for trace spans.", Examples: []string{"httpapi", "store", "worker"}},
			{Name: "job_type", Source: "dead_letter_alerts", Field: "job_type", Description: "Bounded provisioning job type.", Examples: []string{"ensure_service", "delete_service"}},
			{Name: "severity", Source: "slo_burn_rates", Field: "severity", Description: "Alert severity for SLO and operational alerts.", Examples: []string{"ticket", "page"}},
			{Name: "drift_kind", Source: "reconciliation_drift_alerts", Field: "drift_kind", Description: "Reconciliation drift category.", Examples: []string{"safe", "dangerous", "none"}},
			{Name: "redaction_surface", Source: "secret_redaction_canaries", Field: "surface", Description: "Secret-redaction canary surface.", Examples: []string{"request_logs", "error_envelopes", "audit_metadata"}},
		},
		JoinHints: joinHints,
		Panels: []DashboardPanel{
			{
				ID:            "http-requests",
				Title:         "HTTP Requests",
				Source:        "requests",
				Metric:        "count",
				Visualization: "timeseries",
				GroupBy:       []string{"method", "route", "status_code", "status_class"},
				JoinHints:     []string{"request_id", "correlation_id", "organization_id", "principal_id"},
				Thresholds:    []string{"page when 5xx count is sustained for the active SLO window", "ticket when 4xx spikes on a single route after deploy"},
				Description:   "Tracks API traffic by stable route and status dimensions; latest request and tenant hints are for log joins only.",
			},
			{
				ID:            "trace-spans",
				Title:         "Trace Spans",
				Source:        "trace_spans",
				Metric:        "count",
				Visualization: "table",
				GroupBy:       []string{"name", "kind", "route", "component", "outcome", "status_class", "error_code"},
				JoinHints:     []string{"request_id", "correlation_id", "organization_id", "principal_id", "resource_id", "job_id"},
				Description:   "Finds slow or failing spans without placing tenant identifiers in labels.",
			},
			{
				ID:            "dokploy-dependencies",
				Title:         "Dokploy Dependency",
				Source:        "dokploy_dependencies",
				Metric:        "count",
				Visualization: "timeseries",
				GroupBy:       []string{"method", "endpoint", "outcome", "status_class", "error_code", "retryable"},
				JoinHints:     []string{"request_id", "correlation_id", "organization_id", "project_id", "environment_id", "service_id", "job_id"},
				Thresholds:    []string{"page when dependency 5xx or retryable errors burn the worker SLO", "ticket when a single normalized endpoint regresses after deploy"},
				Description:   "Shows private Dokploy client behavior with normalized endpoints and retryability.",
			},
			{
				ID:            "quota-decisions",
				Title:         "Quota Decisions",
				Source:        "quota_usage",
				Metric:        "count",
				Visualization: "table",
				GroupBy:       []string{"resource", "enforcement_mode", "outcome", "reason"},
				JoinHints:     []string{"request_id", "correlation_id", "organization_id", "principal_id", "job_id"},
				Description:   "Separates allowed reservations, hard-limit rejections, validation failures, and quota infrastructure errors.",
			},
			{
				ID:            "audit-policy",
				Title:         "Audit And Policy",
				Source:        "audit_events,policy_decisions",
				Metric:        "count",
				Visualization: "table",
				GroupBy:       []string{"action", "resource_kind", "decision", "outcome", "reason", "error_code"},
				JoinHints:     []string{"request_id", "correlation_id", "organization_id", "principal_id", "resource_id"},
				Description:   "Correlates authorization decisions with immutable audit append outcomes.",
			},
			{
				ID:            "readiness-slo",
				Title:         "Readiness And SLO Burn",
				Source:        "readiness_degradation,slo_burn_rates",
				Metric:        "count",
				Visualization: "stat",
				GroupBy:       []string{"check", "status", "reason", "objective", "window", "severity", "signal"},
				JoinHints:     []string{"request_id", "correlation_id", "organization_id", "principal_id", "job_id"},
				Thresholds:    []string{"page on firing page-severity SLO burn", "block rollout while readiness dependency gates are failing"},
				Description:   "Shows startup dependency degradation and active budget burn signals.",
			},
			{
				ID:            "worker-reconcile",
				Title:         "Worker And Reconciliation Alerts",
				Source:        "dead_letter_alerts,reconciliation_drift_alerts",
				Metric:        "count",
				Visualization: "table",
				GroupBy:       []string{"job_type", "reason", "severity", "status", "drift_kind", "action_type"},
				JoinHints:     []string{"request_id", "correlation_id", "organization_id", "project_id", "environment_id", "service_id", "job_id"},
				Thresholds:    []string{"page on firing dead-letter or dangerous drift alerts"},
				Description:   "Starts incident triage for exhausted retry budgets and reconciliation drift.",
			},
			{
				ID:            "secret-redaction",
				Title:         "Secret Redaction Canaries",
				Source:        "secret_redaction_canaries",
				Metric:        "count",
				Visualization: "stat",
				GroupBy:       []string{"surface", "vector", "outcome", "reason"},
				JoinHints:     []string{"request_id", "correlation_id", "organization_id", "resource_id", "job_id"},
				Thresholds:    []string{"page on any failed canary after deploy"},
				Description:   "Verifies that log, error, audit, and metrics redaction probes are passing.",
			},
		},
		IncidentFlows: []DashboardIncidentRun{
			{
				ID:          "api-error-spike",
				Title:       "API error spike",
				StartPanels: []string{"http-requests", "trace-spans", "audit-policy"},
				JoinHints:   []string{"request_id", "correlation_id", "organization_id", "principal_id"},
				Steps: []string{
					"Filter HTTP requests by route and status_class.",
					"Open trace spans for the same route and outcome.",
					"Join the latest request_id or correlation_id to structured logs before inspecting tenant-specific rows.",
				},
			},
			{
				ID:          "provisioning-stall",
				Title:       "Provisioning stall",
				StartPanels: []string{"worker-reconcile", "dokploy-dependencies", "quota-decisions"},
				JoinHints:   []string{"job_id", "correlation_id", "organization_id", "service_id"},
				Steps: []string{
					"Start from firing dead-letter or drift series.",
					"Join the latest job_id to the provisioning job row and worker logs.",
					"Check Dokploy dependency retryability and quota rejection series before retrying or escalating.",
				},
			},
			{
				ID:          "secret-redaction-regression",
				Title:       "Secret redaction regression",
				StartPanels: []string{"secret-redaction", "audit-policy", "http-requests"},
				JoinHints:   []string{"request_id", "correlation_id", "resource_id", "job_id"},
				Steps: []string{
					"Page on a failed canary series.",
					"Use only request_id, correlation_id, resource_id, or job_id to join diagnostics.",
					"Do not search logs for raw canary values; the canary emitter never stores them.",
				},
			},
		},
	}
}
