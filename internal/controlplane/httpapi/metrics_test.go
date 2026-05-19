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
	quotaMetrics := telemetry.NewQuotaUsageMetrics()
	auditMetrics := telemetry.NewAuditEventMetrics()
	policyMetrics := telemetry.NewPolicyDecisionMetrics()
	traceMetrics := telemetry.NewTraceSpanMetrics()
	slowQueryMetrics := telemetry.NewSlowQueryMetrics()
	readinessMetrics := telemetry.NewReadinessDegradationMetrics()
	sloMetrics := telemetry.NewSLOBurnRateMetrics()
	deadLetterMetrics := telemetry.NewDeadLetterAlertMetrics()
	readiness := runtime.NewReadiness("database", "migrations", "queue")
	readiness.MarkReady("migrations")
	readiness.MarkReady("queue")
	sloMetrics.RecordSLOBurnRate(telemetry.WithCorrelation(context.Background(), telemetry.Correlation{
		RequestID:     "req_slo_metrics",
		CorrelationID: "corr_slo_metrics",
	}), telemetry.SLOBurnRateObservation{
		Objective:      "api_availability",
		Window:         "5m",
		Severity:       "page",
		Status:         "firing",
		Signal:         "http_5xx_ratio",
		BurnRate:       12,
		ErrorBudgetPct: 1.5,
		OrganizationID: "org_metrics_slo",
		JobID:          "job_metrics_slo",
	})
	deadLetterMetrics.RecordDeadLetterAlert(telemetry.WithCorrelation(context.Background(), telemetry.Correlation{
		RequestID:     "req_dead_letter_metrics",
		CorrelationID: "corr_dead_letter_metrics",
	}), telemetry.DeadLetterAlertObservation{
		JobType:        "ensure_service",
		Reason:         "retry_budget_exhausted",
		Severity:       "page",
		Status:         "firing",
		OrganizationID: "org_metrics_dead_letter",
		ServiceID:      "svc_metrics_dead_letter",
		JobID:          "job_metrics_dead_letter",
		Attempt:        5,
		MaxAttempts:    5,
	})
	dokployMetrics.RecordDokployDependencyCall(context.Background(), telemetry.DokployDependencyEvent{
		Method:     http.MethodGet,
		Path:       "/api/projects/proj_metrics_probe",
		StatusCode: http.StatusOK,
	})
	quotaMetrics.RecordQuotaUsageDecision(context.Background(), telemetry.QuotaUsageEvent{
		Resource:        "projects",
		EnforcementMode: "hard",
		Outcome:         telemetry.QuotaUsageOutcomeAllowed,
		Reason:          "reserved",
		Current:         1,
		Reserved:        0,
		Requested:       1,
		Limit:           5,
		OrganizationID:  "org_metrics_quota",
	})
	auditMetrics.RecordAuditEventAppend(context.Background(), telemetry.AuditEventObservation{
		Action:         "project.create",
		ResourceKind:   "project",
		Decision:       "allowed",
		Outcome:        telemetry.AuditEventOutcomeRecorded,
		Reason:         "allowed_by_role",
		OrganizationID: "org_metrics_audit",
		ResourceID:     "proj_metrics_audit",
	})
	policyMetrics.RecordPolicyDecision(context.Background(), telemetry.PolicyDecisionObservation{
		Action:         "project.create",
		ResourceKind:   "project",
		Decision:       "denied",
		Reason:         "denied_no_capability",
		OrganizationID: "org_metrics_policy",
		ResourceID:     "proj_metrics_policy",
	})
	slowQueryMetrics.RecordSlowQuery(context.Background(), telemetry.SlowQueryObservation{
		Operation: "read",
		QueryKind: "select",
		Outcome:   "success",
	})
	handler := NewHandler(
		runtime.BuildInfo{Version: "test"}, readiness, nil, nil,
		fakeAuthenticator{}, policy.NewEngine(), fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, metrics, dokployMetrics, quotaMetrics, auditMetrics, policyMetrics,
		traceMetrics, slowQueryMetrics, readinessMetrics, sloMetrics, deadLetterMetrics,
	)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodGet, "/missing", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("X-Request-Id", "req-readyz-metrics")
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
			QuotaUsage          telemetry.QuotaUsageMetricsSnapshot        `json:"quota_usage"`
			AuditEvents         telemetry.AuditEventMetricsSnapshot        `json:"audit_events"`
			PolicyDecisions     telemetry.PolicyDecisionMetricsSnapshot    `json:"policy_decisions"`
			TraceSpans          telemetry.TraceSpanMetricsSnapshot         `json:"trace_spans"`
			SlowQueries         telemetry.SlowQueryMetricsSnapshot         `json:"slow_queries"`
			Readiness           telemetry.ReadinessDegradationSnapshot     `json:"readiness_degradation"`
			SLOBurnRates        telemetry.SLOBurnRateMetricsSnapshot       `json:"slo_burn_rates"`
			DeadLetterAlerts    telemetry.DeadLetterAlertMetricsSnapshot   `json:"dead_letter_alerts"`
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
	if env.Data.QuotaUsage.TotalDecisions != 1 {
		t.Fatalf("quota total_decisions = %d, want 1", env.Data.QuotaUsage.TotalDecisions)
	}
	if len(env.Data.QuotaUsage.Series) != 1 || env.Data.QuotaUsage.Series[0].Resource != "projects" {
		t.Fatalf("quota usage series = %+v, want projects metric", env.Data.QuotaUsage.Series)
	}
	if env.Data.AuditEvents.TotalEvents != 1 {
		t.Fatalf("audit total_events = %d, want 1", env.Data.AuditEvents.TotalEvents)
	}
	if len(env.Data.AuditEvents.Series) != 1 || env.Data.AuditEvents.Series[0].Action != "project.create" || env.Data.AuditEvents.Series[0].OrganizationID != "org_metrics_audit" {
		t.Fatalf("audit event series = %+v, want project.create with safe org hint", env.Data.AuditEvents.Series)
	}
	if env.Data.PolicyDecisions.TotalDecisions != 1 {
		t.Fatalf("policy total_decisions = %d, want 1", env.Data.PolicyDecisions.TotalDecisions)
	}
	if len(env.Data.PolicyDecisions.Series) != 1 || env.Data.PolicyDecisions.Series[0].Decision != "denied" || env.Data.PolicyDecisions.Series[0].OrganizationID != "org_metrics_policy" {
		t.Fatalf("policy decision series = %+v, want denied project.create with safe org hint", env.Data.PolicyDecisions.Series)
	}
	if env.Data.TraceSpans.TotalSpans < 2 {
		t.Fatalf("trace total_spans = %d, want at least healthz and missing spans", env.Data.TraceSpans.TotalSpans)
	}
	if env.Data.SlowQueries.TotalQueries != 1 {
		t.Fatalf("slow query total_queries = %d, want 1", env.Data.SlowQueries.TotalQueries)
	}
	if len(env.Data.SlowQueries.Series) != 1 || env.Data.SlowQueries.Series[0].Operation != "read" || env.Data.SlowQueries.Series[0].QueryKind != "select" {
		t.Fatalf("slow query series = %+v, want read/select metric", env.Data.SlowQueries.Series)
	}
	if env.Data.Readiness.TotalProbes == 0 {
		t.Fatalf("readiness total_probes = %d, want readyz probe observations", env.Data.Readiness.TotalProbes)
	}
	if env.Data.SLOBurnRates.TotalObservations != 1 {
		t.Fatalf("slo burn-rate total_observations = %d, want 1", env.Data.SLOBurnRates.TotalObservations)
	}
	if len(env.Data.SLOBurnRates.Series) != 1 || env.Data.SLOBurnRates.Series[0].Objective != "api_availability" || env.Data.SLOBurnRates.Series[0].OrganizationID != "org_metrics_slo" {
		t.Fatalf("slo burn-rate series = %+v, want api_availability with safe org hint", env.Data.SLOBurnRates.Series)
	}
	if env.Data.DeadLetterAlerts.TotalAlerts != 1 {
		t.Fatalf("dead-letter total_alerts = %d, want 1", env.Data.DeadLetterAlerts.TotalAlerts)
	}
	if len(env.Data.DeadLetterAlerts.Series) != 1 || env.Data.DeadLetterAlerts.Series[0].JobType != "ensure_service" || env.Data.DeadLetterAlerts.Series[0].OrganizationID != "org_metrics_dead_letter" || env.Data.DeadLetterAlerts.Series[0].JobID != "job_metrics_dead_letter" {
		t.Fatalf("dead-letter alert series = %+v, want ensure_service with safe org/job hints", env.Data.DeadLetterAlerts.Series)
	}
	foundReadyzFailure := false
	for _, series := range env.Data.Readiness.Series {
		if series.Check == "database" && series.Status == "failing" && series.Reason == "pending" && series.RequestID == "req-readyz-metrics" {
			foundReadyzFailure = true
			break
		}
	}
	if !foundReadyzFailure {
		t.Fatalf("readiness metrics missing database pending failure: %+v", env.Data.Readiness.Series)
	}
	foundRequestFailure := false
	for _, metric := range env.Data.Requests {
		if metric.Route == "unmatched" {
			foundRequestFailure = true
			break
		}
	}
	if !foundRequestFailure {
		t.Fatalf("metrics response did not include unmatched route series: %+v", env.Data.Requests)
	}
	foundSuccess := false
	foundFailure := false
	for _, span := range env.Data.TraceSpans.Series {
		if span.Name == "http.request" && span.Kind == "server" && span.Route == "/healthz" && span.Outcome == "success" {
			foundSuccess = true
		}
		if span.Name == "http.request" && span.Kind == "server" && span.Route == "unmatched" && span.Outcome == "error" && span.StatusClass == "4xx" {
			foundFailure = true
		}
	}
	if !foundSuccess || !foundFailure {
		t.Fatalf("trace spans missing success=%v failure=%v: %+v", foundSuccess, foundFailure, env.Data.TraceSpans.Series)
	}
}

func TestMetricsEndpointIncludesReadinessDegradation(t *testing.T) {
	t.Parallel()

	readiness := runtime.NewReadiness("database", "migrations", "queue")
	readiness.MarkReady("migrations")
	readiness.MarkReady("queue")
	readinessMetrics := telemetry.NewReadinessDegradationMetrics()
	handler := NewHandler(
		runtime.BuildInfo{Version: "test"}, readiness, nil, nil,
		fakeAuthenticator{}, policy.NewEngine(), fakeOrganizationReader{}, fakeOrganizationCreator{}, fakeOrganizationUpdater{}, fakeOrganizationDeleter{}, fakeMembershipReader{}, fakeMembershipCreator{}, fakeMembershipUpdater{}, fakeMembershipRemover{}, fakeLimitsReader{}, fakeLimitsUpdater{}, fakeUsageReader{}, fakeAuditEventReader{}, fakeOrgVariableReader{}, fakeOrgVariableReplacer{}, fakeOrgVariablePatcher{}, fakeOrgVariableDeleter{}, fakeAPIKeyReader{}, fakeAPIKeyCreator{}, fakeAPIKeyUpdater{}, fakeAPIKeyRevoker{}, fakeAPIKeyRotator{}, fakeProjectReader{}, fakeProjectCreator{}, fakeProjectUpdater{}, fakeProjectDeleter{}, fakeProjectRestorer{}, fakeProjectGrantReader{}, fakeProjectGrantReplacer{}, fakeProjectVariableReader{}, fakeProjectVariableReplacer{}, fakeProjectEnvironmentReader{}, fakeEnvironmentCreator{}, fakeEnvironmentReader{}, fakeEnvironmentUpdater{}, fakeEnvironmentDeleter{}, fakeEnvironmentCloner{}, fakeEnvironmentGrantReader{}, fakeEnvironmentGrantReplacer{}, fakeEnvironmentVariableReader{}, fakeEnvironmentVariableReplacer{}, fakeEnvironmentServiceReader{}, fakeEnvironmentServiceCreator{}, fakeServiceReader{}, fakeServiceUpdater{}, fakeServiceDeleter{}, fakeServiceRestorer{}, fakeServiceRestarter{}, fakeServiceStarter{}, fakeServiceStopper{}, fakeServiceLogReader{}, fakeServiceMetricsReader{}, fakeServiceDomainReader{}, fakeServiceDomainCreator{}, fakeServiceDomainUpdater{}, fakeServiceDomainDeleter{}, fakeServiceBackupReader{}, fakeServiceBackupCreator{}, fakeServiceBackupUpdater{}, fakeServiceBackupRunner{}, fakeServiceBackupDeleter{}, fakeServiceVariableReader{}, fakeServiceVariableReplacer{}, fakeDeploymentCreator{}, fakeDeploymentLister{}, fakeDeploymentGetter{}, fakeDeploymentCanceler{}, fakeDeploymentRollbacker{}, fakeBreakGlassController{}, nil, nil, readinessMetrics,
	)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.Header.Set("X-Request-Id", "req-readyz-metrics")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var env struct {
		Data struct {
			Readiness telemetry.ReadinessDegradationSnapshot `json:"readiness_degradation"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode metrics response: %v", err)
	}
	if env.Data.Readiness.TotalProbes != 3 {
		t.Fatalf("readiness total_probes = %d, want one observation per gate", env.Data.Readiness.TotalProbes)
	}
	var foundFailure bool
	for _, series := range env.Data.Readiness.Series {
		if series.Check == "database" && series.Status == "failing" && series.Reason == "pending" && series.RequestID == "req-readyz-metrics" {
			foundFailure = true
		}
	}
	if !foundFailure {
		t.Fatalf("readiness degradation series missing pending database failure: %+v", env.Data.Readiness.Series)
	}
}
