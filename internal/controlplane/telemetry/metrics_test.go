package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestMetricsRecordsLowCardinalityOutcomes(t *testing.T) {
	t.Parallel()

	metrics := NewHTTPMetrics()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		SetOrgID(r.Context(), "org_metrics_safe")
		SetPrincipalID(r.Context(), "usr_metrics_safe")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	})
	wrapped := Correlate(RequestLogging(nil)(RequestMetrics(metrics)(handler)))

	req := httptest.NewRequest(http.MethodPost, "/v1/projects", nil)
	req.Pattern = "/v1/projects"
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodGet, "/missing?token=secret-query-value", nil)
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	snapshot := metrics.Snapshot()
	if snapshot.TotalRequests != 2 {
		t.Fatalf("total_requests = %d, want 2", snapshot.TotalRequests)
	}
	if len(snapshot.Requests) != 2 {
		t.Fatalf("requests len = %d, want 2: %+v", len(snapshot.Requests), snapshot.Requests)
	}

	created := findHTTPRequestMetric(snapshot.Requests, http.MethodPost, "/v1/projects", http.StatusCreated)
	if created == nil {
		t.Fatalf("missing POST /v1/projects 201 metric: %+v", snapshot.Requests)
	}
	if created.StatusClass != "2xx" || created.Count != 1 || created.ResponseBytes != int64(len("created")) {
		t.Errorf("created metric = %+v, want 2xx count=1 bytes=%d", *created, len("created"))
	}
	if created.RequestID == "" || created.CorrelationID == "" {
		t.Errorf("created metric = %+v, want request and correlation ids for log joining", *created)
	}
	if created.OrganizationID != "org_metrics_safe" || created.PrincipalID != "usr_metrics_safe" {
		t.Errorf("created metric = %+v, want safe org/principal enrichment", *created)
	}

	missing := findHTTPRequestMetric(snapshot.Requests, http.MethodGet, "unmatched", http.StatusNotFound)
	if missing == nil {
		t.Fatalf("missing GET /missing 404 metric: %+v", snapshot.Requests)
	}
	if missing.StatusClass != "4xx" || missing.Count != 1 {
		t.Errorf("missing metric = %+v, want 4xx count=1", *missing)
	}
	if missing.OrganizationID != "" || missing.PrincipalID != "" {
		t.Errorf("missing metric = %+v, want no unknown org/principal labels", *missing)
	}
}

func TestRequestMetricsBoundsCardinalityAndRedactsTarget(t *testing.T) {
	t.Parallel()

	metrics := NewHTTPMetrics()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := Correlate(RequestMetrics(metrics)(handler))

	req := httptest.NewRequest("BREW", "/anything?api_key=super-secret", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	snapshot := metrics.Snapshot()
	got := findHTTPRequestMetric(snapshot.Requests, "OTHER", "unmatched", http.StatusOK)
	if got == nil {
		t.Fatalf("missing bounded-cardinality metric: %+v", snapshot.Requests)
	}
	if got.Target != "/anything?api_key=[REDACTED]" {
		t.Errorf("target = %q, want redacted query secret", got.Target)
	}
}

func findHTTPRequestMetric(metrics []HTTPRequestMetric, method, route string, status int) *HTTPRequestMetric {
	for i := range metrics {
		if metrics[i].Method == method && metrics[i].Route == route && metrics[i].StatusCode == status {
			return &metrics[i]
		}
	}
	return nil
}

func TestJobQueueMetricsRecordsLowCardinalityOutcomes(t *testing.T) {
	t.Parallel()

	metrics := NewJobQueueMetrics()
	metrics.RecordJobQueueEvent(JobQueueEvent{
		Event:          JobQueueEventClaimed,
		JobType:        "ensure_project",
		Status:         "running",
		JobID:          "job_metrics_claimed",
		RequestID:      "req_metrics_claimed",
		CorrelationID:  "corr_metrics_claimed",
		OrganizationID: "org_metrics_safe",
		ProjectID:      "proj_metrics_safe",
	})
	metrics.RecordJobQueueEvent(JobQueueEvent{
		Event:          JobQueueEventCompleted,
		JobType:        "ensure_project",
		Status:         "succeeded",
		JobID:          "job_metrics_succeeded",
		RequestID:      "req_metrics_succeeded",
		CorrelationID:  "corr_metrics_succeeded",
		OrganizationID: "org_metrics_safe",
		ProjectID:      "proj_metrics_safe",
	})
	metrics.RecordJobQueueEvent(JobQueueEvent{
		Event:          JobQueueEventCompleted,
		JobType:        "ensure_project",
		Status:         "retrying",
		JobID:          "job_metrics_retry",
		RequestID:      "req_metrics_retry",
		CorrelationID:  "corr_metrics_retry",
		OrganizationID: "org_metrics_safe",
		ProjectID:      "proj_metrics_safe",
		NextRunDelayMS: 30000,
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalEvents != 3 {
		t.Fatalf("total_events = %d, want 3", snapshot.TotalEvents)
	}
	if len(snapshot.Series) != 3 {
		t.Fatalf("series len = %d, want 3: %+v", len(snapshot.Series), snapshot.Series)
	}

	claimed := findJobQueueMetric(snapshot.Series, JobQueueEventClaimed, "ensure_project", "running")
	if claimed == nil {
		t.Fatalf("missing claimed metric: %+v", snapshot.Series)
	}
	if claimed.Count != 1 || claimed.JobID != "job_metrics_claimed" || claimed.OrganizationID != "org_metrics_safe" {
		t.Errorf("claimed metric = %+v, want latest claim hints", *claimed)
	}

	retrying := findJobQueueMetric(snapshot.Series, JobQueueEventCompleted, "ensure_project", "retrying")
	if retrying == nil {
		t.Fatalf("missing retrying metric: %+v", snapshot.Series)
	}
	if retrying.StatusClass != "retry" || retrying.NextRunDelayMS != 30000 {
		t.Errorf("retrying metric = %+v, want retry class and delay hint", *retrying)
	}
	if retrying.RequestID == "" || retrying.CorrelationID == "" || retrying.ProjectID == "" {
		t.Errorf("retrying metric = %+v, want request/correlation/resource hints", *retrying)
	}
}

func findJobQueueMetric(metrics []JobQueueMetric, event JobQueueEventName, jobType, status string) *JobQueueMetric {
	for i := range metrics {
		if metrics[i].Event == event && metrics[i].JobType == jobType && metrics[i].Status == status {
			return &metrics[i]
		}
	}
	return nil
}

func TestDokployDependencyMetricsRecordsLowCardinalityOutcomes(t *testing.T) {
	t.Parallel()

	metrics := NewDokployDependencyMetrics()
	ctx := WithCorrelation(contextWithFields(t), Correlation{
		RequestID:     "req_dokploy_metrics",
		CorrelationID: "corr_dokploy_metrics",
	})
	SetOrgID(ctx, "org_dokploy_metrics")
	SetPrincipalID(ctx, "usr_dokploy_metrics")

	metrics.RecordDokployDependencyCall(ctx, DokployDependencyEvent{
		Method:         http.MethodGet,
		Path:           "/api/services/svc_sensitive/status",
		StatusCode:     http.StatusOK,
		Attempt:        1,
		Latency:        12,
		OrganizationID: "org_dokploy_hint",
		ServiceID:      "svc_yalla_safe",
	})
	metrics.RecordDokployDependencyCall(ctx, DokployDependencyEvent{
		Method:    "BREW",
		Path:      "/api/services/svc_secret/backups/backup_secret/restore?token=secret",
		ErrorCode: "E_DOKPLOY_UNAVAILABLE",
		Retryable: true,
		Attempt:   2,
		Latency:   34,
		ServiceID: "svc_yalla_safe",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalCalls != 2 {
		t.Fatalf("total_calls = %d, want 2", snapshot.TotalCalls)
	}
	if len(snapshot.Series) != 2 {
		t.Fatalf("series len = %d, want 2: %+v", len(snapshot.Series), snapshot.Series)
	}

	success := findDokployDependencyMetric(snapshot.Series, http.MethodGet, "/api/services/{id}/status", "success")
	if success == nil {
		t.Fatalf("missing success metric: %+v", snapshot.Series)
	}
	if success.Count != 1 || success.StatusCode != http.StatusOK || success.StatusClass != "2xx" {
		t.Errorf("success metric = %+v, want 200 2xx count=1", *success)
	}
	if success.RequestID != "req_dokploy_metrics" || success.CorrelationID != "corr_dokploy_metrics" {
		t.Errorf("success metric = %+v, want request/correlation hints", *success)
	}
	if success.OrganizationID != "org_dokploy_hint" || success.PrincipalID != "usr_dokploy_metrics" || success.ServiceID != "svc_yalla_safe" {
		t.Errorf("success metric = %+v, want safe resource hints", *success)
	}

	failure := findDokployDependencyMetric(snapshot.Series, "OTHER", "/api/services/{id}/backups/{id}/restore", "failure")
	if failure == nil {
		t.Fatalf("missing failure metric: %+v", snapshot.Series)
	}
	if failure.ErrorCode != "E_DOKPLOY_UNAVAILABLE" || !failure.Retryable || failure.StatusClass != "dependency_error" {
		t.Errorf("failure metric = %+v, want dependency error retry hints", *failure)
	}
	if strings.Contains(failure.Endpoint, "svc_secret") || strings.Contains(failure.Endpoint, "backup_secret") || strings.Contains(failure.Endpoint, "token") {
		t.Errorf("failure endpoint = %q, want normalized redacted endpoint", failure.Endpoint)
	}
}

func contextWithFields(t *testing.T) context.Context {
	t.Helper()
	return withRequestFields(context.Background())
}

func findDokployDependencyMetric(metrics []DokployDependencyMetric, method, endpoint, outcome string) *DokployDependencyMetric {
	for i := range metrics {
		if metrics[i].Method == method && metrics[i].Endpoint == endpoint && metrics[i].Outcome == outcome {
			return &metrics[i]
		}
	}
	return nil
}

func TestQuotaUsageMetricsRecordsLowCardinalityDecisions(t *testing.T) {
	t.Parallel()

	metrics := NewQuotaUsageMetrics()
	ctx := WithCorrelation(contextWithFields(t), Correlation{
		RequestID:     "req_quota_metrics",
		CorrelationID: "corr_quota_metrics",
	})
	SetOrgID(ctx, "org_context")
	SetPrincipalID(ctx, "usr_quota_metrics")

	metrics.RecordQuotaUsageDecision(ctx, QuotaUsageEvent{
		Resource:        "projects",
		EnforcementMode: "hard",
		Outcome:         QuotaUsageOutcomeAllowed,
		Reason:          "reserved",
		Current:         1,
		Reserved:        2,
		Requested:       1,
		Limit:           5,
		OrganizationID:  "org_quota_safe",
		JobID:           "job_quota_safe",
	})
	metrics.RecordQuotaUsageDecision(ctx, QuotaUsageEvent{
		Resource:        "projects",
		EnforcementMode: "hard",
		Outcome:         QuotaUsageOutcomeRejected,
		Reason:          "limit_exceeded",
		Current:         1,
		Reserved:        4,
		Requested:       1,
		Limit:           5,
		OrganizationID:  "org_quota_safe",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalDecisions != 2 {
		t.Fatalf("total_decisions = %d, want 2", snapshot.TotalDecisions)
	}
	if len(snapshot.Series) != 2 {
		t.Fatalf("series len = %d, want 2: %+v", len(snapshot.Series), snapshot.Series)
	}

	allowed := findQuotaUsageMetric(snapshot.Series, "projects", "hard", QuotaUsageOutcomeAllowed, "reserved")
	if allowed == nil {
		t.Fatalf("missing allowed metric: %+v", snapshot.Series)
	}
	if allowed.Count != 1 || allowed.Current != 1 || allowed.Reserved != 2 || allowed.Requested != 1 || allowed.Limit != 5 {
		t.Errorf("allowed metric = %+v, want latest quota counts", *allowed)
	}
	if allowed.RequestID != "req_quota_metrics" || allowed.CorrelationID != "corr_quota_metrics" {
		t.Errorf("allowed metric = %+v, want request/correlation hints", *allowed)
	}
	if allowed.OrganizationID != "org_quota_safe" || allowed.PrincipalID != "usr_quota_metrics" || allowed.JobID != "job_quota_safe" {
		t.Errorf("allowed metric = %+v, want safe latest-sample hints", *allowed)
	}

	rejected := findQuotaUsageMetric(snapshot.Series, "projects", "hard", QuotaUsageOutcomeRejected, "limit_exceeded")
	if rejected == nil {
		t.Fatalf("missing rejected metric: %+v", snapshot.Series)
	}
	if rejected.Count != 1 || rejected.Reserved != 4 {
		t.Errorf("rejected metric = %+v, want rejection counts", *rejected)
	}
}

func TestQuotaUsageMetricsBoundsCardinality(t *testing.T) {
	t.Parallel()

	metrics := NewQuotaUsageMetrics()
	metrics.RecordQuotaUsageDecision(context.Background(), QuotaUsageEvent{
		Resource:        "projects\nAuthorization: Bearer yka_secret",
		EnforcementMode: "strange-mode",
		Outcome:         "surprising",
		Reason:          "user supplied reason with token=secret",
		Current:         -1,
		Reserved:        -2,
		Requested:       -3,
		Limit:           -4,
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalDecisions != 1 || len(snapshot.Series) != 1 {
		t.Fatalf("snapshot = %+v, want one bounded series", snapshot)
	}
	got := snapshot.Series[0]
	if got.Resource != "unknown" || got.EnforcementMode != "other" || got.Outcome != QuotaUsageOutcomeError || got.Reason != "other" {
		t.Fatalf("metric = %+v, want bounded resource/mode/outcome/reason", got)
	}
	if got.Current != 0 || got.Reserved != 0 || got.Requested != 0 || got.Limit != 0 {
		t.Fatalf("metric = %+v, want negative counts clamped to zero", got)
	}
}

func findQuotaUsageMetric(metrics []QuotaUsageMetric, resource, mode string, outcome QuotaUsageOutcome, reason string) *QuotaUsageMetric {
	for i := range metrics {
		if metrics[i].Resource == resource && metrics[i].EnforcementMode == mode && metrics[i].Outcome == outcome && metrics[i].Reason == reason {
			return &metrics[i]
		}
	}
	return nil
}

func TestAuditEventMetricsRecordsSuccessAndFailure(t *testing.T) {
	t.Parallel()

	metrics := NewAuditEventMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{
		RequestID:     "req_audit_context",
		CorrelationID: "corr_audit_context",
	})

	metrics.RecordAuditEventAppend(ctx, AuditEventObservation{
		Action:         "project.create",
		ResourceKind:   "project",
		ResourceID:     "proj_audit_metrics",
		Decision:       "allowed",
		Outcome:        AuditEventOutcomeRecorded,
		Reason:         "allowed_by_role",
		RequestID:      "req_audit_row",
		CorrelationID:  "corr_audit_row",
		OrganizationID: "org_audit_metrics",
		ActorID:        "usr_audit_metrics",
		JobID:          "job_audit_metrics",
	})
	metrics.RecordAuditEventAppend(ctx, AuditEventObservation{
		Action:         "project.create",
		ResourceKind:   "project",
		ResourceID:     "proj_audit_metrics",
		Decision:       "allowed",
		Outcome:        AuditEventOutcomeFailed,
		Reason:         "write_failed",
		ErrorCode:      "E_DB_UNAVAILABLE",
		OrganizationID: "org_audit_metrics",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalEvents != 2 {
		t.Fatalf("total_events = %d, want 2", snapshot.TotalEvents)
	}
	if len(snapshot.Series) != 2 {
		t.Fatalf("series len = %d, want 2: %+v", len(snapshot.Series), snapshot.Series)
	}

	recorded := findAuditEventMetric(snapshot.Series, "project.create", "project", "allowed", AuditEventOutcomeRecorded, "allowed_by_role")
	if recorded == nil {
		t.Fatalf("missing recorded metric: %+v", snapshot.Series)
	}
	if recorded.Count != 1 || recorded.ErrorCode != "" {
		t.Errorf("recorded metric = %+v, want count=1 and no error code", *recorded)
	}
	if recorded.RequestID != "req_audit_row" || recorded.CorrelationID != "corr_audit_row" {
		t.Errorf("recorded metric = %+v, want audit row request/correlation ids", *recorded)
	}
	if recorded.OrganizationID != "org_audit_metrics" || recorded.ResourceID != "proj_audit_metrics" || recorded.ActorID != "usr_audit_metrics" || recorded.JobID != "job_audit_metrics" {
		t.Errorf("recorded metric = %+v, want latest-sample identity hints", *recorded)
	}

	failed := findAuditEventMetric(snapshot.Series, "project.create", "project", "allowed", AuditEventOutcomeFailed, "write_failed")
	if failed == nil {
		t.Fatalf("missing failed metric: %+v", snapshot.Series)
	}
	if failed.ErrorCode != "E_DB_UNAVAILABLE" || failed.RequestID != "req_audit_context" || failed.CorrelationID != "corr_audit_context" {
		t.Errorf("failed metric = %+v, want stable error code and context correlation fallback", *failed)
	}
}

func TestAuditEventMetricsBoundsCardinalityAndDropsUnsafeIdentifiers(t *testing.T) {
	t.Parallel()

	metrics := NewAuditEventMetrics()
	metrics.RecordAuditEventAppend(context.Background(), AuditEventObservation{
		Action:         "project.create\nAuthorization: Bearer yka_secret",
		ResourceKind:   "project",
		ResourceID:     "proj_bad\nsecret",
		Decision:       "maybe",
		Outcome:        "surprising",
		Reason:         "reason with token=secret",
		ErrorCode:      "E_DB_UNAVAILABLE\nsecret",
		OrganizationID: "org_ok",
		ActorID:        "usr ok",
		JobID:          "job_ok",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalEvents != 1 || len(snapshot.Series) != 1 {
		t.Fatalf("snapshot = %+v, want one bounded series", snapshot)
	}
	got := snapshot.Series[0]
	if got.Action != "other" || got.ResourceKind != "project" || got.Decision != "other" || got.Outcome != AuditEventOutcomeFailed || got.Reason != "other" || got.ErrorCode != "other" {
		t.Fatalf("metric = %+v, want bounded dimensions", got)
	}
	if got.OrganizationID != "org_ok" || got.ResourceID != "" || got.ActorID != "" || got.JobID != "job_ok" {
		t.Fatalf("metric = %+v, want only safe identifiers retained", got)
	}
}

func findAuditEventMetric(metrics []AuditEventMetric, action, resourceKind, decision string, outcome AuditEventOutcome, reason string) *AuditEventMetric {
	for i := range metrics {
		if metrics[i].Action == action && metrics[i].ResourceKind == resourceKind && metrics[i].Decision == decision && metrics[i].Outcome == outcome && metrics[i].Reason == reason {
			return &metrics[i]
		}
	}
	return nil
}
