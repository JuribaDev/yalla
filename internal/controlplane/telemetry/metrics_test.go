package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestSlowQueryMetricsRecordsLowCardinalityOutcomes(t *testing.T) {
	t.Parallel()

	metrics := NewSlowQueryMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{RequestID: "req_slow_query", CorrelationID: "corr_slow_query"})
	ctx = withRequestFields(ctx)
	SetOrgID(ctx, "org_slow_query")
	SetPrincipalID(ctx, "usr_slow_query")
	SetResource(ctx, "service", "svc_slow_query")
	SetJobID(ctx, "job_slow_query")

	metrics.RecordSlowQuery(ctx, SlowQueryObservation{
		Operation: "read",
		QueryKind: "select",
		Outcome:   "success",
		Duration:  1500 * time.Millisecond,
		Threshold: 250 * time.Millisecond,
	})
	metrics.RecordSlowQuery(context.Background(), SlowQueryObservation{
		Operation: "write",
		QueryKind: "insert",
		Outcome:   "error",
		Duration:  275 * time.Millisecond,
		Threshold: 250 * time.Millisecond,
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalQueries != 2 {
		t.Fatalf("total_queries = %d, want 2", snapshot.TotalQueries)
	}
	read := findSlowQueryMetric(snapshot.Series, "read", "select", "success")
	if read == nil {
		t.Fatalf("missing read/select/success slow-query metric: %+v", snapshot.Series)
	}
	if read.Count != 1 || read.LastDurationMS != 1500 || read.ThresholdMS != 250 {
		t.Errorf("read slow-query metric = %+v, want count=1 last=1500 threshold=250", *read)
	}
	if read.RequestID != "req_slow_query" || read.CorrelationID != "corr_slow_query" ||
		read.OrganizationID != "org_slow_query" || read.PrincipalID != "usr_slow_query" ||
		read.ResourceKind != "service" || read.ResourceID != "svc_slow_query" ||
		read.JobID != "job_slow_query" {
		t.Errorf("read slow-query hints = %+v, want request/resource/job correlation", *read)
	}

	write := findSlowQueryMetric(snapshot.Series, "write", "insert", "error")
	if write == nil {
		t.Fatalf("missing write/insert/error slow-query metric: %+v", snapshot.Series)
	}
	if write.RequestID != "" || write.OrganizationID != "" {
		t.Errorf("write slow-query metric without context = %+v, want no unsafe identifiers", *write)
	}
}

func TestSlowQueryMetricsBoundsCardinalityAndDropsUnsafeIdentifiers(t *testing.T) {
	t.Parallel()

	metrics := NewSlowQueryMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{
		RequestID:     "req\nbad",
		CorrelationID: "corr_slow_safe",
	})
	ctx = withRequestFields(ctx)
	SetOrgID(ctx, "org bad")
	SetPrincipalID(ctx, "usr_slow_safe")
	SetResource(ctx, "service\nbad", "svc_slow_safe")

	metrics.RecordSlowQuery(ctx, SlowQueryObservation{
		Operation: "COPY users TO PROGRAM",
		QueryKind: "select * from secrets where token='topsecret'",
		Outcome:   "weird",
		Duration:  time.Second,
		Threshold: time.Millisecond,
	})

	snapshot := metrics.Snapshot()
	got := findSlowQueryMetric(snapshot.Series, "other", "other", "error")
	if got == nil {
		t.Fatalf("missing bounded-cardinality slow-query metric: %+v", snapshot.Series)
	}
	if got.RequestID != "" || got.CorrelationID != "corr_slow_safe" {
		t.Errorf("correlation hints = %q/%q, want unsafe request dropped and safe correlation kept", got.RequestID, got.CorrelationID)
	}
	if got.OrganizationID != "" || got.PrincipalID != "usr_slow_safe" || got.ResourceKind != "" || got.ResourceID != "svc_slow_safe" {
		t.Errorf("identifier hints = %+v, want only SafeID-clean values", *got)
	}
}

func findSlowQueryMetric(metrics []SlowQueryMetric, operation, queryKind, outcome string) *SlowQueryMetric {
	for i := range metrics {
		if metrics[i].Operation == operation && metrics[i].QueryKind == queryKind && metrics[i].Outcome == outcome {
			return &metrics[i]
		}
	}
	return nil
}

func TestSLOBurnRateMetricsRecordsLowCardinalityAlerts(t *testing.T) {
	t.Parallel()

	metrics := NewSLOBurnRateMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{RequestID: "req_slo_burn", CorrelationID: "corr_slo_burn"})
	ctx = withRequestFields(ctx)
	SetOrgID(ctx, "org_slo_safe")
	SetPrincipalID(ctx, "usr_slo_safe")
	SetResource(ctx, "service", "svc_slo_safe")
	SetJobID(ctx, "job_slo_safe")

	metrics.RecordSLOBurnRate(ctx, SLOBurnRateObservation{
		Objective:      "api_availability",
		Window:         "5m",
		Severity:       "page",
		Status:         "firing",
		Signal:         "http_5xx_ratio",
		BurnRate:       14.25,
		ErrorBudgetPct: 2.5,
		OrganizationID: "org_slo_override",
		JobID:          "job_slo_override",
	})
	metrics.RecordSLOBurnRate(context.Background(), SLOBurnRateObservation{
		Objective: "api_availability",
		Window:    "1h",
		Severity:  "ticket",
		Status:    "resolved",
		Signal:    "http_5xx_ratio",
		BurnRate:  0.5,
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalObservations != 2 {
		t.Fatalf("total_observations = %d, want 2", snapshot.TotalObservations)
	}
	firing := findSLOBurnRateMetric(snapshot.Series, "api_availability", "5m", "page", "firing", "http_5xx_ratio")
	if firing == nil {
		t.Fatalf("missing firing SLO burn-rate metric: %+v", snapshot.Series)
	}
	if firing.Count != 1 || firing.LastBurnRate != 14.25 || firing.LastErrorBudgetPct != 2.5 {
		t.Errorf("firing metric = %+v, want count=1 burn=14.25 budget=2.5", *firing)
	}
	if firing.RequestID != "req_slo_burn" || firing.CorrelationID != "corr_slo_burn" ||
		firing.OrganizationID != "org_slo_override" || firing.PrincipalID != "usr_slo_safe" ||
		firing.ResourceKind != "service" || firing.ResourceID != "svc_slo_safe" ||
		firing.JobID != "job_slo_override" {
		t.Errorf("firing hints = %+v, want request/resource/job correlation", *firing)
	}
	resolved := findSLOBurnRateMetric(snapshot.Series, "api_availability", "1h", "ticket", "resolved", "http_5xx_ratio")
	if resolved == nil {
		t.Fatalf("missing resolved SLO burn-rate metric: %+v", snapshot.Series)
	}
	if resolved.RequestID != "" || resolved.OrganizationID != "" {
		t.Errorf("resolved metric without context = %+v, want no unsafe identifiers", *resolved)
	}
}

func TestSLOBurnRateMetricsBoundsCardinalityAndDropsUnsafeIdentifiers(t *testing.T) {
	t.Parallel()

	metrics := NewSLOBurnRateMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{RequestID: "req\nbad", CorrelationID: "corr_slo_safe"})
	ctx = withRequestFields(ctx)
	SetOrgID(ctx, "org unsafe")
	SetPrincipalID(ctx, "usr_slo_safe")
	SetResource(ctx, "service\nbad", "svc_slo_safe")

	metrics.RecordSLOBurnRate(ctx, SLOBurnRateObservation{
		Objective:      "api_availability:prod",
		Window:         "5000m",
		Severity:       "wake-the-world",
		Status:         "maybe",
		Signal:         "http_5xx_ratio?api_key=secret",
		BurnRate:       -2,
		ErrorBudgetPct: -10,
	})

	snapshot := metrics.Snapshot()
	got := findSLOBurnRateMetric(snapshot.Series, "other", "other", "other", "unknown", "other")
	if got == nil {
		t.Fatalf("missing bounded-cardinality SLO burn-rate metric: %+v", snapshot.Series)
	}
	if got.LastBurnRate != 0 || got.LastErrorBudgetPct != 0 {
		t.Errorf("bounded metric = %+v, want negative numeric values clamped to zero", *got)
	}
	if got.RequestID != "" || got.CorrelationID != "corr_slo_safe" {
		t.Errorf("correlation hints = %q/%q, want unsafe request dropped and safe correlation kept", got.RequestID, got.CorrelationID)
	}
	if got.OrganizationID != "" || got.PrincipalID != "usr_slo_safe" || got.ResourceKind != "" || got.ResourceID != "svc_slo_safe" {
		t.Errorf("identifier hints = %+v, want only SafeID-clean values", *got)
	}
}

func findSLOBurnRateMetric(metrics []SLOBurnRateMetric, objective, window, severity, status, signal string) *SLOBurnRateMetric {
	for i := range metrics {
		if metrics[i].Objective == objective && metrics[i].Window == window && metrics[i].Severity == severity && metrics[i].Status == status && metrics[i].Signal == signal {
			return &metrics[i]
		}
	}
	return nil
}

func TestDeadLetterAlertMetricsRecordsLowCardinalityAlerts(t *testing.T) {
	t.Parallel()

	metrics := NewDeadLetterAlertMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{RequestID: "req_dead_letter", CorrelationID: "corr_dead_letter"})
	ctx = withRequestFields(ctx)
	SetOrgID(ctx, "org_context_dead_letter")
	SetPrincipalID(ctx, "usr_dead_letter")
	SetResource(ctx, "service", "svc_dead_letter")
	SetJobID(ctx, "job_context_dead_letter")

	metrics.RecordDeadLetterAlert(ctx, DeadLetterAlertObservation{
		JobType:        "ensure_service",
		Reason:         "retry_budget_exhausted",
		Severity:       "page",
		Status:         "firing",
		OrganizationID: "org_dead_letter",
		ProjectID:      "proj_dead_letter",
		EnvironmentID:  "env_dead_letter",
		ServiceID:      "svc_dead_letter",
		JobID:          "job_dead_letter",
		Attempt:        3,
		MaxAttempts:    3,
	})
	metrics.RecordDeadLetterAlert(context.Background(), DeadLetterAlertObservation{
		JobType:  "ensure_service",
		Reason:   "operator_requeued",
		Severity: "ticket",
		Status:   "resolved",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalAlerts != 2 {
		t.Fatalf("total_alerts = %d, want 2", snapshot.TotalAlerts)
	}
	firing := findDeadLetterAlertMetric(snapshot.Series, "ensure_service", "retry_budget_exhausted", "page", "firing")
	if firing == nil {
		t.Fatalf("missing firing dead-letter alert metric: %+v", snapshot.Series)
	}
	if firing.Count != 1 || firing.Attempt != 3 || firing.MaxAttempts != 3 {
		t.Errorf("firing metric = %+v, want count=1 attempt=3 max_attempts=3", *firing)
	}
	if firing.RequestID != "req_dead_letter" || firing.CorrelationID != "corr_dead_letter" ||
		firing.OrganizationID != "org_dead_letter" || firing.ProjectID != "proj_dead_letter" ||
		firing.EnvironmentID != "env_dead_letter" || firing.ServiceID != "svc_dead_letter" ||
		firing.PrincipalID != "usr_dead_letter" || firing.ResourceKind != "service" ||
		firing.ResourceID != "svc_dead_letter" || firing.JobID != "job_dead_letter" {
		t.Errorf("firing hints = %+v, want request/resource/job correlation", *firing)
	}

	resolved := findDeadLetterAlertMetric(snapshot.Series, "ensure_service", "operator_requeued", "ticket", "resolved")
	if resolved == nil {
		t.Fatalf("missing resolved dead-letter alert metric: %+v", snapshot.Series)
	}
	if resolved.RequestID != "" || resolved.OrganizationID != "" {
		t.Errorf("resolved metric without context = %+v, want no unsafe identifiers", *resolved)
	}
}

func TestDeadLetterAlertMetricsBoundsCardinalityAndDropsUnsafeIdentifiers(t *testing.T) {
	t.Parallel()

	metrics := NewDeadLetterAlertMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{RequestID: "req\nbad", CorrelationID: "corr_dead_letter_safe"})
	ctx = withRequestFields(ctx)
	SetOrgID(ctx, "org unsafe")
	SetPrincipalID(ctx, "usr_dead_letter_safe")
	SetResource(ctx, "service\nbad", "svc_dead_letter_safe")

	metrics.RecordDeadLetterAlert(ctx, DeadLetterAlertObservation{
		JobType:        "ensure-service:prod",
		Reason:         "ran out of retries with token=secret",
		Severity:       "wake-the-world",
		Status:         "maybe",
		OrganizationID: "org unsafe",
		ProjectID:      "proj_dead_letter_safe",
		Attempt:        -1,
		MaxAttempts:    -2,
	})

	snapshot := metrics.Snapshot()
	got := findDeadLetterAlertMetric(snapshot.Series, "other", "other", "other", "unknown")
	if got == nil {
		t.Fatalf("missing bounded-cardinality dead-letter alert metric: %+v", snapshot.Series)
	}
	if got.Attempt != 0 || got.MaxAttempts != 0 {
		t.Errorf("bounded metric = %+v, want negative counts clamped to zero", *got)
	}
	if got.RequestID != "" || got.CorrelationID != "corr_dead_letter_safe" {
		t.Errorf("correlation hints = %q/%q, want unsafe request dropped and safe correlation kept", got.RequestID, got.CorrelationID)
	}
	if got.OrganizationID != "" || got.PrincipalID != "usr_dead_letter_safe" || got.ResourceKind != "" || got.ResourceID != "svc_dead_letter_safe" || got.ProjectID != "proj_dead_letter_safe" {
		t.Errorf("identifier hints = %+v, want only SafeID-clean values", *got)
	}
}

func findDeadLetterAlertMetric(metrics []DeadLetterAlertMetric, jobType, reason, severity, status string) *DeadLetterAlertMetric {
	for i := range metrics {
		if metrics[i].JobType == jobType && metrics[i].Reason == reason && metrics[i].Severity == severity && metrics[i].Status == status {
			return &metrics[i]
		}
	}
	return nil
}

func TestReconciliationDriftAlertMetricsRecordsLowCardinalityAlerts(t *testing.T) {
	t.Parallel()

	metrics := NewReconciliationDriftAlertMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{RequestID: "req_drift_alert", CorrelationID: "corr_drift_alert"})
	ctx = withRequestFields(ctx)
	SetOrgID(ctx, "org_context_drift")
	SetPrincipalID(ctx, "usr_drift")
	SetResource(ctx, "service", "svc_drift")
	SetJobID(ctx, "job_context_drift")

	metrics.RecordReconciliationDriftAlert(ctx, ReconciliationDriftAlertObservation{
		DriftKind:      "dangerous",
		ActionType:     "review_missing_service",
		Reason:         "service_missing",
		Severity:       "page",
		Status:         "firing",
		OrganizationID: "org_drift",
		ProjectID:      "proj_drift",
		EnvironmentID:  "env_drift",
		ServiceID:      "svc_drift",
		JobID:          "job_drift",
		ActionCount:    2,
		FailureCount:   1,
	})
	metrics.RecordReconciliationDriftAlert(context.Background(), ReconciliationDriftAlertObservation{
		DriftKind:  "none",
		ActionType: "none",
		Reason:     "no_drift",
		Severity:   "info",
		Status:     "resolved",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalAlerts != 2 {
		t.Fatalf("total_alerts = %d, want 2", snapshot.TotalAlerts)
	}
	firing := findReconciliationDriftAlertMetric(snapshot.Series, "dangerous", "review_missing_service", "service_missing", "page", "firing")
	if firing == nil {
		t.Fatalf("missing firing reconciliation drift alert metric: %+v", snapshot.Series)
	}
	if firing.Count != 1 || firing.ActionCount != 2 || firing.FailureCount != 1 {
		t.Errorf("firing metric = %+v, want count=1 action_count=2 failure_count=1", *firing)
	}
	if firing.RequestID != "req_drift_alert" || firing.CorrelationID != "corr_drift_alert" ||
		firing.OrganizationID != "org_drift" || firing.ProjectID != "proj_drift" ||
		firing.EnvironmentID != "env_drift" || firing.ServiceID != "svc_drift" ||
		firing.PrincipalID != "usr_drift" || firing.ResourceKind != "service" ||
		firing.ResourceID != "svc_drift" || firing.JobID != "job_drift" {
		t.Errorf("firing hints = %+v, want request/resource/job correlation", *firing)
	}

	resolved := findReconciliationDriftAlertMetric(snapshot.Series, "none", "none", "no_drift", "info", "resolved")
	if resolved == nil {
		t.Fatalf("missing resolved reconciliation drift alert metric: %+v", snapshot.Series)
	}
	if resolved.RequestID != "" || resolved.OrganizationID != "" {
		t.Errorf("resolved metric without context = %+v, want no unsafe identifiers", *resolved)
	}
}

func TestReconciliationDriftAlertMetricsBoundsCardinalityAndDropsUnsafeIdentifiers(t *testing.T) {
	t.Parallel()

	metrics := NewReconciliationDriftAlertMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{RequestID: "req\nbad", CorrelationID: "corr_drift_safe"})
	ctx = withRequestFields(ctx)
	SetOrgID(ctx, "org unsafe")
	SetPrincipalID(ctx, "usr_drift_safe")
	SetResource(ctx, "service\nbad", "svc_drift_safe")

	metrics.RecordReconciliationDriftAlert(ctx, ReconciliationDriftAlertObservation{
		DriftKind:      "dangerous:prod",
		ActionType:     "review_missing_service?token=secret",
		Reason:         "service_missing Authorization: Bearer secret",
		Severity:       "wake-the-world",
		Status:         "maybe",
		OrganizationID: "org unsafe",
		ProjectID:      "proj_drift_safe",
		ActionCount:    -1,
		FailureCount:   -2,
	})

	snapshot := metrics.Snapshot()
	got := findReconciliationDriftAlertMetric(snapshot.Series, "other", "other", "other", "other", "unknown")
	if got == nil {
		t.Fatalf("missing bounded-cardinality reconciliation drift alert metric: %+v", snapshot.Series)
	}
	if got.ActionCount != 0 || got.FailureCount != 0 {
		t.Errorf("bounded metric = %+v, want negative counts clamped to zero", *got)
	}
	if got.RequestID != "" || got.CorrelationID != "corr_drift_safe" {
		t.Errorf("correlation hints = %q/%q, want unsafe request dropped and safe correlation kept", got.RequestID, got.CorrelationID)
	}
	if got.OrganizationID != "" || got.PrincipalID != "usr_drift_safe" || got.ResourceKind != "" || got.ResourceID != "svc_drift_safe" || got.ProjectID != "proj_drift_safe" {
		t.Errorf("identifier hints = %+v, want only SafeID-clean values", *got)
	}
}

func findReconciliationDriftAlertMetric(metrics []ReconciliationDriftAlertMetric, driftKind, actionType, reason, severity, status string) *ReconciliationDriftAlertMetric {
	for i := range metrics {
		if metrics[i].DriftKind == driftKind && metrics[i].ActionType == actionType && metrics[i].Reason == reason && metrics[i].Severity == severity && metrics[i].Status == status {
			return &metrics[i]
		}
	}
	return nil
}

func TestTraceSpanMetricsRecordsHTTPSpansForSuccessAndFailure(t *testing.T) {
	t.Parallel()

	spans := NewTraceSpanMetrics()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			SetResource(r.Context(), "project", "proj_trace_failure")
			http.Error(w, "failed", http.StatusInternalServerError)
			return
		}
		SetOrgID(r.Context(), "org_trace_safe")
		SetPrincipalID(r.Context(), "usr_trace_safe")
		SetResource(r.Context(), "project", "proj_trace_success")
		w.WriteHeader(http.StatusCreated)
	})
	wrapped := Correlate(RequestLogging(nil)(TraceHTTPSpans(spans)(handler)))

	req := httptest.NewRequest(http.MethodPost, "/v1/projects", nil)
	req.Pattern = "/v1/projects"
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	req = httptest.NewRequest(http.MethodGet, "/fail?token=secret-query-value", nil)
	req.Pattern = "/v1/failures/{id}"
	rec = httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	snapshot := spans.Snapshot()
	if snapshot.TotalSpans != 2 {
		t.Fatalf("total_spans = %d, want 2", snapshot.TotalSpans)
	}
	success := findTraceSpanMetric(snapshot.Series, "http.request", "server", "/v1/projects", "success")
	if success == nil {
		t.Fatalf("missing success span metric: %+v", snapshot.Series)
	}
	if success.Count != 1 || success.StatusClass != "2xx" || success.OrganizationID != "org_trace_safe" || success.PrincipalID != "usr_trace_safe" {
		t.Errorf("success span = %+v, want 2xx with safe org/principal hints", *success)
	}
	if success.RequestID == "" || success.CorrelationID == "" || success.ResourceID != "proj_trace_success" {
		t.Errorf("success span = %+v, want request/correlation/resource hints", *success)
	}

	failure := findTraceSpanMetric(snapshot.Series, "http.request", "server", "/v1/failures/{id}", "error")
	if failure == nil {
		t.Fatalf("missing failure span metric: %+v", snapshot.Series)
	}
	if failure.Count != 1 || failure.StatusClass != "5xx" || failure.LastDurationMS < 0 {
		t.Errorf("failure span = %+v, want 5xx error span with non-negative duration", *failure)
	}
	if strings.Contains(failure.Target, "secret-query-value") {
		t.Errorf("failure target leaked secret query value: %q", failure.Target)
	}
}

func findTraceSpanMetric(metrics []TraceSpanMetric, name, kind, route, outcome string) *TraceSpanMetric {
	for i := range metrics {
		if metrics[i].Name == name && metrics[i].Kind == kind && metrics[i].Route == route && metrics[i].Outcome == outcome {
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

func TestPolicyDecisionMetricsRecordsDenialsWithSafeHints(t *testing.T) {
	t.Parallel()

	metrics := NewPolicyDecisionMetrics()
	ctx := WithCorrelation(contextWithFields(t), Correlation{
		RequestID:     "req_policy_metrics",
		CorrelationID: "corr_policy_metrics",
	})
	SetOrgID(ctx, "org_context_policy")
	SetPrincipalID(ctx, "usr_policy_metrics")

	metrics.RecordPolicyDecision(ctx, PolicyDecisionObservation{
		Action:         "project.create",
		ResourceKind:   "project",
		ResourceID:     "proj_policy_metrics",
		Decision:       "denied",
		Reason:         "denied_no_capability",
		OrganizationID: "org_policy_metrics",
		ProjectID:      "proj_policy_metrics",
	})
	metrics.RecordPolicyDecision(ctx, PolicyDecisionObservation{
		Action:         "project.create",
		ResourceKind:   "project",
		ResourceID:     "proj_policy_metrics_2",
		Decision:       "allowed",
		Reason:         "allowed_by_role",
		OrganizationID: "org_policy_metrics",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalDecisions != 2 {
		t.Fatalf("total_decisions = %d, want 2", snapshot.TotalDecisions)
	}
	if len(snapshot.Series) != 2 {
		t.Fatalf("series len = %d, want 2: %+v", len(snapshot.Series), snapshot.Series)
	}

	denied := findPolicyDecisionMetric(snapshot.Series, "project.create", "project", "denied", "denied_no_capability")
	if denied == nil {
		t.Fatalf("missing denied metric: %+v", snapshot.Series)
	}
	if denied.Count != 1 || denied.RequestID != "req_policy_metrics" || denied.CorrelationID != "corr_policy_metrics" {
		t.Errorf("denied metric = %+v, want request/correlation hints", *denied)
	}
	if denied.OrganizationID != "org_policy_metrics" || denied.PrincipalID != "usr_policy_metrics" || denied.ResourceID != "proj_policy_metrics" || denied.ProjectID != "proj_policy_metrics" {
		t.Errorf("denied metric = %+v, want safe latest-sample identity hints", *denied)
	}
}

func TestPolicyDecisionMetricsBoundsCardinalityAndDropsUnsafeIdentifiers(t *testing.T) {
	t.Parallel()

	metrics := NewPolicyDecisionMetrics()
	metrics.RecordPolicyDecision(context.Background(), PolicyDecisionObservation{
		Action:         "project.create\nAuthorization: Bearer yka_secret",
		ResourceKind:   "project",
		ResourceID:     "proj_bad\nsecret",
		Decision:       "maybe",
		Reason:         "reason with token=secret",
		OrganizationID: "org_ok",
		ProjectID:      "proj ok",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalDecisions != 1 || len(snapshot.Series) != 1 {
		t.Fatalf("snapshot = %+v, want one bounded series", snapshot)
	}
	got := snapshot.Series[0]
	if got.Action != "other" || got.ResourceKind != "project" || got.Decision != "other" || got.Reason != "other" {
		t.Fatalf("metric = %+v, want bounded dimensions", got)
	}
	if got.OrganizationID != "org_ok" || got.ResourceID != "" || got.ProjectID != "" {
		t.Fatalf("metric = %+v, want only safe identifiers retained", got)
	}
}

func findPolicyDecisionMetric(metrics []PolicyDecisionMetric, action, resourceKind, decision, reason string) *PolicyDecisionMetric {
	for i := range metrics {
		if metrics[i].Action == action && metrics[i].ResourceKind == resourceKind && metrics[i].Decision == decision && metrics[i].Reason == reason {
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

func TestReadinessDegradationMetricsRecordsReasons(t *testing.T) {
	t.Parallel()

	metrics := NewReadinessDegradationMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{
		RequestID:     "req_readyz_context",
		CorrelationID: "corr_readyz_context",
	})

	metrics.RecordReadinessProbe(ctx, ReadinessDegradationObservation{
		Check:  "database",
		Status: "failing",
		Reason: "pending",
	})
	metrics.RecordReadinessProbe(ctx, ReadinessDegradationObservation{
		Check:  "database",
		Status: "passing",
		Reason: "ready",
		JobID:  "job_readyz_context",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalProbes != 2 {
		t.Fatalf("total_probes = %d, want 2", snapshot.TotalProbes)
	}
	if len(snapshot.Series) != 2 {
		t.Fatalf("series len = %d, want 2: %+v", len(snapshot.Series), snapshot.Series)
	}

	failing := findReadinessDegradationMetric(snapshot.Series, "database", "failing", "pending")
	if failing == nil {
		t.Fatalf("missing failing database readiness metric: %+v", snapshot.Series)
	}
	if failing.Count != 1 || failing.RequestID != "req_readyz_context" || failing.CorrelationID != "corr_readyz_context" {
		t.Errorf("failing metric = %+v, want context correlation hints", *failing)
	}

	passing := findReadinessDegradationMetric(snapshot.Series, "database", "passing", "ready")
	if passing == nil {
		t.Fatalf("missing passing database readiness metric: %+v", snapshot.Series)
	}
	if passing.JobID != "job_readyz_context" {
		t.Errorf("passing metric = %+v, want safe job id hint", *passing)
	}
}

func TestReadinessDegradationMetricsBoundsCardinalityAndDropsUnsafeIdentifiers(t *testing.T) {
	t.Parallel()

	metrics := NewReadinessDegradationMetrics()
	metrics.RecordReadinessProbe(context.Background(), ReadinessDegradationObservation{
		Check:          "database\nAuthorization: Bearer yka_secret",
		Status:         "flapping",
		Reason:         "token=secret",
		OrganizationID: "org_readyz_safe",
		JobID:          "job bad",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalProbes != 1 || len(snapshot.Series) != 1 {
		t.Fatalf("snapshot = %+v, want one bounded series", snapshot)
	}
	got := snapshot.Series[0]
	if got.Check != "other" || got.Status != "unknown" || got.Reason != "other" {
		t.Fatalf("metric = %+v, want bounded dimensions", got)
	}
	if got.OrganizationID != "org_readyz_safe" || got.JobID != "" {
		t.Fatalf("metric = %+v, want only safe identifiers retained", got)
	}
}

func findReadinessDegradationMetric(metrics []ReadinessDegradationMetric, check, status, reason string) *ReadinessDegradationMetric {
	for i := range metrics {
		if metrics[i].Check == check && metrics[i].Status == status && metrics[i].Reason == reason {
			return &metrics[i]
		}
	}
	return nil
}
