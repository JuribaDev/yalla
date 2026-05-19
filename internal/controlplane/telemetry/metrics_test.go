package telemetry

import (
	"net/http"
	"net/http/httptest"
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
