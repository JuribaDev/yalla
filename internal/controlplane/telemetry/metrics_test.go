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
