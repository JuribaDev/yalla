package metering

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestTraefikAdapterCollectsWindowedPrometheusMetrics(t *testing.T) {
	t.Parallel()

	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" {
			t.Fatalf("path = %q, want /api/v1/query_range", r.URL.Path)
		}
		q := r.URL.Query()
		queries = append(queries, q.Get("query"))
		if q.Get("start") != "1770000000" || q.Get("end") != "1770000060" || q.Get("step") != "15" {
			t.Fatalf("window query = %s, want bounded start/end/step", r.URL.RawQuery)
		}
		writePromMatrix(t, w, promSeriesForQuery(q.Get("query")))
	}))
	defer server.Close()

	adapter, err := NewTraefikAdapter(TraefikAdapterConfig{
		BaseURL:      server.URL,
		QueryVersion: "traefik-prom-v1",
		HTTPClient:   server.Client(),
	})
	if err != nil {
		t.Fatalf("NewTraefikAdapter: %v", err)
	}

	start := time.Unix(1770000000, 0).UTC()
	end := start.Add(time.Minute)
	got, err := adapter.Collect(context.Background(), TraefikCollectInput{
		Start: start,
		End:   end,
		Step:  15 * time.Second,
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got.WindowStart != start || got.WindowEnd != end || got.QueryVersion != "traefik-prom-v1" {
		t.Fatalf("window metadata = (%v, %v, %q), want (%v, %v, traefik-prom-v1)", got.WindowStart, got.WindowEnd, got.QueryVersion, start, end)
	}
	if got.RawSampleChecksum == "" || len(got.RawSampleChecksum) != 64 {
		t.Fatalf("RawSampleChecksum = %q, want sha256 hex", got.RawSampleChecksum)
	}
	if got.DroppedSeries != 1 {
		t.Fatalf("DroppedSeries = %d, want 1 missing-service series skipped", got.DroppedSeries)
	}
	if len(queries) != 4 {
		t.Fatalf("queried %d metrics, want 4", len(queries))
	}

	byKey := map[string]TraefikMetricSample{}
	for _, s := range got.Samples {
		key := s.Name + "|" + s.Service + "|" + s.Status + "|" + s.Bucket
		byKey[key] = s
		if s.WindowStart != start || s.WindowEnd != end || s.QueryVersion != "traefik-prom-v1" {
			t.Fatalf("sample window metadata = %+v", s)
		}
		if s.RawSampleChecksum != got.RawSampleChecksum {
			t.Fatalf("sample checksum = %q, want collection checksum %q", s.RawSampleChecksum, got.RawSampleChecksum)
		}
	}

	assertSample(t, byKey, "http_requests|yalla-svc_123|200|", 19, "request")
	assertSample(t, byKey, "http_requests|yalla-svc_123|500|", 2, "request")
	assertSample(t, byKey, "http_5xx_count|yalla-svc_123||", 2, "response")
	assertSample(t, byKey, "http_rps_peak_1m|yalla-svc_123||", 0.8, "requests_per_second")
	assertSample(t, byKey, "http_request_bytes|yalla-svc_123||", 600, "byte")
	assertSample(t, byKey, "http_response_bytes|yalla-svc_123||", 1200, "byte")
	assertSample(t, byKey, "http_bandwidth_total|yalla-svc_123||", 1800, "byte")
	assertSample(t, byKey, "http_request_duration_seconds_bucket|yalla-svc_123||0.1", 12, "observation")
	assertSample(t, byKey, "http_request_duration_seconds_bucket|yalla-svc_123||+Inf", 14, "observation")
}

func TestTraefikAdapterRejectsInvalidWindowAndEndpoint(t *testing.T) {
	t.Parallel()

	if _, err := NewTraefikAdapter(TraefikAdapterConfig{BaseURL: "://bad"}); err == nil {
		t.Fatal("NewTraefikAdapter accepted malformed base URL")
	}
	adapter, err := NewTraefikAdapter(TraefikAdapterConfig{BaseURL: "https://prometheus.invalid"})
	if err != nil {
		t.Fatalf("NewTraefikAdapter: %v", err)
	}
	_, err = adapter.Collect(context.Background(), TraefikCollectInput{
		Start: time.Unix(10, 0),
		End:   time.Unix(10, 0),
		Step:  time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "end must be after start") {
		t.Fatalf("Collect invalid window error = %v, want end-after-start validation", err)
	}
	_, err = adapter.Collect(context.Background(), TraefikCollectInput{
		Start: time.Unix(0, 0),
		End:   time.Unix(1, 0),
		Step:  0,
	})
	if err == nil || !strings.Contains(err.Error(), "step must be positive") {
		t.Fatalf("Collect invalid step error = %v, want positive step validation", err)
	}
}

func TestTraefikAdapterProducesStableChecksumForDuplicateWindows(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writePromMatrix(t, w, promSeriesForQuery(r.URL.Query().Get("query")))
	}))
	defer server.Close()

	adapter, err := NewTraefikAdapter(TraefikAdapterConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewTraefikAdapter: %v", err)
	}
	in := TraefikCollectInput{Start: time.Unix(1770000000, 0), End: time.Unix(1770000060, 0), Step: 15 * time.Second}
	first, err := adapter.Collect(context.Background(), in)
	if err != nil {
		t.Fatalf("first Collect: %v", err)
	}
	second, err := adapter.Collect(context.Background(), in)
	if err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if first.RawSampleChecksum != second.RawSampleChecksum {
		t.Fatalf("duplicate window checksum drift: %q != %q", first.RawSampleChecksum, second.RawSampleChecksum)
	}
	if len(first.Samples) != len(second.Samples) {
		t.Fatalf("duplicate window sample count drift: %d != %d", len(first.Samples), len(second.Samples))
	}
}

func assertSample(t *testing.T, samples map[string]TraefikMetricSample, key string, want float64, unit string) {
	t.Helper()
	s, ok := samples[key]
	if !ok {
		keys := make([]string, 0, len(samples))
		for k := range samples {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Fatalf("missing sample %q; got keys %v", key, keys)
	}
	if math.Abs(s.Value-want) > 0.000000001 || s.Unit != unit {
		t.Fatalf("%s = (%v, %q), want (%v, %q)", key, s.Value, s.Unit, want, unit)
	}
}

func writePromMatrix(t *testing.T, w http.ResponseWriter, series []promSeries) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"status": "success",
		"data": map[string]any{
			"resultType": "matrix",
			"result":     series,
		},
	}); err != nil {
		t.Fatalf("write prometheus response: %v", err)
	}
}

type promSeries struct {
	Metric map[string]string `json:"metric"`
	Values [][]any           `json:"values"`
}

func promSeriesForQuery(query string) []promSeries {
	u, _ := url.ParseQuery("q=" + url.QueryEscape(query))
	query = u.Get("q")
	switch {
	case strings.Contains(query, "traefik_service_requests_total"):
		return []promSeries{
			{Metric: map[string]string{"service": "yalla-svc_123", "code": "200"}, Values: promValues(10, 5, 14)}, // reset: +5 +9 = 14
			{Metric: map[string]string{"service": "yalla-svc_123", "code": "200"}, Values: promValues(0, 5)},      // duplicate series merges to 19 after reset math: first series 14 + 5
			{Metric: map[string]string{"service": "yalla-svc_123", "code": "500"}, Values: promValues(1, 3)},
			{Metric: map[string]string{"code": "200"}, Values: promValues(1, 2)},
		}
	case strings.Contains(query, "traefik_service_requests_bytes_total"):
		return []promSeries{{Metric: map[string]string{"service": "yalla-svc_123"}, Values: promValues(100, 400, 700)}}
	case strings.Contains(query, "traefik_service_responses_bytes_total"):
		return []promSeries{{Metric: map[string]string{"service": "yalla-svc_123"}, Values: [][]any{{float64(1770000000), "1000"}, {float64(1770000015), "NaN"}, {float64(1770000030), "2200"}}}}
	case strings.Contains(query, "traefik_service_request_duration_seconds_bucket"):
		return []promSeries{
			{Metric: map[string]string{"service": "yalla-svc_123", "le": "0.1"}, Values: promValues(3, 9, 15)},
			{Metric: map[string]string{"service": "yalla-svc_123", "le": "+Inf"}, Values: promValues(10, 5, 14)},
		}
	default:
		return nil
	}
}

func promValues(vals ...float64) [][]any {
	out := make([][]any, 0, len(vals))
	for i, v := range vals {
		out = append(out, []any{float64(1770000000 + i*15), jsonNumber(v)})
	}
	return out
}

func jsonNumber(v float64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
