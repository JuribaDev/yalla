package telemetry

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultHTTPMetrics is the process-wide request metrics collector used by the
// API handler unless tests or embedders inject their own collector.
var DefaultHTTPMetrics = NewHTTPMetrics()

// HTTPMetrics stores low-cardinality HTTP request counters and latency totals.
// It is safe for concurrent use by net/http handlers.
type HTTPMetrics struct {
	mu       sync.Mutex
	total    int64
	requests map[httpMetricKey]*httpMetricSeries
}

type httpMetricKey struct {
	method      string
	route       string
	statusCode  int
	statusClass string
}

type httpMetricSeries struct {
	HTTPRequestMetric
}

// HTTPMetricsSnapshot is the JSON-serializable operational view exposed to
// operators and tests.
type HTTPMetricsSnapshot struct {
	TotalRequests int64               `json:"total_requests"`
	Requests      []HTTPRequestMetric `json:"requests"`
}

// HTTPRequestMetric is one aggregate request-metric series. Method, Route,
// StatusCode, and StatusClass are the stable low-cardinality dimensions.
// RequestID, CorrelationID, OrganizationID, PrincipalID, and Target describe
// only the most recent request that updated the series so operators can join
// aggregates back to structured logs without making those identifiers labels.
type HTTPRequestMetric struct {
	Method         string `json:"method"`
	Route          string `json:"route"`
	StatusCode     int    `json:"status_code"`
	StatusClass    string `json:"status_class"`
	Count          int64  `json:"count"`
	TotalLatencyMS int64  `json:"total_latency_ms"`
	ResponseBytes  int64  `json:"response_bytes"`
	LastLatencyMS  int64  `json:"last_latency_ms"`
	RequestID      string `json:"request_id,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	PrincipalID    string `json:"principal_id,omitempty"`
	Target         string `json:"target,omitempty"`
}

// NewHTTPMetrics returns an empty HTTP request metrics collector.
func NewHTTPMetrics() *HTTPMetrics {
	return &HTTPMetrics{requests: make(map[httpMetricKey]*httpMetricSeries)}
}

// Snapshot returns a deterministic copy of all request metrics currently held
// by the collector.
func (m *HTTPMetrics) Snapshot() HTTPMetricsSnapshot {
	if m == nil {
		return HTTPMetricsSnapshot{Requests: []HTTPRequestMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := HTTPMetricsSnapshot{
		TotalRequests: m.total,
		Requests:      make([]HTTPRequestMetric, 0, len(m.requests)),
	}
	for _, series := range m.requests {
		out.Requests = append(out.Requests, series.HTTPRequestMetric)
	}
	sort.Slice(out.Requests, func(i, j int) bool {
		a, b := out.Requests[i], out.Requests[j]
		if a.Route != b.Route {
			return a.Route < b.Route
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		return a.StatusCode < b.StatusCode
	})
	return out
}

func (m *HTTPMetrics) record(r *http.Request, status, bytes int, latency time.Duration) {
	if m == nil {
		return
	}
	method := metricMethod(r.Method)
	route := metricRoute(r)
	statusClass := strconv.Itoa(status/100) + "xx"
	latencyMS := latency.Milliseconds()
	if latencyMS < 0 {
		latencyMS = 0
	}
	orgID, principalID := "", ""
	if f := fieldsFromContext(r.Context()); f != nil {
		orgID, principalID = f.snapshot()
	}
	c := FromContext(r.Context())
	target := logRedactor.Redact(r.URL.RequestURI())

	key := httpMetricKey{
		method:      method,
		route:       route,
		statusCode:  status,
		statusClass: statusClass,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.requests[key]
	if series == nil {
		series = &httpMetricSeries{HTTPRequestMetric: HTTPRequestMetric{
			Method:      method,
			Route:       route,
			StatusCode:  status,
			StatusClass: statusClass,
		}}
		m.requests[key] = series
	}
	series.Count++
	series.TotalLatencyMS += latencyMS
	series.ResponseBytes += int64(bytes)
	series.LastLatencyMS = latencyMS
	series.RequestID = c.RequestID
	series.CorrelationID = c.CorrelationID
	series.OrganizationID = orgID
	series.PrincipalID = principalID
	series.Target = target
}

func metricMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	default:
		return "OTHER"
	}
}

func metricRoute(r *http.Request) string {
	if r == nil || r.Pattern == "" {
		return "unmatched"
	}
	if i := strings.IndexByte(r.Pattern, ' '); i >= 0 && i+1 < len(r.Pattern) {
		return r.Pattern[i+1:]
	}
	return r.Pattern
}

// RequestMetrics records one aggregate metric after every request. It should
// run inside Correlate so request/correlation identifiers are available, and
// inside RequestLogging when org/principal enrichment should be visible.
func RequestMetrics(metrics *HTTPMetrics) func(http.Handler) http.Handler {
	if metrics == nil {
		metrics = DefaultHTTPMetrics
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			metrics.record(r, rec.status, rec.bytes, time.Since(start))
		})
	}
}
