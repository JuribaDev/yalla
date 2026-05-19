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

// DefaultJobQueueMetrics is the process-wide durable-job queue metrics
// collector used by worker claimers unless tests or embedders inject their own.
var DefaultJobQueueMetrics = NewJobQueueMetrics()

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

// JobQueueEventName is a bounded event dimension for durable-job queue
// telemetry. Keep this closed and low-cardinality; individual job ids live on
// the metric as latest-sample hints, not labels.
type JobQueueEventName string

const (
	// JobQueueEventClaimed records a worker successfully leasing a job.
	JobQueueEventClaimed JobQueueEventName = "claimed"
	// JobQueueEventCompleted records a worker committing an outcome.
	JobQueueEventCompleted JobQueueEventName = "completed"
)

// JobQueueEvent is one durable-job queue observation. Event, JobType, Status,
// and StatusClass are the intended aggregate dimensions. JobID, request and
// resource identifiers are latest-sample hints for joining to logs and source
// rows during incidents.
type JobQueueEvent struct {
	Event          JobQueueEventName
	JobType        string
	Status         string
	StatusClass    string
	JobID          string
	RequestID      string
	CorrelationID  string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Attempt        int
	MaxAttempts    int
	NextRunDelayMS int64
}

// JobQueueMetric is one aggregate durable-job queue series.
type JobQueueMetric struct {
	Event          JobQueueEventName `json:"event"`
	JobType        string            `json:"job_type"`
	Status         string            `json:"status"`
	StatusClass    string            `json:"status_class"`
	Count          int64             `json:"count"`
	JobID          string            `json:"job_id,omitempty"`
	RequestID      string            `json:"request_id,omitempty"`
	CorrelationID  string            `json:"correlation_id,omitempty"`
	OrganizationID string            `json:"organization_id,omitempty"`
	ProjectID      string            `json:"project_id,omitempty"`
	EnvironmentID  string            `json:"environment_id,omitempty"`
	ServiceID      string            `json:"service_id,omitempty"`
	Attempt        int               `json:"attempt,omitempty"`
	MaxAttempts    int               `json:"max_attempts,omitempty"`
	NextRunDelayMS int64             `json:"next_run_delay_ms,omitempty"`
}

// JobQueueMetricsSnapshot is the JSON-serializable operational view exposed to
// operators, tests, and future metrics endpoints.
type JobQueueMetricsSnapshot struct {
	TotalEvents int64            `json:"total_events"`
	Series      []JobQueueMetric `json:"series"`
}

// JobQueueMetrics stores low-cardinality durable-job queue event counters. It
// is safe for concurrent use by workers.
type JobQueueMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[jobQueueMetricKey]*jobQueueMetricSeries
}

type jobQueueMetricKey struct {
	event       JobQueueEventName
	jobType     string
	status      string
	statusClass string
}

type jobQueueMetricSeries struct {
	JobQueueMetric
}

// NewHTTPMetrics returns an empty HTTP request metrics collector.
func NewHTTPMetrics() *HTTPMetrics {
	return &HTTPMetrics{requests: make(map[httpMetricKey]*httpMetricSeries)}
}

// NewJobQueueMetrics returns an empty durable-job queue metrics collector.
func NewJobQueueMetrics() *JobQueueMetrics {
	return &JobQueueMetrics{series: make(map[jobQueueMetricKey]*jobQueueMetricSeries)}
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

// Snapshot returns a deterministic copy of all durable-job queue metrics
// currently held by the collector.
func (m *JobQueueMetrics) Snapshot() JobQueueMetricsSnapshot {
	if m == nil {
		return JobQueueMetricsSnapshot{Series: []JobQueueMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := JobQueueMetricsSnapshot{
		TotalEvents: m.total,
		Series:      make([]JobQueueMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.JobQueueMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.Event != b.Event {
			return a.Event < b.Event
		}
		if a.JobType != b.JobType {
			return a.JobType < b.JobType
		}
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		return a.StatusClass < b.StatusClass
	})
	return out
}

// RecordJobQueueEvent aggregates one durable-job queue observation.
func (m *JobQueueMetrics) RecordJobQueueEvent(event JobQueueEvent) {
	if m == nil {
		return
	}
	event.Event = metricJobQueueEvent(event.Event)
	event.JobType = metricJobType(event.JobType)
	event.Status = metricJobStatus(event.Status)
	if strings.TrimSpace(event.StatusClass) == "" {
		event.StatusClass = metricJobStatusClass(event.Status)
	}

	key := jobQueueMetricKey{
		event:       event.Event,
		jobType:     event.JobType,
		status:      event.Status,
		statusClass: event.StatusClass,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &jobQueueMetricSeries{JobQueueMetric: JobQueueMetric{
			Event:       event.Event,
			JobType:     event.JobType,
			Status:      event.Status,
			StatusClass: event.StatusClass,
		}}
		m.series[key] = series
	}
	series.Count++
	series.JobID = event.JobID
	series.RequestID = event.RequestID
	series.CorrelationID = event.CorrelationID
	series.OrganizationID = event.OrganizationID
	series.ProjectID = event.ProjectID
	series.EnvironmentID = event.EnvironmentID
	series.ServiceID = event.ServiceID
	series.Attempt = event.Attempt
	series.MaxAttempts = event.MaxAttempts
	series.NextRunDelayMS = event.NextRunDelayMS
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

func metricJobQueueEvent(event JobQueueEventName) JobQueueEventName {
	switch event {
	case JobQueueEventClaimed, JobQueueEventCompleted:
		return event
	default:
		return "other"
	}
}

func metricJobType(jobType string) string {
	jobType = strings.TrimSpace(jobType)
	if jobType == "" {
		return "unknown"
	}
	return jobType
}

func metricJobStatus(status string) string {
	status = strings.TrimSpace(status)
	if status == "" {
		return "unknown"
	}
	return status
}

func metricJobStatusClass(status string) string {
	switch status {
	case "queued", "running":
		return "active"
	case "retrying":
		return "retry"
	case "succeeded":
		return "success"
	case "failed", "dead_letter", "cancelled":
		return "failure"
	default:
		return "other"
	}
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
