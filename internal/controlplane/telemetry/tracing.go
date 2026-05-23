package telemetry

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultTraceSpanMetrics is the process-wide span collector used by the HTTP
// stack unless tests or embedders inject their own collector.
var DefaultTraceSpanMetrics = NewTraceSpanMetrics()

// TraceSpanKind is a bounded span-kind dimension. Keep this closed and
// low-cardinality; individual request, job, and resource identifiers belong on
// the metric as latest-sample hints only.
type TraceSpanKind string

const (
	// TraceSpanKindServer records inbound server-side work such as HTTP API
	// request handling.
	TraceSpanKindServer TraceSpanKind = "server"
	// TraceSpanKindClient records outbound dependency calls.
	TraceSpanKindClient TraceSpanKind = "client"
	// TraceSpanKindWorker records background worker job execution.
	TraceSpanKindWorker TraceSpanKind = "worker"
	// TraceSpanKindInternal records local internal control-plane work.
	TraceSpanKindInternal TraceSpanKind = "internal"
)

// TraceSpanObservation is one completed span observation. Name, Kind, Route,
// Component, Outcome, StatusClass, and ErrorCode are aggregate dimensions.
// Request/job/resource identifiers are latest-sample hints for joining a hot
// series to logs, audit rows, queue rows, and typed dependency metrics.
type TraceSpanObservation struct {
	Name           string
	Kind           TraceSpanKind
	Route          string
	Component      string
	Outcome        string
	StatusCode     int
	StatusClass    string
	ErrorCode      string
	Duration       time.Duration
	RequestID      string
	CorrelationID  string
	OrganizationID string
	PrincipalID    string
	ResourceKind   string
	ResourceID     string
	JobID          string
	Target         string
}

// TraceSpanMetric is one aggregate trace-span series. Dimensions are bounded
// and low-cardinality; identifiers describe only the latest sample.
type TraceSpanMetric struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Route           string `json:"route,omitempty"`
	Component       string `json:"component"`
	Outcome         string `json:"outcome"`
	StatusCode      int    `json:"status_code,omitempty"`
	StatusClass     string `json:"status_class"`
	ErrorCode       string `json:"error_code,omitempty"`
	Count           int64  `json:"count"`
	TotalDurationMS int64  `json:"total_duration_ms"`
	LastDurationMS  int64  `json:"last_duration_ms"`
	RequestID       string `json:"request_id,omitempty"`
	CorrelationID   string `json:"correlation_id,omitempty"`
	OrganizationID  string `json:"organization_id,omitempty"`
	PrincipalID     string `json:"principal_id,omitempty"`
	ResourceKind    string `json:"resource_kind,omitempty"`
	ResourceID      string `json:"resource_id,omitempty"`
	JobID           string `json:"job_id,omitempty"`
	Target          string `json:"target,omitempty"`
}

// TraceSpanMetricsSnapshot is the JSON-serializable operational view exposed
// to operators, tests, and the /metrics endpoint.
type TraceSpanMetricsSnapshot struct {
	TotalSpans int64             `json:"total_spans"`
	Series     []TraceSpanMetric `json:"series"`
}

// TraceSpanMetrics stores low-cardinality completed-span counters. It is safe
// for concurrent use by HTTP handlers and worker goroutines.
type TraceSpanMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[traceSpanMetricKey]*traceSpanMetricSeries
}

type traceSpanMetricKey struct {
	name        string
	kind        string
	route       string
	component   string
	outcome     string
	statusClass string
	errorCode   string
}

type traceSpanMetricSeries struct {
	TraceSpanMetric
}

// NewTraceSpanMetrics returns an empty distributed trace-span collector.
func NewTraceSpanMetrics() *TraceSpanMetrics {
	return &TraceSpanMetrics{series: make(map[traceSpanMetricKey]*traceSpanMetricSeries)}
}

// Snapshot returns a deterministic copy of all span metrics currently held by
// the collector.
func (m *TraceSpanMetrics) Snapshot() TraceSpanMetricsSnapshot {
	if m == nil {
		return TraceSpanMetricsSnapshot{Series: []TraceSpanMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := TraceSpanMetricsSnapshot{
		TotalSpans: m.total,
		Series:     make([]TraceSpanMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.TraceSpanMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Route != b.Route {
			return a.Route < b.Route
		}
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		if a.Outcome != b.Outcome {
			return a.Outcome < b.Outcome
		}
		return a.ErrorCode < b.ErrorCode
	})
	return out
}

// RecordTraceSpan aggregates one completed span.
func (m *TraceSpanMetrics) RecordTraceSpan(ctx context.Context, event TraceSpanObservation) {
	if m == nil {
		return
	}
	corr := FromContext(ctx)
	if event.RequestID != "" {
		corr.RequestID = event.RequestID
	}
	if event.CorrelationID != "" {
		corr.CorrelationID = event.CorrelationID
	}

	name := metricAuditToken(event.Name, "unknown")
	kind := metricTraceSpanKind(event.Kind)
	route := metricTraceRoute(event.Route)
	component := metricAuditToken(event.Component, "unknown")
	outcome := metricTraceOutcome(event.Outcome, event.StatusCode, event.ErrorCode)
	statusClass := strings.TrimSpace(event.StatusClass)
	if statusClass == "" && event.StatusCode > 0 {
		statusClass = strconv.Itoa(event.StatusCode/100) + "xx"
	}
	if statusClass == "" {
		statusClass = "none"
	}
	errorCode := metricAuditErrorCode(event.ErrorCode)
	if outcome == "success" {
		errorCode = ""
	}
	durationMS := event.Duration.Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}

	orgID, principalID, resourceKind, resourceID, jobID, fieldErrorCode := "", "", "", "", "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID, resourceKind, resourceID, jobID, fieldErrorCode = f.logSnapshot()
	}
	if event.ErrorCode == "" {
		errorCode = metricAuditErrorCode(fieldErrorCode)
	}
	if event.OrganizationID != "" {
		orgID = event.OrganizationID
	}
	if event.PrincipalID != "" {
		principalID = event.PrincipalID
	}
	if event.ResourceKind != "" {
		resourceKind = event.ResourceKind
	}
	if event.ResourceID != "" {
		resourceID = event.ResourceID
	}
	if event.JobID != "" {
		jobID = event.JobID
	}

	key := traceSpanMetricKey{
		name:        name,
		kind:        kind,
		route:       route,
		component:   component,
		outcome:     outcome,
		statusClass: statusClass,
		errorCode:   errorCode,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &traceSpanMetricSeries{TraceSpanMetric: TraceSpanMetric{
			Name:        name,
			Kind:        kind,
			Route:       route,
			Component:   component,
			Outcome:     outcome,
			StatusCode:  event.StatusCode,
			StatusClass: statusClass,
			ErrorCode:   errorCode,
		}}
		m.series[key] = series
	}
	series.Count++
	series.TotalDurationMS += durationMS
	series.LastDurationMS = durationMS
	series.RequestID = safeMetricID(corr.RequestID)
	series.CorrelationID = safeMetricID(corr.CorrelationID)
	series.OrganizationID = safeMetricID(orgID)
	series.PrincipalID = safeMetricID(principalID)
	series.ResourceKind = metricAuditToken(resourceKind, "")
	series.ResourceID = safeMetricID(resourceID)
	series.JobID = safeMetricID(jobID)
	series.Target = logRedactor.Redact(event.Target)
}

// TraceHTTPSpans records a server span for every HTTP request. It should run
// inside Correlate and RequestLogging so request/job/resource identifiers are
// available as latest-sample hints.
func TraceHTTPSpans(metrics *TraceSpanMetrics) func(http.Handler) http.Handler {
	if metrics == nil {
		metrics = DefaultTraceSpanMetrics
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, ctx: r.Context(), status: http.StatusOK}
			next.ServeHTTP(rec, r)
			status := rec.status
			metrics.RecordTraceSpan(r.Context(), TraceSpanObservation{
				Name:        "http.request",
				Kind:        TraceSpanKindServer,
				Route:       metricRoute(r),
				Component:   "httpapi",
				Outcome:     metricTraceOutcome("", status, ""),
				StatusCode:  status,
				StatusClass: statusClass(status),
				Duration:    time.Since(start),
				Target:      r.URL.RequestURI(),
			})
		})
	}
}

func metricTraceSpanKind(kind TraceSpanKind) string {
	switch kind {
	case TraceSpanKindServer, TraceSpanKindClient, TraceSpanKindWorker, TraceSpanKindInternal:
		return string(kind)
	default:
		return "internal"
	}
}

func metricTraceRoute(route string) string {
	route = strings.TrimSpace(route)
	if route == "" {
		return "unmatched"
	}
	return route
}

func metricTraceOutcome(outcome string, statusCode int, errorCode string) string {
	switch strings.TrimSpace(outcome) {
	case "success", "error", "cancelled":
		return strings.TrimSpace(outcome)
	}
	if strings.TrimSpace(errorCode) != "" || statusCode >= 400 {
		return "error"
	}
	return "success"
}
