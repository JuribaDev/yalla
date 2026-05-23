package telemetry

import (
	"context"
	"math"
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

// DefaultDokployDependencyMetrics is the process-wide private-Dokploy
// dependency metrics collector used by the typed client unless tests or
// embedders inject their own collector.
var DefaultDokployDependencyMetrics = NewDokployDependencyMetrics()

// DefaultQuotaUsageMetrics is the process-wide quota decision metrics
// collector used by the quota checker unless tests or embedders inject their
// own collector.
var DefaultQuotaUsageMetrics = NewQuotaUsageMetrics()

// DefaultAuditEventMetrics is the process-wide audit-log append metrics
// collector used by the audit repository unless tests or embedders inject
// their own collector.
var DefaultAuditEventMetrics = NewAuditEventMetrics()

// DefaultPolicyDecisionMetrics is the process-wide policy authorization
// metrics collector used by the policy engine unless tests or embedders inject
// their own collector.
var DefaultPolicyDecisionMetrics = NewPolicyDecisionMetrics()

// DefaultSlowQueryMetrics is the process-wide datastore slow-query collector
// used by the store unless tests or embedders inject their own collector.
var DefaultSlowQueryMetrics = NewSlowQueryMetrics()

// DefaultReadinessDegradationMetrics is the process-wide readiness probe
// collector used by the HTTP API unless tests or embedders inject their own.
var DefaultReadinessDegradationMetrics = NewReadinessDegradationMetrics()

// DefaultSLOBurnRateMetrics is the process-wide SLO burn-rate alert collector
// used by operational alert adapters unless tests or embedders inject their
// own collector.
var DefaultSLOBurnRateMetrics = NewSLOBurnRateMetrics()

// DefaultDeadLetterAlertMetrics is the process-wide dead-letter alert
// collector used by worker claimers unless tests or embedders inject their own.
var DefaultDeadLetterAlertMetrics = NewDeadLetterAlertMetrics()

// DefaultReconciliationDriftAlertMetrics is the process-wide reconciliation
// drift alert collector used by reconcilers unless tests or embedders inject
// their own collector.
var DefaultReconciliationDriftAlertMetrics = NewReconciliationDriftAlertMetrics()

// DefaultSecretRedactionCanaryMetrics is the process-wide collector for
// redaction canary observations emitted by tests, smoke probes, or operational
// verification hooks.
var DefaultSecretRedactionCanaryMetrics = NewSecretRedactionCanaryMetrics()

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

// DokployDependencyEvent is one typed-client observation for the private
// Dokploy dependency. Method, Path, StatusCode, and ErrorCode are normalized
// into low-cardinality aggregate dimensions; request and Yalla resource IDs are
// latest-sample hints only.
type DokployDependencyEvent struct {
	Method         string
	Path           string
	StatusCode     int
	ErrorCode      string
	Retryable      bool
	Attempt        int
	Latency        time.Duration
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	JobID          string
}

// DokployDependencyMetric is one aggregate private-Dokploy dependency series.
// Method, Endpoint, Outcome, StatusCode, StatusClass, ErrorCode, and Retryable
// are the stable low-cardinality dimensions. Identifiers describe only the
// latest sample, so operators can join aggregate behavior to request/job logs.
type DokployDependencyMetric struct {
	Method         string `json:"method"`
	Endpoint       string `json:"endpoint"`
	Outcome        string `json:"outcome"`
	StatusCode     int    `json:"status_code,omitempty"`
	StatusClass    string `json:"status_class"`
	ErrorCode      string `json:"error_code,omitempty"`
	Retryable      bool   `json:"retryable,omitempty"`
	Count          int64  `json:"count"`
	TotalLatencyMS int64  `json:"total_latency_ms"`
	LastLatencyMS  int64  `json:"last_latency_ms"`
	RequestID      string `json:"request_id,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	EnvironmentID  string `json:"environment_id,omitempty"`
	ServiceID      string `json:"service_id,omitempty"`
	PrincipalID    string `json:"principal_id,omitempty"`
	JobID          string `json:"job_id,omitempty"`
	Attempt        int    `json:"attempt,omitempty"`
}

// DokployDependencyMetricsSnapshot is the JSON-serializable operational view
// exposed to operators, tests, and metrics endpoints.
type DokployDependencyMetricsSnapshot struct {
	TotalCalls int64                     `json:"total_calls"`
	Series     []DokployDependencyMetric `json:"series"`
}

// DokployDependencyMetrics stores low-cardinality private-Dokploy dependency
// counters. It is safe for concurrent use by API and worker goroutines.
type DokployDependencyMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[dokployDependencyMetricKey]*dokployDependencyMetricSeries
}

type dokployDependencyMetricKey struct {
	method      string
	endpoint    string
	outcome     string
	statusCode  int
	statusClass string
	errorCode   string
	retryable   bool
}

type dokployDependencyMetricSeries struct {
	DokployDependencyMetric
}

// QuotaUsageOutcome is the bounded outcome dimension for quota decisions.
// Keep this closed and low-cardinality; detailed counts and identifiers live
// on each metric as latest-sample hints.
type QuotaUsageOutcome string

const (
	// QuotaUsageOutcomeAllowed records a quota decision that allowed the unit
	// of work to proceed.
	QuotaUsageOutcomeAllowed QuotaUsageOutcome = "allowed"
	// QuotaUsageOutcomeRejected records a hard quota decision that rejected the
	// attempted allocation.
	QuotaUsageOutcomeRejected QuotaUsageOutcome = "rejected"
	// QuotaUsageOutcomeError records validation, dependency, or unexpected
	// errors reached while evaluating quota.
	QuotaUsageOutcomeError QuotaUsageOutcome = "error"
)

// QuotaUsageEvent is one quota checker observation. Resource, EnforcementMode,
// Outcome, and Reason are aggregate dimensions; request, organization,
// principal, and job identifiers are latest-sample hints for incident joins.
type QuotaUsageEvent struct {
	Resource        string
	EnforcementMode string
	Outcome         QuotaUsageOutcome
	Reason          string
	Current         int64
	Reserved        int64
	Requested       int64
	Limit           int64
	OrganizationID  string
	JobID           string
}

// QuotaUsageMetric is one aggregate quota-decision series.
type QuotaUsageMetric struct {
	Resource        string            `json:"resource"`
	EnforcementMode string            `json:"enforcement_mode"`
	Outcome         QuotaUsageOutcome `json:"outcome"`
	Reason          string            `json:"reason"`
	Count           int64             `json:"count"`
	Current         int64             `json:"current,omitempty"`
	Reserved        int64             `json:"reserved,omitempty"`
	Requested       int64             `json:"requested,omitempty"`
	Limit           int64             `json:"limit,omitempty"`
	RequestID       string            `json:"request_id,omitempty"`
	CorrelationID   string            `json:"correlation_id,omitempty"`
	OrganizationID  string            `json:"organization_id,omitempty"`
	PrincipalID     string            `json:"principal_id,omitempty"`
	JobID           string            `json:"job_id,omitempty"`
}

// QuotaUsageMetricsSnapshot is the JSON-serializable operational view exposed
// to operators, tests, and metrics endpoints.
type QuotaUsageMetricsSnapshot struct {
	TotalDecisions int64              `json:"total_decisions"`
	Series         []QuotaUsageMetric `json:"series"`
}

// QuotaUsageMetrics stores low-cardinality quota decision counters. It is safe
// for concurrent use by API and worker goroutines.
type QuotaUsageMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[quotaUsageMetricKey]*quotaUsageMetricSeries
}

type quotaUsageMetricKey struct {
	resource        string
	enforcementMode string
	outcome         QuotaUsageOutcome
	reason          string
}

type quotaUsageMetricSeries struct {
	QuotaUsageMetric
}

// AuditEventOutcome is the bounded outcome dimension for immutable audit-log
// append attempts.
type AuditEventOutcome string

const (
	// AuditEventOutcomeRecorded records an audit event that was durably
	// appended.
	AuditEventOutcomeRecorded AuditEventOutcome = "recorded"
	// AuditEventOutcomeFailed records an append attempt that failed before the
	// audit row was durably written.
	AuditEventOutcomeFailed AuditEventOutcome = "failed"
)

// AuditEventObservation is one immutable audit-log append observation. Action,
// ResourceKind, Decision, Outcome, Reason, and ErrorCode are aggregate
// dimensions; identifiers are latest-sample hints for incident joins.
type AuditEventObservation struct {
	Action         string
	ResourceKind   string
	ResourceID     string
	Decision       string
	Outcome        AuditEventOutcome
	Reason         string
	ErrorCode      string
	RequestID      string
	CorrelationID  string
	OrganizationID string
	ActorID        string
	JobID          string
}

// AuditEventMetric is one aggregate audit-log append series.
type AuditEventMetric struct {
	Action         string            `json:"action"`
	ResourceKind   string            `json:"resource_kind"`
	Decision       string            `json:"decision"`
	Outcome        AuditEventOutcome `json:"outcome"`
	Reason         string            `json:"reason"`
	ErrorCode      string            `json:"error_code,omitempty"`
	Count          int64             `json:"count"`
	RequestID      string            `json:"request_id,omitempty"`
	CorrelationID  string            `json:"correlation_id,omitempty"`
	OrganizationID string            `json:"organization_id,omitempty"`
	ResourceID     string            `json:"resource_id,omitempty"`
	ActorID        string            `json:"actor_id,omitempty"`
	JobID          string            `json:"job_id,omitempty"`
}

// AuditEventMetricsSnapshot is the JSON-serializable operational view exposed
// to operators, tests, and metrics endpoints.
type AuditEventMetricsSnapshot struct {
	TotalEvents int64              `json:"total_events"`
	Series      []AuditEventMetric `json:"series"`
}

// AuditEventMetrics stores low-cardinality audit-log append counters. It is
// safe for concurrent use by API and worker goroutines.
type AuditEventMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[auditEventMetricKey]*auditEventMetricSeries
}

type auditEventMetricKey struct {
	action       string
	resourceKind string
	decision     string
	outcome      AuditEventOutcome
	reason       string
	errorCode    string
}

type auditEventMetricSeries struct {
	AuditEventMetric
}

// PolicyDecisionObservation is one policy authorization observation. Action,
// ResourceKind, Decision, and Reason are aggregate dimensions; identifiers are
// latest-sample hints for incident joins and must never be used as labels.
type PolicyDecisionObservation struct {
	Action         string
	ResourceKind   string
	ResourceID     string
	Decision       string
	Reason         string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	PrincipalID    string
	JobID          string
}

// PolicyDecisionMetric is one aggregate policy authorization series.
type PolicyDecisionMetric struct {
	Action         string `json:"action"`
	ResourceKind   string `json:"resource_kind"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason"`
	Count          int64  `json:"count"`
	RequestID      string `json:"request_id,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	EnvironmentID  string `json:"environment_id,omitempty"`
	ServiceID      string `json:"service_id,omitempty"`
	ResourceID     string `json:"resource_id,omitempty"`
	PrincipalID    string `json:"principal_id,omitempty"`
	JobID          string `json:"job_id,omitempty"`
}

// PolicyDecisionMetricsSnapshot is the JSON-serializable operational view
// exposed to operators, tests, and metrics endpoints.
type PolicyDecisionMetricsSnapshot struct {
	TotalDecisions int64                  `json:"total_decisions"`
	Series         []PolicyDecisionMetric `json:"series"`
}

// PolicyDecisionMetrics stores low-cardinality authorization decision
// counters. It is safe for concurrent use by API and worker goroutines.
type PolicyDecisionMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[policyDecisionMetricKey]*policyDecisionMetricSeries
}

type policyDecisionMetricKey struct {
	action       string
	resourceKind string
	decision     string
	reason       string
}

type policyDecisionMetricSeries struct {
	PolicyDecisionMetric
}

// SlowQueryObservation is one datastore query observation that exceeded the
// configured slow-query threshold. Operation, QueryKind, and Outcome are the
// only aggregate dimensions; identifiers are latest-sample incident hints.
type SlowQueryObservation struct {
	Operation string
	QueryKind string
	Outcome   string
	Duration  time.Duration
	Threshold time.Duration
}

// SlowQueryMetric is one aggregate datastore slow-query series.
type SlowQueryMetric struct {
	Operation       string `json:"operation"`
	QueryKind       string `json:"query_kind"`
	Outcome         string `json:"outcome"`
	Count           int64  `json:"count"`
	TotalDurationMS int64  `json:"total_duration_ms"`
	LastDurationMS  int64  `json:"last_duration_ms"`
	ThresholdMS     int64  `json:"threshold_ms"`
	RequestID       string `json:"request_id,omitempty"`
	CorrelationID   string `json:"correlation_id,omitempty"`
	OrganizationID  string `json:"organization_id,omitempty"`
	PrincipalID     string `json:"principal_id,omitempty"`
	ResourceKind    string `json:"resource_kind,omitempty"`
	ResourceID      string `json:"resource_id,omitempty"`
	JobID           string `json:"job_id,omitempty"`
}

// SlowQueryMetricsSnapshot is the JSON-serializable operational view exposed
// to operators, tests, and metrics endpoints.
type SlowQueryMetricsSnapshot struct {
	TotalQueries int64             `json:"total_queries"`
	Series       []SlowQueryMetric `json:"series"`
}

// SlowQueryMetrics stores low-cardinality datastore slow-query counters. It is
// safe for concurrent use by API and worker goroutines.
type SlowQueryMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[slowQueryMetricKey]*slowQueryMetricSeries
}

type slowQueryMetricKey struct {
	operation string
	queryKind string
	outcome   string
}

type slowQueryMetricSeries struct {
	SlowQueryMetric
}

// ReadinessDegradationObservation is one /readyz dependency-gate observation.
// Check, Status, and Reason are aggregate dimensions; identifiers are latest
// sample hints for incident joins and must never be used as dashboard labels.
type ReadinessDegradationObservation struct {
	Check          string
	Status         string
	Reason         string
	OrganizationID string
	PrincipalID    string
	JobID          string
}

// ReadinessDegradationMetric is one aggregate readiness degradation series.
type ReadinessDegradationMetric struct {
	Check          string `json:"check"`
	Status         string `json:"status"`
	Reason         string `json:"reason"`
	Count          int64  `json:"count"`
	RequestID      string `json:"request_id,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	PrincipalID    string `json:"principal_id,omitempty"`
	JobID          string `json:"job_id,omitempty"`
}

// ReadinessDegradationSnapshot is the JSON-serializable operational view
// exposed to operators, tests, and metrics endpoints.
type ReadinessDegradationSnapshot struct {
	TotalProbes int64                        `json:"total_probes"`
	Series      []ReadinessDegradationMetric `json:"series"`
}

// ReadinessDegradationMetrics stores low-cardinality readiness probe counters.
// It is safe for concurrent use by API handlers.
type ReadinessDegradationMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[readinessDegradationMetricKey]*readinessDegradationMetricSeries
}

type readinessDegradationMetricKey struct {
	check  string
	status string
	reason string
}

type readinessDegradationMetricSeries struct {
	ReadinessDegradationMetric
}

// SLOBurnRateObservation is one operational burn-rate alert observation.
// Objective, Window, Severity, Status, and Signal are bounded aggregate
// dimensions. Identifiers and numeric values describe only the latest sample,
// so operators can join a hot series to logs or job rows without turning
// tenant/resource ids into labels.
type SLOBurnRateObservation struct {
	Objective      string
	Window         string
	Severity       string
	Status         string
	Signal         string
	BurnRate       float64
	ErrorBudgetPct float64
	OrganizationID string
	PrincipalID    string
	ResourceKind   string
	ResourceID     string
	JobID          string
}

// SLOBurnRateMetric is one aggregate SLO burn-rate alert series.
type SLOBurnRateMetric struct {
	Objective          string  `json:"objective"`
	Window             string  `json:"window"`
	Severity           string  `json:"severity"`
	Status             string  `json:"status"`
	Signal             string  `json:"signal"`
	Count              int64   `json:"count"`
	LastBurnRate       float64 `json:"last_burn_rate"`
	LastErrorBudgetPct float64 `json:"last_error_budget_pct"`
	RequestID          string  `json:"request_id,omitempty"`
	CorrelationID      string  `json:"correlation_id,omitempty"`
	OrganizationID     string  `json:"organization_id,omitempty"`
	PrincipalID        string  `json:"principal_id,omitempty"`
	ResourceKind       string  `json:"resource_kind,omitempty"`
	ResourceID         string  `json:"resource_id,omitempty"`
	JobID              string  `json:"job_id,omitempty"`
}

// SLOBurnRateMetricsSnapshot is the JSON-serializable operational view exposed
// to operators, tests, and the /metrics endpoint.
type SLOBurnRateMetricsSnapshot struct {
	TotalObservations int64               `json:"total_observations"`
	Series            []SLOBurnRateMetric `json:"series"`
}

// SLOBurnRateMetrics stores low-cardinality SLO burn-rate alert counters. It
// is safe for concurrent use by API and worker goroutines.
type SLOBurnRateMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[sloBurnRateMetricKey]*sloBurnRateMetricSeries
}

type sloBurnRateMetricKey struct {
	objective string
	window    string
	severity  string
	status    string
	signal    string
}

type sloBurnRateMetricSeries struct {
	SLOBurnRateMetric
}

// DeadLetterAlertObservation is one operational alert observation for a
// provisioning job that reached dead_letter. JobType, Reason, Severity, and
// Status are bounded aggregate dimensions; identifiers describe only the
// latest sample so dashboards stay low-cardinality.
type DeadLetterAlertObservation struct {
	JobType        string
	Reason         string
	Severity       string
	Status         string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	PrincipalID    string
	ResourceKind   string
	ResourceID     string
	JobID          string
	Attempt        int
	MaxAttempts    int
}

// DeadLetterAlertMetric is one aggregate dead-letter alert series.
type DeadLetterAlertMetric struct {
	JobType        string `json:"job_type"`
	Reason         string `json:"reason"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	Count          int64  `json:"count"`
	RequestID      string `json:"request_id,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	EnvironmentID  string `json:"environment_id,omitempty"`
	ServiceID      string `json:"service_id,omitempty"`
	PrincipalID    string `json:"principal_id,omitempty"`
	ResourceKind   string `json:"resource_kind,omitempty"`
	ResourceID     string `json:"resource_id,omitempty"`
	JobID          string `json:"job_id,omitempty"`
	Attempt        int    `json:"attempt,omitempty"`
	MaxAttempts    int    `json:"max_attempts,omitempty"`
}

// DeadLetterAlertMetricsSnapshot is the JSON-serializable operational view
// exposed to operators, tests, and the /metrics endpoint.
type DeadLetterAlertMetricsSnapshot struct {
	TotalAlerts int64                   `json:"total_alerts"`
	Series      []DeadLetterAlertMetric `json:"series"`
}

// DeadLetterAlertMetrics stores low-cardinality dead-letter alert counters.
// It is safe for concurrent use by API and worker goroutines.
type DeadLetterAlertMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[deadLetterAlertMetricKey]*deadLetterAlertMetricSeries
}

type deadLetterAlertMetricKey struct {
	jobType  string
	reason   string
	severity string
	status   string
}

type deadLetterAlertMetricSeries struct {
	DeadLetterAlertMetric
}

// ReconciliationDriftAlertObservation is one operational alert observation
// produced by a reconciliation tick. DriftKind, ActionType, Reason, Severity,
// and Status are bounded aggregate dimensions; identifiers describe only the
// latest sample so dashboards stay low-cardinality.
type ReconciliationDriftAlertObservation struct {
	DriftKind      string
	ActionType     string
	Reason         string
	Severity       string
	Status         string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	PrincipalID    string
	ResourceKind   string
	ResourceID     string
	JobID          string
	ActionCount    int
	FailureCount   int
}

// ReconciliationDriftAlertMetric is one aggregate reconciliation drift alert
// series.
type ReconciliationDriftAlertMetric struct {
	DriftKind      string `json:"drift_kind"`
	ActionType     string `json:"action_type"`
	Reason         string `json:"reason"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	Count          int64  `json:"count"`
	RequestID      string `json:"request_id,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	EnvironmentID  string `json:"environment_id,omitempty"`
	ServiceID      string `json:"service_id,omitempty"`
	PrincipalID    string `json:"principal_id,omitempty"`
	ResourceKind   string `json:"resource_kind,omitempty"`
	ResourceID     string `json:"resource_id,omitempty"`
	JobID          string `json:"job_id,omitempty"`
	ActionCount    int    `json:"action_count,omitempty"`
	FailureCount   int    `json:"failure_count,omitempty"`
}

// ReconciliationDriftAlertMetricsSnapshot is the JSON-serializable
// operational view exposed to operators, tests, and the /metrics endpoint.
type ReconciliationDriftAlertMetricsSnapshot struct {
	TotalAlerts int64                            `json:"total_alerts"`
	Series      []ReconciliationDriftAlertMetric `json:"series"`
}

// ReconciliationDriftAlertMetrics stores low-cardinality reconciliation drift
// alert counters. It is safe for concurrent use by API and worker goroutines.
type ReconciliationDriftAlertMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[reconciliationDriftAlertMetricKey]*reconciliationDriftAlertMetricSeries
}

type reconciliationDriftAlertMetricKey struct {
	driftKind  string
	actionType string
	reason     string
	severity   string
	status     string
}

type reconciliationDriftAlertMetricSeries struct {
	ReconciliationDriftAlertMetric
}

// SecretRedactionCanaryObservation is one redaction canary probe result.
// Surface, Vector, Outcome, and Reason are bounded aggregate dimensions;
// identifiers are latest-sample hints only. The probe secret itself must never
// be supplied to this type.
type SecretRedactionCanaryObservation struct {
	Surface        string
	Vector         string
	Outcome        string
	Reason         string
	OrganizationID string
	PrincipalID    string
	ResourceKind   string
	ResourceID     string
	JobID          string
}

// SecretRedactionCanaryMetric is one aggregate redaction canary series.
type SecretRedactionCanaryMetric struct {
	Surface        string `json:"surface"`
	Vector         string `json:"vector"`
	Outcome        string `json:"outcome"`
	Reason         string `json:"reason"`
	Count          int64  `json:"count"`
	RequestID      string `json:"request_id,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
	OrganizationID string `json:"organization_id,omitempty"`
	PrincipalID    string `json:"principal_id,omitempty"`
	ResourceKind   string `json:"resource_kind,omitempty"`
	ResourceID     string `json:"resource_id,omitempty"`
	JobID          string `json:"job_id,omitempty"`
}

// SecretRedactionCanaryMetricsSnapshot is the JSON-serializable operational
// view exposed to operators, tests, and the /metrics endpoint.
type SecretRedactionCanaryMetricsSnapshot struct {
	TotalObservations int64                         `json:"total_observations"`
	Series            []SecretRedactionCanaryMetric `json:"series"`
}

// SecretRedactionCanaryMetrics stores low-cardinality canary probe counters.
// It is safe for concurrent use by API, worker, and test goroutines.
type SecretRedactionCanaryMetrics struct {
	mu     sync.Mutex
	total  int64
	series map[secretRedactionCanaryMetricKey]*secretRedactionCanaryMetricSeries
}

type secretRedactionCanaryMetricKey struct {
	surface string
	vector  string
	outcome string
	reason  string
}

type secretRedactionCanaryMetricSeries struct {
	SecretRedactionCanaryMetric
}

// NewHTTPMetrics returns an empty HTTP request metrics collector.
func NewHTTPMetrics() *HTTPMetrics {
	return &HTTPMetrics{requests: make(map[httpMetricKey]*httpMetricSeries)}
}

// NewJobQueueMetrics returns an empty durable-job queue metrics collector.
func NewJobQueueMetrics() *JobQueueMetrics {
	return &JobQueueMetrics{series: make(map[jobQueueMetricKey]*jobQueueMetricSeries)}
}

// NewDokployDependencyMetrics returns an empty private-Dokploy dependency
// metrics collector.
func NewDokployDependencyMetrics() *DokployDependencyMetrics {
	return &DokployDependencyMetrics{series: make(map[dokployDependencyMetricKey]*dokployDependencyMetricSeries)}
}

// NewQuotaUsageMetrics returns an empty quota decision metrics collector.
func NewQuotaUsageMetrics() *QuotaUsageMetrics {
	return &QuotaUsageMetrics{series: make(map[quotaUsageMetricKey]*quotaUsageMetricSeries)}
}

// NewAuditEventMetrics returns an empty audit-log append metrics collector.
func NewAuditEventMetrics() *AuditEventMetrics {
	return &AuditEventMetrics{series: make(map[auditEventMetricKey]*auditEventMetricSeries)}
}

// NewPolicyDecisionMetrics returns an empty policy authorization decision
// metrics collector.
func NewPolicyDecisionMetrics() *PolicyDecisionMetrics {
	return &PolicyDecisionMetrics{series: make(map[policyDecisionMetricKey]*policyDecisionMetricSeries)}
}

// NewSlowQueryMetrics returns an empty datastore slow-query metrics collector.
func NewSlowQueryMetrics() *SlowQueryMetrics {
	return &SlowQueryMetrics{series: make(map[slowQueryMetricKey]*slowQueryMetricSeries)}
}

// NewReadinessDegradationMetrics returns an empty readiness degradation
// collector.
func NewReadinessDegradationMetrics() *ReadinessDegradationMetrics {
	return &ReadinessDegradationMetrics{series: make(map[readinessDegradationMetricKey]*readinessDegradationMetricSeries)}
}

// NewSLOBurnRateMetrics returns an empty SLO burn-rate alert collector.
func NewSLOBurnRateMetrics() *SLOBurnRateMetrics {
	return &SLOBurnRateMetrics{series: make(map[sloBurnRateMetricKey]*sloBurnRateMetricSeries)}
}

// NewDeadLetterAlertMetrics returns an empty dead-letter alert collector.
func NewDeadLetterAlertMetrics() *DeadLetterAlertMetrics {
	return &DeadLetterAlertMetrics{series: make(map[deadLetterAlertMetricKey]*deadLetterAlertMetricSeries)}
}

// NewReconciliationDriftAlertMetrics returns an empty reconciliation drift
// alert collector.
func NewReconciliationDriftAlertMetrics() *ReconciliationDriftAlertMetrics {
	return &ReconciliationDriftAlertMetrics{series: make(map[reconciliationDriftAlertMetricKey]*reconciliationDriftAlertMetricSeries)}
}

// NewSecretRedactionCanaryMetrics returns an empty redaction canary collector.
func NewSecretRedactionCanaryMetrics() *SecretRedactionCanaryMetrics {
	return &SecretRedactionCanaryMetrics{series: make(map[secretRedactionCanaryMetricKey]*secretRedactionCanaryMetricSeries)}
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

// Snapshot returns a deterministic copy of all private-Dokploy dependency
// metrics currently held by the collector.
func (m *DokployDependencyMetrics) Snapshot() DokployDependencyMetricsSnapshot {
	if m == nil {
		return DokployDependencyMetricsSnapshot{Series: []DokployDependencyMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := DokployDependencyMetricsSnapshot{
		TotalCalls: m.total,
		Series:     make([]DokployDependencyMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.DokployDependencyMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.Endpoint != b.Endpoint {
			return a.Endpoint < b.Endpoint
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		if a.Outcome != b.Outcome {
			return a.Outcome < b.Outcome
		}
		if a.StatusCode != b.StatusCode {
			return a.StatusCode < b.StatusCode
		}
		return a.ErrorCode < b.ErrorCode
	})
	return out
}

// Snapshot returns a deterministic copy of all quota decision metrics currently
// held by the collector.
func (m *QuotaUsageMetrics) Snapshot() QuotaUsageMetricsSnapshot {
	if m == nil {
		return QuotaUsageMetricsSnapshot{Series: []QuotaUsageMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := QuotaUsageMetricsSnapshot{
		TotalDecisions: m.total,
		Series:         make([]QuotaUsageMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.QuotaUsageMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		if a.EnforcementMode != b.EnforcementMode {
			return a.EnforcementMode < b.EnforcementMode
		}
		if a.Outcome != b.Outcome {
			return a.Outcome < b.Outcome
		}
		return a.Reason < b.Reason
	})
	return out
}

// Snapshot returns a deterministic copy of all audit-log append metrics
// currently held by the collector.
func (m *AuditEventMetrics) Snapshot() AuditEventMetricsSnapshot {
	if m == nil {
		return AuditEventMetricsSnapshot{Series: []AuditEventMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := AuditEventMetricsSnapshot{
		TotalEvents: m.total,
		Series:      make([]AuditEventMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.AuditEventMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		if a.ResourceKind != b.ResourceKind {
			return a.ResourceKind < b.ResourceKind
		}
		if a.Decision != b.Decision {
			return a.Decision < b.Decision
		}
		if a.Outcome != b.Outcome {
			return a.Outcome < b.Outcome
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return a.ErrorCode < b.ErrorCode
	})
	return out
}

// Snapshot returns a deterministic copy of all policy authorization decision
// metrics currently held by the collector.
func (m *PolicyDecisionMetrics) Snapshot() PolicyDecisionMetricsSnapshot {
	if m == nil {
		return PolicyDecisionMetricsSnapshot{Series: []PolicyDecisionMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := PolicyDecisionMetricsSnapshot{
		TotalDecisions: m.total,
		Series:         make([]PolicyDecisionMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.PolicyDecisionMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		if a.ResourceKind != b.ResourceKind {
			return a.ResourceKind < b.ResourceKind
		}
		if a.Decision != b.Decision {
			return a.Decision < b.Decision
		}
		return a.Reason < b.Reason
	})
	return out
}

// Snapshot returns a deterministic copy of all datastore slow-query metrics
// currently held by the collector.
func (m *SlowQueryMetrics) Snapshot() SlowQueryMetricsSnapshot {
	if m == nil {
		return SlowQueryMetricsSnapshot{Series: []SlowQueryMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := SlowQueryMetricsSnapshot{
		TotalQueries: m.total,
		Series:       make([]SlowQueryMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.SlowQueryMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.Operation != b.Operation {
			return a.Operation < b.Operation
		}
		if a.QueryKind != b.QueryKind {
			return a.QueryKind < b.QueryKind
		}
		return a.Outcome < b.Outcome
	})
	return out
}

// Snapshot returns a deterministic copy of all readiness degradation metrics
// currently held by the collector.
func (m *ReadinessDegradationMetrics) Snapshot() ReadinessDegradationSnapshot {
	if m == nil {
		return ReadinessDegradationSnapshot{Series: []ReadinessDegradationMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := ReadinessDegradationSnapshot{
		TotalProbes: m.total,
		Series:      make([]ReadinessDegradationMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.ReadinessDegradationMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		return a.Reason < b.Reason
	})
	return out
}

// Snapshot returns a deterministic copy of all SLO burn-rate alert metrics
// currently held by the collector.
func (m *SLOBurnRateMetrics) Snapshot() SLOBurnRateMetricsSnapshot {
	if m == nil {
		return SLOBurnRateMetricsSnapshot{Series: []SLOBurnRateMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := SLOBurnRateMetricsSnapshot{
		TotalObservations: m.total,
		Series:            make([]SLOBurnRateMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.SLOBurnRateMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.Objective != b.Objective {
			return a.Objective < b.Objective
		}
		if a.Window != b.Window {
			return a.Window < b.Window
		}
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		return a.Signal < b.Signal
	})
	return out
}

// Snapshot returns a deterministic copy of all dead-letter alert metrics
// currently held by the collector.
func (m *DeadLetterAlertMetrics) Snapshot() DeadLetterAlertMetricsSnapshot {
	if m == nil {
		return DeadLetterAlertMetricsSnapshot{Series: []DeadLetterAlertMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := DeadLetterAlertMetricsSnapshot{
		TotalAlerts: m.total,
		Series:      make([]DeadLetterAlertMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.DeadLetterAlertMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.JobType != b.JobType {
			return a.JobType < b.JobType
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		return a.Status < b.Status
	})
	return out
}

// Snapshot returns a deterministic copy of all reconciliation drift alert
// metrics currently held by the collector.
func (m *ReconciliationDriftAlertMetrics) Snapshot() ReconciliationDriftAlertMetricsSnapshot {
	if m == nil {
		return ReconciliationDriftAlertMetricsSnapshot{Series: []ReconciliationDriftAlertMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := ReconciliationDriftAlertMetricsSnapshot{
		TotalAlerts: m.total,
		Series:      make([]ReconciliationDriftAlertMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.ReconciliationDriftAlertMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.DriftKind != b.DriftKind {
			return a.DriftKind < b.DriftKind
		}
		if a.ActionType != b.ActionType {
			return a.ActionType < b.ActionType
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		return a.Status < b.Status
	})
	return out
}

// Snapshot returns a deterministic copy of all redaction canary metrics
// currently held by the collector.
func (m *SecretRedactionCanaryMetrics) Snapshot() SecretRedactionCanaryMetricsSnapshot {
	if m == nil {
		return SecretRedactionCanaryMetricsSnapshot{Series: []SecretRedactionCanaryMetric{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	out := SecretRedactionCanaryMetricsSnapshot{
		TotalObservations: m.total,
		Series:            make([]SecretRedactionCanaryMetric, 0, len(m.series)),
	}
	for _, series := range m.series {
		out.Series = append(out.Series, series.SecretRedactionCanaryMetric)
	}
	sort.Slice(out.Series, func(i, j int) bool {
		a, b := out.Series[i], out.Series[j]
		if a.Surface != b.Surface {
			return a.Surface < b.Surface
		}
		if a.Vector != b.Vector {
			return a.Vector < b.Vector
		}
		if a.Outcome != b.Outcome {
			return a.Outcome < b.Outcome
		}
		return a.Reason < b.Reason
	})
	return out
}

// RecordPolicyDecision aggregates one policy authorization observation.
func (m *PolicyDecisionMetrics) RecordPolicyDecision(ctx context.Context, event PolicyDecisionObservation) {
	if m == nil {
		return
	}
	action := metricAuditToken(event.Action, "unknown")
	resourceKind := metricAuditToken(event.ResourceKind, "unknown")
	decision := metricAuditDecision(event.Decision)
	reason := metricAuditToken(event.Reason, "unknown")

	corr := FromContext(ctx)
	orgID, principalID := "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID = f.snapshot()
	}
	if strings.TrimSpace(event.OrganizationID) != "" {
		orgID = strings.TrimSpace(event.OrganizationID)
	}
	if strings.TrimSpace(event.PrincipalID) != "" {
		principalID = strings.TrimSpace(event.PrincipalID)
	}

	key := policyDecisionMetricKey{
		action:       action,
		resourceKind: resourceKind,
		decision:     decision,
		reason:       reason,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &policyDecisionMetricSeries{PolicyDecisionMetric: PolicyDecisionMetric{
			Action:       action,
			ResourceKind: resourceKind,
			Decision:     decision,
			Reason:       reason,
		}}
		m.series[key] = series
	}
	series.Count++
	series.RequestID = corr.RequestID
	series.CorrelationID = corr.CorrelationID
	series.OrganizationID = safeMetricID(orgID)
	series.ProjectID = safeMetricID(event.ProjectID)
	series.EnvironmentID = safeMetricID(event.EnvironmentID)
	series.ServiceID = safeMetricID(event.ServiceID)
	series.ResourceID = safeMetricID(event.ResourceID)
	series.PrincipalID = safeMetricID(principalID)
	series.JobID = safeMetricID(event.JobID)
}

// RecordAuditEventAppend aggregates one immutable audit-log append observation.
func (m *AuditEventMetrics) RecordAuditEventAppend(ctx context.Context, event AuditEventObservation) {
	if m == nil {
		return
	}
	action := metricAuditToken(event.Action, "unknown")
	resourceKind := metricAuditToken(event.ResourceKind, "unknown")
	decision := metricAuditDecision(event.Decision)
	outcome := metricAuditOutcome(event.Outcome)
	reason := metricAuditToken(event.Reason, "unknown")
	errorCode := metricAuditErrorCode(event.ErrorCode)
	if outcome == AuditEventOutcomeRecorded {
		errorCode = ""
	}

	corr := FromContext(ctx)
	if event.RequestID != "" {
		corr.RequestID = event.RequestID
	}
	if event.CorrelationID != "" {
		corr.CorrelationID = event.CorrelationID
	}

	key := auditEventMetricKey{
		action:       action,
		resourceKind: resourceKind,
		decision:     decision,
		outcome:      outcome,
		reason:       reason,
		errorCode:    errorCode,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &auditEventMetricSeries{AuditEventMetric: AuditEventMetric{
			Action:       action,
			ResourceKind: resourceKind,
			Decision:     decision,
			Outcome:      outcome,
			Reason:       reason,
			ErrorCode:    errorCode,
		}}
		m.series[key] = series
	}
	series.Count++
	series.RequestID = corr.RequestID
	series.CorrelationID = corr.CorrelationID
	series.OrganizationID = safeMetricID(event.OrganizationID)
	series.ResourceID = safeMetricID(event.ResourceID)
	series.ActorID = safeMetricID(event.ActorID)
	series.JobID = safeMetricID(event.JobID)
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

// RecordDokployDependencyCall aggregates one private-Dokploy dependency
// observation. The endpoint is normalized before storage so Dokploy object IDs,
// query strings, and credentials never become metric labels.
func (m *DokployDependencyMetrics) RecordDokployDependencyCall(ctx context.Context, event DokployDependencyEvent) {
	if m == nil {
		return
	}
	method := metricMethod(event.Method)
	endpoint := metricDokployEndpoint(event.Path)
	outcome := "success"
	statusClass := "none"
	if event.StatusCode > 0 {
		statusClass = strconv.Itoa(event.StatusCode/100) + "xx"
	}
	errorCode := strings.TrimSpace(event.ErrorCode)
	if errorCode != "" || event.StatusCode >= 400 {
		outcome = "failure"
	}
	if errorCode != "" {
		statusClass = "dependency_error"
	}
	latencyMS := event.Latency.Milliseconds()
	if latencyMS < 0 {
		latencyMS = 0
	}

	corr := FromContext(ctx)
	orgID, principalID := "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID = f.snapshot()
	}
	if strings.TrimSpace(event.OrganizationID) != "" {
		orgID = strings.TrimSpace(event.OrganizationID)
	}

	key := dokployDependencyMetricKey{
		method:      method,
		endpoint:    endpoint,
		outcome:     outcome,
		statusCode:  event.StatusCode,
		statusClass: statusClass,
		errorCode:   errorCode,
		retryable:   event.Retryable,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &dokployDependencyMetricSeries{DokployDependencyMetric: DokployDependencyMetric{
			Method:      method,
			Endpoint:    endpoint,
			Outcome:     outcome,
			StatusCode:  event.StatusCode,
			StatusClass: statusClass,
			ErrorCode:   errorCode,
			Retryable:   event.Retryable,
		}}
		m.series[key] = series
	}
	series.Count++
	series.TotalLatencyMS += latencyMS
	series.LastLatencyMS = latencyMS
	series.RequestID = corr.RequestID
	series.CorrelationID = corr.CorrelationID
	series.OrganizationID = orgID
	series.ProjectID = strings.TrimSpace(event.ProjectID)
	series.EnvironmentID = strings.TrimSpace(event.EnvironmentID)
	series.ServiceID = strings.TrimSpace(event.ServiceID)
	series.PrincipalID = principalID
	series.JobID = strings.TrimSpace(event.JobID)
	series.Attempt = event.Attempt
}

// RecordQuotaUsageDecision aggregates one quota checker observation.
func (m *QuotaUsageMetrics) RecordQuotaUsageDecision(ctx context.Context, event QuotaUsageEvent) {
	if m == nil {
		return
	}
	resource := metricQuotaResource(event.Resource)
	mode := metricQuotaEnforcementMode(event.EnforcementMode)
	outcome := metricQuotaOutcome(event.Outcome)
	reason := metricQuotaReason(event.Reason)

	corr := FromContext(ctx)
	orgID, principalID := "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID = f.snapshot()
	}
	if strings.TrimSpace(event.OrganizationID) != "" {
		orgID = strings.TrimSpace(event.OrganizationID)
	}

	key := quotaUsageMetricKey{
		resource:        resource,
		enforcementMode: mode,
		outcome:         outcome,
		reason:          reason,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &quotaUsageMetricSeries{QuotaUsageMetric: QuotaUsageMetric{
			Resource:        resource,
			EnforcementMode: mode,
			Outcome:         outcome,
			Reason:          reason,
		}}
		m.series[key] = series
	}
	series.Count++
	series.Current = clampMetricCount(event.Current)
	series.Reserved = clampMetricCount(event.Reserved)
	series.Requested = clampMetricCount(event.Requested)
	series.Limit = clampMetricCount(event.Limit)
	series.RequestID = corr.RequestID
	series.CorrelationID = corr.CorrelationID
	series.OrganizationID = orgID
	series.PrincipalID = principalID
	series.JobID = strings.TrimSpace(event.JobID)
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

// RecordSlowQuery aggregates one datastore slow-query observation.
func (m *SlowQueryMetrics) RecordSlowQuery(ctx context.Context, event SlowQueryObservation) {
	if m == nil {
		return
	}
	operation := metricStoreOperation(event.Operation)
	queryKind := metricQueryKind(event.QueryKind)
	outcome := metricStoreOutcome(event.Outcome)
	durationMS := event.Duration.Milliseconds()
	if durationMS < 0 {
		durationMS = 0
	}
	thresholdMS := event.Threshold.Milliseconds()
	if thresholdMS < 0 {
		thresholdMS = 0
	}

	corr := FromContext(ctx)
	orgID, principalID, resourceKind, resourceID, jobID := "", "", "", "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID, resourceKind, resourceID, jobID, _ = f.logSnapshot()
	}

	key := slowQueryMetricKey{
		operation: operation,
		queryKind: queryKind,
		outcome:   outcome,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &slowQueryMetricSeries{SlowQueryMetric: SlowQueryMetric{
			Operation: operation,
			QueryKind: queryKind,
			Outcome:   outcome,
		}}
		m.series[key] = series
	}
	series.Count++
	series.TotalDurationMS += durationMS
	series.LastDurationMS = durationMS
	series.ThresholdMS = thresholdMS
	series.RequestID = safeMetricID(corr.RequestID)
	series.CorrelationID = safeMetricID(corr.CorrelationID)
	series.OrganizationID = safeMetricID(orgID)
	series.PrincipalID = safeMetricID(principalID)
	series.ResourceKind = safeMetricID(resourceKind)
	series.ResourceID = safeMetricID(resourceID)
	series.JobID = safeMetricID(jobID)
}

// RecordReadinessProbe aggregates one readiness dependency-gate observation.
func (m *ReadinessDegradationMetrics) RecordReadinessProbe(ctx context.Context, event ReadinessDegradationObservation) {
	if m == nil {
		return
	}
	check := metricAuditToken(event.Check, "unknown")
	status := metricReadinessStatus(event.Status)
	reason := metricAuditToken(event.Reason, "unknown")

	corr := FromContext(ctx)
	orgID, principalID := "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID = f.snapshot()
	}
	if strings.TrimSpace(event.OrganizationID) != "" {
		orgID = strings.TrimSpace(event.OrganizationID)
	}
	if strings.TrimSpace(event.PrincipalID) != "" {
		principalID = strings.TrimSpace(event.PrincipalID)
	}

	key := readinessDegradationMetricKey{
		check:  check,
		status: status,
		reason: reason,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &readinessDegradationMetricSeries{ReadinessDegradationMetric: ReadinessDegradationMetric{
			Check:  check,
			Status: status,
			Reason: reason,
		}}
		m.series[key] = series
	}
	series.Count++
	series.RequestID = safeMetricID(corr.RequestID)
	series.CorrelationID = safeMetricID(corr.CorrelationID)
	series.OrganizationID = safeMetricID(orgID)
	series.PrincipalID = safeMetricID(principalID)
	series.JobID = safeMetricID(event.JobID)
}

// RecordSLOBurnRate aggregates one SLO burn-rate alert observation.
func (m *SLOBurnRateMetrics) RecordSLOBurnRate(ctx context.Context, event SLOBurnRateObservation) {
	if m == nil {
		return
	}
	objective := metricSLOToken(event.Objective, "unknown")
	window := metricSLOWindow(event.Window)
	severity := metricSLOSeverity(event.Severity)
	status := metricSLOStatus(event.Status)
	signal := metricSLOToken(event.Signal, "unknown")

	corr := FromContext(ctx)
	orgID, principalID, resourceKind, resourceID, jobID := "", "", "", "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID, resourceKind, resourceID, jobID, _ = f.logSnapshot()
	}
	if strings.TrimSpace(event.OrganizationID) != "" {
		orgID = strings.TrimSpace(event.OrganizationID)
	}
	if strings.TrimSpace(event.PrincipalID) != "" {
		principalID = strings.TrimSpace(event.PrincipalID)
	}
	if strings.TrimSpace(event.ResourceKind) != "" {
		resourceKind = strings.TrimSpace(event.ResourceKind)
	}
	if strings.TrimSpace(event.ResourceID) != "" {
		resourceID = strings.TrimSpace(event.ResourceID)
	}
	if strings.TrimSpace(event.JobID) != "" {
		jobID = strings.TrimSpace(event.JobID)
	}

	key := sloBurnRateMetricKey{
		objective: objective,
		window:    window,
		severity:  severity,
		status:    status,
		signal:    signal,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &sloBurnRateMetricSeries{SLOBurnRateMetric: SLOBurnRateMetric{
			Objective: objective,
			Window:    window,
			Severity:  severity,
			Status:    status,
			Signal:    signal,
		}}
		m.series[key] = series
	}
	series.Count++
	series.LastBurnRate = clampMetricFloat(event.BurnRate)
	series.LastErrorBudgetPct = clampMetricFloat(event.ErrorBudgetPct)
	series.RequestID = safeMetricID(corr.RequestID)
	series.CorrelationID = safeMetricID(corr.CorrelationID)
	series.OrganizationID = safeMetricID(orgID)
	series.PrincipalID = safeMetricID(principalID)
	series.ResourceKind = safeMetricID(resourceKind)
	series.ResourceID = safeMetricID(resourceID)
	series.JobID = safeMetricID(jobID)
}

// RecordDeadLetterAlert aggregates one dead-letter alert observation.
func (m *DeadLetterAlertMetrics) RecordDeadLetterAlert(ctx context.Context, event DeadLetterAlertObservation) {
	if m == nil {
		return
	}
	jobType := metricSLOToken(event.JobType, "unknown")
	reason := metricSLOToken(event.Reason, "unknown")
	severity := metricSLOSeverity(event.Severity)
	status := metricSLOStatus(event.Status)

	corr := FromContext(ctx)
	orgID, principalID, resourceKind, resourceID, jobID := "", "", "", "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID, resourceKind, resourceID, jobID, _ = f.logSnapshot()
	}
	if strings.TrimSpace(event.OrganizationID) != "" {
		orgID = strings.TrimSpace(event.OrganizationID)
	}
	if strings.TrimSpace(event.PrincipalID) != "" {
		principalID = strings.TrimSpace(event.PrincipalID)
	}
	if strings.TrimSpace(event.ResourceKind) != "" {
		resourceKind = strings.TrimSpace(event.ResourceKind)
	}
	if strings.TrimSpace(event.ResourceID) != "" {
		resourceID = strings.TrimSpace(event.ResourceID)
	}
	if strings.TrimSpace(event.ServiceID) != "" && resourceID == "" {
		resourceKind = "service"
		resourceID = strings.TrimSpace(event.ServiceID)
	}
	if strings.TrimSpace(event.JobID) != "" {
		jobID = strings.TrimSpace(event.JobID)
	}

	key := deadLetterAlertMetricKey{
		jobType:  jobType,
		reason:   reason,
		severity: severity,
		status:   status,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &deadLetterAlertMetricSeries{DeadLetterAlertMetric: DeadLetterAlertMetric{
			JobType:  jobType,
			Reason:   reason,
			Severity: severity,
			Status:   status,
		}}
		m.series[key] = series
	}
	series.Count++
	series.RequestID = safeMetricID(corr.RequestID)
	series.CorrelationID = safeMetricID(corr.CorrelationID)
	series.OrganizationID = safeMetricID(orgID)
	series.ProjectID = safeMetricID(event.ProjectID)
	series.EnvironmentID = safeMetricID(event.EnvironmentID)
	series.ServiceID = safeMetricID(event.ServiceID)
	series.PrincipalID = safeMetricID(principalID)
	series.ResourceKind = safeMetricID(resourceKind)
	series.ResourceID = safeMetricID(resourceID)
	series.JobID = safeMetricID(jobID)
	series.Attempt = int(clampMetricCount(int64(event.Attempt)))
	series.MaxAttempts = int(clampMetricCount(int64(event.MaxAttempts)))
}

// RecordReconciliationDriftAlert aggregates one reconciliation drift alert
// observation.
func (m *ReconciliationDriftAlertMetrics) RecordReconciliationDriftAlert(ctx context.Context, event ReconciliationDriftAlertObservation) {
	if m == nil {
		return
	}
	driftKind := metricSLOToken(event.DriftKind, "unknown")
	actionType := metricSLOToken(event.ActionType, "unknown")
	reason := metricSLOToken(event.Reason, "unknown")
	severity := metricSLOSeverity(event.Severity)
	status := metricSLOStatus(event.Status)

	corr := FromContext(ctx)
	orgID, principalID, resourceKind, resourceID, jobID := "", "", "", "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID, resourceKind, resourceID, jobID, _ = f.logSnapshot()
	}
	if strings.TrimSpace(event.OrganizationID) != "" {
		orgID = strings.TrimSpace(event.OrganizationID)
	}
	if strings.TrimSpace(event.PrincipalID) != "" {
		principalID = strings.TrimSpace(event.PrincipalID)
	}
	if strings.TrimSpace(event.ResourceKind) != "" {
		resourceKind = strings.TrimSpace(event.ResourceKind)
	}
	if strings.TrimSpace(event.ResourceID) != "" {
		resourceID = strings.TrimSpace(event.ResourceID)
	}
	if strings.TrimSpace(event.ServiceID) != "" && resourceID == "" {
		resourceKind = "service"
		resourceID = strings.TrimSpace(event.ServiceID)
	}
	if strings.TrimSpace(event.JobID) != "" {
		jobID = strings.TrimSpace(event.JobID)
	}

	key := reconciliationDriftAlertMetricKey{
		driftKind:  driftKind,
		actionType: actionType,
		reason:     reason,
		severity:   severity,
		status:     status,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &reconciliationDriftAlertMetricSeries{ReconciliationDriftAlertMetric: ReconciliationDriftAlertMetric{
			DriftKind:  driftKind,
			ActionType: actionType,
			Reason:     reason,
			Severity:   severity,
			Status:     status,
		}}
		m.series[key] = series
	}
	series.Count++
	series.RequestID = safeMetricID(corr.RequestID)
	series.CorrelationID = safeMetricID(corr.CorrelationID)
	series.OrganizationID = safeMetricID(orgID)
	series.ProjectID = safeMetricID(event.ProjectID)
	series.EnvironmentID = safeMetricID(event.EnvironmentID)
	series.ServiceID = safeMetricID(event.ServiceID)
	series.PrincipalID = safeMetricID(principalID)
	series.ResourceKind = safeMetricID(resourceKind)
	series.ResourceID = safeMetricID(resourceID)
	series.JobID = safeMetricID(jobID)
	series.ActionCount = int(clampMetricCount(int64(event.ActionCount)))
	series.FailureCount = int(clampMetricCount(int64(event.FailureCount)))
}

// RecordSecretRedactionCanary aggregates one redaction canary observation.
func (m *SecretRedactionCanaryMetrics) RecordSecretRedactionCanary(ctx context.Context, event SecretRedactionCanaryObservation) {
	if m == nil {
		return
	}
	surface := metricSLOToken(event.Surface, "unknown")
	vector := metricSLOToken(event.Vector, "unknown")
	outcome := metricCanaryOutcome(event.Outcome)
	reason := metricSLOToken(event.Reason, "unknown")

	corr := FromContext(ctx)
	orgID, principalID, resourceKind, resourceID, jobID := "", "", "", "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID, resourceKind, resourceID, jobID, _ = f.logSnapshot()
	}
	if strings.TrimSpace(event.OrganizationID) != "" {
		orgID = strings.TrimSpace(event.OrganizationID)
	}
	if strings.TrimSpace(event.PrincipalID) != "" {
		principalID = strings.TrimSpace(event.PrincipalID)
	}
	if strings.TrimSpace(event.ResourceKind) != "" {
		resourceKind = strings.TrimSpace(event.ResourceKind)
	}
	if strings.TrimSpace(event.ResourceID) != "" {
		resourceID = strings.TrimSpace(event.ResourceID)
	}
	if strings.TrimSpace(event.JobID) != "" {
		jobID = strings.TrimSpace(event.JobID)
	}

	key := secretRedactionCanaryMetricKey{
		surface: surface,
		vector:  vector,
		outcome: outcome,
		reason:  reason,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.total++
	series := m.series[key]
	if series == nil {
		series = &secretRedactionCanaryMetricSeries{SecretRedactionCanaryMetric: SecretRedactionCanaryMetric{
			Surface: surface,
			Vector:  vector,
			Outcome: outcome,
			Reason:  reason,
		}}
		m.series[key] = series
	}
	series.Count++
	series.RequestID = safeMetricID(corr.RequestID)
	series.CorrelationID = safeMetricID(corr.CorrelationID)
	series.OrganizationID = safeMetricID(orgID)
	series.PrincipalID = safeMetricID(principalID)
	series.ResourceKind = safeMetricID(resourceKind)
	series.ResourceID = safeMetricID(resourceID)
	series.JobID = safeMetricID(jobID)
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

func metricDokployEndpoint(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "unknown"
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	parts := strings.Split(path, "/")
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		if dokployPathSegmentIsID(parts, i) {
			parts[i] = "{id}"
		}
	}
	normalized := strings.Join(parts, "/")
	if normalized == "" || normalized == "/" {
		return "unknown"
	}
	return normalized
}

func dokployPathSegmentIsID(parts []string, i int) bool {
	prev := ""
	if i > 0 {
		prev = parts[i-1]
	}
	switch prev {
	case "organizations", "projects", "environments", "applications", "compose",
		"databases", "domains", "deployments", "services", "backups":
		return true
	default:
		return false
	}
}

func metricJobQueueEvent(event JobQueueEventName) JobQueueEventName {
	switch event {
	case JobQueueEventClaimed, JobQueueEventCompleted:
		return event
	default:
		return "other"
	}
}

func metricStoreOperation(operation string) string {
	switch strings.TrimSpace(operation) {
	case "read", "write":
		return strings.TrimSpace(operation)
	case "":
		return "unknown"
	default:
		return "other"
	}
}

func metricQueryKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "select", "insert", "update", "delete", "with", "begin", "commit", "rollback":
		return strings.ToLower(strings.TrimSpace(kind))
	case "":
		return "unknown"
	default:
		return "other"
	}
}

func metricStoreOutcome(outcome string) string {
	switch strings.TrimSpace(outcome) {
	case "success", "error":
		return strings.TrimSpace(outcome)
	case "":
		return "unknown"
	default:
		return "error"
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

func metricReadinessStatus(status string) string {
	switch strings.TrimSpace(status) {
	case "passing", "failing":
		return strings.TrimSpace(status)
	case "":
		return "unknown"
	default:
		return "unknown"
	}
}

func metricSLOWindow(window string) string {
	switch strings.TrimSpace(window) {
	case "1m", "5m", "15m", "30m", "1h", "6h", "24h":
		return strings.TrimSpace(window)
	case "":
		return "unknown"
	default:
		return "other"
	}
}

func metricSLOSeverity(severity string) string {
	switch strings.TrimSpace(severity) {
	case "page", "ticket", "info":
		return strings.TrimSpace(severity)
	case "":
		return "unknown"
	default:
		return "other"
	}
}

func metricSLOStatus(status string) string {
	switch strings.TrimSpace(status) {
	case "firing", "resolved", "suppressed":
		return strings.TrimSpace(status)
	case "":
		return "unknown"
	default:
		return "unknown"
	}
}

func metricCanaryOutcome(outcome string) string {
	switch strings.TrimSpace(outcome) {
	case "passed", "failed":
		return strings.TrimSpace(outcome)
	case "":
		return "unknown"
	default:
		return "unknown"
	}
}

func metricSLOToken(value, empty string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return empty
	}
	if len(value) > 80 {
		return "other"
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			continue
		}
		return "other"
	}
	return value
}

func metricQuotaResource(resource string) string {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "unknown"
	}
	for _, r := range resource {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return "unknown"
	}
	return resource
}

func metricQuotaEnforcementMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case "hard", "soft", "metered", "disabled":
		return strings.TrimSpace(mode)
	case "":
		return "unknown"
	default:
		return "other"
	}
}

func metricQuotaOutcome(outcome QuotaUsageOutcome) QuotaUsageOutcome {
	switch outcome {
	case QuotaUsageOutcomeAllowed, QuotaUsageOutcomeRejected, QuotaUsageOutcomeError:
		return outcome
	default:
		return QuotaUsageOutcomeError
	}
}

func metricQuotaReason(reason string) string {
	switch strings.TrimSpace(reason) {
	case "reserved", "unconstrained", "disabled", "soft_limit", "metered_limit",
		"limit_exceeded", "invalid_organization", "invalid_resource",
		"limit_lookup_failed", "usage_lock_failed", "reservation_sum_failed",
		"reservation_insert_failed", "internal_error":
		return strings.TrimSpace(reason)
	case "":
		return "unknown"
	default:
		return "other"
	}
}

func metricAuditToken(value, empty string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return empty
	}
	if len(value) > 80 {
		return "other"
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			continue
		}
		return "other"
	}
	return value
}

func metricAuditDecision(decision string) string {
	switch strings.TrimSpace(decision) {
	case "allowed", "denied":
		return strings.TrimSpace(decision)
	case "":
		return "unknown"
	default:
		return "other"
	}
}

func metricAuditOutcome(outcome AuditEventOutcome) AuditEventOutcome {
	switch outcome {
	case AuditEventOutcomeRecorded, AuditEventOutcomeFailed:
		return outcome
	default:
		return AuditEventOutcomeFailed
	}
}

func metricAuditErrorCode(code string) string {
	code = strings.TrimSpace(code)
	if code == "" {
		return ""
	}
	if len(code) > 80 {
		return "other"
	}
	for _, r := range code {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return "other"
	}
	return code
}

func safeMetricID(id string) string {
	id = strings.TrimSpace(id)
	if SafeID(id) {
		return id
	}
	return ""
}

func clampMetricCount(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

func clampMetricFloat(n float64) float64 {
	if n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0
	}
	return n
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
			rec := &statusRecorder{ResponseWriter: w, ctx: r.Context(), status: http.StatusOK}
			next.ServeHTTP(rec, r)
			metrics.record(r, rec.status, rec.bytes, time.Since(start))
		})
	}
}
