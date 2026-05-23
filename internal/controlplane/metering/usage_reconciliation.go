package metering

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

// ExpectedUsageMetric identifies a billing-grade usage stream the reconciler
// should validate for a period.
type ExpectedUsageMetric struct {
	Key    string
	Unit   string
	Source string
}

// QuarantinedUsageSample records a source sample that was deliberately kept
// out of usage_events because attribution or validation did not make it safe
// to bill.
type QuarantinedUsageSample struct {
	Key       string
	Unit      string
	Source    string
	Reason    string
	WindowEnd time.Time
}

// ReconcileUsageInput selects one tenant period to replay and inspect.
type ReconcileUsageInput struct {
	OrganizationID     string
	PeriodStart        time.Time
	PeriodEnd          time.Time
	AggregatedAt       time.Time
	AggregationVersion int
	ExpectedMetrics    []ExpectedUsageMetric
	QuarantinedSamples []QuarantinedUsageSample
	RequestID          string
	CorrelationID      string
}

// UsageReconciliationIssue is a stable, value-free anomaly detected during a
// usage reconciliation pass.
type UsageReconciliationIssue struct {
	Type   string
	Key    string
	Unit   string
	Source string
	Reason string
}

// ReconcileUsageResult reports the durable mutations and anomalies from one
// reconciliation pass.
type ReconcileUsageResult struct {
	Counters    []store.UsageCounter
	Adjustments []store.UsageCounterAdjustment
	Findings    []store.DriftFinding
	Issues      []UsageReconciliationIssue
}

// UsageReconciler replays append-only usage events into counters and records
// low-confidence source gaps as drift findings for operator triage.
type UsageReconciler struct {
	store    *store.Store
	counters *store.UsageCounterRepository
	drift    *store.DriftFindingRepository
}

// NewUsageReconciler builds a usage reconciler over the control-plane store.
func NewUsageReconciler(s *store.Store) (*UsageReconciler, error) {
	if s == nil {
		return nil, errors.New("metering: nil store")
	}
	return &UsageReconciler{
		store:    s,
		counters: store.NewUsageCounterRepository(),
		drift:    store.NewDriftFindingRepository(),
	}, nil
}

// Reconcile safely replays one organization/period/key space. Re-running the
// same period rewrites open counters deterministically and relies on the
// counter repository's closed-period delta accounting to avoid double-counting.
func (r *UsageReconciler) Reconcile(ctx context.Context, in ReconcileUsageInput) (ReconcileUsageResult, error) {
	if r == nil || r.store == nil || r.counters == nil || r.drift == nil {
		return ReconcileUsageResult{}, errors.New("metering: nil UsageReconciler")
	}
	input, err := buildReconcileUsageInput(in)
	if err != nil {
		return ReconcileUsageResult{}, err
	}
	result := ReconcileUsageResult{
		Counters:    []store.UsageCounter{},
		Adjustments: []store.UsageCounterAdjustment{},
		Findings:    []store.DriftFinding{},
		Issues:      []UsageReconciliationIssue{},
	}
	err = r.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		issues, inspectErr := r.inspectUsageWindows(ctx, tx, input)
		if inspectErr != nil {
			return inspectErr
		}
		for _, quarantined := range input.QuarantinedSamples {
			issues = append(issues, UsageReconciliationIssue{
				Type:   "quarantined_sample",
				Key:    quarantined.Key,
				Unit:   quarantined.Unit,
				Source: quarantined.Source,
				Reason: quarantined.Reason,
			})
		}

		aggregated, aggregateErr := r.counters.AggregateUsageEvents(ctx, tx, store.AggregateUsageCountersInput{
			OrganizationID:     input.OrganizationID,
			PeriodStart:        input.PeriodStart,
			PeriodEnd:          input.PeriodEnd,
			AggregatedAt:       input.AggregatedAt,
			AggregationVersion: input.AggregationVersion,
			RequestID:          input.RequestID,
			CorrelationID:      input.CorrelationID,
		})
		if aggregateErr != nil {
			return aggregateErr
		}
		result.Counters = aggregated.Counters
		result.Adjustments = aggregated.Adjustments
		result.Issues = issues
		for _, issue := range issues {
			finding, appendErr := r.appendUsageFinding(ctx, tx, input, issue)
			if appendErr != nil {
				return appendErr
			}
			result.Findings = append(result.Findings, finding)
		}
		return nil
	})
	if err != nil {
		return ReconcileUsageResult{}, err
	}
	return result, nil
}

func buildReconcileUsageInput(in ReconcileUsageInput) (ReconcileUsageInput, error) {
	out := ReconcileUsageInput{
		OrganizationID:     strings.TrimSpace(in.OrganizationID),
		PeriodStart:        in.PeriodStart.UTC(),
		PeriodEnd:          in.PeriodEnd.UTC(),
		AggregatedAt:       in.AggregatedAt.UTC(),
		AggregationVersion: in.AggregationVersion,
		ExpectedMetrics:    make([]ExpectedUsageMetric, 0, len(in.ExpectedMetrics)),
		QuarantinedSamples: make([]QuarantinedUsageSample, 0, len(in.QuarantinedSamples)),
		RequestID:          strings.TrimSpace(in.RequestID),
		CorrelationID:      strings.TrimSpace(in.CorrelationID),
	}
	var violations []apierr.FieldViolation
	if out.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	if out.PeriodStart.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "period_start", Reason: "must not be zero"})
	}
	if out.PeriodEnd.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "period_end", Reason: "must not be zero"})
	}
	if !out.PeriodStart.IsZero() && !out.PeriodEnd.IsZero() && !out.PeriodEnd.After(out.PeriodStart) {
		violations = append(violations, apierr.FieldViolation{Field: "period_end", Reason: "must be after period_start"})
	}
	if out.AggregatedAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "aggregated_at", Reason: "must not be zero"})
	}
	if out.AggregationVersion <= 0 {
		violations = append(violations, apierr.FieldViolation{Field: "aggregation_version", Reason: "must be positive"})
	}
	for i, metric := range in.ExpectedMetrics {
		normalized := ExpectedUsageMetric{
			Key:    strings.TrimSpace(metric.Key),
			Unit:   strings.TrimSpace(metric.Unit),
			Source: strings.TrimSpace(metric.Source),
		}
		if normalized.Key == "" {
			violations = append(violations, apierr.FieldViolation{Field: fmt.Sprintf("expected_metrics[%d].key", i), Reason: "must not be blank"})
		}
		if normalized.Unit == "" {
			violations = append(violations, apierr.FieldViolation{Field: fmt.Sprintf("expected_metrics[%d].unit", i), Reason: "must not be blank"})
		}
		if normalized.Source == "" {
			violations = append(violations, apierr.FieldViolation{Field: fmt.Sprintf("expected_metrics[%d].source", i), Reason: "must not be blank"})
		}
		out.ExpectedMetrics = append(out.ExpectedMetrics, normalized)
	}
	for i, quarantined := range in.QuarantinedSamples {
		normalized := QuarantinedUsageSample{
			Key:       strings.TrimSpace(quarantined.Key),
			Unit:      strings.TrimSpace(quarantined.Unit),
			Source:    strings.TrimSpace(quarantined.Source),
			Reason:    safeUsageIssueReason(quarantined.Reason),
			WindowEnd: quarantined.WindowEnd.UTC(),
		}
		if normalized.Key == "" {
			violations = append(violations, apierr.FieldViolation{Field: fmt.Sprintf("quarantined_samples[%d].key", i), Reason: "must not be blank"})
		}
		if normalized.Unit == "" {
			violations = append(violations, apierr.FieldViolation{Field: fmt.Sprintf("quarantined_samples[%d].unit", i), Reason: "must not be blank"})
		}
		if normalized.Source == "" {
			violations = append(violations, apierr.FieldViolation{Field: fmt.Sprintf("quarantined_samples[%d].source", i), Reason: "must not be blank"})
		}
		if normalized.Reason == "" {
			normalized.Reason = "quarantined"
		}
		out.QuarantinedSamples = append(out.QuarantinedSamples, normalized)
	}
	if len(violations) > 0 {
		return ReconcileUsageInput{}, apierr.InvalidInput(violations...)
	}
	if out.RequestID == "" {
		out.RequestID = "usage-reconciliation"
	}
	if out.CorrelationID == "" {
		out.CorrelationID = out.RequestID
	}
	return out, nil
}

type usageWindow struct {
	windowStart  time.Time
	windowEnd    time.Time
	counterStart *float64
	counterEnd   *float64
}

func (r *UsageReconciler) inspectUsageWindows(ctx context.Context, q store.Querier, in ReconcileUsageInput) ([]UsageReconciliationIssue, error) {
	expected := make(map[string]ExpectedUsageMetric, len(in.ExpectedMetrics))
	for _, metric := range in.ExpectedMetrics {
		expected[usageMetricIdentity(metric.Key, metric.Unit, metric.Source)] = metric
	}
	if len(expected) == 0 {
		return nil, nil
	}

	rows, err := q.Query(ctx,
		`SELECT resource::text, unit, source, metadata
		   FROM usage_events
		  WHERE organization_id = $1
		    AND period_start = $2
		    AND period_end = $3
		    AND event_type IN ('committed', 'consumed', 'adjusted')
		  ORDER BY resource, unit, source, occurred_at, id`,
		in.OrganizationID, in.PeriodStart, in.PeriodEnd)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	windowsByMetric := make(map[string][]usageWindow, len(expected))
	for rows.Next() {
		var key, unit, source string
		var rawMetadata []byte
		if err := rows.Scan(&key, &unit, &source, &rawMetadata); err != nil {
			return nil, apierr.StoreUnavailable(err)
		}
		identity := usageMetricIdentity(key, unit, source)
		if _, ok := expected[identity]; !ok {
			continue
		}
		window, ok := usageWindowFromMetadata(rawMetadata)
		if !ok {
			continue
		}
		windowsByMetric[identity] = append(windowsByMetric[identity], window)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}

	var issues []UsageReconciliationIssue
	for identity, metric := range expected {
		windows := windowsByMetric[identity]
		if len(windows) == 0 {
			issues = append(issues, UsageReconciliationIssue{Type: "metric_gap", Key: metric.Key, Unit: metric.Unit, Source: metric.Source, Reason: "missing_window"})
			continue
		}
		sort.SliceStable(windows, func(i, j int) bool {
			return windows[i].windowStart.Before(windows[j].windowStart)
		})
		for i, window := range windows {
			if window.counterStart != nil && window.counterEnd != nil && *window.counterEnd < *window.counterStart {
				issues = append(issues, UsageReconciliationIssue{Type: "counter_reset", Key: metric.Key, Unit: metric.Unit, Source: metric.Source, Reason: "counter_decreased"})
			}
			if i == 0 {
				continue
			}
			prev := windows[i-1]
			if window.windowStart.Before(prev.windowEnd) {
				issues = append(issues, UsageReconciliationIssue{Type: "duplicate_aggregation", Key: metric.Key, Unit: metric.Unit, Source: metric.Source, Reason: "overlapping_window"})
				continue
			}
			if window.windowStart.After(prev.windowEnd) {
				issues = append(issues, UsageReconciliationIssue{Type: "metric_gap", Key: metric.Key, Unit: metric.Unit, Source: metric.Source, Reason: "missing_window"})
			}
		}
	}
	return issues, nil
}

func usageWindowFromMetadata(raw []byte) (usageWindow, bool) {
	if len(raw) == 0 {
		return usageWindow{}, false
	}
	var metadata map[string]string
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return usageWindow{}, false
	}
	start, startOK := parseUsageMetadataTime(metadata["window_start"])
	end, endOK := parseUsageMetadataTime(metadata["window_end"])
	if !startOK || !endOK || !end.After(start) {
		return usageWindow{}, false
	}
	window := usageWindow{windowStart: start, windowEnd: end}
	if v, ok := parseUsageMetadataFloat(metadata["counter_start"]); ok {
		window.counterStart = &v
	}
	if v, ok := parseUsageMetadataFloat(metadata["counter_end"]); ok {
		window.counterEnd = &v
	}
	return window, true
}

func parseUsageMetadataTime(v string) (time.Time, bool) {
	if strings.TrimSpace(v) == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(v))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func parseUsageMetadataFloat(v string) (float64, bool) {
	if strings.TrimSpace(v) == "" {
		return 0, false
	}
	out, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0, false
	}
	return out, true
}

func (r *UsageReconciler) appendUsageFinding(ctx context.Context, tx *store.Tx, in ReconcileUsageInput, issue UsageReconciliationIssue) (store.DriftFinding, error) {
	return r.drift.Append(ctx, tx, store.DriftFinding{
		OrganizationID:    in.OrganizationID,
		Kind:              store.DriftKindSafe,
		Reason:            store.DriftReasonResourceUnmanaged,
		Level:             store.DriftLevelOrganization,
		DokployResourceID: usageFindingResourceID(issue),
		RequestID:         in.RequestID,
		CorrelationID:     in.CorrelationID,
		DetectedAt:        in.AggregatedAt,
	})
}

func usageFindingResourceID(issue UsageReconciliationIssue) string {
	parts := []string{"usage_reconciliation", issue.Type, issue.Key, issue.Unit, issue.Source, issue.Reason}
	for i, part := range parts {
		parts[i] = safeUsageIssueReason(part)
	}
	return strings.Join(parts, ":")
}

func usageMetricIdentity(key, unit, source string) string {
	return strings.TrimSpace(key) + "\x00" + strings.TrimSpace(unit) + "\x00" + strings.TrimSpace(source)
}

func safeUsageIssueReason(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	out := strings.Trim(b.String(), "_.-")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}
