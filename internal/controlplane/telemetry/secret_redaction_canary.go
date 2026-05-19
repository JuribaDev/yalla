package telemetry

import (
	"context"
	"io"
	"log/slog"
)

// ObserveSecretRedactionCanary records a redaction-canary result in metrics
// and emits one structured log line with only bounded dimensions and safe
// incident-join hints. The caller must keep the canary's raw secret value out
// of event fields; this helper deliberately has no parameter for it.
func ObserveSecretRedactionCanary(ctx context.Context, logger *slog.Logger, metrics *SecretRedactionCanaryMetrics, event SecretRedactionCanaryObservation) {
	if metrics == nil {
		metrics = DefaultSecretRedactionCanaryMetrics
	}
	metrics.RecordSecretRedactionCanary(ctx, event)

	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	surface := metricSLOToken(event.Surface, "unknown")
	vector := metricSLOToken(event.Vector, "unknown")
	outcome := metricCanaryOutcome(event.Outcome)
	reason := metricSLOToken(event.Reason, "unknown")

	attrs := []any{
		slog.String("event", "secret_redaction_canary"),
		slog.String("surface", surface),
		slog.String("vector", vector),
		slog.String("outcome", outcome),
		slog.String("reason", reason),
	}
	corr := FromContext(ctx)
	if requestID := safeMetricID(corr.RequestID); requestID != "" {
		attrs = append(attrs, slog.String("request_id", requestID))
	}
	if correlationID := safeMetricID(corr.CorrelationID); correlationID != "" {
		attrs = append(attrs, slog.String("correlation_id", correlationID))
	}
	orgID, principalID, resourceKind, resourceID, jobID := "", "", "", "", ""
	if f := fieldsFromContext(ctx); f != nil {
		orgID, principalID, resourceKind, resourceID, jobID, _ = f.logSnapshot()
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
	if orgID := safeMetricID(orgID); orgID != "" {
		attrs = append(attrs, slog.String("org_id", orgID))
	}
	if principalID := safeMetricID(principalID); principalID != "" {
		attrs = append(attrs, slog.String("principal_id", principalID))
	}
	if resourceKind := safeMetricID(resourceKind); resourceKind != "" {
		attrs = append(attrs, slog.String("resource_kind", resourceKind))
	}
	if resourceID := safeMetricID(resourceID); resourceID != "" {
		attrs = append(attrs, slog.String("resource_id", resourceID))
	}
	if jobID := safeMetricID(jobID); jobID != "" {
		attrs = append(attrs, slog.String("job_id", jobID))
	}

	level := slog.LevelInfo
	if outcome == "failed" {
		level = slog.LevelError
	}
	logger.Log(ctx, level, "secret redaction canary", attrs...)
}
