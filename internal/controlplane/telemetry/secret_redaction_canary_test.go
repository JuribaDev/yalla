package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestSecretRedactionCanaryMetricsRecordSuccessAndFailure(t *testing.T) {
	t.Parallel()

	metrics := NewSecretRedactionCanaryMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{
		RequestID:     "req_canary_metrics",
		CorrelationID: "corr_canary_metrics",
	})
	ctx = WithLogFields(ctx)
	SetOrgID(ctx, "org_canary_ctx")
	SetPrincipalID(ctx, "usr_canary_ctx")
	SetResource(ctx, "service", "svc_canary_ctx")
	SetJobID(ctx, "job_canary_ctx")

	metrics.RecordSecretRedactionCanary(ctx, SecretRedactionCanaryObservation{
		Surface: "request_logs",
		Vector:  "authorization_header",
		Outcome: "passed",
		Reason:  "sentinel_absent",
	})
	metrics.RecordSecretRedactionCanary(context.Background(), SecretRedactionCanaryObservation{
		Surface:        "audit_metadata",
		Vector:         "operator_reason",
		Outcome:        "failed",
		Reason:         "sentinel_found",
		OrganizationID: "org_canary_event",
		ResourceKind:   "api_key",
		ResourceID:     "key_canary_event",
		JobID:          "job_canary_event",
	})

	snapshot := metrics.Snapshot()
	if snapshot.TotalObservations != 2 {
		t.Fatalf("total_observations = %d, want 2", snapshot.TotalObservations)
	}
	passed := findSecretRedactionCanaryMetric(snapshot.Series, "request_logs", "authorization_header", "passed", "sentinel_absent")
	if passed == nil {
		t.Fatalf("missing passing canary metric: %+v", snapshot.Series)
	}
	if passed.Count != 1 || passed.RequestID != "req_canary_metrics" || passed.CorrelationID != "corr_canary_metrics" ||
		passed.OrganizationID != "org_canary_ctx" || passed.PrincipalID != "usr_canary_ctx" ||
		passed.ResourceKind != "service" || passed.ResourceID != "svc_canary_ctx" || passed.JobID != "job_canary_ctx" {
		t.Errorf("passing canary metric = %+v, want request/resource/job hints", *passed)
	}
	failed := findSecretRedactionCanaryMetric(snapshot.Series, "audit_metadata", "operator_reason", "failed", "sentinel_found")
	if failed == nil {
		t.Fatalf("missing failing canary metric: %+v", snapshot.Series)
	}
	if failed.OrganizationID != "org_canary_event" || failed.ResourceKind != "api_key" ||
		failed.ResourceID != "key_canary_event" || failed.JobID != "job_canary_event" {
		t.Errorf("failing canary metric = %+v, want event identifier hints", *failed)
	}
}

func TestSecretRedactionCanaryBoundsCardinalityAndDropsUnsafeIdentifiers(t *testing.T) {
	t.Parallel()

	metrics := NewSecretRedactionCanaryMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{
		RequestID:     "req\nbad",
		CorrelationID: "corr_canary_safe",
	})
	ctx = WithLogFields(ctx)
	SetOrgID(ctx, "org bad")
	SetPrincipalID(ctx, "usr_canary_safe")

	metrics.RecordSecretRedactionCanary(ctx, SecretRedactionCanaryObservation{
		Surface:      "request_logs\nwith_secret",
		Vector:       strings.Repeat("x", 90),
		Outcome:      "leaked",
		Reason:       "password=topsecret",
		ResourceKind: "service bad",
		ResourceID:   "svc_canary_safe",
	})

	snapshot := metrics.Snapshot()
	got := findSecretRedactionCanaryMetric(snapshot.Series, "other", "other", "unknown", "other")
	if got == nil {
		t.Fatalf("missing bounded-cardinality canary metric: %+v", snapshot.Series)
	}
	if got.RequestID != "" || got.CorrelationID != "corr_canary_safe" {
		t.Errorf("correlation hints = %q/%q, want unsafe request dropped and safe correlation kept", got.RequestID, got.CorrelationID)
	}
	if got.OrganizationID != "" || got.PrincipalID != "usr_canary_safe" ||
		got.ResourceKind != "" || got.ResourceID != "svc_canary_safe" {
		t.Errorf("identifier hints = %+v, want only SafeID-clean values", *got)
	}
}

func TestObserveSecretRedactionCanaryLogsBoundedFieldsWithoutProbeSecret(t *testing.T) {
	t.Parallel()

	const probeSecret = "yalla-redaction-canary-secret-42"
	metrics := NewSecretRedactionCanaryMetrics()
	ctx := WithCorrelation(context.Background(), Correlation{
		RequestID:     "req_canary_log",
		CorrelationID: "corr_canary_log",
	})

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ObserveSecretRedactionCanary(ctx, logger, metrics, SecretRedactionCanaryObservation{
		Surface:        "error_envelope",
		Vector:         "database_url",
		Outcome:        "failed",
		Reason:         "sentinel_found",
		OrganizationID: "org_canary_log",
		ResourceKind:   "project",
		ResourceID:     "proj_canary_log",
		JobID:          "job_canary_log",
	})

	raw := strings.TrimSpace(buf.String())
	if raw == "" {
		t.Fatal("missing canary log record")
	}
	if strings.Contains(raw, probeSecret) || strings.Contains(raw, "database://user:"+probeSecret) {
		t.Fatalf("canary log leaked probe secret: %s", raw)
	}
	var record struct {
		Level         string `json:"level"`
		Event         string `json:"event"`
		Surface       string `json:"surface"`
		Vector        string `json:"vector"`
		Outcome       string `json:"outcome"`
		Reason        string `json:"reason"`
		RequestID     string `json:"request_id"`
		CorrelationID string `json:"correlation_id"`
		Organization  string `json:"org_id"`
		ResourceKind  string `json:"resource_kind"`
		ResourceID    string `json:"resource_id"`
		JobID         string `json:"job_id"`
	}
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		t.Fatalf("decode canary log %q: %v", raw, err)
	}
	if record.Level != "ERROR" || record.Event != "secret_redaction_canary" ||
		record.Surface != "error_envelope" || record.Vector != "database_url" ||
		record.Outcome != "failed" || record.Reason != "sentinel_found" {
		t.Fatalf("canary log dimensions = %+v, want bounded failed dimensions", record)
	}
	if record.RequestID != "req_canary_log" || record.CorrelationID != "corr_canary_log" ||
		record.Organization != "org_canary_log" || record.ResourceKind != "project" ||
		record.ResourceID != "proj_canary_log" || record.JobID != "job_canary_log" {
		t.Fatalf("canary log hints = %+v, want safe request/resource/job hints", record)
	}
	if metrics.Snapshot().TotalObservations != 1 {
		t.Fatalf("metrics total_observations = %d, want 1", metrics.Snapshot().TotalObservations)
	}
}

func findSecretRedactionCanaryMetric(metrics []SecretRedactionCanaryMetric, surface, vector, outcome, reason string) *SecretRedactionCanaryMetric {
	for i := range metrics {
		if metrics[i].Surface == surface && metrics[i].Vector == vector && metrics[i].Outcome == outcome && metrics[i].Reason == reason {
			return &metrics[i]
		}
	}
	return nil
}
