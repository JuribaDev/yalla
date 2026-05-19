package worker

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/telemetry"
)

// These are pure unit tests for the queue's decision logic — backoff, failure
// classification, and owner-id minting — that need no database.

func TestBackoffDelayIsBoundedExponential(t *testing.T) {
	t.Parallel()

	b := Backoff{Base: time.Second, Max: time.Minute}
	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 0, want: time.Second}, // clamped to attempt 1
		{attempt: 1, want: time.Second}, // base
		{attempt: 2, want: 2 * time.Second},
		{attempt: 3, want: 4 * time.Second},
		{attempt: 4, want: 8 * time.Second},
		{attempt: 5, want: 16 * time.Second},
		{attempt: 6, want: 32 * time.Second},
		{attempt: 7, want: time.Minute},  // 64s capped at Max
		{attempt: 50, want: time.Minute}, // large attempt stays capped, never overflows
	}
	for _, tc := range cases {
		if got := b.Delay(tc.attempt); got != tc.want {
			t.Errorf("Delay(%d) = %s, want %s", tc.attempt, got, tc.want)
		}
	}
}

func TestBackoffDelayAppliesDefaults(t *testing.T) {
	t.Parallel()

	// A zero-value Backoff is valid and uses the package defaults.
	var b Backoff
	if got := b.Delay(1); got != defaultBackoffBase {
		t.Errorf("zero-value Delay(1) = %s, want the default base %s", got, defaultBackoffBase)
	}
	if got := b.Delay(1000); got != defaultBackoffMax {
		t.Errorf("zero-value Delay(1000) = %s, want the default cap %s", got, defaultBackoffMax)
	}

	// A Max below Base is raised to Base rather than producing a delay shorter
	// than the first retry.
	raised := Backoff{Base: 10 * time.Second, Max: time.Second}
	if got := raised.Delay(5); got != 10*time.Second {
		t.Errorf("Delay with Max<Base = %s, want it raised to Base 10s", got)
	}
}

func TestBackoffDelayJitterStaysWithinBounds(t *testing.T) {
	t.Parallel()

	b := Backoff{Base: time.Second, Max: time.Minute, Jitter: true}
	// attempt 5 would be a flat 16s without jitter; with jitter every sample
	// must fall within [Base, 16s] and at least one must differ from the flat
	// value, proving the spread is actually applied.
	const attempt = 5
	flat := Backoff{Base: time.Second, Max: time.Minute}.Delay(attempt)
	var sawSpread bool
	for i := 0; i < 500; i++ {
		got := b.Delay(attempt)
		if got < time.Second || got > flat {
			t.Fatalf("jittered Delay(%d) = %s, want it within [1s, %s]", attempt, got, flat)
		}
		if got != flat {
			sawSpread = true
		}
	}
	if !sawSpread {
		t.Error("jittered Delay never differed from the flat delay; jitter was not applied")
	}
}

func TestTerminalClassification(t *testing.T) {
	t.Parallel()

	if Terminal(nil) != nil {
		t.Error("Terminal(nil) must be nil")
	}

	transient := errors.New("dokploy timed out")
	if IsTerminal(transient) {
		t.Error("a plain error must not be classified as terminal")
	}

	terminal := Terminal(errors.New("invalid desired state"))
	if !IsTerminal(terminal) {
		t.Error("a Terminal-wrapped error must be classified as terminal")
	}
	// Classification must survive further wrapping.
	wrapped := fmt.Errorf("provisioning failed: %w", terminal)
	if !IsTerminal(wrapped) {
		t.Error("Terminal classification must survive errors.Wrap")
	}
	// The underlying message is preserved for the error summary.
	if !strings.Contains(terminal.Error(), "invalid desired state") {
		t.Errorf("Terminal error lost its message: %q", terminal.Error())
	}
}

func TestNewOwnerIDIsUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		id := NewOwnerID()
		if !strings.HasPrefix(id, "worker-") {
			t.Fatalf("owner id %q does not carry the worker- prefix", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("NewOwnerID produced a duplicate owner id %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestStoreClaimerRecordsJobQueueMetrics(t *testing.T) {
	t.Parallel()

	metrics := telemetry.NewJobQueueMetrics()
	claimer := &StoreClaimer{metrics: metrics}
	job := store.ProvisioningJob{
		ID:             "job_queue_metrics",
		OrganizationID: "org_queue_metrics",
		ProjectID:      "proj_queue_metrics",
		EnvironmentID:  "env_queue_metrics",
		ServiceID:      "svc_queue_metrics",
		JobType:        "sync_variables",
		Status:         store.JobStatusRunning,
		Attempts:       2,
		MaxAttempts:    5,
		RequestID:      "req_queue_metrics",
		CorrelationID:  "corr_queue_metrics",
	}

	claimer.recordClaimMetric(job)
	claimer.recordOutcomeMetric(job, store.JobStatusRetrying, 45*time.Second)

	snapshot := metrics.Snapshot()
	if snapshot.TotalEvents != 2 {
		t.Fatalf("total_events = %d, want 2", snapshot.TotalEvents)
	}
	claimed := findQueueMetric(snapshot.Series, telemetry.JobQueueEventClaimed, "sync_variables", string(store.JobStatusRunning))
	if claimed == nil {
		t.Fatalf("missing claimed metric: %+v", snapshot.Series)
	}
	if claimed.JobID != job.ID || claimed.OrganizationID != job.OrganizationID || claimed.ServiceID != job.ServiceID {
		t.Errorf("claimed metric = %+v, want latest job/resource hints", *claimed)
	}

	retry := findQueueMetric(snapshot.Series, telemetry.JobQueueEventCompleted, "sync_variables", string(store.JobStatusRetrying))
	if retry == nil {
		t.Fatalf("missing retry outcome metric: %+v", snapshot.Series)
	}
	if retry.StatusClass != "retry" || retry.NextRunDelayMS != 45000 {
		t.Errorf("retry metric = %+v, want retry class and 45s delay", *retry)
	}
	if retry.RequestID != job.RequestID || retry.CorrelationID != job.CorrelationID {
		t.Errorf("retry metric = %+v, want request/correlation hints", *retry)
	}
}

func findQueueMetric(metrics []telemetry.JobQueueMetric, event telemetry.JobQueueEventName, jobType, status string) *telemetry.JobQueueMetric {
	for i := range metrics {
		if metrics[i].Event == event && metrics[i].JobType == jobType && metrics[i].Status == status {
			return &metrics[i]
		}
	}
	return nil
}
