package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	yerr "github.com/JuribaDev/yalla/internal/errors"
	"github.com/JuribaDev/yalla/internal/output"
)

// White-box unit tests for the provisioning job repository's pure decision
// logic — the status set, the state machine, id/payload helpers, the error
// redactor, and the constructor guards on Insert and Transition. They need no
// database, so they run on every `go test ./...` regardless of whether
// Postgres is available.

func TestJobStatusValid(t *testing.T) {
	t.Parallel()

	valid := []JobStatus{
		JobStatusQueued, JobStatusRunning, JobStatusRetrying, JobStatusSucceeded,
		JobStatusFailed, JobStatusCancelled, JobStatusDeadLetter,
	}
	for _, s := range valid {
		if !s.Valid() {
			t.Errorf("JobStatus(%q).Valid() = false, want true", s)
		}
		if s.String() != string(s) {
			t.Errorf("JobStatus(%q).String() = %q, want %q", s, s.String(), string(s))
		}
	}
	for _, s := range []JobStatus{"", "QUEUED", "done", "running ", "dead-letter"} {
		if s.Valid() {
			t.Errorf("JobStatus(%q).Valid() = true, want false", s)
		}
	}
}

func TestJobStatusTerminal(t *testing.T) {
	t.Parallel()

	terminal := map[JobStatus]bool{
		JobStatusQueued:     false,
		JobStatusRunning:    false,
		JobStatusRetrying:   false,
		JobStatusSucceeded:  true,
		JobStatusFailed:     true,
		JobStatusCancelled:  true,
		JobStatusDeadLetter: true,
	}
	for s, want := range terminal {
		if got := s.Terminal(); got != want {
			t.Errorf("JobStatus(%q).Terminal() = %v, want %v", s, got, want)
		}
	}
}

// TestJobStatusCanTransitionTo exhaustively checks the state machine: every
// (from, to) pair over the closed status set is asserted against the documented
// transition table, so an accidental edge change is caught immediately.
func TestJobStatusCanTransitionTo(t *testing.T) {
	t.Parallel()

	allowed := map[JobStatus]map[JobStatus]bool{
		JobStatusQueued: {
			JobStatusRunning:   true,
			JobStatusCancelled: true,
		},
		JobStatusRunning: {
			JobStatusSucceeded:  true,
			JobStatusRetrying:   true,
			JobStatusFailed:     true,
			JobStatusDeadLetter: true,
			JobStatusCancelled:  true,
		},
		JobStatusRetrying: {
			JobStatusRunning:   true,
			JobStatusCancelled: true,
		},
	}
	all := []JobStatus{
		JobStatusQueued, JobStatusRunning, JobStatusRetrying, JobStatusSucceeded,
		JobStatusFailed, JobStatusCancelled, JobStatusDeadLetter,
	}
	for _, from := range all {
		for _, to := range all {
			want := allowed[from][to]
			if got := from.CanTransitionTo(to); got != want {
				t.Errorf("%s.CanTransitionTo(%s) = %v, want %v", from, to, got, want)
			}
		}
	}
	// A terminal status has no outgoing edges, including a no-op self-edge.
	for _, s := range []JobStatus{JobStatusSucceeded, JobStatusFailed, JobStatusCancelled, JobStatusDeadLetter} {
		if s.CanTransitionTo(s) {
			t.Errorf("terminal %s.CanTransitionTo(%s) = true, want false", s, s)
		}
	}
	// An unknown status can never transition.
	if JobStatus("bogus").CanTransitionTo(JobStatusRunning) {
		t.Error("JobStatus(\"bogus\").CanTransitionTo(running) = true, want false")
	}
}

func TestRedactJobError(t *testing.T) {
	t.Parallel()

	in := "dokploy call failed: Authorization: Bearer sk-secret-token-value while POST /api"
	got := redactJobError(in)
	if got == in {
		t.Fatalf("redactJobError did not scrub a bearer header: %q", got)
	}
	if !strings.Contains(got, output.Sentinel) {
		t.Errorf("redactJobError(%q) = %q, want it to contain the redaction sentinel", in, got)
	}
	if strings.Contains(got, "sk-secret-token-value") {
		t.Errorf("redactJobError leaked the secret token: %q", got)
	}
	// Redaction is idempotent and leaves clean text untouched.
	clean := "dokploy returned 502 bad gateway"
	if redactJobError(clean) != clean {
		t.Errorf("redactJobError mutated clean text: %q", redactJobError(clean))
	}
	if got := redactJobError(got); strings.Contains(got, "sk-secret-token-value") {
		t.Error("redactJobError is not idempotent")
	}
}

func TestMarshalJobPayloadEmpty(t *testing.T) {
	t.Parallel()

	for name, in := range map[string]map[string]string{
		"nil":   nil,
		"empty": {},
	} {
		b, err := marshalJobPayload(in)
		if err != nil {
			t.Fatalf("marshalJobPayload(%s): %v", name, err)
		}
		if string(b) != "{}" {
			t.Errorf("marshalJobPayload(%s) = %q, want %q", name, b, "{}")
		}
	}
}

func TestJobPayloadRoundTrip(t *testing.T) {
	t.Parallel()

	want := map[string]string{"service_id": "svc_abc", "desired_version": "7"}
	b, err := marshalJobPayload(want)
	if err != nil {
		t.Fatalf("marshalJobPayload: %v", err)
	}
	got, err := unmarshalJobPayload(b)
	if err != nil {
		t.Fatalf("unmarshalJobPayload: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip = %v, want %v", got, want)
	}
}

func TestUnmarshalJobPayloadEmptyYieldsNil(t *testing.T) {
	t.Parallel()

	for name, in := range map[string][]byte{
		"nil bytes":    nil,
		"empty bytes":  {},
		"empty object": []byte("{}"),
	} {
		got, err := unmarshalJobPayload(in)
		if err != nil {
			t.Fatalf("unmarshalJobPayload(%s): %v", name, err)
		}
		if got != nil {
			t.Errorf("unmarshalJobPayload(%s) = %v, want nil", name, got)
		}
	}
}

func TestNullableHelpers(t *testing.T) {
	t.Parallel()

	if nullableID("") != nil {
		t.Error("nullableID(\"\") = non-nil, want nil")
	}
	if got := nullableID("svc_x"); got == nil || *got != "svc_x" {
		t.Errorf("nullableID(%q) = %v, want a pointer to it", "svc_x", got)
	}
	if nullableTime(time.Time{}) != nil {
		t.Error("nullableTime(zero) = non-nil, want nil")
	}
	now := time.Now()
	if got := nullableTime(now); got == nil || !got.Equal(now) {
		t.Errorf("nullableTime(now) = %v, want a pointer to now", got)
	}
}

func TestJobTransitionNowDefaults(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC()
	got := JobTransition{}.now()
	if got.Before(before) {
		t.Errorf("JobTransition{}.now() = %v, want >= %v", got, before)
	}
	fixed := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	if got := (JobTransition{Now: fixed}).now(); !got.Equal(fixed) {
		t.Errorf("JobTransition{Now: fixed}.now() = %v, want %v", got, fixed)
	}
}

func TestJobRepositoryInsertNilTransaction(t *testing.T) {
	t.Parallel()

	repo := NewJobRepository()
	_, err := repo.Insert(context.Background(), nil, ProvisioningJob{
		OrganizationID: "org_x", JobType: "ensure_project", IdempotencyKey: "k1",
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Insert(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

func TestJobRepositoryInsertValidationFailures(t *testing.T) {
	t.Parallel()

	repo := NewJobRepository()
	// A non-nil *Tx is not required: the validation guards run before the
	// transaction is ever touched. Pass a zero-value *Tx to prove that.
	cases := map[string]ProvisioningJob{
		"missing org":             {JobType: "ensure_project", IdempotencyKey: "k"},
		"missing job type":        {OrganizationID: "org_x", IdempotencyKey: "k"},
		"missing idempotency key": {OrganizationID: "org_x", JobType: "ensure_project"},
		"negative desired version": {
			OrganizationID: "org_x", JobType: "ensure_project", IdempotencyKey: "k", DesiredVersion: -1,
		},
		"negative max attempts": {
			OrganizationID: "org_x", JobType: "ensure_project", IdempotencyKey: "k", MaxAttempts: -1,
		},
		"non-queued status": {
			OrganizationID: "org_x", JobType: "ensure_project", IdempotencyKey: "k", Status: JobStatusRunning,
		},
	}
	for name, in := range cases {
		_, err := repo.Insert(context.Background(), &Tx{}, in)
		if ye := yerr.From(err); ye.Code != yerr.CodeValidation {
			t.Errorf("%s: Insert error code = %v, want %s", name, err, yerr.CodeValidation)
		}
	}
}

func TestJobRepositoryTransitionNilTransaction(t *testing.T) {
	t.Parallel()

	repo := NewJobRepository()
	_, err := repo.Transition(context.Background(), nil, "org_x", "job_x", JobStatusRunning, JobTransition{})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Transition(nil tx) error code = %v, want %s", err, yerr.CodeInternal)
	}
}

func TestJobRepositoryTransitionInvalidTargetStatus(t *testing.T) {
	t.Parallel()

	repo := NewJobRepository()
	// The invalid-target guard runs before the transaction is touched, so a
	// zero-value *Tx proves it.
	_, err := repo.Transition(context.Background(), &Tx{}, "org_x", "job_x", JobStatus("bogus"), JobTransition{})
	if ye := yerr.From(err); ye.Code != yerr.CodeInternal {
		t.Fatalf("Transition(invalid status) error code = %v, want %s", err, yerr.CodeInternal)
	}
}
