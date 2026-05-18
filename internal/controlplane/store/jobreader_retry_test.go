package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestJobReaderRetryJobCreatesQueuedCloneAndAudit(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	reader, err := store.NewJobReader(s)
	if err != nil {
		t.Fatalf("new job reader: %v", err)
	}
	f := testutil.NewFactory(t)
	ctx := context.Background()

	org := seedOrg(t, db, f, "RetryOrg")
	proj := seedProject(t, db, f, org, "retry-api")
	source := insertJob(ctx, t, s, repo, func() store.ProvisioningJob {
		j := jobFixture(org.ID, "retry_source")
		j.ProjectID = proj.ID
		j.Payload = map[string]string{"project_id": proj.ID}
		return j
	}())
	running := transitionJob(ctx, t, s, repo, org.ID, source.ID, store.JobStatusRunning, store.JobTransition{
		LeaseOwner:    "worker-1",
		LeaseDuration: time.Minute,
		Now:           time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
	})
	failed := transitionJob(ctx, t, s, repo, org.ID, running.ID, store.JobStatusFailed, store.JobTransition{
		ErrorSummary: "upstream failed with Authorization: Bearer yk_live_secret",
		Now:          time.Date(2026, 5, 18, 12, 1, 0, 0, time.UTC),
	})

	retry, err := reader.RetryJob(ctx, store.RetryProvisioningJobInput{
		OrganizationID: failed.OrganizationID,
		JobID:          failed.ID,
		IdempotencyKey: "operator-retry-1",
		Reason:         "manual retry after token=secret",
		ActorID:        "usr_retry",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
		RequestID:      "req_retry",
		CorrelationID:  "corr_retry",
	})
	if err != nil {
		t.Fatalf("retry job: %v", err)
	}
	if retry.ID == failed.ID {
		t.Fatalf("retry job reused source id %q, want fresh queued job", retry.ID)
	}
	if retry.Status != store.JobStatusQueued || retry.Attempts != 0 || !retry.StartedAt.IsZero() || !retry.FinishedAt.IsZero() {
		t.Fatalf("retry lifecycle = status %q attempts %d started %v finished %v, want fresh queued row", retry.Status, retry.Attempts, retry.StartedAt, retry.FinishedAt)
	}
	if retry.JobType != failed.JobType || retry.ProjectID != failed.ProjectID || retry.DesiredVersion != failed.DesiredVersion {
		t.Fatalf("retry clone = %+v, want source type/scope/version from %+v", retry, failed)
	}
	if retry.Payload["retried_job_id"] != failed.ID || retry.Payload["retry_requested_by"] != "usr_retry" || retry.Payload["project_id"] != proj.ID {
		t.Fatalf("retry payload = %+v, want cloned payload plus retry metadata", retry.Payload)
	}
	if retry.RequestID != "req_retry" || retry.CorrelationID != "corr_retry" {
		t.Fatalf("retry correlation = (%q,%q), want request correlation", retry.RequestID, retry.CorrelationID)
	}

	again, err := reader.RetryJob(ctx, store.RetryProvisioningJobInput{
		OrganizationID: failed.OrganizationID,
		JobID:          failed.ID,
		IdempotencyKey: "operator-retry-1",
		ActorID:        "usr_retry",
		ActorKind:      "usr",
		ActorOrgID:     org.ID,
		RequestID:      "req_retry_again",
		CorrelationID:  "corr_retry",
	})
	if err != nil {
		t.Fatalf("retry same idempotency key: %v", err)
	}
	if again.ID != retry.ID {
		t.Fatalf("idempotent retry id = %q, want existing %q", again.ID, retry.ID)
	}

	var audits []store.AuditEvent
	if err := s.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var readErr error
		audits, readErr = store.NewAuditRepository().ListByOrganization(ctx, q, org.ID, 10)
		return readErr
	}); err != nil {
		t.Fatalf("read audit events: %v", err)
	}
	if len(audits) != 1 {
		t.Fatalf("audit count = %d, want 1 allowed mutation audit", len(audits))
	}
	audit := audits[0]
	if audit.Action != "job.retry" || audit.ResourceID != failed.ID || audit.Metadata["retry_job_id"] != retry.ID {
		t.Fatalf("audit = %+v, want job.retry for source with retry_job_id", audit)
	}
	for _, needle := range []string{"yk_live_secret", "token=secret"} {
		if got := audit.Metadata["reason"]; strings.Contains(got, needle) {
			t.Fatalf("audit reason leaked %q: %q", needle, got)
		}
	}
}

func TestJobReaderRetryJobTenantAndStateGuards(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	s := newStore(t, db)
	repo := store.NewJobRepository()
	reader, err := store.NewJobReader(s)
	if err != nil {
		t.Fatalf("new job reader: %v", err)
	}
	f := testutil.NewFactory(t)
	ctx := context.Background()

	orgA := seedOrg(t, db, f, "RetryA")
	orgB := seedOrg(t, db, f, "RetryB")
	jobA := insertJob(ctx, t, s, repo, jobFixture(orgA.ID, "retry_tenant_a"))
	running := transitionJob(ctx, t, s, repo, orgA.ID, jobA.ID, store.JobStatusRunning, store.JobTransition{
		LeaseOwner:    "worker-1",
		LeaseDuration: time.Minute,
		Now:           time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
	})
	succeeded := transitionJob(ctx, t, s, repo, orgA.ID, running.ID, store.JobStatusSucceeded, store.JobTransition{
		Now: time.Date(2026, 5, 18, 12, 1, 0, 0, time.UTC),
	})

	_, err = reader.RetryJob(ctx, store.RetryProvisioningJobInput{
		OrganizationID: orgB.ID,
		JobID:          succeeded.ID,
		IdempotencyKey: "foreign",
		ActorID:        "usr_retry",
		ActorKind:      "usr",
		ActorOrgID:     orgB.ID,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeNotFound {
		t.Fatalf("RetryJob(cross tenant) code = %s, want %s; err=%v", ye.Code, yerr.CodeNotFound, err)
	}

	_, err = reader.RetryJob(ctx, store.RetryProvisioningJobInput{
		OrganizationID: orgA.ID,
		JobID:          succeeded.ID,
		IdempotencyKey: "succeeded",
		ActorID:        "usr_retry",
		ActorKind:      "usr",
		ActorOrgID:     orgA.ID,
	})
	if ye := yerr.From(err); ye.Code != yerr.CodeConflict {
		t.Fatalf("RetryJob(succeeded) code = %s, want %s; err=%v", ye.Code, yerr.CodeConflict, err)
	}
}
