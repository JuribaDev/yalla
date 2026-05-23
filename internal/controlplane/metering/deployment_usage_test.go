package metering_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/metering"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/testutil"
	yerr "github.com/JuribaDev/yalla/internal/errors"
)

func TestDeploymentUsageEmitterSuccessFailureRetryCancellationAndReplay(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	s := newMeteringStore(t, db)
	seed := seedMeteringHierarchy(t, db, testutil.NewFactory(t))

	emitter, err := metering.NewDeploymentUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewDeploymentUsageEmitter: %v", err)
	}

	successStarted := time.Date(2026, 5, 19, 10, 0, 0, 0, time.UTC)
	successFinished := successStarted.Add(3 * time.Minute)
	successDep := seedDeploymentUsageDeployment(t, db, seed, "success", store.DeploymentStatusSucceeded, successStarted, successFinished)
	seedDeploymentUsageEvent(t, db, seed.OrganizationID, successDep, store.DeploymentEventTypeSucceeded, successFinished)
	successJob := seedDeploymentUsageJob(t, db, seed, successDep, store.JobStatusSucceeded, successStarted, successFinished)
	seedDeploymentUsageAttempt(t, db, seed.OrganizationID, successJob, 1, store.JobAttemptStatusFailed, successStarted, successStarted.Add(time.Minute))
	seedDeploymentUsageAttempt(t, db, seed.OrganizationID, successJob, 2, store.JobAttemptStatusSucceeded, successStarted.Add(90*time.Second), successFinished)

	failureStarted := time.Date(2026, 5, 19, 11, 0, 0, 0, time.UTC)
	failureFinished := failureStarted.Add(2 * time.Minute)
	failedDep := seedDeploymentUsageDeployment(t, db, seed, "failed", store.DeploymentStatusFailed, failureStarted, failureFinished)
	seedDeploymentUsageEvent(t, db, seed.OrganizationID, failedDep, store.DeploymentEventTypeFailed, failureFinished)
	failedJob := seedDeploymentUsageJob(t, db, seed, failedDep, store.JobStatusFailed, failureStarted, failureFinished)
	seedDeploymentUsageAttempt(t, db, seed.OrganizationID, failedJob, 1, store.JobAttemptStatusFailed, failureStarted, failureFinished)

	cancelStarted := time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC)
	cancelFinished := cancelStarted.Add(45 * time.Second)
	cancelledDep := seedDeploymentUsageDeployment(t, db, seed, "cancelled", store.DeploymentStatusCancelled, cancelStarted, cancelFinished)
	seedDeploymentUsageEvent(t, db, seed.OrganizationID, cancelledDep, store.DeploymentEventTypeCancelled, cancelFinished)
	cancelledJob := seedDeploymentUsageJob(t, db, seed, cancelledDep, store.JobStatusCancelled, cancelStarted, cancelFinished)
	seedDeploymentUsageAttempt(t, db, seed.OrganizationID, cancelledJob, 1, store.JobAttemptStatusCancelled, cancelStarted, cancelFinished)

	first, err := emitter.EmitDeployment(ctx, seed.OrganizationID, successDep)
	if err != nil {
		t.Fatalf("EmitDeployment(success): %v", err)
	}
	replayed, err := emitter.EmitDeployment(ctx, seed.OrganizationID, successDep)
	if err != nil {
		t.Fatalf("EmitDeployment(success replay): %v", err)
	}
	failed, err := emitter.EmitDeployment(ctx, seed.OrganizationID, failedDep)
	if err != nil {
		t.Fatalf("EmitDeployment(failed): %v", err)
	}
	cancelled, err := emitter.EmitDeployment(ctx, seed.OrganizationID, cancelledDep)
	if err != nil {
		t.Fatalf("EmitDeployment(cancelled): %v", err)
	}

	if first.DeploymentEvent == nil || first.DeploymentEvent.Resource != store.QuotaResourceDeployments || first.DeploymentEvent.Quantity != 1 {
		t.Fatalf("success deployment event = %+v, want one deployments event", first.DeploymentEvent)
	}
	if first.BuildMinutesEvent == nil || first.BuildMinutesEvent.Resource != store.QuotaResourceBuildMinutes || first.BuildMinutesEvent.Unit != "minute" {
		t.Fatalf("success build event = %+v, want build_minutes/minute", first.BuildMinutesEvent)
	}
	if first.BuildMinutesEvent.Quantity != 2.5 {
		t.Fatalf("success build minutes = %v, want 2.5 from two attempt durations", first.BuildMinutesEvent.Quantity)
	}
	if replayed.DeploymentEvent == nil || replayed.DeploymentEvent.ID != first.DeploymentEvent.ID {
		t.Fatalf("deployment replay returned event %+v, want idempotent id %q", replayed.DeploymentEvent, first.DeploymentEvent.ID)
	}
	if replayed.BuildMinutesEvent == nil || replayed.BuildMinutesEvent.ID != first.BuildMinutesEvent.ID {
		t.Fatalf("build replay returned event %+v, want idempotent id %q", replayed.BuildMinutesEvent, first.BuildMinutesEvent.ID)
	}
	if failed.DeploymentEvent == nil || failed.DeploymentEvent.Resource != store.QuotaResourceFailedDeployments {
		t.Fatalf("failed deployment event = %+v, want failed_deployments event", failed.DeploymentEvent)
	}
	if failed.BuildMinutesEvent == nil || failed.BuildMinutesEvent.Quantity != 2 {
		t.Fatalf("failed build minutes = %+v, want 2", failed.BuildMinutesEvent)
	}
	if cancelled.DeploymentEvent != nil {
		t.Fatalf("cancelled deployment event = %+v, want no billable deployment count", cancelled.DeploymentEvent)
	}
	if cancelled.BuildMinutesEvent == nil || cancelled.BuildMinutesEvent.Quantity != 0.75 {
		t.Fatalf("cancelled build minutes = %+v, want 0.75", cancelled.BuildMinutesEvent)
	}

	assertUsageEventCount(t, db, seed.OrganizationID, 5)
}

func TestDeploymentUsageEmitterValidationNotFoundAndTenantIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	s := newMeteringStore(t, db)
	f := testutil.NewFactory(t)
	alpha := seedMeteringHierarchy(t, db, f)
	bravo := seedMeteringHierarchy(t, db, f)

	emitter, err := metering.NewDeploymentUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewDeploymentUsageEmitter: %v", err)
	}

	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := emitter.EmitDeploymentInTx(ctx, tx, "", "dep_blank")
		return err
	})
	assertYallaCode(t, err, yerr.CodeValidation)

	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := emitter.EmitDeploymentInTx(ctx, tx, alpha.OrganizationID, "dep_missing")
		return err
	})
	assertYallaCode(t, err, yerr.CodeNotFound)

	started := time.Date(2026, 5, 19, 13, 0, 0, 0, time.UTC)
	finished := started.Add(time.Minute)
	bravoDep := seedDeploymentUsageDeployment(t, db, bravo, "foreign", store.DeploymentStatusSucceeded, started, finished)
	seedDeploymentUsageEvent(t, db, bravo.OrganizationID, bravoDep, store.DeploymentEventTypeSucceeded, finished)
	job := seedDeploymentUsageJob(t, db, bravo, bravoDep, store.JobStatusSucceeded, started, finished)
	seedDeploymentUsageAttempt(t, db, bravo.OrganizationID, job, 1, store.JobAttemptStatusSucceeded, started, finished)

	err = s.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := emitter.EmitDeploymentInTx(ctx, tx, alpha.OrganizationID, bravoDep)
		return err
	})
	assertYallaCode(t, err, yerr.CodeNotFound)
	assertUsageEventCount(t, db, alpha.OrganizationID, 0)
	assertUsageEventCount(t, db, bravo.OrganizationID, 0)
}

func TestDeploymentUsageEmitterRequiresDeploymentEventAndJob(t *testing.T) {
	t.Parallel()
	db := testutil.RequireMigratedDB(t)
	ctx := context.Background()
	s := newMeteringStore(t, db)
	seed := seedMeteringHierarchy(t, db, testutil.NewFactory(t))

	emitter, err := metering.NewDeploymentUsageEmitter(s)
	if err != nil {
		t.Fatalf("NewDeploymentUsageEmitter: %v", err)
	}
	started := time.Date(2026, 5, 19, 14, 0, 0, 0, time.UTC)
	finished := started.Add(time.Minute)
	noEventDep := seedDeploymentUsageDeployment(t, db, seed, "no-event", store.DeploymentStatusSucceeded, started, finished)
	seedDeploymentUsageJob(t, db, seed, noEventDep, store.JobStatusSucceeded, started, finished)

	_, err = emitter.EmitDeployment(ctx, seed.OrganizationID, noEventDep)
	assertYallaCode(t, err, yerr.CodeNotFound)

	noJobDep := seedDeploymentUsageDeployment(t, db, seed, "no-job", store.DeploymentStatusSucceeded, started, finished)
	seedDeploymentUsageEvent(t, db, seed.OrganizationID, noJobDep, store.DeploymentEventTypeSucceeded, finished)
	_, err = emitter.EmitDeployment(ctx, seed.OrganizationID, noJobDep)
	assertYallaCode(t, err, yerr.CodeNotFound)
}

type meteringSeed struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

func newMeteringStore(t *testing.T, db *testutil.DB) *store.Store {
	t.Helper()
	s, err := store.New(db.Pool, nil)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s
}

func seedMeteringHierarchy(t *testing.T, db *testutil.DB, f *testutil.Factory) meteringSeed {
	t.Helper()
	org := f.Organization("Metering Org")
	project := f.Project(org, "Metering Project")
	env := f.Environment(project, "Production")
	svc := f.Service(env, "Web")
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO organizations (id, slug, display_name) VALUES ($1, $2, $3)`, org.ID, org.Slug, org.Name); err != nil {
		t.Fatalf("insert organization: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, organization_id, slug, display_name, status) VALUES ($1, $2, $3, $4, 'active')`, project.ID, org.ID, project.Slug, project.Name); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO environments (id, organization_id, project_id, slug, display_name, kind, status) VALUES ($1, $2, $3, $4, $5, $6, 'active')`, env.ID, org.ID, project.ID, env.Slug, env.Name, store.EnvironmentKindStandard); err != nil {
		t.Fatalf("insert environment: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO services (id, organization_id, project_id, environment_id, slug, display_name, kind, status) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')`, svc.ID, org.ID, project.ID, env.ID, svc.Slug, svc.Name, svc.Kind); err != nil {
		t.Fatalf("insert service: %v", err)
	}
	return meteringSeed{OrganizationID: org.ID, ProjectID: project.ID, EnvironmentID: env.ID, ServiceID: svc.ID}
}

func seedDeploymentUsageDeployment(t *testing.T, db *testutil.DB, seed meteringSeed, suffix string, status store.DeploymentStatus, startedAt, finishedAt time.Time) string {
	t.Helper()
	id := "dep_usage_" + suffix + "_" + seed.ServiceID[len(seed.ServiceID)-8:]
	ctx := context.Background()
	if _, err := db.Exec(ctx,
		`INSERT INTO deployments
		    (id, organization_id, project_id, environment_id, service_id, source, source_ref,
		     status, requested_by, idempotency_key, request_id, correlation_id, started_at, finished_at)
		 VALUES ($1, $2, $3, $4, $5, 'git', 'main', $6, 'usr_metering', $7, $8, $9, $10, $11)`,
		id, seed.OrganizationID, seed.ProjectID, seed.EnvironmentID, seed.ServiceID, status.String(),
		"idem-"+id, "req-"+id, "corr-"+id, startedAt, finishedAt); err != nil {
		t.Fatalf("insert deployment %s: %v", id, err)
	}
	return id
}

func seedDeploymentUsageEvent(t *testing.T, db *testutil.DB, orgID, deploymentID string, typ store.DeploymentEventType, occurredAt time.Time) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO deployment_events
		    (id, organization_id, deployment_id, event_type, message, request_id, correlation_id, occurred_at)
		 VALUES ($1, $2, $3, $4, 'done', $5, $6, $7)`,
		"depev_"+deploymentID+"_"+typ.String(), orgID, deploymentID, typ.String(), "req-"+deploymentID, "corr-"+deploymentID, occurredAt); err != nil {
		t.Fatalf("insert deployment event: %v", err)
	}
}

func seedDeploymentUsageJob(t *testing.T, db *testutil.DB, seed meteringSeed, deploymentID string, status store.JobStatus, startedAt, finishedAt time.Time) string {
	t.Helper()
	id := "job_usage_" + deploymentID
	if _, err := db.Exec(context.Background(),
		`INSERT INTO provisioning_jobs
		    (id, organization_id, job_type, project_id, environment_id, service_id, desired_version,
		     idempotency_key, status, attempts, max_attempts, payload, request_id, correlation_id,
		     started_at, finished_at)
		 VALUES ($1, $2, 'service.deploy', $3, $4, $5, 1, $6, $7, 1, 3, $8::jsonb, $9, $10, $11, $12)`,
		id, seed.OrganizationID, seed.ProjectID, seed.EnvironmentID, seed.ServiceID,
		"job-"+deploymentID, status.String(), `{"deployment_id":"`+deploymentID+`"}`, "req-"+deploymentID, "corr-"+deploymentID,
		startedAt, finishedAt); err != nil {
		t.Fatalf("insert provisioning job: %v", err)
	}
	return id
}

func seedDeploymentUsageAttempt(t *testing.T, db *testutil.DB, orgID, jobID string, attempt int, status store.JobAttemptStatus, startedAt, finishedAt time.Time) {
	t.Helper()
	if _, err := db.Exec(context.Background(),
		`INSERT INTO job_attempts
		    (id, organization_id, job_id, attempt_number, worker_id, status,
		     error_summary, error_code, request_id, correlation_id, started_at, finished_at)
		 VALUES ($1, $2, $3, $4, 'worker-metering', $5, '', '', $6, $7, $8, $9)`,
		jobID+"_attempt_"+time.Duration(attempt).String(), orgID, jobID, attempt, status.String(), "req-"+jobID, "corr-"+jobID, startedAt, finishedAt); err != nil {
		t.Fatalf("insert job attempt: %v", err)
	}
}

func assertUsageEventCount(t *testing.T, db *testutil.DB, orgID string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM usage_events WHERE organization_id = $1`, orgID).Scan(&got); err != nil {
		t.Fatalf("count usage_events: %v", err)
	}
	if got != want {
		t.Fatalf("usage_events for %s = %d, want %d", orgID, got, want)
	}
}

func assertYallaCode(t *testing.T, err error, code yerr.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}
	var ye *yerr.Error
	if !errors.As(err, &ye) || ye.Code != code {
		t.Fatalf("error = %v (%T), want %s", err, err, code)
	}
	if violations, ok := apierr.ViolationsOf(err); code == yerr.CodeValidation && (!ok || len(violations) == 0) {
		t.Fatalf("validation error has no field violations: %v", err)
	}
}
