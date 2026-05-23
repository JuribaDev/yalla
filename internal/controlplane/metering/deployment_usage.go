package metering

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/jackc/pgx/v5"
)

const (
	// DeploymentUsageSource is the stable usage_events source for deployment
	// counts derived from Yalla's deployment_events timeline.
	DeploymentUsageSource = "yalla_events"
	// BuildMinutesUsageSource is the stable usage_events source for build
	// duration derived from Yalla worker job timestamps.
	BuildMinutesUsageSource = "yalla_jobs"
)

// DeploymentUsageResult is the set of usage events emitted for one terminal
// deployment. Cancelled deployments do not emit a deployment count, but they
// may emit build_minutes for worker time already spent before cancellation.
type DeploymentUsageResult struct {
	DeploymentEvent   *store.UsageEvent
	BuildMinutesEvent *store.UsageEvent
}

// DeploymentUsageEmitter turns Yalla deployment and worker timelines into
// append-only usage_events rows. It never reads Dokploy current state: the
// deployment outcome comes from deployment_events, while build minutes come
// from provisioning_jobs/job_attempts timestamps.
type DeploymentUsageEmitter struct {
	store *store.Store
	usage *store.UsageEventRepository
}

// NewDeploymentUsageEmitter builds a store-backed deployment usage emitter.
func NewDeploymentUsageEmitter(s *store.Store) (*DeploymentUsageEmitter, error) {
	if s == nil {
		return nil, errors.New("metering: nil store")
	}
	return &DeploymentUsageEmitter{
		store: s,
		usage: store.NewUsageEventRepository(),
	}, nil
}

// EmitDeployment emits usage for deploymentID inside its own transaction.
func (e *DeploymentUsageEmitter) EmitDeployment(ctx context.Context, organizationID, deploymentID string) (DeploymentUsageResult, error) {
	if e == nil || e.store == nil {
		return DeploymentUsageResult{}, errors.New("metering: nil DeploymentUsageEmitter")
	}
	var result DeploymentUsageResult
	err := e.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		result, err = e.EmitDeploymentInTx(ctx, tx, organizationID, deploymentID)
		return err
	})
	if err != nil {
		return DeploymentUsageResult{}, err
	}
	return result, nil
}

// EmitDeploymentInTx emits usage for deploymentID using the caller's
// transaction. Callers that aggregate multiple deployment outcomes can use
// this to keep replay bookkeeping and usage writes atomic.
func (e *DeploymentUsageEmitter) EmitDeploymentInTx(ctx context.Context, tx *store.Tx, organizationID, deploymentID string) (DeploymentUsageResult, error) {
	if e == nil || e.usage == nil {
		return DeploymentUsageResult{}, errors.New("metering: nil DeploymentUsageEmitter")
	}
	if tx == nil {
		return DeploymentUsageResult{}, apierr.Internal(errors.New("metering: EmitDeploymentInTx called with nil transaction"))
	}
	orgID := strings.TrimSpace(organizationID)
	depID := strings.TrimSpace(deploymentID)
	var violations []apierr.FieldViolation
	if orgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	if depID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "deployment_id", Reason: "must not be blank"})
	}
	if len(violations) > 0 {
		return DeploymentUsageResult{}, apierr.InvalidInput(violations...)
	}

	deployment, err := store.NewDeploymentRepository().GetByID(ctx, tx, orgID, depID)
	if err != nil {
		return DeploymentUsageResult{}, err
	}
	if !deploymentUsageTerminal(deployment.Status) {
		return DeploymentUsageResult{}, apierr.Conflict("deployment usage can only be emitted for terminal deployments")
	}

	terminalEvent, err := deploymentUsageTerminalEvent(ctx, tx, deployment)
	if err != nil {
		return DeploymentUsageResult{}, err
	}
	job, err := deploymentUsageJob(ctx, tx, deployment)
	if err != nil {
		return DeploymentUsageResult{}, err
	}

	result := DeploymentUsageResult{}
	if resource, ok := deploymentUsageOutcomeResource(deployment.Status); ok {
		event, appendErr := e.usage.Append(ctx, tx, store.AppendUsageEventInput{
			OrganizationID: deployment.OrganizationID,
			ProjectID:      deployment.ProjectID,
			EnvironmentID:  deployment.EnvironmentID,
			ServiceID:      deployment.ServiceID,
			Resource:       resource,
			EventType:      store.UsageEventTypeConsumed,
			Quantity:       1,
			Unit:           "deployment",
			Source:         DeploymentUsageSource,
			IdempotencyKey: "deployment:" + deployment.ID + ":" + deployment.Status.String(),
			RequestID:      deployment.RequestID,
			OccurredAt:     terminalEvent.OccurredAt,
			Metadata: map[string]string{
				"deployment_id":       deployment.ID,
				"deployment_status":   deployment.Status.String(),
				"deployment_event_id": terminalEvent.ID,
				"job_id":              job.ID,
			},
		})
		if appendErr != nil {
			return DeploymentUsageResult{}, appendErr
		}
		result.DeploymentEvent = &event
	}

	minutes, attempts, err := deploymentUsageBuildMinutes(ctx, tx, job)
	if err != nil {
		return DeploymentUsageResult{}, err
	}
	if minutes > 0 {
		event, appendErr := e.usage.Append(ctx, tx, store.AppendUsageEventInput{
			OrganizationID: deployment.OrganizationID,
			ProjectID:      deployment.ProjectID,
			EnvironmentID:  deployment.EnvironmentID,
			ServiceID:      deployment.ServiceID,
			Resource:       store.QuotaResourceBuildMinutes,
			EventType:      store.UsageEventTypeConsumed,
			Quantity:       minutes,
			Unit:           "minute",
			Source:         BuildMinutesUsageSource,
			IdempotencyKey: "build_minutes:" + job.ID,
			RequestID:      job.RequestID,
			OccurredAt:     deploymentUsageOccurredAt(job, terminalEvent.OccurredAt),
			Metadata: map[string]string{
				"deployment_id":     deployment.ID,
				"deployment_status": deployment.Status.String(),
				"job_id":            job.ID,
				"job_status":        job.Status.String(),
				"attempt_count":     itoa(attempts),
				"rule":              "sum_completed_job_attempt_durations_minutes_fallback_to_terminal_job_duration",
			},
		})
		if appendErr != nil {
			return DeploymentUsageResult{}, appendErr
		}
		result.BuildMinutesEvent = &event
	}
	return result, nil
}

func deploymentUsageTerminal(status store.DeploymentStatus) bool {
	switch status {
	case store.DeploymentStatusSucceeded, store.DeploymentStatusFailed, store.DeploymentStatusCancelled, store.DeploymentStatusRolledBack:
		return true
	default:
		return false
	}
}

func deploymentUsageOutcomeResource(status store.DeploymentStatus) (store.QuotaResource, bool) {
	switch status {
	case store.DeploymentStatusSucceeded, store.DeploymentStatusRolledBack:
		return store.QuotaResourceDeployments, true
	case store.DeploymentStatusFailed:
		return store.QuotaResourceFailedDeployments, true
	default:
		return "", false
	}
}

func deploymentUsageTerminalEvent(ctx context.Context, q store.Querier, deployment store.Deployment) (store.DeploymentEvent, error) {
	events, err := store.NewDeploymentEventRepository().ListByDeployment(ctx, q, deployment.OrganizationID, deployment.ID)
	if err != nil {
		return store.DeploymentEvent{}, err
	}
	want := deployment.Status.String()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].EventType.String() == want {
			return events[i], nil
		}
	}
	return store.DeploymentEvent{}, apierr.NotFound("deployment_event", deployment.ID+":"+want)
}

type deploymentUsageProvisioningJob struct {
	ID             string
	OrganizationID string
	Status         store.JobStatus
	RequestID      string
	StartedAt      time.Time
	FinishedAt     time.Time
}

func deploymentUsageJob(ctx context.Context, q store.Querier, deployment store.Deployment) (deploymentUsageProvisioningJob, error) {
	var row deploymentUsageProvisioningJob
	var status string
	var startedAt, finishedAt *time.Time
	err := q.QueryRow(ctx,
		`SELECT id, organization_id, status, request_id, started_at, finished_at
		   FROM provisioning_jobs
		  WHERE organization_id = $1
		    AND job_type IN ('service.deploy', 'deploy_service')
		    AND payload->>'deployment_id' = $2
		  ORDER BY created_at DESC, id DESC
		  LIMIT 1`,
		deployment.OrganizationID, deployment.ID,
	).Scan(&row.ID, &row.OrganizationID, &status, &row.RequestID, &startedAt, &finishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return deploymentUsageProvisioningJob{}, apierr.NotFound("provisioning job", deployment.ID)
	}
	if err != nil {
		return deploymentUsageProvisioningJob{}, apierr.StoreUnavailable(err)
	}
	row.Status = store.JobStatus(status)
	if startedAt != nil {
		row.StartedAt = startedAt.UTC()
	}
	if finishedAt != nil {
		row.FinishedAt = finishedAt.UTC()
	}
	return row, nil
}

func deploymentUsageBuildMinutes(ctx context.Context, q store.Querier, job deploymentUsageProvisioningJob) (float64, int, error) {
	rows, err := q.Query(ctx,
		`SELECT started_at, finished_at
		   FROM job_attempts
		  WHERE organization_id = $1 AND job_id = $2
		  ORDER BY attempt_number ASC`,
		job.OrganizationID, job.ID)
	if err != nil {
		return 0, 0, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	var total time.Duration
	attempts := 0
	for rows.Next() {
		var started, finished time.Time
		if err := rows.Scan(&started, &finished); err != nil {
			return 0, 0, apierr.StoreUnavailable(err)
		}
		attempts++
		if finished.After(started) {
			total += finished.Sub(started)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, apierr.StoreUnavailable(err)
	}
	if attempts == 0 && !job.StartedAt.IsZero() && job.FinishedAt.After(job.StartedAt) {
		total = job.FinishedAt.Sub(job.StartedAt)
	}
	return total.Minutes(), attempts, nil
}

func deploymentUsageOccurredAt(job deploymentUsageProvisioningJob, fallback time.Time) time.Time {
	if !job.FinishedAt.IsZero() {
		return job.FinishedAt
	}
	return fallback
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
