package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// JobReader is the store-backed read adapter for the customer-facing
// provisioning-jobs list surface. It verifies any supplied parent filter inside
// the caller's tenant before listing jobs, so an unknown or cross-tenant
// project/environment/service id is a deterministic NotFound instead of an
// ambiguous empty list.
type JobReader struct {
	store        *Store
	jobs         *JobRepository
	audit        *AuditRepository
	projects     *ProjectRepository
	environments *EnvironmentRepository
	services     *ServiceRepository
}

// RetryProvisioningJobInput names a failed, cancelled, or dead-lettered job
// to re-issue as a fresh queued provisioning job. IdempotencyKey is caller
// supplied and scoped to the source job by the service before it reaches the
// provisioning_jobs uniqueness constraint.
type RetryProvisioningJobInput struct {
	OrganizationID string
	JobID          string
	IdempotencyKey string
	Reason         string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// NewJobReader builds a JobReader over store.
func NewJobReader(s *Store) (*JobReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &JobReader{
		store:        s,
		jobs:         NewJobRepository(),
		audit:        NewAuditRepository(),
		projects:     NewProjectRepository(),
		environments: NewEnvironmentRepository(),
		services:     NewServiceRepository(),
	}, nil
}

// ListJobs returns the provisioning jobs visible under the supplied tenant and
// optional resource filters.
func (r *JobReader) ListJobs(ctx context.Context, in ListProvisioningJobsInput) ([]ProvisioningJob, error) {
	var out []ProvisioningJob
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if in.ProjectID != "" {
			if _, err := r.projects.Get(ctx, q, in.OrganizationID, in.ProjectID); err != nil {
				return err
			}
		}
		if in.EnvironmentID != "" {
			env, err := r.environments.GetByID(ctx, q, in.OrganizationID, in.EnvironmentID)
			if err != nil {
				return err
			}
			if in.ProjectID != "" && env.ProjectID != in.ProjectID {
				return apierr.NotFound("environment", in.EnvironmentID)
			}
		}
		if in.ServiceID != "" {
			svc, err := r.services.GetByID(ctx, q, in.OrganizationID, in.ServiceID)
			if err != nil {
				return err
			}
			if in.ProjectID != "" && svc.ProjectID != in.ProjectID {
				return apierr.NotFound("service", in.ServiceID)
			}
			if in.EnvironmentID != "" && svc.EnvironmentID != in.EnvironmentID {
				return apierr.NotFound("service", in.ServiceID)
			}
		}
		list, err := r.jobs.List(ctx, q, in)
		if err != nil {
			return err
		}
		out = list
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetJob returns one provisioning job visible inside organizationID. The
// repository lookup is tenant-scoped, so an unknown id and a cross-tenant id
// collapse to the same NotFound shape.
func (r *JobReader) GetJob(ctx context.Context, organizationID, jobID string) (ProvisioningJob, error) {
	var out ProvisioningJob
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		job, err := r.jobs.Get(ctx, q, organizationID, jobID)
		if err != nil {
			return err
		}
		out = job
		return nil
	})
	if err != nil {
		return ProvisioningJob{}, err
	}
	return out, nil
}

// RetryJob clones a retryable terminal job into a new queued job and appends
// the job.retry audit record in the same transaction. The source row remains
// immutable: terminal lifecycle events stay terminal, while the new job is the
// durable unit the worker will claim.
func (r *JobReader) RetryJob(ctx context.Context, in RetryProvisioningJobInput) (ProvisioningJob, error) {
	validated, err := validateRetryProvisioningJobInput(in)
	if err != nil {
		return ProvisioningJob{}, err
	}

	var out ProvisioningJob
	err = r.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		source, err := r.jobs.Get(ctx, tx, validated.OrganizationID, validated.JobID)
		if err != nil {
			return err
		}
		if !source.Status.RetryableByRequest() {
			return apierr.Conflict("only failed, cancelled, or dead-lettered provisioning jobs can be retried")
		}

		key := retryJobIdempotencyKey(source.ID, validated.IdempotencyKey)
		if existing, ok, err := r.jobs.FindByIdempotencyKey(ctx, tx, validated.OrganizationID, key); err != nil {
			return err
		} else if ok {
			if existing.Payload["retried_job_id"] != source.ID {
				return apierr.Conflict("a provisioning job with this retry idempotency key already exists")
			}
			out = existing
			return nil
		}

		payload := cloneJobPayload(source.Payload)
		payload["retried_job_id"] = source.ID
		payload["retry_requested_by"] = validated.ActorID

		retry, err := r.jobs.Insert(ctx, tx, ProvisioningJob{
			OrganizationID: validated.OrganizationID,
			JobType:        source.JobType,
			ProjectID:      source.ProjectID,
			EnvironmentID:  source.EnvironmentID,
			ServiceID:      source.ServiceID,
			DesiredVersion: source.DesiredVersion,
			IdempotencyKey: key,
			MaxAttempts:    source.MaxAttempts,
			NextRunAt:      time.Now().UTC(),
			Payload:        payload,
			RequestID:      validated.RequestID,
			CorrelationID:  validated.CorrelationID,
		})
		if err != nil {
			return err
		}
		event := AuditEvent{
			OrganizationID: validated.ActorOrgID,
			ActorID:        validated.ActorID,
			ActorKind:      validated.ActorKind,
			Action:         "job.retry",
			ResourceKind:   string(domain.KindJob),
			ResourceID:     source.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for job.retry",
			RequestID:      validated.RequestID,
			CorrelationID:  validated.CorrelationID,
			Metadata: map[string]string{
				"job_id":       source.ID,
				"retry_job_id": retry.ID,
				"job_type":     source.JobType,
				"status":       source.Status.String(),
				"reason":       redactJobError(validated.Reason),
			},
		}
		if source.ProjectID != "" {
			event.Metadata["project_id"] = source.ProjectID
		}
		if source.EnvironmentID != "" {
			event.Metadata["environment_id"] = source.EnvironmentID
		}
		if source.ServiceID != "" {
			event.Metadata["service_id"] = source.ServiceID
		}
		if _, err := r.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		out = retry
		return nil
	})
	if err != nil {
		return ProvisioningJob{}, err
	}
	return out, nil
}

// RetryableByRequest reports whether a customer-facing POST /v1/jobs/{id}/retry
// may re-issue this terminal row as a new queued job.
func (s JobStatus) RetryableByRequest() bool {
	switch s {
	case JobStatusFailed, JobStatusCancelled, JobStatusDeadLetter:
		return true
	default:
		return false
	}
}

func validateRetryProvisioningJobInput(in RetryProvisioningJobInput) (RetryProvisioningJobInput, error) {
	in.OrganizationID = strings.TrimSpace(in.OrganizationID)
	in.JobID = strings.TrimSpace(in.JobID)
	in.IdempotencyKey = strings.TrimSpace(in.IdempotencyKey)
	in.Reason = strings.TrimSpace(in.Reason)
	in.ActorID = strings.TrimSpace(in.ActorID)
	in.ActorKind = strings.TrimSpace(in.ActorKind)
	in.ActorOrgID = strings.TrimSpace(in.ActorOrgID)
	in.RequestID = strings.TrimSpace(in.RequestID)
	in.CorrelationID = strings.TrimSpace(in.CorrelationID)

	var violations []apierr.FieldViolation
	if in.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must not be blank"})
	}
	if in.JobID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "job_id", Reason: "must not be blank"})
	}
	if in.IdempotencyKey == "" {
		violations = append(violations, apierr.FieldViolation{Field: "idempotency_key", Reason: "must not be blank"})
	}
	if len(in.IdempotencyKey) > 128 {
		violations = append(violations, apierr.FieldViolation{Field: "idempotency_key", Reason: "must be at most 128 characters"})
	}
	if len(in.Reason) > 512 {
		violations = append(violations, apierr.FieldViolation{Field: "reason", Reason: "must be at most 512 characters"})
	}
	if in.ActorOrgID == "" {
		return RetryProvisioningJobInput{}, apierr.Internal(errors.New("store: RetryJob requires an actor organization for the audit record"))
	}
	if in.ActorID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "requested_by", Reason: "must not be blank"})
	}
	if len(violations) > 0 {
		return RetryProvisioningJobInput{}, apierr.InvalidInput(violations...)
	}
	return in, nil
}

func retryJobIdempotencyKey(jobID, key string) string {
	return "retry:" + jobID + ":" + key
}

func cloneJobPayload(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+2)
	for k, v := range in {
		out[k] = v
	}
	return out
}
