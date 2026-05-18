package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apienvelope"
	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/policy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

var errNoJobReader = errors.New("httpapi: no job reader configured")

const (
	jobListDefaultLimit = 50
	jobListMaxLimit     = 200
)

// JobReader is the narrow read port GET /v1/jobs depends on.
type JobReader interface {
	ListJobs(ctx context.Context, in store.ListProvisioningJobsInput) ([]store.ProvisioningJob, error)
	GetJob(ctx context.Context, organizationID, jobID string) (store.ProvisioningJob, error)
}

type listJobsPayload struct {
	Jobs []jobResource `json:"jobs"`
}

type getJobPayload struct {
	Job jobResource `json:"job"`
}

type jobResource struct {
	ID             string            `json:"id"`
	OrganizationID string            `json:"organization_id"`
	JobType        string            `json:"job_type"`
	ProjectID      string            `json:"project_id,omitempty"`
	EnvironmentID  string            `json:"environment_id,omitempty"`
	ServiceID      string            `json:"service_id,omitempty"`
	DesiredVersion int64             `json:"desired_version"`
	IdempotencyKey string            `json:"idempotency_key"`
	Status         string            `json:"status"`
	Attempts       int               `json:"attempts"`
	MaxAttempts    int               `json:"max_attempts"`
	LeaseOwner     string            `json:"lease_owner,omitempty"`
	LeaseDeadline  *string           `json:"lease_deadline,omitempty"`
	NextRunAt      time.Time         `json:"next_run_at"`
	ErrorSummary   string            `json:"error_summary,omitempty"`
	Payload        map[string]string `json:"payload"`
	RequestID      string            `json:"request_id"`
	CorrelationID  string            `json:"correlation_id,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	StartedAt      *string           `json:"started_at,omitempty"`
	FinishedAt     *string           `json:"finished_at,omitempty"`
}

func jobResourceOf(j store.ProvisioningJob) jobResource {
	out := jobResource{
		ID:             j.ID,
		OrganizationID: j.OrganizationID,
		JobType:        j.JobType,
		ProjectID:      j.ProjectID,
		EnvironmentID:  j.EnvironmentID,
		ServiceID:      j.ServiceID,
		DesiredVersion: j.DesiredVersion,
		IdempotencyKey: j.IdempotencyKey,
		Status:         j.Status.String(),
		Attempts:       j.Attempts,
		MaxAttempts:    j.MaxAttempts,
		LeaseOwner:     j.LeaseOwner,
		NextRunAt:      j.NextRunAt,
		ErrorSummary:   j.ErrorSummary,
		Payload:        j.Payload,
		RequestID:      j.RequestID,
		CorrelationID:  j.CorrelationID,
		CreatedAt:      j.CreatedAt,
		UpdatedAt:      j.UpdatedAt,
	}
	if j.LeaseDeadline.IsZero() {
		out.LeaseDeadline = nil
	} else {
		v := j.LeaseDeadline.UTC().Format(time.RFC3339Nano)
		out.LeaseDeadline = &v
	}
	if j.StartedAt.IsZero() {
		out.StartedAt = nil
	} else {
		v := j.StartedAt.UTC().Format(time.RFC3339Nano)
		out.StartedAt = &v
	}
	if j.FinishedAt.IsZero() {
		out.FinishedAt = nil
	} else {
		v := j.FinishedAt.UTC().Format(time.RFC3339Nano)
		out.FinishedAt = &v
	}
	if out.Payload == nil {
		out.Payload = map[string]string{}
	}
	return out
}

func jobListResolver(r *http.Request) policy.Resource {
	scope := policy.Scope{
		ProjectID:     r.URL.Query().Get("project_id"),
		EnvironmentID: r.URL.Query().Get("environment_id"),
		ServiceID:     r.URL.Query().Get("service_id"),
	}
	if p, ok := policy.PrincipalFromContext(r.Context()); ok {
		scope.OrganizationID = p.OrganizationID
	}
	return policy.Resource{Kind: domain.KindJob, Scope: scope}
}

func jobIDResolver(reader JobReader) ResourceResolver {
	return func(r *http.Request) policy.Resource {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok {
			return policy.Resource{Kind: domain.KindJob}
		}
		res := policy.Resource{Kind: domain.KindJob, Scope: policy.Scope{OrganizationID: p.OrganizationID}}
		if reader == nil {
			return res
		}
		jobID := r.PathValue("job_id")
		id, err := domain.ParseID(jobID)
		if err != nil || id.Kind() != domain.KindJob {
			return res
		}
		job, err := reader.GetJob(r.Context(), p.OrganizationID, jobID)
		if err != nil {
			return res
		}
		res.Scope.ProjectID = job.ProjectID
		res.Scope.EnvironmentID = job.EnvironmentID
		res.Scope.ServiceID = job.ServiceID
		return res
	}
}

func listJobsHandler(reader JobReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoJobReader))
			return
		}
		in, err := parseListJobsInput(r, p.OrganizationID)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		jobs, err := reader.ListJobs(r.Context(), in)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		out := make([]jobResource, 0, len(jobs))
		for _, j := range jobs {
			out = append(out, jobResourceOf(j))
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), listJobsPayload{Jobs: out})
	}
}

func getJobHandler(reader JobReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := policy.PrincipalFromContext(r.Context())
		if !ok || p.ID == "" {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoPrincipalOnContext))
			return
		}
		if reader == nil {
			apienvelope.WriteError(w, requestID(r), apierr.Internal(errNoJobReader))
			return
		}
		jobID := r.PathValue("job_id")
		id, err := domain.ParseID(jobID)
		if err != nil || id.Kind() != domain.KindJob {
			apienvelope.WriteError(w, requestID(r), apierr.InvalidInput(apierr.FieldViolation{
				Field:  "job_id",
				Reason: "must be a valid job id",
			}))
			return
		}
		job, err := reader.GetJob(r.Context(), p.OrganizationID, jobID)
		if err != nil {
			apienvelope.WriteError(w, requestID(r), toAPIError(err))
			return
		}
		apienvelope.WriteData(w, http.StatusOK, requestID(r), getJobPayload{Job: jobResourceOf(job)})
	}
}

func parseListJobsInput(r *http.Request, organizationID string) (store.ListProvisioningJobsInput, error) {
	q := r.URL.Query()
	limit, err := parseJobListLimit(q.Get("limit"))
	if err != nil {
		return store.ListProvisioningJobsInput{}, err
	}
	status := store.JobStatus(q.Get("status"))
	if status != "" && !status.Valid() {
		return store.ListProvisioningJobsInput{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "status",
			Reason: "must be one of queued, running, retrying, succeeded, failed, cancelled, or dead_letter",
		})
	}
	if q.Get("environment_id") != "" && q.Get("project_id") == "" {
		return store.ListProvisioningJobsInput{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "project_id",
			Reason: "is required when environment_id is supplied",
		})
	}
	if q.Get("service_id") != "" && (q.Get("project_id") == "" || q.Get("environment_id") == "") {
		return store.ListProvisioningJobsInput{}, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "requires project_id and environment_id filters",
		})
	}
	return store.ListProvisioningJobsInput{
		OrganizationID: organizationID,
		ProjectID:      q.Get("project_id"),
		EnvironmentID:  q.Get("environment_id"),
		ServiceID:      q.Get("service_id"),
		Status:         status,
		Limit:          limit,
	}, nil
}

func parseJobListLimit(raw string) (int, error) {
	if raw == "" {
		return jobListDefaultLimit, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apierr.InvalidInput(apierr.FieldViolation{Field: "limit", Reason: "must be a positive integer"})
	}
	if n < 1 || n > jobListMaxLimit {
		return 0, apierr.InvalidInput(apierr.FieldViolation{
			Field:  "limit",
			Reason: "must be between 1 and " + strconv.Itoa(jobListMaxLimit),
		})
	}
	return n, nil
}
