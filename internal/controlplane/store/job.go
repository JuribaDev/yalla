package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/jackc/pgx/v5"
)

// JobStatus is the lifecycle state of a provisioning job. It mirrors the
// provisioning_jobs.status CHECK constraint exactly: the set is closed, so a
// value outside it is rejected both by this type's Valid check and by the
// database.
type JobStatus string

// The closed set of provisioning job statuses.
//
// A job is enqueued queued, claimed into running, and then either finishes
// (succeeded), is retried after a transient failure (retrying -> running
// again), fails permanently (failed), exhausts its retry budget (dead_letter),
// or is cancelled. succeeded, failed, cancelled, and dead_letter are terminal.
const (
	JobStatusQueued     JobStatus = "queued"
	JobStatusRunning    JobStatus = "running"
	JobStatusRetrying   JobStatus = "retrying"
	JobStatusSucceeded  JobStatus = "succeeded"
	JobStatusFailed     JobStatus = "failed"
	JobStatusCancelled  JobStatus = "cancelled"
	JobStatusDeadLetter JobStatus = "dead_letter"
)

// jobStatuses is the membership set behind JobStatus.Valid.
var jobStatuses = map[JobStatus]struct{}{
	JobStatusQueued:     {},
	JobStatusRunning:    {},
	JobStatusRetrying:   {},
	JobStatusSucceeded:  {},
	JobStatusFailed:     {},
	JobStatusCancelled:  {},
	JobStatusDeadLetter: {},
}

// jobTransitions is the authoritative provisioning-job state machine: the set
// of statuses each status may move to. A terminal status has no outgoing edges
// and is absent from the map. CanTransitionTo is the only reader.
//
//	queued    -> running, cancelled
//	running   -> succeeded, retrying, failed, dead_letter, cancelled
//	retrying  -> running, cancelled
//	succeeded | failed | cancelled | dead_letter -> (terminal)
var jobTransitions = map[JobStatus]map[JobStatus]struct{}{
	JobStatusQueued: {
		JobStatusRunning:   {},
		JobStatusCancelled: {},
	},
	JobStatusRunning: {
		JobStatusSucceeded:  {},
		JobStatusRetrying:   {},
		JobStatusFailed:     {},
		JobStatusDeadLetter: {},
		JobStatusCancelled:  {},
	},
	JobStatusRetrying: {
		JobStatusRunning:   {},
		JobStatusCancelled: {},
	},
}

// Valid reports whether s is one of the closed set of job statuses.
func (s JobStatus) Valid() bool {
	_, ok := jobStatuses[s]
	return ok
}

// String returns the status's stable string value.
func (s JobStatus) String() string { return string(s) }

// Terminal reports whether s is an end state — a job that has succeeded,
// failed, been cancelled, or been dead-lettered makes no further transitions.
func (s JobStatus) Terminal() bool {
	switch s {
	case JobStatusSucceeded, JobStatusFailed, JobStatusCancelled, JobStatusDeadLetter:
		return true
	default:
		return false
	}
}

// CanTransitionTo reports whether a job in status s may legally move to status
// to. It is the single source of truth for the state machine: a transition
// not present in jobTransitions — including a no-op s -> s and any move out of
// a terminal status — is rejected.
func (s JobStatus) CanTransitionTo(to JobStatus) bool {
	next, ok := jobTransitions[s]
	if !ok {
		return false
	}
	_, ok = next[to]
	return ok
}

// defaultJobMaxAttempts is the retry budget assigned to a job whose caller
// does not specify one. After this many attempts a failing job is
// dead-lettered rather than retried.
const defaultJobMaxAttempts = 20

// jobListMaxLimit caps how many rows a single ListByOrganization call returns,
// so an unbounded query can never be issued by accident. A non-positive or
// larger requested limit is clamped to this value.
const jobListMaxLimit = 200

// jobErrorRedactor scrubs secrets out of a job's error summary before it is
// persisted. It carries no registered literal secrets — it is a structural
// backstop against well-known transport patterns (Authorization headers,
// token-bearing query params) that a Dokploy or datastore error string might
// carry into error_summary. Redaction is idempotent, so an already-clean
// summary passes through unchanged.
var jobErrorRedactor = output.NewRedactor()

// redactJobError returns s with every known secret pattern replaced by the
// redaction sentinel. It is the single chokepoint every persisted error
// summary passes through.
func redactJobError(s string) string { return jobErrorRedactor.Redact(s) }

// ProvisioningJob is the source-of-truth representation of a row in the
// provisioning_jobs table — one durable, idempotent unit of Dokploy
// provisioning work. It is the persistence-layer shape; HTTP request and
// response shapes are the job of the httpapi layer.
//
// The resource-target fields (ProjectID, EnvironmentID, ServiceID) are empty
// when the job does not target that level of the hierarchy. ErrorSummary is
// always redacted: it is run through the output redactor by the repository
// before it is ever persisted, so it can never carry a token or API key.
// Payload holds only non-secret references; no field ever stores a credential.
type ProvisioningJob struct {
	ID             string
	OrganizationID string
	JobType        string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	DesiredVersion int64
	IdempotencyKey string
	Status         JobStatus
	Attempts       int
	MaxAttempts    int
	LeaseOwner     string
	LeaseDeadline  time.Time
	NextRunAt      time.Time
	ErrorSummary   string
	Payload        map[string]string
	RequestID      string
	CorrelationID  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	StartedAt      time.Time
	FinishedAt     time.Time
}

// JobTransition carries the fields a single state transition may change. Which
// fields are honoured depends on the target status; the repository derives the
// lease, attempt-count, and timestamp bookkeeping from the target status so a
// caller cannot leave the row in a shape the database CHECKs reject.
type JobTransition struct {
	// LeaseOwner and LeaseDuration are required when transitioning to
	// JobStatusRunning (a worker claiming the job) and ignored otherwise.
	LeaseOwner    string
	LeaseDuration time.Duration
	// NextRunAt schedules when the job next becomes eligible to claim. It is
	// honoured for JobStatusRetrying (backoff); a zero value defaults to Now.
	NextRunAt time.Time
	// ErrorSummary is the human-readable failure reason. It is redacted before
	// it is persisted. Honoured for retrying, failed, dead_letter, and
	// cancelled; an empty value leaves the stored summary unchanged.
	ErrorSummary string
	// ActorID and ActorKind identify the worker, user, or system actor that
	// caused the transition. When omitted, Transition derives a conservative
	// actor from the lease owner, then falls back to "system".
	ActorID   string
	ActorKind string
	// RequestID and CorrelationID are written to the immutable job event. When
	// omitted, the parent job's originating request/correlation IDs are used.
	RequestID     string
	CorrelationID string
	// Reason is the redacted, human-readable transition reason recorded in the
	// immutable event. ErrorSummary is used as a fallback for failure-like
	// transitions.
	Reason string
	// Now overrides the transition clock; tests set it for determinism. A zero
	// value defaults to time.Now().UTC().
	Now time.Time
}

// now returns the transition clock — the caller-supplied Now, or the wall
// clock in UTC when unset.
func (t JobTransition) now() time.Time {
	if t.Now.IsZero() {
		return time.Now().UTC()
	}
	return t.Now.UTC()
}

// JobRepository is the persistence layer for Yalla's durable provisioning job
// queue. It follows the same transaction pattern as ProjectRepository:
//
//   - Mutations (Insert, Transition) require a *Tx, so they can only run inside
//     Store.Write and commit or roll back atomically with the desired-state
//     write they accompany.
//   - Reads accept a Querier, so they run against a read-only transaction or an
//     open write transaction.
//   - Every query is tenant scoped by organization_id before job id, so a job
//     id from another organization can never match.
//   - Missing rows are reported as a typed apierr.NotFound, never a bare
//     pgx.ErrNoRows.
//
// On top of that pattern it owns the provisioning-job state machine: Transition
// validates every status change against JobStatus.CanTransitionTo, so an
// illegal transition is rejected before it reaches the database, and every
// accepted transition appends an immutable provisioning_job_events row in the
// same transaction.
//
// The repository is stateless; the constructor exists so call sites depend on
// a value rather than a bare struct literal.
type JobRepository struct{}

// NewJobRepository returns a JobRepository.
func NewJobRepository() *JobRepository { return &JobRepository{} }

// provisioningJobColumns is the column list returned by every job query, in
// the order scanProvisioningJob expects.
const provisioningJobColumns = `id, organization_id, job_type, project_id, environment_id, ` +
	`service_id, desired_version, idempotency_key, status, attempts, max_attempts, ` +
	`lease_owner, lease_deadline, next_run_at, error_summary, payload, request_id, ` +
	`correlation_id, created_at, updated_at, started_at, finished_at`

// Insert enqueues a new provisioning job inside tx and returns the persisted
// row, including the database-assigned timestamps. It requires a *Tx — not a
// bare Querier — so a job can never be enqueued outside the transaction that
// also carries its authorization, quota, and desired-state write.
//
// A new job always starts in JobStatusQueued with zero attempts: a non-zero
// Attempts is reset and a non-queued Status is rejected as a programming
// error. A blank ID is minted here. A blank or non-positive MaxAttempts
// defaults to defaultJobMaxAttempts; a zero NextRunAt defaults to now so the
// job is immediately eligible to claim. JobType and IdempotencyKey are
// required. An idempotency key that collides with an existing job in the same
// organization is reported as a Conflict — that is the idempotency guarantee:
// a retried request enqueues the job exactly once.
func (r *JobRepository) Insert(ctx context.Context, tx *Tx, j ProvisioningJob) (ProvisioningJob, error) {
	if tx == nil {
		return ProvisioningJob{}, apierr.Internal(errors.New("store: JobRepository.Insert called with a nil transaction"))
	}
	var violations []apierr.FieldViolation
	if j.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if j.JobType == "" {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "is required"})
	}
	if j.IdempotencyKey == "" {
		violations = append(violations, apierr.FieldViolation{Field: "idempotency_key", Reason: "is required"})
	}
	if j.DesiredVersion < 0 {
		violations = append(violations, apierr.FieldViolation{Field: "desired_version", Reason: "must not be negative"})
	}
	if j.MaxAttempts < 0 {
		violations = append(violations, apierr.FieldViolation{Field: "max_attempts", Reason: "must not be negative"})
	}
	if j.Status != "" && j.Status != JobStatusQueued {
		violations = append(violations, apierr.FieldViolation{Field: "status", Reason: "a new job must start in the queued status"})
	}
	if len(violations) > 0 {
		return ProvisioningJob{}, apierr.InvalidInput(violations...)
	}

	if j.ID == "" {
		id, err := domain.NewID(domain.KindJob)
		if err != nil {
			return ProvisioningJob{}, apierr.Internal(err)
		}
		j.ID = string(id)
	}
	if j.MaxAttempts == 0 {
		j.MaxAttempts = defaultJobMaxAttempts
	}
	// A new job is always queued with no attempts spent yet, regardless of
	// what the caller passed: the lifecycle starts here.
	j.Status = JobStatusQueued
	j.Attempts = 0
	if j.NextRunAt.IsZero() {
		j.NextRunAt = time.Now().UTC()
	}
	j.ErrorSummary = redactJobError(j.ErrorSummary)

	payload, err := marshalJobPayload(j.Payload)
	if err != nil {
		return ProvisioningJob{}, apierr.Internal(err)
	}

	row := tx.QueryRow(ctx,
		`INSERT INTO provisioning_jobs
		   (id, organization_id, job_type, project_id, environment_id, service_id,
		    desired_version, idempotency_key, status, attempts, max_attempts,
		    next_run_at, error_summary, payload, request_id, correlation_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		 RETURNING `+provisioningJobColumns,
		j.ID, j.OrganizationID, j.JobType, nullableID(j.ProjectID), nullableID(j.EnvironmentID),
		nullableID(j.ServiceID), j.DesiredVersion, j.IdempotencyKey, string(j.Status),
		j.Attempts, j.MaxAttempts, j.NextRunAt, j.ErrorSummary, payload, j.RequestID, j.CorrelationID)
	created, err := scanProvisioningJob(row)
	if err != nil {
		return ProvisioningJob{}, mapWriteError(err, "a provisioning job with this idempotency key already exists in the organization")
	}
	return created, nil
}

// Get returns the provisioning job identified by jobID within organizationID.
// The query is tenant scoped: it filters by organization_id first, so a job id
// that belongs to another organization simply does not match and is reported
// as NotFound — a cross-tenant id can never reveal another organization's
// job. It accepts a Querier so it works against a read-only transaction or an
// open write transaction.
func (r *JobRepository) Get(ctx context.Context, q Querier, organizationID, jobID string) (ProvisioningJob, error) {
	row := q.QueryRow(ctx,
		`SELECT `+provisioningJobColumns+`
		   FROM provisioning_jobs
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, jobID)
	j, err := scanProvisioningJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProvisioningJob{}, apierr.NotFound("provisioning job", jobID)
	}
	if err != nil {
		return ProvisioningJob{}, apierr.StoreUnavailable(err)
	}
	return j, nil
}

// FindByIdempotencyKey returns the provisioning job enqueued under key within
// organizationID. The boolean is false when no job exists for the key — that
// is the lookup an idempotency-aware enqueue path runs first to decide whether
// to return the existing job or create a new one. The query is tenant scoped
// by organization_id, so a key from another tenant never matches.
func (r *JobRepository) FindByIdempotencyKey(ctx context.Context, q Querier, organizationID, key string) (ProvisioningJob, bool, error) {
	row := q.QueryRow(ctx,
		`SELECT `+provisioningJobColumns+`
		   FROM provisioning_jobs
		  WHERE organization_id = $1 AND idempotency_key = $2`,
		organizationID, key)
	j, err := scanProvisioningJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProvisioningJob{}, false, nil
	}
	if err != nil {
		return ProvisioningJob{}, false, apierr.StoreUnavailable(err)
	}
	return j, true, nil
}

// ListByOrganization returns the most recent provisioning jobs for
// organizationID, newest first, capped at limit (clamped to jobListMaxLimit,
// and to that maximum when limit is non-positive). The query is tenant scoped
// by organization_id, so a job from another organization can never appear in
// the result. It accepts a Querier so it works against a read-only or an open
// write transaction.
func (r *JobRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string, limit int) ([]ProvisioningJob, error) {
	if limit <= 0 || limit > jobListMaxLimit {
		limit = jobListMaxLimit
	}
	rows, err := q.Query(ctx,
		`SELECT `+provisioningJobColumns+`
		   FROM provisioning_jobs
		  WHERE organization_id = $1
		  ORDER BY created_at DESC, id DESC
		  LIMIT $2`,
		organizationID, limit)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []ProvisioningJob
	for rows.Next() {
		j, scanErr := scanProvisioningJob(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// Transition moves the job identified by jobID within organizationID to status
// to, applying the lease, attempt-count, and timestamp bookkeeping that status
// implies. It is the single mutating path for a job's lifecycle and the
// enforcement point of the state machine.
//
// It requires a *Tx, locks the job row FOR UPDATE so two workers cannot
// transition the same job concurrently, and validates the move against
// JobStatus.CanTransitionTo before touching any column — an illegal transition
// (a no-op, a move out of a terminal status, or any edge not in the state
// machine) is rejected as E_INVALID_STATE_TRANSITION and the row is left
// untouched. A job id from another organization, or one that does not exist,
// is reported as NotFound.
//
// The per-status bookkeeping:
//
//   - running:   takes the lease (LeaseOwner + LeaseDuration are required),
//     increments attempts (rejected as a Conflict if it would exceed the retry
//     budget), and stamps started_at on the first claim.
//   - retrying:  releases the lease and schedules NextRunAt for backoff.
//   - succeeded: releases the lease, stamps finished_at, clears the error
//     summary.
//   - failed / dead_letter / cancelled: releases the lease and stamps
//     finished_at; a non-empty JobTransition.ErrorSummary is redacted and
//     stored, an empty one leaves the existing summary intact.
func (r *JobRepository) Transition(ctx context.Context, tx *Tx, organizationID, jobID string, to JobStatus, mut JobTransition) (ProvisioningJob, error) {
	if tx == nil {
		return ProvisioningJob{}, apierr.Internal(errors.New("store: JobRepository.Transition called with a nil transaction"))
	}
	if !to.Valid() {
		return ProvisioningJob{}, apierr.Internal(fmt.Errorf("store: JobRepository.Transition called with an invalid target status %q", to))
	}

	// Lock the row for the rest of tx so a concurrent worker blocks here rather
	// than racing the same transition.
	locked := tx.QueryRow(ctx,
		`SELECT `+provisioningJobColumns+`
		   FROM provisioning_jobs
		  WHERE organization_id = $1 AND id = $2
		  FOR UPDATE`,
		organizationID, jobID)
	current, err := scanProvisioningJob(locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProvisioningJob{}, apierr.NotFound("provisioning job", jobID)
	}
	if err != nil {
		return ProvisioningJob{}, apierr.StoreUnavailable(err)
	}

	if !current.Status.CanTransitionTo(to) {
		return ProvisioningJob{}, apierr.InvalidStateTransition("provisioning_job", current.Status.String(), to.String())
	}

	// Derive the post-transition shape of the mutable columns from the target
	// status. Everything starts from the current row so an unaffected column
	// is written back unchanged.
	now := mut.now()
	var (
		attempts      = current.Attempts
		leaseOwner    string
		leaseDeadline *time.Time
		nextRunAt     = current.NextRunAt
		errorSummary  = current.ErrorSummary
		startedAt     = nullableTime(current.StartedAt)
		finishedAt    *time.Time
	)

	switch to {
	case JobStatusRunning:
		if mut.LeaseOwner == "" || mut.LeaseDuration <= 0 {
			return ProvisioningJob{}, apierr.Invalid(
				"a transition to running requires a non-empty lease owner and a positive lease duration")
		}
		if attempts+1 > current.MaxAttempts {
			return ProvisioningJob{}, apierr.Conflict(
				"provisioning job has exhausted its retry budget and cannot be claimed again")
		}
		attempts++
		leaseOwner = mut.LeaseOwner
		deadline := now.Add(mut.LeaseDuration)
		leaseDeadline = &deadline
		if startedAt == nil {
			startedAt = &now
		}
	case JobStatusRetrying:
		nextRunAt = mut.NextRunAt
		if nextRunAt.IsZero() {
			nextRunAt = now
		}
		if mut.ErrorSummary != "" {
			errorSummary = redactJobError(mut.ErrorSummary)
		}
	case JobStatusSucceeded:
		finishedAt = &now
		errorSummary = ""
	case JobStatusFailed, JobStatusDeadLetter, JobStatusCancelled:
		finishedAt = &now
		if mut.ErrorSummary != "" {
			errorSummary = redactJobError(mut.ErrorSummary)
		}
	}

	row := tx.QueryRow(ctx,
		`UPDATE provisioning_jobs
		    SET status = $3,
		        attempts = $4,
		        lease_owner = $5,
		        lease_deadline = $6,
		        next_run_at = $7,
		        error_summary = $8,
		        started_at = $9,
		        finished_at = $10
		  WHERE organization_id = $1 AND id = $2
		  RETURNING `+provisioningJobColumns,
		organizationID, jobID, string(to), attempts, leaseOwner, leaseDeadline,
		nextRunAt, errorSummary, startedAt, finishedAt)
	updated, err := scanProvisioningJob(row)
	if err != nil {
		return ProvisioningJob{}, mapWriteError(err, "the provisioning job transition conflicts with the current job state")
	}
	if _, err := NewJobEventRepository().Append(ctx, tx, jobEventForTransition(current, updated, mut)); err != nil {
		return ProvisioningJob{}, err
	}
	return updated, nil
}

func jobEventForTransition(previous, next ProvisioningJob, mut JobTransition) JobEvent {
	reason := strings.TrimSpace(mut.Reason)
	if reason == "" {
		reason = strings.TrimSpace(mut.ErrorSummary)
	}
	reason = redactJobError(reason)

	requestID := strings.TrimSpace(mut.RequestID)
	if requestID == "" {
		requestID = previous.RequestID
	}
	correlationID := strings.TrimSpace(mut.CorrelationID)
	if correlationID == "" {
		correlationID = previous.CorrelationID
	}

	actorID := strings.TrimSpace(mut.ActorID)
	actorKind := strings.TrimSpace(mut.ActorKind)
	if actorID == "" && mut.LeaseOwner != "" {
		actorID = strings.TrimSpace(mut.LeaseOwner)
		if actorKind == "" {
			actorKind = "worker"
		}
	}
	if actorID == "" && previous.LeaseOwner != "" {
		actorID = strings.TrimSpace(previous.LeaseOwner)
		if actorKind == "" {
			actorKind = "worker"
		}
	}
	if actorID == "" {
		actorID = "system"
	}
	if actorKind == "" {
		actorKind = "system"
	}

	return JobEvent{
		OrganizationID: next.OrganizationID,
		JobID:          next.ID,
		EventType:      next.Status.jobEventType(),
		Message:        reason,
		Metadata: map[string]string{
			"actor_id":       actorID,
			"actor_kind":     actorKind,
			"previous_state": previous.Status.String(),
			"next_state":     next.Status.String(),
			"reason":         reason,
		},
		RequestID:     requestID,
		CorrelationID: correlationID,
		OccurredAt:    mut.now(),
	}
}

// ClaimNext leases the next eligible provisioning job to owner for
// leaseDuration, atomically inside tx, and returns it in the running status.
// It is the SKIP LOCKED claim path that lets many workers poll the same queue
// without ever running a job twice: the SELECT ... FOR UPDATE SKIP LOCKED takes
// a row lock that a concurrent claimer skips rather than blocks on, so two
// workers never select the same job, and the transition to running commits or
// rolls back atomically with that lock held.
//
// A job is eligible when it is queued or retrying and due (next_run_at <= now),
// or running with an expired lease (lease_deadline < now) — a job whose worker
// crashed. The boolean is false when nothing is eligible; that is the
// empty-queue signal the worker loop backs off on.
//
// An expired-lease job is reclaimed through the state machine — running ->
// retrying -> running — so attempt counting and lease bookkeeping stay
// identical to a normal retry. A job that has already spent its retry budget is
// dead-lettered instead of reclaimed, and ClaimNext reports nothing claimed for
// that poll rather than handing a worker a job that can never run.
//
// It requires a *Tx, so a claim can never escape the transaction that owns the
// row lock. owner must be non-empty and leaseDuration positive — both are
// programming errors otherwise; a zero now defaults to the current UTC time.
func (r *JobRepository) ClaimNext(ctx context.Context, tx *Tx, owner string, leaseDuration time.Duration, now time.Time) (ProvisioningJob, bool, error) {
	if tx == nil {
		return ProvisioningJob{}, false, apierr.Internal(errors.New("store: JobRepository.ClaimNext called with a nil transaction"))
	}
	if owner == "" || leaseDuration <= 0 {
		return ProvisioningJob{}, false, apierr.Internal(
			errors.New("store: JobRepository.ClaimNext requires a non-empty owner and a positive lease duration"))
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	// Find the single most-eligible job and lock its row. SKIP LOCKED is what
	// makes concurrent workers safe: a row another worker is already claiming
	// inside its own open transaction is skipped, not waited on.
	var (
		jobID  string
		orgID  string
		status string
	)
	row := tx.QueryRow(ctx,
		`SELECT id, organization_id, status
		   FROM provisioning_jobs
		  WHERE (status IN ('queued', 'retrying') AND next_run_at <= $1)
		     OR (status = 'running' AND lease_deadline < $1)
		  ORDER BY next_run_at, created_at
		  FOR UPDATE SKIP LOCKED
		  LIMIT 1`,
		now)
	switch err := row.Scan(&jobID, &orgID, &status); {
	case errors.Is(err, pgx.ErrNoRows):
		return ProvisioningJob{}, false, nil
	case err != nil:
		return ProvisioningJob{}, false, apierr.StoreUnavailable(err)
	}

	// An expired-lease running job is reclaimed through the state machine. If
	// it has already spent its retry budget it is dead-lettered instead, and
	// this poll claims nothing rather than returning a doomed job.
	if JobStatus(status) == JobStatusRunning {
		reclaimable, err := r.reclaimExpiredLease(ctx, tx, orgID, jobID, now)
		if err != nil {
			return ProvisioningJob{}, false, err
		}
		if !reclaimable {
			return ProvisioningJob{}, false, nil
		}
	}

	claimed, err := r.Transition(ctx, tx, orgID, jobID, JobStatusRunning, JobTransition{
		LeaseOwner:    owner,
		LeaseDuration: leaseDuration,
		Now:           now,
	})
	if err != nil {
		return ProvisioningJob{}, false, err
	}
	return claimed, true, nil
}

// reclaimExpiredLease moves a running job whose lease has expired back to a
// claimable state. It returns true when the job was sent to retrying and is
// ready to be claimed again, and false when the job had already spent its
// retry budget and was dead-lettered instead. The job row is already locked
// FOR UPDATE by the caller, so the read sees the committed state and the two
// transitions cannot race another worker.
func (r *JobRepository) reclaimExpiredLease(ctx context.Context, tx *Tx, organizationID, jobID string, now time.Time) (bool, error) {
	current, err := r.Get(ctx, tx, organizationID, jobID)
	if err != nil {
		return false, err
	}
	if current.Attempts >= current.MaxAttempts {
		if _, err := r.Transition(ctx, tx, organizationID, jobID, JobStatusDeadLetter, JobTransition{
			ErrorSummary: "lease expired and the retry budget is exhausted; the previous worker did not finish the job",
			Now:          now,
		}); err != nil {
			return false, err
		}
		return false, nil
	}
	if _, err := r.Transition(ctx, tx, organizationID, jobID, JobStatusRetrying, JobTransition{
		NextRunAt:    now,
		ErrorSummary: "lease expired; the previous worker did not finish the job",
		Now:          now,
	}); err != nil {
		return false, err
	}
	return true, nil
}

// scanProvisioningJob scans one provisioning_jobs row in
// provisioningJobColumns order, mapping the nullable resource-target,
// lease-deadline, and timestamp columns to their zero values when absent.
// pgx.Rows satisfies pgx.Row, so the same scanner serves both single-row
// RETURNING queries and the ListByOrganization loop.
func scanProvisioningJob(row pgx.Row) (ProvisioningJob, error) {
	var (
		j             ProvisioningJob
		projectID     *string
		environmentID *string
		serviceID     *string
		status        string
		leaseDeadline *time.Time
		payload       []byte
		startedAt     *time.Time
		finishedAt    *time.Time
	)
	if err := row.Scan(
		&j.ID, &j.OrganizationID, &j.JobType, &projectID, &environmentID, &serviceID,
		&j.DesiredVersion, &j.IdempotencyKey, &status, &j.Attempts, &j.MaxAttempts,
		&j.LeaseOwner, &leaseDeadline, &j.NextRunAt, &j.ErrorSummary, &payload,
		&j.RequestID, &j.CorrelationID, &j.CreatedAt, &j.UpdatedAt, &startedAt, &finishedAt,
	); err != nil {
		return ProvisioningJob{}, err
	}
	j.Status = JobStatus(status)
	if projectID != nil {
		j.ProjectID = *projectID
	}
	if environmentID != nil {
		j.EnvironmentID = *environmentID
	}
	if serviceID != nil {
		j.ServiceID = *serviceID
	}
	if leaseDeadline != nil {
		j.LeaseDeadline = *leaseDeadline
	}
	if startedAt != nil {
		j.StartedAt = *startedAt
	}
	if finishedAt != nil {
		j.FinishedAt = *finishedAt
	}
	parsed, err := unmarshalJobPayload(payload)
	if err != nil {
		return ProvisioningJob{}, err
	}
	j.Payload = parsed
	return j, nil
}

// nullableID maps an empty resource-target id to SQL NULL so the composite
// foreign keys (which are MATCH SIMPLE) are enforced only when the target is
// actually set, and a non-empty id to itself.
func nullableID(id string) *string {
	if id == "" {
		return nil
	}
	return &id
}

// nullableTime maps a zero time to a nil *time.Time (SQL NULL) and a non-zero
// time to a pointer to it, so an unstamped started_at/finished_at column is
// written as NULL rather than the Go zero instant.
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// marshalJobPayload renders a job payload for the jsonb column. A nil or empty
// map becomes the empty JSON object so the column never stores SQL NULL,
// keeping reads total. json.Marshal sorts map keys, so the stored document is
// deterministic.
func marshalJobPayload(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("store: marshalling job payload: %w", err)
	}
	return b, nil
}

// unmarshalJobPayload parses the jsonb payload column back into a map. An empty
// or empty-object document yields a nil map so callers do not have to
// distinguish "no payload" from "empty payload".
func unmarshalJobPayload(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("store: unmarshalling job payload: %w", err)
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}
