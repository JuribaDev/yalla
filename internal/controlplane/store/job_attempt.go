package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
	"github.com/jackc/pgx/v5"
)

// JobAttemptStatus is the closed terminal taxonomy a job_attempts row may
// carry. A running attempt is not persisted in this table -- the running
// state lives on the parent provisioning_jobs row's lease columns -- so a
// job_attempts row is always a complete, immutable post-mortem of a finished
// attempt. The string values match the job_attempts.status CHECK constraint
// verbatim and are public compatibility contract for any future timeline
// endpoint.
type JobAttemptStatus string

const (
	// JobAttemptStatusSucceeded records an attempt that converged the job to
	// its terminal succeeded state.
	JobAttemptStatusSucceeded JobAttemptStatus = "succeeded"
	// JobAttemptStatusFailed records an attempt that ended in a failure
	// observed by the worker -- transient or permanent. The retry decision
	// (retry vs. dead-letter) is owned by the parent provisioning_jobs row;
	// the attempt row simply records what the worker observed.
	JobAttemptStatusFailed JobAttemptStatus = "failed"
	// JobAttemptStatusCancelled records an attempt that the worker
	// abandoned because the job's lifecycle was cancelled by a customer or
	// an operator.
	JobAttemptStatusCancelled JobAttemptStatus = "cancelled"
	// JobAttemptStatusTimedOut records an attempt whose lease expired
	// before the worker released it: the reclaimer observed the expired
	// lease and reclaimed the job.
	JobAttemptStatusTimedOut JobAttemptStatus = "timed_out"
)

// jobAttemptStatuses is the membership set behind JobAttemptStatus.Valid.
var jobAttemptStatuses = map[JobAttemptStatus]struct{}{
	JobAttemptStatusSucceeded: {},
	JobAttemptStatusFailed:    {},
	JobAttemptStatusCancelled: {},
	JobAttemptStatusTimedOut:  {},
}

// Valid reports whether s is one of the closed set of job attempt statuses.
func (s JobAttemptStatus) Valid() bool {
	_, ok := jobAttemptStatuses[s]
	return ok
}

// String returns the status's stable string value, matching the database
// CHECK constraint verbatim.
func (s JobAttemptStatus) String() string { return string(s) }

// jobAttemptListMaxRows caps how many job_attempts rows a single ListByJob
// call returns, so an unbounded query can never be issued by accident; an
// HTTP layer that wants pagination later will add an explicit offset or
// cursor parameter rather than relax this ceiling.
const jobAttemptListMaxRows = 500

// jobAttemptErrorRedactor scrubs secrets out of a job_attempts row's error
// summary before it is persisted. Like jobErrorRedactor on the parent
// provisioning_jobs row, it carries no registered literal secrets -- it is
// a structural backstop against well-known transport patterns
// (Authorization headers, token-bearing query params) that a Dokploy or
// datastore error string might carry into error_summary. Redaction is
// idempotent, so an already-clean summary passes through unchanged.
var jobAttemptErrorRedactor = output.NewRedactor()

// redactJobAttemptError returns s with every known secret pattern replaced
// by the redaction sentinel. It is the single chokepoint every persisted
// attempt error summary passes through.
func redactJobAttemptError(s string) string { return jobAttemptErrorRedactor.Redact(s) }

// JobAttempt is the source-of-truth representation of a row in the
// job_attempts table -- one immutable record on the runtime history of a
// single provisioning job. A JobAttempt is written exactly once, when the
// worker releases the lease (succeeded / failed / cancelled / timed_out);
// the row's lifecycle is append-only and the database BEFORE UPDATE
// trigger rejects every update.
//
// The struct carries no credential material -- ErrorSummary and ErrorCode
// are redacted by the repository before they reach the database, and no
// other field stores tokens, API keys, cookies, or rendered environment
// variable values.
type JobAttempt struct {
	ID             string
	OrganizationID string
	JobID          string
	AttemptNumber  int
	WorkerID       string
	Status         JobAttemptStatus
	ErrorSummary   string
	ErrorCode      string
	RequestID      string
	CorrelationID  string
	StartedAt      time.Time
	FinishedAt     time.Time
	CreatedAt      time.Time
}

// LogValue keeps a stray slog record that captures a JobAttempt safe.
// ErrorSummary is redacted by the writer before this layer, but LogValue
// omits it at the slog boundary too so a panic stack trace that happens to
// include an attempt payload cannot inadvertently widen the redaction
// surface. The structural identifiers and status are non-secret and are
// safe to log.
func (a JobAttempt) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", a.ID),
		slog.String("organization_id", a.OrganizationID),
		slog.String("job_id", a.JobID),
		slog.Int("attempt_number", a.AttemptNumber),
		slog.String("worker_id", a.WorkerID),
		slog.String("status", a.Status.String()),
		slog.String("request_id", a.RequestID),
		slog.String("correlation_id", a.CorrelationID),
	)
}

// jobAttemptColumns is the SELECT projection used by every read in this
// repository. Keeping it as a single string keeps the column list in
// lockstep with scanJobAttempt.
const jobAttemptColumns = `id, organization_id, job_id, attempt_number, worker_id,
	status, error_summary, error_code, request_id, correlation_id,
	started_at, finished_at, created_at`

// JobAttemptRepository is the persistence half of the job_attempts surface.
// Every read and every write is tenant-scoped: the organization_id leg of
// the predicate is non-optional, so a missing or cross-tenant id matches
// no rows -- never another tenant's job attempts. The repository is
// stateless; the constructor exists so call sites depend on a value
// rather than a bare struct literal.
//
// There is no per-row Update or Delete here: job_attempts is append-only
// by design -- the database BEFORE UPDATE trigger rejects every update
// and the store package exposes no row-level delete of its own. Row
// removal is reachable only through ON DELETE CASCADE when the parent
// provisioning_jobs row (and in turn the organization) is deleted.
type JobAttemptRepository struct{}

// NewJobAttemptRepository returns a JobAttemptRepository.
func NewJobAttemptRepository() *JobAttemptRepository {
	return &JobAttemptRepository{}
}

// Append persists a as a new job_attempts row inside tx and returns the
// committed row (including the database-owned created_at and id when
// blank). It requires a *Tx -- not a bare Querier -- so an attempt can be
// written in the same transaction as the parent provisioning_jobs
// Transition it records, and so the attempt write commits or rolls back
// atomically with that mutation. A blank ID is minted here with the
// jatt_ prefix. A blank Status, a non-positive AttemptNumber, a blank
// WorkerID, a zero StartedAt, or a zero FinishedAt are all rejected as
// programming errors at the application boundary (the database CHECKs
// are the belt-and-braces).
//
// The schema enforces the tenant invariant -- the composite foreign key
// (organization_id, job_id) references provisioning_jobs
// (organization_id, id) so an attempt can never sit under a foreign
// tenant's job -- and the status CHECK rejects an unknown status as a
// deterministic apierr.Conflict through mapWriteError; the raw constraint
// name never leaks into the user-facing message.
func (r *JobAttemptRepository) Append(ctx context.Context, tx *Tx, a JobAttempt) (JobAttempt, error) {
	if tx == nil {
		return JobAttempt{}, apierr.Internal(errors.New("store: JobAttemptRepository.Append called with a nil transaction"))
	}
	var violations []apierr.FieldViolation
	if a.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if a.JobID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "job_id", Reason: "is required"})
	}
	if a.AttemptNumber <= 0 {
		violations = append(violations, apierr.FieldViolation{Field: "attempt_number", Reason: "must be greater than zero"})
	}
	if a.WorkerID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "worker_id", Reason: "is required"})
	}
	if a.Status == "" {
		violations = append(violations, apierr.FieldViolation{Field: "status", Reason: "is required"})
	} else if !a.Status.Valid() {
		violations = append(violations, apierr.FieldViolation{Field: "status", Reason: "is not a recognised job attempt status"})
	}
	if a.StartedAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "started_at", Reason: "is required"})
	}
	if a.FinishedAt.IsZero() {
		violations = append(violations, apierr.FieldViolation{Field: "finished_at", Reason: "is required"})
	}
	if !a.StartedAt.IsZero() && !a.FinishedAt.IsZero() && a.FinishedAt.Before(a.StartedAt) {
		violations = append(violations, apierr.FieldViolation{Field: "finished_at", Reason: "must not be before started_at"})
	}
	if len(violations) > 0 {
		return JobAttempt{}, apierr.InvalidInput(violations...)
	}

	if a.ID == "" {
		id, err := newJobAttemptID()
		if err != nil {
			return JobAttempt{}, apierr.Internal(err)
		}
		a.ID = id
	}
	a.ErrorSummary = redactJobAttemptError(a.ErrorSummary)

	row := tx.QueryRow(ctx,
		`INSERT INTO job_attempts
		   (id, organization_id, job_id, attempt_number, worker_id,
		    status, error_summary, error_code, request_id, correlation_id,
		    started_at, finished_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 RETURNING `+jobAttemptColumns,
		a.ID, a.OrganizationID, a.JobID, a.AttemptNumber, a.WorkerID,
		a.Status.String(), a.ErrorSummary, a.ErrorCode, a.RequestID, a.CorrelationID,
		a.StartedAt, a.FinishedAt)
	created, err := scanJobAttempt(row)
	if err != nil {
		return JobAttempt{}, mapWriteError(err, "a job attempt with this id or attempt number already exists for this job")
	}
	return created, nil
}

// ListByJob returns every attempt owned by (organizationID, jobID), in
// chronological order (attempt_number ASC), so the timeline endpoint
// renders the job's retry history unfolding forward in time. The read is
// tenant-scoped at the SQL predicate, so a cross-tenant tuple matches no
// rows. The query is bounded by jobAttemptListMaxRows; a future
// pagination story will add an explicit cursor.
//
// This method does NOT verify the parent job exists; callers that need to
// distinguish "job missing" from "job has no attempts" must Get the job
// first.
func (r *JobAttemptRepository) ListByJob(ctx context.Context, q Querier, organizationID, jobID string) ([]JobAttempt, error) {
	rows, err := q.Query(ctx,
		`SELECT `+jobAttemptColumns+`
		   FROM job_attempts
		  WHERE organization_id = $1 AND job_id = $2
		  ORDER BY attempt_number ASC
		  LIMIT $3`,
		organizationID, jobID, jobAttemptListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]JobAttempt, 0)
	for rows.Next() {
		a, scanErr := scanJobAttempt(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// GetByID returns the single job_attempts row identified by
// (organizationID, attemptID), tenant-scoped at the SQL predicate. The
// composite predicate is non-optional: a missing or cross-tenant
// organizationID matches no row even when an attempt with the same id
// exists in another tenant -- the response is never an oracle that
// reveals another organization's attempt ids. A row that does not exist
// surfaces as the same typed apierr.NotFound, never as a 500 leaking the
// cause; the not-found payload names only the attempt id the caller
// already supplied.
func (r *JobAttemptRepository) GetByID(ctx context.Context, q Querier, organizationID, attemptID string) (JobAttempt, error) {
	row := q.QueryRow(ctx,
		`SELECT `+jobAttemptColumns+`
		   FROM job_attempts
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, attemptID)
	a, err := scanJobAttempt(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return JobAttempt{}, apierr.NotFound("job_attempt", attemptID)
	}
	if err != nil {
		return JobAttempt{}, apierr.StoreUnavailable(err)
	}
	return a, nil
}

// scanJobAttempt scans one job_attempts row in jobAttemptColumns order.
func scanJobAttempt(row scanRow) (JobAttempt, error) {
	var (
		a         JobAttempt
		statusStr string
	)
	if err := row.Scan(
		&a.ID,
		&a.OrganizationID,
		&a.JobID,
		&a.AttemptNumber,
		&a.WorkerID,
		&statusStr,
		&a.ErrorSummary,
		&a.ErrorCode,
		&a.RequestID,
		&a.CorrelationID,
		&a.StartedAt,
		&a.FinishedAt,
		&a.CreatedAt,
	); err != nil {
		return JobAttempt{}, err
	}
	a.Status = JobAttemptStatus(statusStr)
	return a, nil
}

// newJobAttemptID mints an opaque, non-guessable id for a job_attempts
// row. Job attempts are an internal accounting trail rather than a
// customer-facing addressable resource (the customer addresses the
// attempt history through its parent job id, not through individual
// attempt ids), so -- like audit_events, quota_reservations, and
// deployment_events -- they carry their own prefixed id rather than a
// domain.Kind id.
func newJobAttemptID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("store: generating job attempt id entropy: %w", err)
	}
	return "jatt_" + hex.EncodeToString(buf[:]), nil
}
