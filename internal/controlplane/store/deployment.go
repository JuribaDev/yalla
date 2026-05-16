package store

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// DeploymentSource is the closed-set Dokploy-aligned taxonomy of customer
// intent: which surface the deployment originates from. The database
// CHECK on deployments.source confines values to this set; the
// application validates the same set before any database work, so a
// value outside the taxonomy is a typed 400 with a stable field
// violation — never a 500 leaking the constraint name.
type DeploymentSource string

// The canonical deployment source values. Each value maps to a Dokploy
// provisioning surface: 'git' deploys from a Git branch / commit, 'image'
// deploys from a container image reference, 'manual' re-rolls the existing
// desired state with no new ref.
const (
	DeploymentSourceGit    DeploymentSource = "git"
	DeploymentSourceImage  DeploymentSource = "image"
	DeploymentSourceManual DeploymentSource = "manual"
)

// deploymentSources is the membership set behind DeploymentSource.Valid.
var deploymentSources = map[DeploymentSource]struct{}{
	DeploymentSourceGit:    {},
	DeploymentSourceImage:  {},
	DeploymentSourceManual: {},
}

// Valid reports whether s is a canonical deployment source.
func (s DeploymentSource) Valid() bool {
	_, ok := deploymentSources[s]
	return ok
}

// String returns the canonical wire value.
func (s DeploymentSource) String() string { return string(s) }

// DeploymentStatus is the closed-set lifecycle the deployments table
// permits. The set mirrors provisioning_jobs.status semantics so the
// customer-visible deployment status and the internal job status
// converge through the same state machine. A terminal status always
// carries finished_at; a non-terminal one never does — enforced by the
// deployments_finished_consistent table CHECK.
type DeploymentStatus string

// The canonical deployment lifecycle status values. The set mirrors
// provisioning_jobs.status semantics so the customer-visible deployment
// status and the internal job status converge through the same state
// machine. 'queued' and 'running' are non-terminal (no finished_at);
// 'succeeded', 'failed', 'cancelled', and 'rolled_back' are terminal (always
// carry finished_at) — the deployments_finished_consistent table CHECK
// enforces this invariant at the database.
const (
	DeploymentStatusQueued     DeploymentStatus = "queued"
	DeploymentStatusRunning    DeploymentStatus = "running"
	DeploymentStatusSucceeded  DeploymentStatus = "succeeded"
	DeploymentStatusFailed     DeploymentStatus = "failed"
	DeploymentStatusCancelled  DeploymentStatus = "cancelled"
	DeploymentStatusRolledBack DeploymentStatus = "rolled_back"
)

// String returns the canonical wire value.
func (s DeploymentStatus) String() string { return string(s) }

// Deployment is the source-of-truth representation of a row in the
// deployments table. A deployment captures the customer intent to
// deploy a single service (Source / SourceRef), the principal who asked
// for it (RequestedBy), the immutable per-request correlation
// identifiers the audit trail and the worker job share (RequestID /
// CorrelationID), and the converged lifecycle status the worker writes
// as it observes the provisioning job.
//
// The struct carries no credential material — the deployments table
// stores only structural identifiers and a source reference (a
// branch / commit / tag / image name); tokens, API keys, cookies, and
// rendered environment variable values are persisted in their own
// scoped tables and redacted wherever they are handled. ErrorMessage
// is the most recent redacted failure summary the worker observed; the
// worker runs every value through the output redactor before writing
// the column.
type Deployment struct {
	ID             string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Source         DeploymentSource
	SourceRef      string
	Status         DeploymentStatus
	RequestedBy    string
	IdempotencyKey string
	ErrorCode      string
	ErrorMessage   string
	Version        int64
	RequestID      string
	CorrelationID  string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
}

// LogValue keeps a stray slog record that captures a Deployment safe.
// The deployments table itself carries no credential material — the
// fields are structural identifiers, a closed-set source taxonomy, a
// caller-supplied source reference, and a redacted error summary — but
// LogValue still omits the source reference and error summary at the
// slog boundary so a panic stack trace or debug log cannot accidentally
// surface either to log sinks that do not honour the per-record
// redaction policy. The HTTP layer renders the same fields verbatim in
// the wire shape because the redactor at the wire boundary is the
// authoritative chokepoint; logs see less.
func (d Deployment) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", d.ID),
		slog.String("organization_id", d.OrganizationID),
		slog.String("project_id", d.ProjectID),
		slog.String("environment_id", d.EnvironmentID),
		slog.String("service_id", d.ServiceID),
		slog.String("source", d.Source.String()),
		slog.String("status", d.Status.String()),
		slog.String("requested_by", d.RequestedBy),
		slog.Int64("version", d.Version),
	)
}

// deploymentColumns is the SELECT projection used by every read in this
// repository. Keeping it as a single string keeps the column list in
// lockstep with scanDeployment.
const deploymentColumns = `id, organization_id, project_id, environment_id, service_id,
	source, source_ref, status, requested_by, idempotency_key,
	error_code, error_message, version, request_id, correlation_id,
	created_at, updated_at, started_at, finished_at`

// deploymentListMaxRows caps how many rows a single ListByService call
// returns. An unbounded query can never be issued by accident; an HTTP
// layer that wants pagination later will add an explicit offset or
// cursor parameter rather than relax this ceiling.
const deploymentListMaxRows = 200

// DeploymentRepository is the persistence half of the deployments
// surface. Every read and every write is tenant-scoped: the
// organization_id leg of the predicate is non-optional, so a missing
// or cross-tenant id matches no rows — never another tenant's
// deployments. The repository is stateless; the constructor exists so
// call sites depend on a value rather than a bare struct literal.
type DeploymentRepository struct{}

// NewDeploymentRepository builds a stateless DeploymentRepository.
func NewDeploymentRepository() *DeploymentRepository {
	return &DeploymentRepository{}
}

// Insert persists d as a new deployments row inside tx and returns the
// committed row (including the database-owned created_at, updated_at,
// version, and lifecycle timestamps). It requires a *Tx — not a bare
// Querier — so a deployment can never be persisted outside the
// transaction that also carries its provisioning job and its audit
// record.
//
// The schema enforces the tenant invariant — composite foreign keys
// (organization_id, project_id), (organization_id, environment_id), and
// (organization_id, service_id) ensure the row references the same
// tenant's parents — so a deployment whose parent ids do not match
// its organization_id is rejected at the database before it can be
// persisted, regardless of application bugs. The source CHECK confines
// source to the closed Dokploy-aligned taxonomy, the status CHECK
// confines status to the closed lifecycle taxonomy, the
// deployments_finished_consistent CHECK keeps finished_at in lockstep
// with status, and UNIQUE (organization_id, idempotency_key) ensures a
// retried customer request never produces two deployments. A duplicate
// idempotency key, a parent that does not exist in the tenant, and the
// table's CHECK constraints all surface as deterministic
// apierr.Conflict through mapWriteError — never a 500 leaking the
// constraint name.
func (r *DeploymentRepository) Insert(ctx context.Context, tx *Tx, d Deployment) (Deployment, error) {
	if tx == nil {
		return Deployment{}, apierr.Internal(errors.New("store: DeploymentRepository.Insert called with a nil transaction"))
	}
	status := d.Status
	if status == "" {
		status = DeploymentStatusQueued
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO deployments
		     (id, organization_id, project_id, environment_id, service_id,
		      source, source_ref, status, requested_by, idempotency_key,
		      request_id, correlation_id)
		 VALUES ($1, $2, $3, $4, $5,
		         $6, $7, $8, $9, $10,
		         $11, $12)
		 RETURNING `+deploymentColumns,
		d.ID, d.OrganizationID, d.ProjectID, d.EnvironmentID, d.ServiceID,
		d.Source.String(), d.SourceRef, status.String(), d.RequestedBy, d.IdempotencyKey,
		d.RequestID, d.CorrelationID)
	out, err := scanDeployment(row)
	if err != nil {
		return Deployment{}, mapWriteError(err, "a deployment with this idempotency key already exists")
	}
	return out, nil
}

// GetByID returns the single deployments row identified by
// (organizationID, deploymentID), tenant-scoped at the SQL predicate.
// The composite predicate is non-optional: a missing or cross-tenant
// organizationID matches no row even when a deployment with the same id
// exists in another tenant, so the response is never an oracle that
// reveals another organization's deployment ids. A row that does not
// exist surfaces as the same typed apierr.NotFound, never as a 500
// leaking the cause; the not-found payload names only the deployment_id
// the caller already supplied.
func (r *DeploymentRepository) GetByID(ctx context.Context, q Querier, organizationID, deploymentID string) (Deployment, error) {
	row := q.QueryRow(ctx,
		`SELECT `+deploymentColumns+`
		   FROM deployments
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, deploymentID)
	d, err := scanDeployment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, apierr.NotFound("deployment", deploymentID)
	}
	if err != nil {
		return Deployment{}, apierr.StoreUnavailable(err)
	}
	return d, nil
}

// FindByIdempotencyKey returns the deployment a previous request
// already enqueued under (organizationID, idempotencyKey), or
// (Deployment{}, false, nil) when no such row exists. The lookup is
// tenant-scoped at the SQL predicate, so a key that belongs to
// another tenant matches no rows. Callers use it to make POST
// /v1/services/{service_id}/deployments idempotent: a retry with the
// same key returns the previously persisted deployment rather than
// inserting a duplicate.
func (r *DeploymentRepository) FindByIdempotencyKey(ctx context.Context, q Querier, organizationID, key string) (Deployment, bool, error) {
	row := q.QueryRow(ctx,
		`SELECT `+deploymentColumns+`
		   FROM deployments
		  WHERE organization_id = $1 AND idempotency_key = $2`,
		organizationID, key)
	d, err := scanDeployment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, false, nil
	}
	if err != nil {
		return Deployment{}, false, apierr.StoreUnavailable(err)
	}
	return d, true, nil
}

// ListByService returns every deployment owned by (organizationID,
// serviceID), in reverse chronological order (created_at DESC, id DESC
// as a tiebreaker), so an agent observing the response sees a stable
// ordering across calls and the most recent deployment first. The read
// is tenant-scoped at the SQL predicate, so a cross-tenant tuple
// matches no rows. The query is bounded by deploymentListMaxRows; a
// future pagination story will add an explicit cursor.
//
// This method does NOT verify the service exists; callers that need to
// distinguish "service missing" from "service has no deployments" must
// Get the service first.
func (r *DeploymentRepository) ListByService(ctx context.Context, q Querier, organizationID, serviceID string) ([]Deployment, error) {
	rows, err := q.Query(ctx,
		`SELECT `+deploymentColumns+`
		   FROM deployments
		  WHERE organization_id = $1 AND service_id = $2
		  ORDER BY created_at DESC, id DESC
		  LIMIT $3`,
		organizationID, serviceID, deploymentListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]Deployment, 0)
	for rows.Next() {
		d, scanErr := scanDeployment(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// DeploymentReader is the read-only adapter the GET
// /v1/services/{service_id}/deployments endpoint depends on. It
// composes ServiceRepository and DeploymentRepository through a
// short-lived read-only transaction (Store.Read), so the
// tenant-scoping guarantees the repositories prove in their
// integration tests are inherited for free, and every cross-tenant or
// unknown service_id surfaces as a deterministic apierr.NotFound
// rather than an empty list.
type DeploymentReader struct {
	store       *Store
	services    *ServiceRepository
	deployments *DeploymentRepository
}

// NewDeploymentReader builds a DeploymentReader over store. It returns
// an error for a nil store so a misconfigured adapter fails at
// construction rather than on its first request.
func NewDeploymentReader(s *Store) (*DeploymentReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &DeploymentReader{
		store:       s,
		services:    NewServiceRepository(),
		deployments: NewDeploymentRepository(),
	}, nil
}

// ListServiceDeployments returns every deployment owned by
// (organizationID, serviceID), in reverse chronological order. The
// read is tenant scoped at both legs: it Gets the service first so a
// cross-tenant or unknown service_id surfaces as a deterministic
// apierr.NotFound — never as an empty list, which would invite an
// agent to believe the service exists with no deployments. A live
// service with no deployments is then a deterministic empty slice. A
// datastore failure is propagated as its own typed error.
//
// The deployments table itself stores no credential material — the
// columns are structural identifiers, the closed-set source taxonomy,
// the customer-supplied source reference (a branch / commit / image
// reference — never tokens), and the worker-written redacted error
// summary — so the reader returns rows verbatim and the HTTP layer
// renders them through the wire projection.
func (r *DeploymentReader) ListServiceDeployments(ctx context.Context, organizationID, serviceID string) ([]Deployment, error) {
	var out []Deployment
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, getErr := r.services.GetByID(ctx, q, organizationID, serviceID); getErr != nil {
			return getErr
		}
		list, listErr := r.deployments.ListByService(ctx, q, organizationID, serviceID)
		if listErr != nil {
			return listErr
		}
		out = list
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// deploymentCreateAction is the action recorded on the audit event
// emitted by every deployment create. It matches the wire-level action
// constant the policy engine authorizes (deployment.create), so an
// audit reader can correlate the audit event back to the API surface
// that produced it without a translation table.
const deploymentCreateAction = "deployment.create"

// deploymentProvisionJob is the job_type the worker observes when
// claiming a deployment provisioning job. Like deploymentCreateAction
// it is the wire-level constant the durable job queue persists and the
// worker dispatches on.
const deploymentProvisionJob = "service.deploy"

// scanDeployment scans one deployments row in deploymentColumns order.
func scanDeployment(row scanRow) (Deployment, error) {
	var (
		d              Deployment
		sourceStr      string
		statusStr      string
		startedAtNull  *time.Time
		finishedAtNull *time.Time
	)
	if err := row.Scan(
		&d.ID,
		&d.OrganizationID,
		&d.ProjectID,
		&d.EnvironmentID,
		&d.ServiceID,
		&sourceStr,
		&d.SourceRef,
		&statusStr,
		&d.RequestedBy,
		&d.IdempotencyKey,
		&d.ErrorCode,
		&d.ErrorMessage,
		&d.Version,
		&d.RequestID,
		&d.CorrelationID,
		&d.CreatedAt,
		&d.UpdatedAt,
		&startedAtNull,
		&finishedAtNull,
	); err != nil {
		return Deployment{}, err
	}
	d.Source = DeploymentSource(sourceStr)
	d.Status = DeploymentStatus(statusStr)
	d.StartedAt = startedAtNull
	d.FinishedAt = finishedAtNull
	return d, nil
}
