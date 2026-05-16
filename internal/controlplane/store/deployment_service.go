package store

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
)

// deploymentIdempotencyKeyMaxLen bounds a caller-supplied idempotency
// key. It is generous — the value is opaque to Yalla and the database
// idempotency_key column carries it verbatim — but not unbounded, so a
// pathological client cannot push a megabyte string into the keyspace.
// The same ceiling is enforced before any database work so an oversize
// key never reaches the UNIQUE constraint.
const deploymentIdempotencyKeyMaxLen = 256

// CreateDeploymentInput is the unvalidated input to DeploymentService.Create.
// OrganizationID and ServiceID name the deployment target: the
// deployment row's project_id and environment_id legs are derived from
// the persisted services row inside the transaction, never from caller
// input, so the child can never land in another project or environment
// even if a request body field tried to redirect it. Source / SourceRef
// describe the customer intent (which git branch / commit / image
// tag / manual surface the deploy mirrors into Dokploy). IdempotencyKey
// is required: it is the per-organization unique key that makes a
// retried POST /v1/services/{service_id}/deployments structurally
// idempotent.
//
// The Actor* and correlation fields describe the authenticated
// principal performing the create and are recorded verbatim on the
// audit event. They are plain strings so the store layer takes no build
// dependency on the policy or telemetry packages — the httpapi
// handler, which already holds the resolved principal and the request
// correlation, fills them in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ServiceID is sourced from the {service_id} PATH
// parameter; the create unit of work reads the parent service under
// (OrganizationID, ServiceID) before any write — a cross-tenant or
// unknown service_id surfaces as a deterministic apierr.NotFound
// rather than a 500 or a silent success, and the parent's project_id
// and environment_id are derived from the persisted service row.
type CreateDeploymentInput struct {
	OrganizationID string
	ServiceID      string
	Source         DeploymentSource
	SourceRef      string
	IdempotencyKey string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// DeploymentService is the unit-of-work orchestrator for POST
// /v1/services/{service_id}/deployments. Create composes — in this
// fixed order, inside one transaction opened by Store.Write — a
// tenant-scoped parent-service existence check, an idempotency
// short-circuit, an in-transaction authorization check, a quota
// reservation against the concurrent_deployments resource, the
// deployment row write, the provisioning-job enqueue, and the
// immutable audit record. Because every step shares the *Tx, a failure
// in any of them rolls the others back: a partial create and an
// orphaned audit record are both impossible, and the deployment row
// can never exist without its provisioning job.
//
// The httpapi RequireAuth middleware is the authoritative
// authorization gate for action deployment.create (service-scoped via
// serviceIDResolver). The store-layer Authorize call is
// defense-in-depth against a grant change that landed between the HTTP
// authorize and the quota reservation — it runs on the same *Tx as
// the write so the in-transaction policy view sees exactly the state
// the row commits against.
type DeploymentService struct {
	store       *Store
	services    *ServiceRepository
	deployments *DeploymentRepository
	authz       Authorizer
	quota       QuotaReserver
	jobs        JobEnqueuer
	audit       AuditAppender
}

// NewDeploymentService wires a DeploymentService from its dependencies.
// It returns a typed error if any dependency is nil, so a misconfigured
// service fails at construction rather than on its first request — the
// same fail-fast posture every other unit-of-work orchestrator in this
// package takes.
func NewDeploymentService(s *Store, services *ServiceRepository, deployments *DeploymentRepository, authz Authorizer, quota QuotaReserver, jobs JobEnqueuer, audit AuditAppender) (*DeploymentService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case services == nil:
		return nil, errors.New("store: nil service repository")
	case deployments == nil:
		return nil, errors.New("store: nil deployment repository")
	case authz == nil:
		return nil, errors.New("store: nil authorizer")
	case quota == nil:
		return nil, errors.New("store: nil quota reserver")
	case jobs == nil:
		return nil, errors.New("store: nil job enqueuer")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &DeploymentService{
		store:       s,
		services:    services,
		deployments: deployments,
		authz:       authz,
		quota:       quota,
		jobs:        jobs,
		audit:       audit,
	}, nil
}

// Create validates in, then runs the create-deployment unit of work
// inside one transaction: confirm the parent service exists under
// (OrganizationID, ServiceID) — and learn its parent project_id and
// environment_id from the persisted row, never from caller input —
// short-circuit on a previously persisted idempotency key, authorize,
// reserve quota, write the deployment row, enqueue the provisioning
// job, append the immutable audit record. Validation runs before the
// transaction is opened, so an invalid request never touches the
// database.
//
// The parent-service Get is tenant-scoped — it filters by
// organization_id first — so a cross-tenant or unknown service_id
// surfaces as a deterministic apierr.NotFound. This is the same
// boundary GET /v1/services/{service_id} inherits, so a foreign
// service_id reaches the persistence layer with the principal's home
// organization id and is reported as 404 here just as it is on the
// read side, never disguised as a 403 that would confirm the foreign
// service's existence.
//
// Idempotency: a retried POST with the same idempotency_key returns
// the previously persisted deployment verbatim — no second row, no
// duplicate audit event, no duplicate provisioning job. The
// short-circuit happens INSIDE the transaction so a concurrent retry
// observed by the second writer rolls back deterministically.
func (svc *DeploymentService) Create(ctx context.Context, in CreateDeploymentInput) (Deployment, error) {
	deployment, err := validateCreateDeploymentInput(in)
	if err != nil {
		return Deployment{}, err
	}

	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Deployment{}, apierr.Internal(errors.New("store: DeploymentService.Create requires an actor organization for the audit record"))
	}

	var created Deployment
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Parent-service existence is tenant-scoped: a cross-tenant or
		// unknown service_id surfaces as the typed apierr.NotFound the
		// repository produces, never a 500 or a silent success. The
		// project_id and environment_id legs of the new deployment row
		// are taken from the PERSISTED service row — never from caller
		// input — so the child cannot accidentally land in another
		// project or environment even if a later request body field
		// tried to redirect it.
		parent, getErr := svc.services.GetByID(ctx, tx, deployment.OrganizationID, deployment.ServiceID)
		if getErr != nil {
			return getErr
		}
		// A service that has already been scheduled for teardown
		// cannot accept new deployments: a deployment job would race
		// the soft-delete worker and either succeed against a
		// half-torn-down service or fail mid-flight. Refuse the create
		// at the boundary with a deterministic 409 rather than emit a
		// job whose outcome is undefined.
		if parent.DeletionScheduledAt != nil {
			return apierr.Conflict("the service is scheduled for deletion and cannot accept new deployments")
		}
		deployment.ProjectID = parent.ProjectID
		deployment.EnvironmentID = parent.EnvironmentID

		// Idempotency short-circuit: a previous request with the same
		// (organization_id, idempotency_key) is returned verbatim. The
		// lookup shares the *Tx so a concurrent retry that races us is
		// rejected by the UNIQUE constraint when this transaction
		// reaches Insert below — never as a 5xx, always as a
		// deterministic idempotent return.
		if existing, ok, lookupErr := svc.deployments.FindByIdempotencyKey(ctx, tx, deployment.OrganizationID, deployment.IdempotencyKey); lookupErr != nil {
			return lookupErr
		} else if ok {
			created = existing
			return nil
		}

		// Defense-in-depth: the HTTP RequireAuth middleware already
		// authorized action deployment.create against the (home org,
		// service_id) resource the path names. The in-transaction
		// Authorize is a redundant check whose real adapter reads
		// grant rows from the same *Tx as the desired-state write —
		// so a grant change that landed between the HTTP authorize
		// and this point still cannot let the write through.
		if err := svc.authz.Authorize(ctx, tx, deploymentCreateAction, deployment.OrganizationID); err != nil {
			return err
		}
		if err := svc.quota.Reserve(ctx, tx, deployment.OrganizationID, string(QuotaResourceConcurrentDeployments)); err != nil {
			return err
		}
		row, err := svc.deployments.Insert(ctx, tx, deployment)
		if err != nil {
			return err
		}
		// The deployment row and its provisioning job commit atomically:
		// every JobEnqueuer adapter pins the job's organization_id to
		// the deployment's tenant, and the row's UNIQUE
		// (organization_id, idempotency_key) collides with the
		// equivalent job idempotency key, so a duplicate job is
		// structurally impossible even under retry.
		if err := svc.jobs.Enqueue(ctx, tx, deployment.OrganizationID, deploymentProvisionJob, row.ID); err != nil {
			return err
		}
		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         deploymentCreateAction,
			ResourceKind:   string(domain.KindDeployment),
			ResourceID:     row.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for deployment.create",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			// The structural identifiers and the closed-taxonomy source
			// enum are safe to record verbatim. The idempotency key is
			// opaque caller input and is NOT projected onto audit
			// metadata — a future support reader sees the deployment
			// id, not the caller's deduplication token.
			Metadata: map[string]string{
				"service_id":     row.ServiceID,
				"environment_id": row.EnvironmentID,
				"project_id":     row.ProjectID,
				"source":         row.Source.String(),
			},
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		created = row
		return nil
	})
	if txErr != nil {
		return Deployment{}, txErr
	}
	return created, nil
}

// validateCreateDeploymentInput checks in and returns the Deployment
// row it would map to. Validation runs before any transaction is
// opened, so an invalid request never touches the database. The source
// is validated against the closed taxonomy (git, image, manual) before
// any database work — a value outside that set is a typed 400 with a
// stable field violation, not a 500 leaking the database CHECK
// constraint name. Source-specific ref validation (a git branch /
// commit, an image reference, an empty manual ref) routes through the
// shared validate package so the same redaction posture (the field
// reason never echoes caller input) is preserved.
//
// ProjectID and EnvironmentID are intentionally NOT validated here:
// the parent service's project_id and environment_id are the source of
// truth, and Create fills the fields from the persisted service row
// inside the transaction.
//
// The ID and Status are minted here so the unit of work commits with a
// non-guessable id and the canonical initial status. RequestedBy is
// filled from ActorID at the service boundary — the actor that called
// the endpoint is the deployment's requester.
func validateCreateDeploymentInput(in CreateDeploymentInput) (Deployment, error) {
	violations := validate.New()

	orgID := strings.TrimSpace(in.OrganizationID)
	if id, err := domain.ParseID(orgID); err != nil || id.Kind() != domain.KindOrganization {
		violations.Add("organization_id", "must be a valid organization id")
	}

	serviceID := strings.TrimSpace(in.ServiceID)
	if id, err := domain.ParseID(serviceID); err != nil || id.Kind() != domain.KindService {
		violations.Add("service_id", "must be a valid service id")
	}

	source := DeploymentSource(strings.TrimSpace(string(in.Source)))
	if !source.Valid() {
		violations.Add("source", `must be one of "git", "image", or "manual"`)
	}

	ref := strings.TrimSpace(in.SourceRef)
	switch source {
	case DeploymentSourceGit:
		// Accept either a branch reference or a commit SHA. Validate
		// the branch shape first, and fall back to the commit
		// validator only if the branch validator rejected the input
		// — so a value that satisfies either path passes.
		if ref == "" {
			violations.Add("source_ref", `must not be blank for source "git"`)
		} else {
			branchCollector := validate.New()
			validate.GitBranch(branchCollector, "source_ref", ref)
			if branchCollector.Err() != nil {
				commitCollector := validate.New()
				validate.GitCommit(commitCollector, "source_ref", ref)
				if commitCollector.Err() != nil {
					violations.Add("source_ref", "must be a Git branch name or 7-40 character commit SHA")
				}
			}
		}
	case DeploymentSourceImage:
		if ref == "" {
			violations.Add("source_ref", `must not be blank for source "image"`)
		} else {
			validate.ImageRef(violations, "source_ref", ref)
		}
	case DeploymentSourceManual:
		// A manual deploy has no ref by definition — the operator just
		// asks the worker to re-roll whatever the desired state
		// already says. We keep any caller-supplied label
		// (length-bounded, UTF-8, no control chars) so an operator can
		// note WHY they triggered the manual roll, but we never
		// require it.
		if ref != "" {
			if !utf8.ValidString(ref) {
				violations.Add("source_ref", "must be valid UTF-8")
			} else if len(ref) > validate.MaxGitRefLen {
				violations.Addf("source_ref", "must be at most %d characters", validate.MaxGitRefLen)
			}
		}
	}

	key := strings.TrimSpace(in.IdempotencyKey)
	switch {
	case key == "":
		violations.Add("idempotency_key", "must not be blank")
	case !utf8.ValidString(key):
		violations.Add("idempotency_key", "must be valid UTF-8")
	case len(key) > deploymentIdempotencyKeyMaxLen:
		violations.Addf("idempotency_key", "must be at most %d characters", deploymentIdempotencyKeyMaxLen)
	case strings.ContainsRune(key, 0):
		violations.Add("idempotency_key", "must not contain NUL bytes")
	}

	actorID := strings.TrimSpace(in.ActorID)
	if actorID == "" {
		// ActorID is the requested_by column; the database CHECK
		// rejects an empty value, so validate before any database
		// work. A missing actor is a wiring error (an authenticated
		// request always carries one) but it is surfaced as a typed
		// 400 here rather than letting the DB CHECK leak into a 5xx.
		violations.Add("requested_by", "must not be blank")
	}

	if err := violations.Err(); err != nil {
		return Deployment{}, err
	}

	id, err := domain.NewID(domain.KindDeployment)
	if err != nil {
		return Deployment{}, apierr.Internal(err)
	}

	return Deployment{
		ID:             id.String(),
		OrganizationID: orgID,
		ServiceID:      serviceID,
		Source:         source,
		SourceRef:      ref,
		Status:         DeploymentStatusQueued,
		RequestedBy:    actorID,
		IdempotencyKey: key,
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
	}, nil
}
