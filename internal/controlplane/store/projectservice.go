package store

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

// Authorizer decides whether the current principal may perform an action
// against an organization scope. The store layer depends only on this narrow
// port; the real RBAC engine lands in internal/controlplane/policy. Authorize
// receives the same Querier as the surrounding unit of work, so a policy
// decision that reads grant rows sees exactly the state the write commits
// against. A denied decision is returned as a typed apierr.Forbidden error.
type Authorizer interface {
	Authorize(ctx context.Context, q Querier, action, organizationID string) error
}

// QuotaReserver reserves quota for a resource within an organization. The
// store layer depends only on this narrow port; the real quota service lands
// in internal/controlplane/quota. Reserve receives the *Tx of the surrounding
// unit of work, so the reservation it records commits or rolls back atomically
// with the resource it guards. An exhausted limit is returned as a typed
// apierr.QuotaExceeded error.
type QuotaReserver interface {
	Reserve(ctx context.Context, tx *Tx, organizationID, resource string) error
}

// JobEnqueuer enqueues a durable provisioning job. The store layer depends
// only on this narrow port; the real durable job queue lands in
// internal/controlplane/jobs. Enqueue receives the *Tx of the surrounding unit
// of work, so the job row commits atomically with the desired-state write —
// the system can never persist a resource without its provisioning job, or a
// job without its resource.
type JobEnqueuer interface {
	Enqueue(ctx context.Context, tx *Tx, organizationID, jobKind, resourceID string) error
}

// The action, job kind, and quota resource a project creation composes
// against. They are duplicated as plain strings here on purpose: the policy
// action catalog, the quota schema, and the durable job table are later
// stories, and the store layer must not take a build dependency on them. When
// those packages land they own these constants; the store layer keeps only
// the port interfaces above.
const (
	projectCreateAction  = "project.create"
	projectProvisionJob  = "project.provision"
	projectQuotaResource = "projects"
)

// CreateProjectInput is the unvalidated input to ProjectService.Create.
// OrganizationID, ProjectID, Slug, and DisplayName are the caller-supplied
// resource fields; the Actor* and correlation fields describe the
// authenticated principal performing the create and are recorded verbatim on
// the audit event. They are plain strings so the store layer takes no build
// dependency on the policy or telemetry packages — the httpapi handler, which
// already holds the resolved principal and the request correlation, fills
// them in.
type CreateProjectInput struct {
	OrganizationID string
	ProjectID      string
	Slug           string
	DisplayName    string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// ProjectService is the reference unit-of-work orchestrator for the repository
// transaction pattern. Create composes — in this fixed order, inside one
// transaction — an authorization check, a quota reservation, the desired-state
// write, the provisioning-job enqueue, and the immutable audit record.
// Because every step shares the *Tx opened by Store.Write, a failure in any
// step rolls back every other step: the authorization, quota, and audit
// checks are impossible to bypass, and desired state is never persisted
// without its provisioning job or its audit trail.
type ProjectService struct {
	store *Store
	repo  *ProjectRepository
	authz Authorizer
	quota QuotaReserver
	jobs  JobEnqueuer
	audit AuditAppender
}

// NewProjectService wires a ProjectService from its dependencies. It returns a
// typed error if any dependency is nil, so a misconfigured service fails at
// construction rather than on its first request.
func NewProjectService(s *Store, repo *ProjectRepository, authz Authorizer, quota QuotaReserver, jobs JobEnqueuer, audit AuditAppender) (*ProjectService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case repo == nil:
		return nil, errors.New("store: nil project repository")
	case authz == nil:
		return nil, errors.New("store: nil authorizer")
	case quota == nil:
		return nil, errors.New("store: nil quota reserver")
	case jobs == nil:
		return nil, errors.New("store: nil job enqueuer")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &ProjectService{store: s, repo: repo, authz: authz, quota: quota, jobs: jobs, audit: audit}, nil
}

// Create validates in, then runs the create-project unit of work inside one
// transaction: authorize, reserve quota, write the project row, enqueue the
// provisioning job, append the immutable audit record. Validation runs before
// the transaction is opened, so an invalid request never touches the database.
// Every failure after that point — a denied authorization decision, an
// exhausted quota, a slug conflict, a failed provisioning-job enqueue, or a
// failed audit append — rolls the whole transaction back, so the project row
// is never persisted without its job and audit trail and the checks can never
// be skipped.
func (svc *ProjectService) Create(ctx context.Context, in CreateProjectInput) (Project, error) {
	project, err := validateCreateProjectInput(in)
	if err != nil {
		return Project{}, err
	}

	// The audit record is filed under the actor's home organization — the
	// tenant the principal authenticated into — while its resource id names
	// the project that was created. A missing actor organization is a wiring
	// error (an authenticated request always carries one), not client input,
	// so it is reported as Internal rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return Project{}, apierr.Internal(errors.New("store: ProjectService.Create requires an actor organization for the audit record"))
	}

	event := AuditEvent{
		OrganizationID: actorOrgID,
		ActorID:        strings.TrimSpace(in.ActorID),
		ActorKind:      strings.TrimSpace(in.ActorKind),
		Action:         projectCreateAction,
		ResourceKind:   string(domain.KindProject),
		ResourceID:     project.ID,
		Decision:       AuditDecisionAllowed,
		Reason:         "authorization granted for project.create",
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
		// The slug is a canonical [a-z0-9-] identifier — it carries no secret
		// material — so it is safe to record verbatim as audit context.
		Metadata: map[string]string{"slug": project.Slug},
	}

	var created Project
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if err := svc.authz.Authorize(ctx, tx, projectCreateAction, project.OrganizationID); err != nil {
			return err
		}
		if err := svc.quota.Reserve(ctx, tx, project.OrganizationID, projectQuotaResource); err != nil {
			return err
		}
		row, err := svc.repo.Insert(ctx, tx, project)
		if err != nil {
			return err
		}
		if err := svc.jobs.Enqueue(ctx, tx, project.OrganizationID, projectProvisionJob, row.ID); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		created = row
		return nil
	})
	if txErr != nil {
		return Project{}, txErr
	}
	return created, nil
}

// validateCreateProjectInput checks in and returns the Project row it would
// persist. It is split out from Create so the validation rules are unit
// testable without a database, and so an invalid request is rejected before a
// transaction is ever opened. On failure it returns a typed apierr.InvalidInput
// carrying stable field paths — never the submitted values — so the rejection
// can name the offending field without leaking input.
func validateCreateProjectInput(in CreateProjectInput) (Project, error) {
	var violations []apierr.FieldViolation

	orgID := strings.TrimSpace(in.OrganizationID)
	if id, err := domain.ParseID(orgID); err != nil || id.Kind() != domain.KindOrganization {
		violations = append(violations, apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization id",
		})
	}

	projectID := strings.TrimSpace(in.ProjectID)
	if id, err := domain.ParseID(projectID); err != nil || id.Kind() != domain.KindProject {
		violations = append(violations, apierr.FieldViolation{
			Field:  "project_id",
			Reason: "must be a valid project id",
		})
	}

	slug, err := domain.ParseSlug(in.Slug)
	if err != nil {
		violations = append(violations, apierr.FieldViolation{
			Field:  "slug",
			Reason: "must be a canonical slug",
		})
	}

	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		violations = append(violations, apierr.FieldViolation{
			Field:  "display_name",
			Reason: "must not be empty",
		})
	}

	if len(violations) > 0 {
		return Project{}, apierr.InvalidInput(violations...)
	}
	return Project{
		ID:             projectID,
		OrganizationID: orgID,
		Slug:           slug.String(),
		DisplayName:    displayName,
	}, nil
}
