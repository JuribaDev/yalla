package store

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
)

const (
	previewCreateAction = "preview.create"
	previewDeleteAction = "preview.delete"
	previewCreateJob    = "create_preview_environment"
	previewDeleteJob    = "delete_preview_environment"
	previewChangeRefMax = 200
)

// CreatePreviewEnvironmentInput is the unvalidated input for creating a
// project-scoped preview. The preview row wraps a newly-created
// kind=preview environment clone and points back at its source environment.
type CreatePreviewEnvironmentInput struct {
	OrganizationID      string
	ProjectID           string
	PreviewID           string
	EnvironmentID       string
	SourceEnvironmentID string
	Slug                string
	DisplayName         string
	ChangeRef           string
	ExpiresAt           *time.Time
	ActorID             string
	ActorKind           string
	ActorOrgID          string
	RequestID           string
	CorrelationID       string
}

// DeletePreviewEnvironmentInput is the unvalidated input for scheduling a
// preview lifecycle row for worker-driven teardown.
type DeletePreviewEnvironmentInput struct {
	OrganizationID string
	ProjectID      string
	PreviewID      string
	IfMatchVersion *int64
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// PreviewEnvironmentService creates preview environments as one source-of-
// truth unit of work: validate, resolve parent/source scope, authorize,
// reserve quota through the preview-kind environment insert, write the
// preview wrapper, enqueue provisioning, and append audit.
type PreviewEnvironmentService struct {
	store        *Store
	projects     *ProjectRepository
	environments *EnvironmentRepository
	previews     *PreviewEnvironmentRepository
	authz        Authorizer
	quota        QuotaReserver
	jobs         JobEnqueuer
	audit        AuditAppender
}

// NewPreviewEnvironmentService wires a PreviewEnvironmentService from its
// dependencies.
func NewPreviewEnvironmentService(s *Store, projects *ProjectRepository, environments *EnvironmentRepository, previews *PreviewEnvironmentRepository, authz Authorizer, quota QuotaReserver, jobs JobEnqueuer, audit AuditAppender) (*PreviewEnvironmentService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case projects == nil:
		return nil, errors.New("store: nil project repository")
	case environments == nil:
		return nil, errors.New("store: nil environment repository")
	case previews == nil:
		return nil, errors.New("store: nil preview environment repository")
	case authz == nil:
		return nil, errors.New("store: nil authorizer")
	case quota == nil:
		return nil, errors.New("store: nil quota reserver")
	case jobs == nil:
		return nil, errors.New("store: nil job enqueuer")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &PreviewEnvironmentService{
		store:        s,
		projects:     projects,
		environments: environments,
		previews:     previews,
		authz:        authz,
		quota:        quota,
		jobs:         jobs,
		audit:        audit,
	}, nil
}

// Create validates and persists a preview environment unit of work.
func (svc *PreviewEnvironmentService) Create(ctx context.Context, in CreatePreviewEnvironmentInput) (PreviewEnvironment, error) {
	validated, err := validateCreatePreviewEnvironmentInput(in)
	if err != nil {
		return PreviewEnvironment{}, err
	}
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return PreviewEnvironment{}, apierr.Internal(errors.New("store: PreviewEnvironmentService.Create requires an actor organization for the audit record"))
	}

	var created PreviewEnvironment
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.projects.Get(ctx, tx, validated.OrganizationID, validated.ProjectID); err != nil {
			return err
		}
		source, err := svc.environments.GetByID(ctx, tx, validated.OrganizationID, validated.SourceEnvironmentID)
		if err != nil {
			return err
		}
		if source.ProjectID != validated.ProjectID {
			return apierr.NotFound("environment", validated.SourceEnvironmentID)
		}
		if source.DeletionScheduledAt != nil {
			return apierr.Conflict("source environment is scheduled for deletion")
		}
		if err := svc.authz.Authorize(ctx, tx, previewCreateAction, validated.OrganizationID); err != nil {
			return err
		}
		if err := svc.quota.Reserve(ctx, tx, validated.OrganizationID, string(QuotaResourceEnvironments)); err != nil {
			return err
		}
		if err := svc.quota.Reserve(ctx, tx, validated.OrganizationID, string(QuotaResourcePreviewEnvironments)); err != nil {
			return err
		}

		env, err := svc.environments.Insert(ctx, tx, Environment{
			ID:             validated.EnvironmentID,
			OrganizationID: validated.OrganizationID,
			ProjectID:      validated.ProjectID,
			Slug:           validated.Slug,
			DisplayName:    validated.DisplayName,
			Kind:           EnvironmentKindPreview,
		})
		if err != nil {
			return err
		}
		preview, err := svc.previews.Insert(ctx, tx, PreviewEnvironment{
			ID:                  validated.PreviewID,
			OrganizationID:      validated.OrganizationID,
			ProjectID:           validated.ProjectID,
			EnvironmentID:       env.ID,
			SourceEnvironmentID: source.ID,
			DisplayName:         validated.DisplayName,
			ChangeRef:           validated.ChangeRef,
			ExpiresAt:           validated.ExpiresAt,
		})
		if err != nil {
			return err
		}
		if err := svc.jobs.Enqueue(ctx, tx, validated.OrganizationID, previewCreateJob, preview.ID); err != nil {
			return err
		}
		if _, err := svc.audit.Append(ctx, tx, AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         previewCreateAction,
			ResourceKind:   string(domain.KindPreviewEnvironment),
			ResourceID:     preview.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for preview.create",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			Metadata: map[string]string{
				"project_id":            preview.ProjectID,
				"environment_id":        preview.EnvironmentID,
				"source_environment_id": preview.SourceEnvironmentID,
				"change_ref":            preview.ChangeRef,
			},
		}); err != nil {
			return err
		}
		created = preview
		return nil
	})
	if txErr != nil {
		return PreviewEnvironment{}, txErr
	}
	return created, nil
}

// ListProjectPreviews returns every preview lifecycle row for a verified
// tenant-scoped project. The parent project check is deliberate: an unknown or
// cross-tenant project id must surface as E_NOT_FOUND instead of a successful
// empty list that could mislead callers about resource existence.
func (svc *PreviewEnvironmentService) ListProjectPreviews(ctx context.Context, organizationID, projectID string) ([]PreviewEnvironment, error) {
	var previews []PreviewEnvironment
	err := svc.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, err := svc.projects.Get(ctx, q, organizationID, projectID); err != nil {
			return err
		}
		rows, err := svc.previews.ListByProject(ctx, q, organizationID, projectID)
		if err != nil {
			return err
		}
		previews = rows
		return nil
	})
	if err != nil {
		return nil, err
	}
	if previews == nil {
		previews = make([]PreviewEnvironment, 0)
	}
	return previews, nil
}

// ScheduleDeletion marks a preview for worker-driven teardown, enqueues the
// delete_preview_environment job, and records the immutable audit event in the
// same transaction as the source-of-truth lifecycle update.
func (svc *PreviewEnvironmentService) ScheduleDeletion(ctx context.Context, in DeletePreviewEnvironmentInput) (PreviewEnvironment, error) {
	validated, err := validateDeletePreviewEnvironmentInput(in)
	if err != nil {
		return PreviewEnvironment{}, err
	}
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return PreviewEnvironment{}, apierr.Internal(errors.New("store: PreviewEnvironmentService.ScheduleDeletion requires an actor organization for the audit record"))
	}

	var scheduled PreviewEnvironment
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		if _, err := svc.projects.Get(ctx, tx, validated.OrganizationID, validated.ProjectID); err != nil {
			return err
		}
		current, err := svc.previews.GetByID(ctx, tx, validated.OrganizationID, validated.ProjectID, validated.PreviewID)
		if err != nil {
			return err
		}
		if in.IfMatchVersion != nil && current.Version != *in.IfMatchVersion {
			return apierr.ConflictStale(current.Version)
		}
		if current.DeletionScheduledAt != nil || current.Status == PreviewEnvironmentStatusDeleting {
			return apierr.Conflict("preview environment deletion is already scheduled")
		}
		row, err := svc.previews.ScheduleDeletion(ctx, tx, validated.OrganizationID, validated.ProjectID, validated.PreviewID, in.IfMatchVersion)
		if err != nil {
			return err
		}
		if err := svc.jobs.Enqueue(ctx, tx, validated.OrganizationID, previewDeleteJob, row.ID); err != nil {
			return err
		}

		metadata := map[string]string{
			"project_id":            row.ProjectID,
			"environment_id":        row.EnvironmentID,
			"source_environment_id": row.SourceEnvironmentID,
			"status":                row.Status,
		}
		if row.DeletionScheduledAt != nil {
			metadata["deletion_scheduled_at"] = row.DeletionScheduledAt.UTC().Format(time.RFC3339Nano)
		}
		if _, err := svc.audit.Append(ctx, tx, AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         previewDeleteAction,
			ResourceKind:   string(domain.KindPreviewEnvironment),
			ResourceID:     row.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for preview.delete",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			Metadata:       metadata,
		}); err != nil {
			return err
		}
		scheduled = row
		return nil
	})
	if txErr != nil {
		return PreviewEnvironment{}, txErr
	}
	return scheduled, nil
}

type createPreviewEnvironmentValidated struct {
	OrganizationID      string
	ProjectID           string
	PreviewID           string
	EnvironmentID       string
	SourceEnvironmentID string
	Slug                string
	DisplayName         string
	ChangeRef           string
	ExpiresAt           *time.Time
}

type deletePreviewEnvironmentValidated struct {
	OrganizationID string
	ProjectID      string
	PreviewID      string
}

func validateDeletePreviewEnvironmentInput(in DeletePreviewEnvironmentInput) (deletePreviewEnvironmentValidated, error) {
	var violations []apierr.FieldViolation

	orgID := strings.TrimSpace(in.OrganizationID)
	if id, err := domain.ParseID(orgID); err != nil || id.Kind() != domain.KindOrganization {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must be a valid organization id"})
	}

	projectID := strings.TrimSpace(in.ProjectID)
	if id, err := domain.ParseID(projectID); err != nil || id.Kind() != domain.KindProject {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "must be a valid project id"})
	}

	previewID := strings.TrimSpace(in.PreviewID)
	if id, err := domain.ParseID(previewID); err != nil || id.Kind() != domain.KindPreviewEnvironment {
		violations = append(violations, apierr.FieldViolation{Field: "preview_id", Reason: "must be a valid preview environment id"})
	}

	if len(violations) > 0 {
		return deletePreviewEnvironmentValidated{}, apierr.InvalidInput(violations...)
	}
	return deletePreviewEnvironmentValidated{
		OrganizationID: orgID,
		ProjectID:      projectID,
		PreviewID:      previewID,
	}, nil
}

func validateCreatePreviewEnvironmentInput(in CreatePreviewEnvironmentInput) (createPreviewEnvironmentValidated, error) {
	var violations []apierr.FieldViolation

	orgID := strings.TrimSpace(in.OrganizationID)
	if id, err := domain.ParseID(orgID); err != nil || id.Kind() != domain.KindOrganization {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "must be a valid organization id"})
	}

	projectID := strings.TrimSpace(in.ProjectID)
	if id, err := domain.ParseID(projectID); err != nil || id.Kind() != domain.KindProject {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "must be a valid project id"})
	}

	previewID := strings.TrimSpace(in.PreviewID)
	if id, err := domain.ParseID(previewID); err != nil || id.Kind() != domain.KindPreviewEnvironment {
		violations = append(violations, apierr.FieldViolation{Field: "preview_id", Reason: "must be a valid preview environment id"})
	}

	environmentID := strings.TrimSpace(in.EnvironmentID)
	if id, err := domain.ParseID(environmentID); err != nil || id.Kind() != domain.KindEnvironment {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "must be a valid environment id"})
	}

	sourceID := strings.TrimSpace(in.SourceEnvironmentID)
	if id, err := domain.ParseID(sourceID); err != nil || id.Kind() != domain.KindEnvironment {
		violations = append(violations, apierr.FieldViolation{Field: "source_environment_id", Reason: "must be a valid source environment id"})
	}
	if environmentID != "" && sourceID != "" && environmentID == sourceID {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "must differ from the source environment id"})
	}

	slug, slugErr := domain.ParseSlug(in.Slug)
	if slugErr != nil {
		violations = append(violations, apierr.FieldViolation{Field: "slug", Reason: "must be a canonical slug"})
	}

	displayName, dnViolation := validateEnvironmentDisplayName(in.DisplayName)
	if dnViolation != nil {
		violations = append(violations, *dnViolation)
	}

	changeRef, crViolation := validatePreviewChangeRef(in.ChangeRef)
	if crViolation != nil {
		violations = append(violations, *crViolation)
	}

	if in.ExpiresAt != nil && !in.ExpiresAt.After(time.Now().UTC()) {
		violations = append(violations, apierr.FieldViolation{Field: "expires_at", Reason: "must be in the future"})
	}

	if len(violations) > 0 {
		return createPreviewEnvironmentValidated{}, apierr.InvalidInput(violations...)
	}
	return createPreviewEnvironmentValidated{
		OrganizationID:      orgID,
		ProjectID:           projectID,
		PreviewID:           previewID,
		EnvironmentID:       environmentID,
		SourceEnvironmentID: sourceID,
		Slug:                slug.String(),
		DisplayName:         displayName,
		ChangeRef:           changeRef,
		ExpiresAt:           in.ExpiresAt,
	}, nil
}

func validatePreviewChangeRef(raw string) (string, *apierr.FieldViolation) {
	changeRef := strings.TrimSpace(raw)
	switch {
	case changeRef == "":
		return "", &apierr.FieldViolation{Field: "change_ref", Reason: "must not be blank"}
	case !utf8.ValidString(changeRef):
		return "", &apierr.FieldViolation{Field: "change_ref", Reason: "must be valid UTF-8"}
	case containsControlRune(changeRef):
		return "", &apierr.FieldViolation{Field: "change_ref", Reason: "must not contain control characters"}
	case utf8.RuneCountInString(changeRef) > previewChangeRefMax:
		return "", &apierr.FieldViolation{Field: "change_ref", Reason: "exceeds the maximum length"}
	}
	return changeRef, nil
}
