package jobs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

const (
	projectProvisionKind     = "project.provision"
	environmentProvisionKind = "environment.provision"
	serviceProvisionKind     = "service.provision"
)

// Enqueuer translates store-layer mutation intents into durable provisioning
// jobs. It must be called inside the same *store.Tx as the desired-state write
// so the resource row and its provisioning job commit or roll back together.
type Enqueuer struct {
	jobs          *store.JobRepository
	organizations *store.OrganizationRepository
	projects      *store.ProjectRepository
	environments  *store.EnvironmentRepository
	services      *store.ServiceRepository
	backups       *store.ServiceBackupRepository
	deployments   *store.DeploymentRepository
}

// NewEnqueuer builds the production store.JobEnqueuer adapter backed by the
// durable provisioning_jobs queue.
func NewEnqueuer() *Enqueuer {
	return &Enqueuer{
		jobs:          store.NewJobRepository(),
		organizations: store.NewOrganizationRepository(),
		projects:      store.NewProjectRepository(),
		environments:  store.NewEnvironmentRepository(),
		services:      store.NewServiceRepository(),
		backups:       store.NewServiceBackupRepository(),
		deployments:   store.NewDeploymentRepository(),
	}
}

// Enqueue inserts the durable provisioning job for in, unless a job with the
// same tenant-scoped, versioned idempotency key already exists.
func (e *Enqueuer) Enqueue(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	if e == nil {
		return apierr.Internal(errors.New("jobs: nil Enqueuer"))
	}
	if tx == nil {
		return apierr.Internal(errors.New("jobs: Enqueuer.Enqueue called with a nil transaction"))
	}
	in = normalizeInput(in)

	switch in.JobKind {
	case TypeEnsureDokployOrganization:
		return e.enqueueOrganization(ctx, tx, in)
	case projectProvisionKind:
		return e.enqueueProject(ctx, tx, in)
	case environmentProvisionKind:
		return e.enqueueEnvironment(ctx, tx, in)
	case serviceProvisionKind:
		return e.enqueueService(ctx, tx, in)
	case TypeDeployService, TypeDeployServiceAlias:
		return e.enqueueDeployment(ctx, tx, in)
	case TypeRestartService, TypeRestartServiceAlias,
		TypeRollbackService, TypeRollbackServiceAlias,
		TypeStopService, TypeStopServiceAlias,
		TypeStartService, TypeStartServiceAlias,
		TypeDeleteService, TypeDeleteServiceAlias,
		TypeSyncDomains,
		TypeSyncVariables,
		TypeReconcileService,
		TypeServiceBuildUpdate:
		return e.enqueueServiceRuntime(ctx, tx, in)
	case TypeDeleteEnvironment, TypeDeleteEnvironmentAlias:
		return e.enqueueDeleteEnvironment(ctx, tx, in)
	case TypeDeleteProject, TypeDeleteProjectAlias:
		return e.enqueueDeleteProject(ctx, tx, in)
	case TypeRunBackup, TypeRestoreBackup:
		return e.enqueueBackup(ctx, tx, in)
	case TypeCreatePreviewEnvironment, TypeDeletePreviewEnvironment:
		return e.enqueuePreview(ctx, tx, in)
	default:
		return apierr.Internal(fmt.Errorf("jobs: unsupported job kind %q", in.JobKind))
	}
}

func normalizeInput(in store.EnqueueJobInput) store.EnqueueJobInput {
	return store.EnqueueJobInput{
		OrganizationID: strings.TrimSpace(in.OrganizationID),
		JobKind:        strings.TrimSpace(in.JobKind),
		ResourceID:     strings.TrimSpace(in.ResourceID),
		ServiceID:      strings.TrimSpace(in.ServiceID),
		RequestID:      strings.TrimSpace(in.RequestID),
		CorrelationID:  strings.TrimSpace(in.CorrelationID),
	}
}

func (e *Enqueuer) enqueueOrganization(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	org, err := e.organizations.Get(ctx, tx, in.ResourceID)
	if err != nil {
		return err
	}
	if in.OrganizationID != "" && in.OrganizationID != org.ID {
		return apierr.NotFound("organization", in.ResourceID)
	}
	return e.insertIfAbsent(ctx, tx, store.ProvisioningJob{
		OrganizationID: org.ID,
		JobType:        TypeEnsureDokployOrganization,
		DesiredVersion: org.Version,
		IdempotencyKey: idempotencyKey(TypeEnsureDokployOrganization, org.ID, org.Version),
		RequestID:      in.RequestID,
		CorrelationID:  in.CorrelationID,
		Payload: map[string]string{
			"organization_id": org.ID,
		},
	})
}

func (e *Enqueuer) enqueueProject(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	project, err := e.projects.Get(ctx, tx, in.OrganizationID, in.ResourceID)
	if err != nil {
		return err
	}
	return e.insertIfAbsent(ctx, tx, store.ProvisioningJob{
		OrganizationID: project.OrganizationID,
		JobType:        TypeEnsureProject,
		ProjectID:      project.ID,
		DesiredVersion: project.Version,
		IdempotencyKey: idempotencyKey(in.JobKind, project.ID, project.Version),
		RequestID:      in.RequestID,
		CorrelationID:  in.CorrelationID,
		Payload: map[string]string{
			"organization_id": project.OrganizationID,
			"project_id":      project.ID,
		},
	})
}

func (e *Enqueuer) enqueueEnvironment(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	env, err := e.environments.GetByID(ctx, tx, in.OrganizationID, in.ResourceID)
	if err != nil {
		return err
	}
	return e.insertIfAbsent(ctx, tx, store.ProvisioningJob{
		OrganizationID: env.OrganizationID,
		JobType:        TypeEnsureEnvironment,
		ProjectID:      env.ProjectID,
		EnvironmentID:  env.ID,
		DesiredVersion: env.Version,
		IdempotencyKey: idempotencyKey(in.JobKind, env.ID, env.Version),
		RequestID:      in.RequestID,
		CorrelationID:  in.CorrelationID,
		Payload: map[string]string{
			"organization_id": env.OrganizationID,
			"project_id":      env.ProjectID,
			"environment_id":  env.ID,
		},
	})
}

func (e *Enqueuer) enqueueService(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	svc, err := e.services.GetByID(ctx, tx, in.OrganizationID, in.ResourceID)
	if err != nil {
		return err
	}
	jobType, payload, err := serviceProvisionPayload(svc)
	if err != nil {
		return err
	}
	return e.insertIfAbsent(ctx, tx, store.ProvisioningJob{
		OrganizationID: svc.OrganizationID,
		JobType:        jobType,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		DesiredVersion: svc.Version,
		IdempotencyKey: idempotencyKey(in.JobKind, svc.ID, svc.Version),
		RequestID:      in.RequestID,
		CorrelationID:  in.CorrelationID,
		Payload:        payload,
	})
}

func serviceProvisionPayload(svc store.Service) (string, map[string]string, error) {
	payload := servicePayload(svc)
	switch svc.Kind {
	case store.ServiceKindApplication:
		return TypeEnsureApplicationService, payload, nil
	case store.ServiceKindCompose:
		return TypeEnsureComposeService, payload, nil
	case store.ServiceKindDatabase:
		payload["engine"] = dokploy.EnginePostgres
		return TypeEnsureDatabaseService, payload, nil
	default:
		return "", nil, apierr.Internal(fmt.Errorf("jobs: unsupported service kind %q", svc.Kind))
	}
}

func (e *Enqueuer) enqueueServiceRuntime(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	svc, err := e.services.GetByID(ctx, tx, in.OrganizationID, in.ResourceID)
	if err != nil {
		return err
	}
	return e.insertIfAbsent(ctx, tx, store.ProvisioningJob{
		OrganizationID: svc.OrganizationID,
		JobType:        in.JobKind,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		DesiredVersion: svc.Version,
		IdempotencyKey: idempotencyKey(in.JobKind, svc.ID, svc.Version),
		RequestID:      in.RequestID,
		CorrelationID:  in.CorrelationID,
		Payload:        servicePayload(svc),
	})
}

func servicePayload(svc store.Service) map[string]string {
	return map[string]string{
		"organization_id": svc.OrganizationID,
		"project_id":      svc.ProjectID,
		"environment_id":  svc.EnvironmentID,
		"service_id":      svc.ID,
	}
}

func (e *Enqueuer) enqueueDeployment(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	deployment, err := e.deployments.GetByID(ctx, tx, in.OrganizationID, in.ResourceID)
	if err != nil {
		return err
	}
	return e.insertIfAbsent(ctx, tx, store.ProvisioningJob{
		OrganizationID: deployment.OrganizationID,
		JobType:        TypeDeployService,
		ProjectID:      deployment.ProjectID,
		EnvironmentID:  deployment.EnvironmentID,
		ServiceID:      deployment.ServiceID,
		DesiredVersion: deployment.Version,
		IdempotencyKey: idempotencyKey(in.JobKind, deployment.ID, deployment.Version),
		RequestID:      in.RequestID,
		CorrelationID:  in.CorrelationID,
		Payload: map[string]string{
			"organization_id": deployment.OrganizationID,
			"project_id":      deployment.ProjectID,
			"environment_id":  deployment.EnvironmentID,
			"service_id":      deployment.ServiceID,
			"deployment_id":   deployment.ID,
		},
	})
}

func (e *Enqueuer) enqueueDeleteEnvironment(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	env, err := e.environments.GetByID(ctx, tx, in.OrganizationID, in.ResourceID)
	if err != nil {
		return err
	}
	return e.insertIfAbsent(ctx, tx, store.ProvisioningJob{
		OrganizationID: env.OrganizationID,
		JobType:        in.JobKind,
		ProjectID:      env.ProjectID,
		EnvironmentID:  env.ID,
		DesiredVersion: env.Version,
		IdempotencyKey: idempotencyKey(in.JobKind, env.ID, env.Version),
		RequestID:      in.RequestID,
		CorrelationID:  in.CorrelationID,
		Payload: map[string]string{
			"organization_id": env.OrganizationID,
			"project_id":      env.ProjectID,
			"environment_id":  env.ID,
		},
	})
}

func (e *Enqueuer) enqueueDeleteProject(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	project, err := e.projects.Get(ctx, tx, in.OrganizationID, in.ResourceID)
	if err != nil {
		return err
	}
	return e.insertIfAbsent(ctx, tx, store.ProvisioningJob{
		OrganizationID: project.OrganizationID,
		JobType:        in.JobKind,
		ProjectID:      project.ID,
		DesiredVersion: project.Version,
		IdempotencyKey: idempotencyKey(in.JobKind, project.ID, project.Version),
		RequestID:      in.RequestID,
		CorrelationID:  in.CorrelationID,
		Payload: map[string]string{
			"organization_id": project.OrganizationID,
			"project_id":      project.ID,
		},
	})
}

func (e *Enqueuer) enqueueBackup(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	if in.ServiceID == "" {
		return apierr.Internal(errors.New("jobs: backup job requires service_id"))
	}
	backup, err := e.backups.GetByID(ctx, tx, in.OrganizationID, in.ServiceID, in.ResourceID)
	if err != nil {
		return err
	}
	svc, err := e.services.GetByID(ctx, tx, in.OrganizationID, backup.ServiceID)
	if err != nil {
		return err
	}
	return e.insertIfAbsent(ctx, tx, store.ProvisioningJob{
		OrganizationID: backup.OrganizationID,
		JobType:        in.JobKind,
		ProjectID:      svc.ProjectID,
		EnvironmentID:  svc.EnvironmentID,
		ServiceID:      svc.ID,
		DesiredVersion: backup.Version,
		IdempotencyKey: idempotencyKey(in.JobKind, backup.ID, backup.Version),
		RequestID:      in.RequestID,
		CorrelationID:  in.CorrelationID,
		Payload: map[string]string{
			"organization_id": backup.OrganizationID,
			"project_id":      svc.ProjectID,
			"environment_id":  svc.EnvironmentID,
			"service_id":      svc.ID,
			"backup_id":       backup.ID,
		},
	})
}

func (e *Enqueuer) enqueuePreview(ctx context.Context, tx *store.Tx, in store.EnqueueJobInput) error {
	preview, err := loadPreviewByOrganization(ctx, tx, in.OrganizationID, in.ResourceID)
	if err != nil {
		return err
	}
	return e.insertIfAbsent(ctx, tx, store.ProvisioningJob{
		OrganizationID: preview.OrganizationID,
		JobType:        in.JobKind,
		ProjectID:      preview.ProjectID,
		EnvironmentID:  preview.EnvironmentID,
		DesiredVersion: preview.Version,
		IdempotencyKey: idempotencyKey(in.JobKind, preview.ID, preview.Version),
		RequestID:      in.RequestID,
		CorrelationID:  in.CorrelationID,
		Payload: map[string]string{
			"organization_id": preview.OrganizationID,
			"project_id":      preview.ProjectID,
			"environment_id":  preview.EnvironmentID,
			"preview_id":      preview.ID,
		},
	})
}

func (e *Enqueuer) insertIfAbsent(ctx context.Context, tx *store.Tx, job store.ProvisioningJob) error {
	if _, exists, err := e.jobs.FindByIdempotencyKey(ctx, tx, job.OrganizationID, job.IdempotencyKey); err != nil {
		return err
	} else if exists {
		return nil
	}
	_, err := e.jobs.Insert(ctx, tx, job)
	return err
}

func idempotencyKey(kind, resourceID string, version int64) string {
	return kind + ":" + resourceID + ":v" + strconv.FormatInt(version, 10)
}

type previewTarget struct {
	ID             string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	Version        int64
}

func loadPreviewByOrganization(ctx context.Context, q store.Querier, organizationID, previewID string) (previewTarget, error) {
	row := q.QueryRow(ctx,
		`SELECT id, organization_id, project_id, environment_id, version
		   FROM preview_environments
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, previewID)
	var out previewTarget
	if err := row.Scan(&out.ID, &out.OrganizationID, &out.ProjectID, &out.EnvironmentID, &out.Version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return previewTarget{}, apierr.NotFound("preview environment", previewID)
		}
		return previewTarget{}, apierr.StoreUnavailable(err)
	}
	return out, nil
}
