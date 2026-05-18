package worker

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/secrets"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/JuribaDev/yalla/internal/controlplane/variables"
)

// JobTypeEnsureDokployOrganization is the durable provisioning job that makes
// the tenant's Dokploy organization mapping exist.
const JobTypeEnsureDokployOrganization = "ensure_dokploy_organization"

// JobTypeEnsureProject is the durable provisioning job that makes the tenant's
// Dokploy project mapping exist.
const JobTypeEnsureProject = "ensure_project"

// JobTypeEnsureEnvironment is the durable provisioning job that makes the
// tenant's Dokploy environment mapping exist.
const JobTypeEnsureEnvironment = "ensure_environment"

// JobTypeEnsureApplicationService is the durable provisioning job that makes
// the tenant's Dokploy application mapping exist for an application service.
const JobTypeEnsureApplicationService = "ensure_application_service"

// JobTypeEnsureComposeService is the durable provisioning job that makes the
// tenant's Dokploy compose mapping exist for a compose service.
const JobTypeEnsureComposeService = "ensure_compose_service"

// JobTypeEnsureDatabaseService is the durable provisioning job that makes the
// tenant's Dokploy database mapping exist for a database service.
const JobTypeEnsureDatabaseService = "ensure_database_service"

// JobTypeDeployService is the durable provisioning job enqueued by the public
// deployment endpoints. The persisted API contract historically uses
// service.deploy; JobTypeDeployServiceAlias accepts the PRD's deploy_service
// spelling for forward compatibility with manually seeded jobs.
const JobTypeDeployService = "service.deploy"

// JobTypeDeployServiceAlias is accepted by the worker as an alias for
// JobTypeDeployService.
const JobTypeDeployServiceAlias = "deploy_service"

// JobTypeRestartService is the durable provisioning job enqueued by the public
// service restart endpoint. JobTypeRestartServiceAlias accepts the PRD's
// restart_service spelling for forward compatibility with manually seeded jobs.
const JobTypeRestartService = "service.restart"

// JobTypeRestartServiceAlias is accepted by the worker as an alias for
// JobTypeRestartService.
const JobTypeRestartServiceAlias = "restart_service"

// JobTypeRollbackService is the durable provisioning job enqueued by service
// rollback workflows. JobTypeRollbackServiceAlias accepts the PRD's
// rollback_service spelling for compatibility with manually seeded jobs.
const JobTypeRollbackService = "service.rollback"

// JobTypeRollbackServiceAlias is accepted by the worker as an alias for
// JobTypeRollbackService.
const JobTypeRollbackServiceAlias = "rollback_service"

// JobTypeStopService is the durable provisioning job enqueued by the public
// service stop endpoint. JobTypeStopServiceAlias accepts the PRD's stop_service
// spelling for forward compatibility with manually seeded jobs.
const JobTypeStopService = "service.stop"

// JobTypeStopServiceAlias is accepted by the worker as an alias for
// JobTypeStopService.
const JobTypeStopServiceAlias = "stop_service"

// JobTypeStartService is the durable provisioning job enqueued by the public
// service start endpoint. JobTypeStartServiceAlias accepts the PRD's
// start_service spelling for forward compatibility with manually seeded jobs.
const JobTypeStartService = "service.start"

// JobTypeStartServiceAlias is accepted by the worker as an alias for
// JobTypeStartService.
const JobTypeStartServiceAlias = "start_service"

// JobTypeDeleteService is the durable provisioning job enqueued by service
// deletion workflows. JobTypeDeleteServiceAlias accepts the PRD's
// delete_service spelling for compatibility with manually seeded jobs.
const JobTypeDeleteService = "service.delete"

// JobTypeDeleteServiceAlias is accepted by the worker as an alias for
// JobTypeDeleteService.
const JobTypeDeleteServiceAlias = "delete_service"

// JobTypeDeleteEnvironment is the durable provisioning job enqueued by
// environment deletion workflows. JobTypeDeleteEnvironmentAlias accepts the
// PRD's delete_environment spelling for compatibility with manually seeded
// jobs.
const JobTypeDeleteEnvironment = "environment.delete"

// JobTypeDeleteEnvironmentAlias is accepted by the worker as an alias for
// JobTypeDeleteEnvironment.
const JobTypeDeleteEnvironmentAlias = "delete_environment"

// JobTypeDeleteProject is the durable provisioning job enqueued by project
// deletion workflows. JobTypeDeleteProjectAlias accepts the PRD's
// delete_project spelling for compatibility with manually seeded jobs.
const JobTypeDeleteProject = "project.delete"

// JobTypeDeleteProjectAlias is accepted by the worker as an alias for
// JobTypeDeleteProject.
const JobTypeDeleteProjectAlias = "delete_project"

// JobTypeSyncDomains is the durable provisioning job that reconciles
// service_domains desired state into Dokploy domain bindings.
const JobTypeSyncDomains = "sync_domains"

// JobTypeSyncVariables is the durable provisioning job that reconciles the
// effective Yalla variable hierarchy into a Dokploy service environment.
const JobTypeSyncVariables = "sync_variables"

// JobTypeRunBackup is the durable provisioning job that triggers one
// service_backups policy against the mapped Dokploy service.
const JobTypeRunBackup = "run_backup"

// JobTypeRestoreBackup is the durable provisioning job that restores a service
// from one service_backups policy against the mapped Dokploy service.
const JobTypeRestoreBackup = "restore_backup"

// DokployClient is the narrow typed-client surface these worker jobs
// needs. *dokploy.Client satisfies it in production; tests can supply fakes.
type DokployClient interface {
	EnsureOrganization(context.Context, dokploy.EnsureOrganizationInput) (dokploy.Organization, error)
	EnsureProject(context.Context, dokploy.EnsureProjectInput) (dokploy.Project, error)
	EnsureEnvironment(context.Context, dokploy.EnsureEnvironmentInput) (dokploy.Environment, error)
	EnsureService(context.Context, dokploy.EnsureServiceInput) (dokploy.Service, error)
	EnsureDomain(context.Context, dokploy.EnsureDomainInput) (dokploy.Domain, error)
	SyncVariables(context.Context, dokploy.SyncVariablesInput) error
	DeployService(context.Context, dokploy.DeployServiceInput) (dokploy.Deployment, error)
	RunBackup(context.Context, dokploy.RunBackupInput) (dokploy.BackupRun, error)
	RestoreBackup(context.Context, dokploy.RestoreBackupInput) (dokploy.BackupRun, error)
	RestartService(context.Context, dokploy.RestartServiceInput) (dokploy.ServiceStatus, error)
	RollbackService(context.Context, dokploy.RollbackServiceInput) (dokploy.ServiceStatus, error)
	StopService(context.Context, dokploy.StopServiceInput) (dokploy.ServiceStatus, error)
	StartService(context.Context, dokploy.StartServiceInput) (dokploy.ServiceStatus, error)
	RemoveProject(context.Context, dokploy.RemoveProjectInput) error
	RemoveService(context.Context, dokploy.RemoveServiceInput) error
	RemoveEnvironment(context.Context, dokploy.RemoveEnvironmentInput) error
}

// EnsureDokployOrganizationPayload is the typed schema carried by
// provisioning_jobs.payload for JobTypeEnsureDokployOrganization.
type EnsureDokployOrganizationPayload struct {
	OrganizationID string
}

// ParseEnsureDokployOrganizationPayload validates job's typed payload and
// returns a terminal error for payload shapes retrying cannot repair.
func ParseEnsureDokployOrganizationPayload(job store.ProvisioningJob) (EnsureDokployOrganizationPayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeEnsureDokployOrganization {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be ensure_dokploy_organization"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "must be empty for this job type"})
	}
	if job.EnvironmentID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "must be empty for this job type"})
	}
	if job.ServiceID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "must be empty for this job type"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	if len(violations) > 0 {
		return EnsureDokployOrganizationPayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return EnsureDokployOrganizationPayload{OrganizationID: payloadOrgID}, nil
}

// EnsureProjectPayload is the typed schema carried by provisioning_jobs.payload
// for JobTypeEnsureProject.
type EnsureProjectPayload struct {
	OrganizationID string
	ProjectID      string
}

// ParseEnsureProjectPayload validates job's typed payload and returns a
// terminal error for payload shapes retrying cannot repair.
func ParseEnsureProjectPayload(job store.ProvisioningJob) (EnsureProjectPayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeEnsureProject {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be ensure_project"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "must be empty for this job type"})
	}
	if job.ServiceID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "must be empty for this job type"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	if len(violations) > 0 {
		return EnsureProjectPayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return EnsureProjectPayload{OrganizationID: payloadOrgID, ProjectID: payloadProjectID}, nil
}

// EnsureEnvironmentPayload is the typed schema carried by
// provisioning_jobs.payload for JobTypeEnsureEnvironment.
type EnsureEnvironmentPayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
}

// ParseEnsureEnvironmentPayload validates job's typed payload and returns a
// terminal error for payload shapes retrying cannot repair.
func ParseEnsureEnvironmentPayload(job store.ProvisioningJob) (EnsureEnvironmentPayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeEnsureEnvironment {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be ensure_environment"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "must be empty for this job type"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	if len(violations) > 0 {
		return EnsureEnvironmentPayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return EnsureEnvironmentPayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
	}, nil
}

// EnsureApplicationServicePayload is the typed schema carried by
// provisioning_jobs.payload for JobTypeEnsureApplicationService.
type EnsureApplicationServicePayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

// EnsureComposeServicePayload is the typed schema carried by
// provisioning_jobs.payload for JobTypeEnsureComposeService.
type EnsureComposeServicePayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

// EnsureDatabaseServicePayload is the typed schema carried by
// provisioning_jobs.payload for JobTypeEnsureDatabaseService.
type EnsureDatabaseServicePayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Engine         string
}

// DeployServicePayload is the typed schema carried by provisioning_jobs.payload
// for JobTypeDeployService / JobTypeDeployServiceAlias.
type DeployServicePayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	DeploymentID   string
}

// RestartServicePayload is the typed schema carried by
// provisioning_jobs.payload for JobTypeRestartService /
// JobTypeRestartServiceAlias.
type RestartServicePayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

// RollbackServicePayload is the typed schema carried by
// provisioning_jobs.payload for JobTypeRollbackService /
// JobTypeRollbackServiceAlias.
type RollbackServicePayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

// StopServicePayload is the typed schema carried by provisioning_jobs.payload
// for JobTypeStopService / JobTypeStopServiceAlias.
type StopServicePayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

// StartServicePayload is the typed schema carried by provisioning_jobs.payload
// for JobTypeStartService / JobTypeStartServiceAlias.
type StartServicePayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

// DeleteServicePayload is the typed schema carried by
// provisioning_jobs.payload for JobTypeDeleteService /
// JobTypeDeleteServiceAlias.
type DeleteServicePayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

// DeleteEnvironmentPayload is the typed schema carried by
// provisioning_jobs.payload for JobTypeDeleteEnvironment /
// JobTypeDeleteEnvironmentAlias.
type DeleteEnvironmentPayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
}

// DeleteProjectPayload is the typed schema carried by provisioning_jobs.payload
// for JobTypeDeleteProject / JobTypeDeleteProjectAlias.
type DeleteProjectPayload struct {
	OrganizationID string
	ProjectID      string
}

// SyncDomainsPayload is the typed schema carried by provisioning_jobs.payload
// for JobTypeSyncDomains.
type SyncDomainsPayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
}

// ParseEnsureApplicationServicePayload validates job's typed payload and
// returns a terminal error for payload shapes retrying cannot repair.
func ParseEnsureApplicationServicePayload(job store.ProvisioningJob) (EnsureApplicationServicePayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeEnsureApplicationService {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be ensure_application_service"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	if len(violations) > 0 {
		return EnsureApplicationServicePayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return EnsureApplicationServicePayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
	}, nil
}

// ParseEnsureComposeServicePayload validates job's typed payload and returns a
// terminal error for payload shapes retrying cannot repair.
func ParseEnsureComposeServicePayload(job store.ProvisioningJob) (EnsureComposeServicePayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeEnsureComposeService {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be ensure_compose_service"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	if len(violations) > 0 {
		return EnsureComposeServicePayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return EnsureComposeServicePayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
	}, nil
}

// ParseEnsureDatabaseServicePayload validates job's typed payload and returns a
// terminal error for payload shapes retrying cannot repair.
func ParseEnsureDatabaseServicePayload(job store.ProvisioningJob) (EnsureDatabaseServicePayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeEnsureDatabaseService {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be ensure_database_service"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	engine := job.Payload["engine"]
	if !databaseEngineValid(engine) {
		violations = append(violations, apierr.FieldViolation{Field: "payload.engine", Reason: "must be postgres, mysql, mariadb, mongo, or redis"})
	}
	if len(violations) > 0 {
		return EnsureDatabaseServicePayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return EnsureDatabaseServicePayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
		Engine:         engine,
	}, nil
}

// ParseDeployServicePayload validates a deploy-service job payload and returns
// a terminal error for payload shapes retrying cannot repair.
func ParseDeployServicePayload(job store.ProvisioningJob) (DeployServicePayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeDeployService && job.JobType != JobTypeDeployServiceAlias {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be service.deploy or deploy_service"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	payloadDeploymentID := job.Payload["deployment_id"]
	if payloadDeploymentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.deployment_id", Reason: "is required"})
	}
	if len(violations) > 0 {
		return DeployServicePayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return DeployServicePayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
		DeploymentID:   payloadDeploymentID,
	}, nil
}

// ParseRestartServicePayload validates a restart-service job payload and
// returns a terminal error for payload shapes retrying cannot repair.
func ParseRestartServicePayload(job store.ProvisioningJob) (RestartServicePayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeRestartService && job.JobType != JobTypeRestartServiceAlias {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be service.restart or restart_service"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	if len(violations) > 0 {
		return RestartServicePayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return RestartServicePayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
	}, nil
}

// ParseRollbackServicePayload validates a rollback-service job payload and
// returns a terminal error for payload shapes retrying cannot repair.
func ParseRollbackServicePayload(job store.ProvisioningJob) (RollbackServicePayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeRollbackService && job.JobType != JobTypeRollbackServiceAlias {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be service.rollback or rollback_service"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	if len(violations) > 0 {
		return RollbackServicePayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return RollbackServicePayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
	}, nil
}

// ParseStopServicePayload validates a stop-service job payload and returns a
// terminal error for payload shapes retrying cannot repair.
func ParseStopServicePayload(job store.ProvisioningJob) (StopServicePayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeStopService && job.JobType != JobTypeStopServiceAlias {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be service.stop or stop_service"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	if len(violations) > 0 {
		return StopServicePayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return StopServicePayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
	}, nil
}

// ParseStartServicePayload validates a start-service job payload and returns a
// terminal error for payload shapes retrying cannot repair.
func ParseStartServicePayload(job store.ProvisioningJob) (StartServicePayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeStartService && job.JobType != JobTypeStartServiceAlias {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be service.start or start_service"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	if len(violations) > 0 {
		return StartServicePayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return StartServicePayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
	}, nil
}

// ParseDeleteServicePayload validates a delete-service job payload and returns
// a terminal error for payload shapes retrying cannot repair.
func ParseDeleteServicePayload(job store.ProvisioningJob) (DeleteServicePayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeDeleteService && job.JobType != JobTypeDeleteServiceAlias {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be service.delete or delete_service"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	if len(violations) > 0 {
		return DeleteServicePayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return DeleteServicePayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
	}, nil
}

// ParseSyncDomainsPayload validates a sync-domains job payload and returns a
// terminal error for payload shapes retrying cannot repair.
func ParseSyncDomainsPayload(job store.ProvisioningJob) (SyncDomainsPayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeSyncDomains {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be sync_domains"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	if len(violations) > 0 {
		return SyncDomainsPayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return SyncDomainsPayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
	}, nil
}

// SyncVariablesPayload is the typed schema carried by provisioning_jobs.payload
// for JobTypeSyncVariables.
type SyncVariablesPayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	Engine         string
}

// RunBackupPayload is the typed schema carried by provisioning_jobs.payload
// for JobTypeRunBackup.
type RunBackupPayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	BackupID       string
}

// RestoreBackupPayload is the typed schema carried by provisioning_jobs.payload
// for JobTypeRestoreBackup.
type RestoreBackupPayload struct {
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	ServiceID      string
	BackupID       string
}

// ParseSyncVariablesPayload validates a sync-variables job payload and returns
// a terminal error for payload shapes retrying cannot repair.
func ParseSyncVariablesPayload(job store.ProvisioningJob) (SyncVariablesPayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeSyncVariables {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be sync_variables"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	if len(violations) > 0 {
		return SyncVariablesPayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return SyncVariablesPayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
		Engine:         job.Payload["engine"],
	}, nil
}

// ParseRunBackupPayload validates a run_backup job payload and returns a
// terminal error for payload shapes retrying cannot repair.
func ParseRunBackupPayload(job store.ProvisioningJob) (RunBackupPayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeRunBackup {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be run_backup"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}
	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	payloadBackupID := job.Payload["backup_id"]
	if payloadBackupID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.backup_id", Reason: "is required"})
	}
	if len(violations) > 0 {
		return RunBackupPayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return RunBackupPayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
		BackupID:       payloadBackupID,
	}, nil
}

// ParseRestoreBackupPayload validates a restore_backup job payload and returns
// a terminal error for payload shapes retrying cannot repair.
func ParseRestoreBackupPayload(job store.ProvisioningJob) (RestoreBackupPayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeRestoreBackup {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be restore_backup"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "is required"})
	}
	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	payloadServiceID := job.Payload["service_id"]
	if payloadServiceID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "is required"})
	} else if job.ServiceID != "" && payloadServiceID != job.ServiceID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.service_id", Reason: "must match the job service_id"})
	}
	payloadBackupID := job.Payload["backup_id"]
	if payloadBackupID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.backup_id", Reason: "is required"})
	}
	if len(violations) > 0 {
		return RestoreBackupPayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return RestoreBackupPayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
		ServiceID:      payloadServiceID,
		BackupID:       payloadBackupID,
	}, nil
}

// ParseDeleteEnvironmentPayload validates a delete-environment job payload and
// returns a terminal error for payload shapes retrying cannot repair.
func ParseDeleteEnvironmentPayload(job store.ProvisioningJob) (DeleteEnvironmentPayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeDeleteEnvironment && job.JobType != JobTypeDeleteEnvironmentAlias {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be environment.delete or delete_environment"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "is required"})
	}
	if job.ServiceID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "must be empty for this job type"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	payloadEnvironmentID := job.Payload["environment_id"]
	if payloadEnvironmentID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "is required"})
	} else if job.EnvironmentID != "" && payloadEnvironmentID != job.EnvironmentID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.environment_id", Reason: "must match the job environment_id"})
	}
	if len(violations) > 0 {
		return DeleteEnvironmentPayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return DeleteEnvironmentPayload{
		OrganizationID: payloadOrgID,
		ProjectID:      payloadProjectID,
		EnvironmentID:  payloadEnvironmentID,
	}, nil
}

// ParseDeleteProjectPayload validates a delete-project job payload and returns
// a terminal error for payload shapes retrying cannot repair.
func ParseDeleteProjectPayload(job store.ProvisioningJob) (DeleteProjectPayload, error) {
	var violations []apierr.FieldViolation
	if job.JobType != JobTypeDeleteProject && job.JobType != JobTypeDeleteProjectAlias {
		violations = append(violations, apierr.FieldViolation{Field: "job_type", Reason: "must be project.delete or delete_project"})
	}
	if job.OrganizationID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "organization_id", Reason: "is required"})
	}
	if job.ProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "project_id", Reason: "is required"})
	}
	if job.EnvironmentID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "environment_id", Reason: "must be empty for this job type"})
	}
	if job.ServiceID != "" {
		violations = append(violations, apierr.FieldViolation{Field: "service_id", Reason: "must be empty for this job type"})
	}

	payloadOrgID := job.Payload["organization_id"]
	if payloadOrgID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "is required"})
	} else if job.OrganizationID != "" && payloadOrgID != job.OrganizationID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.organization_id", Reason: "must match the job organization_id"})
	}
	payloadProjectID := job.Payload["project_id"]
	if payloadProjectID == "" {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "is required"})
	} else if job.ProjectID != "" && payloadProjectID != job.ProjectID {
		violations = append(violations, apierr.FieldViolation{Field: "payload.project_id", Reason: "must match the job project_id"})
	}
	if len(violations) > 0 {
		return DeleteProjectPayload{}, Terminal(apierr.InvalidInput(violations...))
	}
	return DeleteProjectPayload{OrganizationID: payloadOrgID, ProjectID: payloadProjectID}, nil
}

func databaseEngineValid(engine string) bool {
	switch engine {
	case dokploy.EnginePostgres, dokploy.EngineMysql, dokploy.EngineMariadb, dokploy.EngineMongo, dokploy.EngineRedis:
		return true
	default:
		return false
	}
}

// ProvisionerConfig configures a Provisioner.
type ProvisionerConfig struct {
	Store         *store.Store
	Organizations *store.OrganizationRepository
	Projects      *store.ProjectRepository
	Environments  *store.EnvironmentRepository
	Services      *store.ServiceRepository
	Backups       *store.ServiceBackupRepository
	Domains       *store.ServiceDomainRepository
	OrgVariables  *store.OrganizationVariableRepository
	ProjVariables *store.ProjectVariableRepository
	EnvVariables  *store.EnvironmentVariableRepository
	SvcVariables  *store.ServiceVariableRepository
	Deployments   *store.DeploymentRepository
	Refs          *store.DokployRefRepository
	Mapper        *dokploy.Mapper
	Secrets       secrets.Provider
	Client        DokployClient
}

// Provisioner executes typed durable provisioning jobs.
type Provisioner struct {
	store         *store.Store
	organizations *store.OrganizationRepository
	projects      *store.ProjectRepository
	environments  *store.EnvironmentRepository
	services      *store.ServiceRepository
	backups       *store.ServiceBackupRepository
	domains       *store.ServiceDomainRepository
	orgVariables  *store.OrganizationVariableRepository
	projVariables *store.ProjectVariableRepository
	envVariables  *store.EnvironmentVariableRepository
	svcVariables  *store.ServiceVariableRepository
	deployments   *store.DeploymentRepository
	refs          *store.DokployRefRepository
	mapper        *dokploy.Mapper
	resolver      *variables.Resolver
	client        DokployClient
}

// NewProvisioner validates cfg and returns a durable job runner.
func NewProvisioner(cfg ProvisionerConfig) (*Provisioner, error) {
	var violations []apierr.FieldViolation
	if cfg.Store == nil {
		violations = append(violations, apierr.FieldViolation{Field: "store", Reason: "is required"})
	}
	if cfg.Client == nil {
		violations = append(violations, apierr.FieldViolation{Field: "client", Reason: "is required"})
	}
	if len(violations) > 0 {
		return nil, apierr.InvalidInput(violations...)
	}
	orgs := cfg.Organizations
	if orgs == nil {
		orgs = store.NewOrganizationRepository()
	}
	projects := cfg.Projects
	if projects == nil {
		projects = store.NewProjectRepository()
	}
	environments := cfg.Environments
	if environments == nil {
		environments = store.NewEnvironmentRepository()
	}
	services := cfg.Services
	if services == nil {
		services = store.NewServiceRepository()
	}
	backups := cfg.Backups
	if backups == nil {
		backups = store.NewServiceBackupRepository()
	}
	domains := cfg.Domains
	if domains == nil {
		domains = store.NewServiceDomainRepository()
	}
	orgVariables := cfg.OrgVariables
	if orgVariables == nil {
		orgVariables = store.NewOrganizationVariableRepository()
	}
	projVariables := cfg.ProjVariables
	if projVariables == nil {
		projVariables = store.NewProjectVariableRepository()
	}
	envVariables := cfg.EnvVariables
	if envVariables == nil {
		envVariables = store.NewEnvironmentVariableRepository()
	}
	svcVariables := cfg.SvcVariables
	if svcVariables == nil {
		svcVariables = store.NewServiceVariableRepository()
	}
	deployments := cfg.Deployments
	if deployments == nil {
		deployments = store.NewDeploymentRepository()
	}
	refs := cfg.Refs
	if refs == nil {
		refs = store.NewDokployRefRepository()
	}
	mapper := cfg.Mapper
	if mapper == nil {
		mapper = dokploy.NewMapper()
	}
	provider := cfg.Secrets
	if provider == nil {
		provider = secrets.NewPlaintext()
	}
	resolver, err := variables.NewResolver(provider)
	if err != nil {
		return nil, apierr.InvalidInput(apierr.FieldViolation{Field: "secrets", Reason: "must be a valid secrets provider"})
	}
	return &Provisioner{
		store:         cfg.Store,
		organizations: orgs,
		projects:      projects,
		environments:  environments,
		services:      services,
		backups:       backups,
		domains:       domains,
		orgVariables:  orgVariables,
		projVariables: projVariables,
		envVariables:  envVariables,
		svcVariables:  svcVariables,
		deployments:   deployments,
		refs:          refs,
		mapper:        mapper,
		resolver:      resolver,
		client:        cfg.Client,
	}, nil
}

// Run executes job. Unknown or permanently invalid jobs are terminal; transient
// dependency failures are returned plain so StoreClaimer can retry them.
func (p *Provisioner) Run(ctx context.Context, job store.ProvisioningJob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch job.JobType {
	case JobTypeEnsureDokployOrganization:
		return p.runEnsureDokployOrganization(ctx, job)
	case JobTypeEnsureProject:
		return p.runEnsureProject(ctx, job)
	case JobTypeEnsureEnvironment:
		return p.runEnsureEnvironment(ctx, job)
	case JobTypeEnsureApplicationService:
		return p.runEnsureApplicationService(ctx, job)
	case JobTypeEnsureComposeService:
		return p.runEnsureComposeService(ctx, job)
	case JobTypeEnsureDatabaseService:
		return p.runEnsureDatabaseService(ctx, job)
	case JobTypeDeployService, JobTypeDeployServiceAlias:
		return p.runDeployService(ctx, job)
	case JobTypeRestartService, JobTypeRestartServiceAlias:
		return p.runRestartService(ctx, job)
	case JobTypeRollbackService, JobTypeRollbackServiceAlias:
		return p.runRollbackService(ctx, job)
	case JobTypeStopService, JobTypeStopServiceAlias:
		return p.runStopService(ctx, job)
	case JobTypeStartService, JobTypeStartServiceAlias:
		return p.runStartService(ctx, job)
	case JobTypeDeleteService, JobTypeDeleteServiceAlias:
		return p.runDeleteService(ctx, job)
	case JobTypeDeleteEnvironment, JobTypeDeleteEnvironmentAlias:
		return p.runDeleteEnvironment(ctx, job)
	case JobTypeDeleteProject, JobTypeDeleteProjectAlias:
		return p.runDeleteProject(ctx, job)
	case JobTypeSyncDomains:
		return p.runSyncDomains(ctx, job)
	case JobTypeSyncVariables:
		return p.runSyncVariables(ctx, job)
	case JobTypeRunBackup:
		return p.runBackup(ctx, job)
	case JobTypeRestoreBackup:
		return p.runRestoreBackup(ctx, job)
	default:
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "job_type",
			Reason: "is not supported by this worker",
		}))
	}
}

func (p *Provisioner) runEnsureDokployOrganization(ctx context.Context, job store.ProvisioningJob) error {
	payload, err := ParseEnsureDokployOrganizationPayload(job)
	if err != nil {
		return err
	}

	org, existingID, err := p.loadOrganizationTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	orgID, parseErr := domain.ParseID(org.ID)
	if parseErr != nil {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization id",
		}))
	}
	if orgID.Kind() != domain.KindOrganization {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization id",
		}))
	}
	target, err := p.mapper.Organization(dokploy.YallaOrganization{
		ID:        orgID,
		Label:     org.DisplayName,
		DokployID: existingID,
	})
	if err != nil {
		return Terminal(err)
	}

	dokployID := target.DokployID
	if target.EnsureInput != nil {
		ensured, ensureErr := p.client.EnsureOrganization(ctx, *target.EnsureInput)
		if ensureErr != nil {
			if interrupted(ctx, ensureErr) {
				return ensureErr
			}
			if apierr.Retryable(ensureErr) {
				return ensureErr
			}
			return Terminal(ensureErr)
		}
		dokployID = ensured.ID
	}
	if dokployID == "" {
		return Terminal(apierr.Internal(errors.New("worker: ensure_dokploy_organization resolved an empty Dokploy organization id")))
	}

	return p.persistOrganizationRef(ctx, job, payload, dokployID)
}

func (p *Provisioner) runEnsureProject(ctx context.Context, job store.ProvisioningJob) error {
	payload, err := ParseEnsureProjectPayload(job)
	if err != nil {
		return err
	}

	project, parentDokployID, existingID, err := p.loadProjectTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	projectID, parseErr := domain.ParseID(project.ID)
	if parseErr != nil || projectID.Kind() != domain.KindProject {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "project_id",
			Reason: "must be a valid project id",
		}))
	}
	orgID, parseErr := domain.ParseID(project.OrganizationID)
	if parseErr != nil || orgID.Kind() != domain.KindOrganization {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization id",
		}))
	}

	in, err := p.mapper.Project(parentDokployID, dokploy.YallaProject{
		ID:             projectID,
		OrganizationID: orgID,
		Label:          project.DisplayName,
		DokployID:      existingID,
	})
	if err != nil {
		return Terminal(err)
	}

	ensured, ensureErr := p.client.EnsureProject(ctx, in)
	if ensureErr != nil {
		if interrupted(ctx, ensureErr) {
			return ensureErr
		}
		if apierr.Retryable(ensureErr) {
			return ensureErr
		}
		return Terminal(ensureErr)
	}
	if ensured.ID == "" {
		return Terminal(apierr.Internal(errors.New("worker: ensure_project resolved an empty Dokploy project id")))
	}

	return p.persistProjectRef(ctx, job, payload, ensured.ID)
}

func (p *Provisioner) runEnsureEnvironment(ctx context.Context, job store.ProvisioningJob) error {
	payload, err := ParseEnsureEnvironmentPayload(job)
	if err != nil {
		return err
	}

	env, parentDokployID, existingID, err := p.loadEnvironmentTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	envID, parseErr := domain.ParseID(env.ID)
	if parseErr != nil || envID.Kind() != domain.KindEnvironment {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "environment_id",
			Reason: "must be a valid environment id",
		}))
	}
	projectID, parseErr := domain.ParseID(env.ProjectID)
	if parseErr != nil || projectID.Kind() != domain.KindProject {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "project_id",
			Reason: "must be a valid project id",
		}))
	}

	in, err := p.mapper.Environment(parentDokployID, dokploy.YallaEnvironment{
		ID:        envID,
		ProjectID: projectID,
		Label:     env.DisplayName,
		DokployID: existingID,
	})
	if err != nil {
		return Terminal(err)
	}

	ensured, ensureErr := p.client.EnsureEnvironment(ctx, in)
	if ensureErr != nil {
		if interrupted(ctx, ensureErr) {
			return ensureErr
		}
		if apierr.Retryable(ensureErr) {
			return ensureErr
		}
		return Terminal(ensureErr)
	}
	if ensured.ID == "" {
		return Terminal(apierr.Internal(errors.New("worker: ensure_environment resolved an empty Dokploy environment id")))
	}

	return p.persistEnvironmentRef(ctx, job, payload, ensured.ID)
}

func (p *Provisioner) runEnsureApplicationService(ctx context.Context, job store.ProvisioningJob) error {
	payload, err := ParseEnsureApplicationServicePayload(job)
	if err != nil {
		return err
	}

	svc, parentDokployID, existingID, err := p.loadApplicationServiceTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	svcID, parseErr := domain.ParseID(svc.ID)
	if parseErr != nil || svcID.Kind() != domain.KindService {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must be a valid service id",
		}))
	}
	envID, parseErr := domain.ParseID(svc.EnvironmentID)
	if parseErr != nil || envID.Kind() != domain.KindEnvironment {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "environment_id",
			Reason: "must be a valid environment id",
		}))
	}

	in, err := p.mapper.Service(parentDokployID, dokploy.YallaService{
		ID:            svcID,
		EnvironmentID: envID,
		Label:         svc.DisplayName,
		Type:          dokploy.ServiceApplication,
		DokployID:     existingID,
	})
	if err != nil {
		return Terminal(err)
	}

	ensured, ensureErr := p.client.EnsureService(ctx, in)
	if ensureErr != nil {
		if interrupted(ctx, ensureErr) {
			return ensureErr
		}
		if apierr.Retryable(ensureErr) {
			return ensureErr
		}
		return Terminal(ensureErr)
	}
	if ensured.ID == "" {
		return Terminal(apierr.Internal(errors.New("worker: ensure_application_service resolved an empty Dokploy application id")))
	}

	return p.persistApplicationServiceRef(ctx, job, payload, ensured.ID)
}

func (p *Provisioner) runEnsureComposeService(ctx context.Context, job store.ProvisioningJob) error {
	payload, err := ParseEnsureComposeServicePayload(job)
	if err != nil {
		return err
	}

	svc, parentDokployID, existingID, err := p.loadComposeServiceTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	svcID, parseErr := domain.ParseID(svc.ID)
	if parseErr != nil || svcID.Kind() != domain.KindService {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must be a valid service id",
		}))
	}
	envID, parseErr := domain.ParseID(svc.EnvironmentID)
	if parseErr != nil || envID.Kind() != domain.KindEnvironment {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "environment_id",
			Reason: "must be a valid environment id",
		}))
	}

	in, err := p.mapper.Service(parentDokployID, dokploy.YallaService{
		ID:            svcID,
		EnvironmentID: envID,
		Label:         svc.DisplayName,
		Type:          dokploy.ServiceCompose,
		DokployID:     existingID,
	})
	if err != nil {
		return Terminal(err)
	}

	ensured, ensureErr := p.client.EnsureService(ctx, in)
	if ensureErr != nil {
		if interrupted(ctx, ensureErr) {
			return ensureErr
		}
		if apierr.Retryable(ensureErr) {
			return ensureErr
		}
		return Terminal(ensureErr)
	}
	if ensured.ID == "" {
		return Terminal(apierr.Internal(errors.New("worker: ensure_compose_service resolved an empty Dokploy compose id")))
	}

	return p.persistComposeServiceRef(ctx, job, payload, ensured.ID)
}

func (p *Provisioner) runEnsureDatabaseService(ctx context.Context, job store.ProvisioningJob) error {
	payload, err := ParseEnsureDatabaseServicePayload(job)
	if err != nil {
		return err
	}

	svc, parentDokployID, existingID, err := p.loadDatabaseServiceTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	svcID, parseErr := domain.ParseID(svc.ID)
	if parseErr != nil || svcID.Kind() != domain.KindService {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service_id",
			Reason: "must be a valid service id",
		}))
	}
	envID, parseErr := domain.ParseID(svc.EnvironmentID)
	if parseErr != nil || envID.Kind() != domain.KindEnvironment {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "environment_id",
			Reason: "must be a valid environment id",
		}))
	}

	in, err := p.mapper.Service(parentDokployID, dokploy.YallaService{
		ID:            svcID,
		EnvironmentID: envID,
		Label:         svc.DisplayName,
		Type:          dokploy.ServiceDatabase,
		Engine:        payload.Engine,
		DokployID:     existingID,
	})
	if err != nil {
		return Terminal(err)
	}

	ensured, ensureErr := p.client.EnsureService(ctx, in)
	if ensureErr != nil {
		if interrupted(ctx, ensureErr) {
			return ensureErr
		}
		if apierr.Retryable(ensureErr) {
			return ensureErr
		}
		return Terminal(ensureErr)
	}
	if ensured.ID == "" {
		return Terminal(apierr.Internal(errors.New("worker: ensure_database_service resolved an empty Dokploy database id")))
	}

	return p.persistDatabaseServiceRef(ctx, job, payload, ensured.ID)
}

func (p *Provisioner) runDeployService(ctx context.Context, job store.ProvisioningJob) error {
	payload, err := ParseDeployServicePayload(job)
	if err != nil {
		return err
	}

	deployment, dokployServiceID, err := p.loadDeploymentTarget(ctx, job, payload)
	if err != nil {
		return err
	}
	if deployment.Status == store.DeploymentStatusSucceeded {
		return nil
	}

	if err := p.markDeploymentRunning(ctx, job, payload); err != nil {
		return err
	}

	upstream, deployErr := p.client.DeployService(ctx, dokploy.DeployServiceInput{ServiceID: dokployServiceID})
	if deployErr != nil {
		if interrupted(ctx, deployErr) {
			return deployErr
		}
		if apierr.Retryable(deployErr) {
			return deployErr
		}
		_ = p.markDeploymentFailed(ctx, job, payload, "dokploy_error", deployErr.Error())
		return Terminal(deployErr)
	}
	if upstream.ID == "" {
		err := apierr.Internal(errors.New("worker: deploy_service resolved an empty Dokploy deployment id"))
		_ = p.markDeploymentFailed(ctx, job, payload, "internal", err.Error())
		return Terminal(err)
	}
	switch upstream.Status {
	case "", dokploy.DeploymentSucceeded:
		return p.markDeploymentSucceeded(ctx, job, payload)
	case dokploy.DeploymentPending, dokploy.DeploymentRunning:
		return apierr.DokployUnavailable(errors.New("dokploy deployment is still running"))
	case dokploy.DeploymentFailed:
		err := apierr.DokployUnavailable(errors.New("dokploy deployment failed"))
		if markErr := p.markDeploymentFailed(ctx, job, payload, "dokploy_failed", err.Error()); markErr != nil {
			return markErr
		}
		return Terminal(err)
	default:
		err := apierr.InvalidInput(apierr.FieldViolation{
			Field:  "dokploy_deployment.status",
			Reason: "must be pending, running, succeeded, or failed",
		})
		_ = p.markDeploymentFailed(ctx, job, payload, "dokploy_invalid_status", err.Error())
		return Terminal(err)
	}
}

func (p *Provisioner) runRestartService(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseRestartServicePayload(job)
	if err != nil {
		return err
	}

	dokployServiceID, err := p.loadRestartServiceTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	status, restartErr := p.client.RestartService(ctx, dokploy.RestartServiceInput{ServiceID: dokployServiceID})
	if restartErr != nil {
		if interrupted(ctx, restartErr) {
			return restartErr
		}
		if apierr.Retryable(restartErr) {
			return restartErr
		}
		return Terminal(restartErr)
	}
	if status.ServiceID == "" {
		return Terminal(apierr.Internal(errors.New("worker: restart_service resolved an empty Dokploy service id")))
	}
	return nil
}

func (p *Provisioner) runRollbackService(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseRollbackServicePayload(job)
	if err != nil {
		return err
	}

	dokployServiceID, err := p.loadRollbackServiceTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	status, rollbackErr := p.client.RollbackService(ctx, dokploy.RollbackServiceInput{ServiceID: dokployServiceID})
	if rollbackErr != nil {
		if interrupted(ctx, rollbackErr) {
			return rollbackErr
		}
		if apierr.Retryable(rollbackErr) {
			return rollbackErr
		}
		return Terminal(rollbackErr)
	}
	if status.ServiceID == "" {
		return Terminal(apierr.Internal(errors.New("worker: rollback_service resolved an empty Dokploy service id")))
	}
	return nil
}

func (p *Provisioner) runStopService(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseStopServicePayload(job)
	if err != nil {
		return err
	}

	dokployServiceID, err := p.loadStopServiceTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	status, stopErr := p.client.StopService(ctx, dokploy.StopServiceInput{ServiceID: dokployServiceID})
	if stopErr != nil {
		if interrupted(ctx, stopErr) {
			return stopErr
		}
		if apierr.Retryable(stopErr) {
			return stopErr
		}
		return Terminal(stopErr)
	}
	if status.ServiceID == "" {
		return Terminal(apierr.Internal(errors.New("worker: stop_service resolved an empty Dokploy service id")))
	}
	return nil
}

func (p *Provisioner) runStartService(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseStartServicePayload(job)
	if err != nil {
		return err
	}

	dokployServiceID, err := p.loadStartServiceTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	status, startErr := p.client.StartService(ctx, dokploy.StartServiceInput{ServiceID: dokployServiceID})
	if startErr != nil {
		if interrupted(ctx, startErr) {
			return startErr
		}
		if apierr.Retryable(startErr) {
			return startErr
		}
		return Terminal(startErr)
	}
	if status.ServiceID == "" {
		return Terminal(apierr.Internal(errors.New("worker: start_service resolved an empty Dokploy service id")))
	}
	return nil
}

func (p *Provisioner) runDeleteService(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseDeleteServicePayload(job)
	if err != nil {
		return err
	}

	dokployServiceID, err := p.loadDeleteServiceTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	removeErr := p.client.RemoveService(ctx, dokploy.RemoveServiceInput{ServiceID: dokployServiceID})
	if removeErr != nil {
		if interrupted(ctx, removeErr) {
			return removeErr
		}
		if apierr.Retryable(removeErr) {
			return removeErr
		}
		return Terminal(removeErr)
	}
	return nil
}

func (p *Provisioner) runDeleteEnvironment(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseDeleteEnvironmentPayload(job)
	if err != nil {
		return err
	}

	dokployEnvironmentID, err := p.loadDeleteEnvironmentTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	removeErr := p.client.RemoveEnvironment(ctx, dokploy.RemoveEnvironmentInput{EnvironmentID: dokployEnvironmentID})
	if removeErr != nil {
		if interrupted(ctx, removeErr) {
			return removeErr
		}
		if apierr.Retryable(removeErr) {
			return removeErr
		}
		return Terminal(removeErr)
	}
	return nil
}

func (p *Provisioner) runDeleteProject(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseDeleteProjectPayload(job)
	if err != nil {
		return err
	}

	dokployProjectID, err := p.loadDeleteProjectTarget(ctx, job, payload)
	if err != nil {
		return err
	}

	removeErr := p.client.RemoveProject(ctx, dokploy.RemoveProjectInput{ProjectID: dokployProjectID})
	if removeErr != nil {
		if interrupted(ctx, removeErr) {
			return removeErr
		}
		if apierr.Retryable(removeErr) {
			return removeErr
		}
		return Terminal(removeErr)
	}
	return nil
}

func (p *Provisioner) runSyncDomains(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseSyncDomainsPayload(job)
	if err != nil {
		return err
	}

	targets, err := p.loadSyncDomainsTarget(ctx, job, payload)
	if err != nil {
		return err
	}
	for _, target := range targets {
		ensured, ensureErr := p.client.EnsureDomain(ctx, dokploy.EnsureDomainInput{
			ExistingID: target.ExistingDokployID,
			ServiceID:  target.DokployServiceID,
			Host:       target.Domain.Hostname,
			HTTPS:      target.Domain.HTTPS,
		})
		if ensureErr != nil {
			if interrupted(ctx, ensureErr) {
				return ensureErr
			}
			if apierr.Retryable(ensureErr) {
				return ensureErr
			}
			return Terminal(ensureErr)
		}
		if ensured.ID == "" {
			return Terminal(apierr.Internal(errors.New("worker: sync_domains resolved an empty Dokploy domain id")))
		}
		if err := p.persistServiceDomainRef(ctx, job, payload, target.Domain.ID, ensured.ID); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provisioner) runSyncVariables(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseSyncVariablesPayload(job)
	if err != nil {
		return err
	}

	target, err := p.loadSyncVariablesTarget(ctx, job, payload)
	if err != nil {
		return err
	}
	syncErr := p.client.SyncVariables(ctx, dokploy.SyncVariablesInput{
		ServiceID: target.DokployServiceID,
		Type:      target.ServiceType,
		Engine:    target.Engine,
		Env:       target.Env,
	})
	if syncErr != nil {
		if interrupted(ctx, syncErr) {
			return syncErr
		}
		if apierr.Retryable(syncErr) {
			return syncErr
		}
		return Terminal(syncErr)
	}
	return nil
}

func (p *Provisioner) runBackup(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseRunBackupPayload(job)
	if err != nil {
		return err
	}

	target, err := p.loadRunBackupTarget(ctx, job, payload)
	if err != nil {
		return err
	}
	if target.Backup.Status == store.ServiceBackupStatusSucceeded {
		return nil
	}

	if err := p.markBackupRunning(ctx, payload); err != nil {
		return err
	}
	run, runErr := p.client.RunBackup(ctx, dokploy.RunBackupInput{
		ServiceID: target.DokployServiceID,
		BackupID:  payload.BackupID,
	})
	if runErr != nil {
		if interrupted(ctx, runErr) {
			return runErr
		}
		_ = p.markBackupFailed(context.WithoutCancel(ctx), payload)
		if apierr.Retryable(runErr) {
			return runErr
		}
		return Terminal(runErr)
	}
	if run.ID == "" {
		err := apierr.Internal(errors.New("worker: run_backup resolved an empty Dokploy backup run id"))
		_ = p.markBackupFailed(context.WithoutCancel(ctx), payload)
		return Terminal(err)
	}
	switch run.Status {
	case "", dokploy.DeploymentSucceeded:
		return p.markBackupSucceeded(ctx, payload)
	case dokploy.DeploymentPending, dokploy.DeploymentRunning:
		return apierr.DokployUnavailable(errors.New("dokploy backup is still running"))
	case dokploy.DeploymentFailed:
		err := apierr.DokployUnavailable(errors.New("dokploy backup failed"))
		if markErr := p.markBackupFailed(ctx, payload); markErr != nil {
			return markErr
		}
		return Terminal(err)
	default:
		err := apierr.InvalidInput(apierr.FieldViolation{
			Field:  "dokploy_backup.status",
			Reason: "must be pending, running, succeeded, or failed",
		})
		_ = p.markBackupFailed(context.WithoutCancel(ctx), payload)
		return Terminal(err)
	}
}

func (p *Provisioner) runRestoreBackup(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseRestoreBackupPayload(job)
	if err != nil {
		return err
	}

	target, err := p.loadRestoreBackupTarget(ctx, job, payload)
	if err != nil {
		return err
	}
	run, runErr := p.client.RestoreBackup(ctx, dokploy.RestoreBackupInput{
		ServiceID: target.DokployServiceID,
		BackupID:  payload.BackupID,
	})
	if runErr != nil {
		if interrupted(ctx, runErr) {
			return runErr
		}
		if apierr.Retryable(runErr) {
			return runErr
		}
		return Terminal(runErr)
	}
	if run.ID == "" {
		return Terminal(apierr.Internal(errors.New("worker: restore_backup resolved an empty Dokploy backup restore id")))
	}
	switch run.Status {
	case "", dokploy.DeploymentSucceeded:
		return nil
	case dokploy.DeploymentPending, dokploy.DeploymentRunning:
		return apierr.DokployUnavailable(errors.New("dokploy backup restore is still running"))
	case dokploy.DeploymentFailed:
		return Terminal(apierr.DokployUnavailable(errors.New("dokploy backup restore failed")))
	default:
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "dokploy_backup_restore.status",
			Reason: "must be pending, running, succeeded, or failed",
		}))
	}
}

type syncDomainTarget struct {
	Domain            store.ServiceDomain
	DokployServiceID  string
	ExistingDokployID string
}

type syncVariablesTarget struct {
	DokployServiceID string
	ServiceType      dokploy.ServiceType
	Engine           string
	Env              string
}

type runBackupTarget struct {
	Backup           store.ServiceBackup
	DokployServiceID string
}

type restoreBackupTarget struct {
	Backup           store.ServiceBackup
	DokployServiceID string
}

func (p *Provisioner) loadOrganizationTarget(ctx context.Context, job store.ProvisioningJob, payload EnsureDokployOrganizationPayload) (store.Organization, string, error) {
	var (
		org        store.Organization
		existingID string
	)
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		org, getErr = p.organizations.Get(ctx, q, payload.OrganizationID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if job.DesiredVersion > 0 && org.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(org.Version))
		}
		refs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindOrganization, payload.OrganizationID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range refs {
			if ref.DokployResource == store.DokployResourceOrganization {
				existingID = ref.DokployID
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return store.Organization{}, "", err
	}
	return org, existingID, nil
}

func (p *Provisioner) loadProjectTarget(ctx context.Context, job store.ProvisioningJob, payload EnsureProjectPayload) (store.Project, string, string, error) {
	var (
		project           store.Project
		parentDokployID   string
		existingDokployID string
	)
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		project, getErr = p.projects.Get(ctx, q, payload.OrganizationID, payload.ProjectID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if project.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the project organization_id",
			}))
		}
		if job.DesiredVersion > 0 && project.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(project.Version))
		}
		orgRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindOrganization, project.OrganizationID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range orgRefs {
			if ref.DokployResource == store.DokployResourceOrganization {
				parentDokployID = ref.DokployID
				break
			}
		}
		if parentDokployID == "" {
			return Terminal(apierr.Conflict("parent Dokploy organization mapping is required before ensuring a project"))
		}
		projectRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindProject, project.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range projectRefs {
			if ref.DokployResource == store.DokployResourceProject {
				existingDokployID = ref.DokployID
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return store.Project{}, "", "", err
	}
	return project, parentDokployID, existingDokployID, nil
}

func (p *Provisioner) loadEnvironmentTarget(ctx context.Context, job store.ProvisioningJob, payload EnsureEnvironmentPayload) (store.Environment, string, string, error) {
	var (
		env               store.Environment
		parentDokployID   string
		existingDokployID string
	)
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		env, getErr = p.environments.GetByID(ctx, q, payload.OrganizationID, payload.EnvironmentID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if env.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the environment organization_id",
			}))
		}
		if env.ProjectID != payload.ProjectID || env.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the environment project_id",
			}))
		}
		if job.DesiredVersion > 0 && env.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(env.Version))
		}
		projectRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindProject, env.ProjectID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range projectRefs {
			if ref.DokployResource == store.DokployResourceProject {
				parentDokployID = ref.DokployID
				break
			}
		}
		if parentDokployID == "" {
			return Terminal(apierr.Conflict("parent Dokploy project mapping is required before ensuring an environment"))
		}
		envRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindEnvironment, env.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range envRefs {
			if ref.DokployResource == store.DokployResourceEnvironment {
				existingDokployID = ref.DokployID
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return store.Environment{}, "", "", err
	}
	return env, parentDokployID, existingDokployID, nil
}

func (p *Provisioner) loadApplicationServiceTarget(ctx context.Context, job store.ProvisioningJob, payload EnsureApplicationServicePayload) (store.Service, string, string, error) {
	var (
		svc               store.Service
		parentDokployID   string
		existingDokployID string
	)
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		svc, getErr = p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.Kind != store.ServiceKindApplication {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "service.kind",
				Reason: "must be application for ensure_application_service",
			}))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}
		envRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindEnvironment, svc.EnvironmentID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range envRefs {
			if ref.DokployResource == store.DokployResourceEnvironment {
				parentDokployID = ref.DokployID
				break
			}
		}
		if parentDokployID == "" {
			return Terminal(apierr.Conflict("parent Dokploy environment mapping is required before ensuring an application service"))
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == store.DokployResourceApplication {
				existingDokployID = ref.DokployID
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return store.Service{}, "", "", err
	}
	return svc, parentDokployID, existingDokployID, nil
}

func (p *Provisioner) loadComposeServiceTarget(ctx context.Context, job store.ProvisioningJob, payload EnsureComposeServicePayload) (store.Service, string, string, error) {
	var (
		svc               store.Service
		parentDokployID   string
		existingDokployID string
	)
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		svc, getErr = p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.Kind != store.ServiceKindCompose {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "service.kind",
				Reason: "must be compose for ensure_compose_service",
			}))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}
		envRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindEnvironment, svc.EnvironmentID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range envRefs {
			if ref.DokployResource == store.DokployResourceEnvironment {
				parentDokployID = ref.DokployID
				break
			}
		}
		if parentDokployID == "" {
			return Terminal(apierr.Conflict("parent Dokploy environment mapping is required before ensuring a compose service"))
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == store.DokployResourceCompose {
				existingDokployID = ref.DokployID
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return store.Service{}, "", "", err
	}
	return svc, parentDokployID, existingDokployID, nil
}

func (p *Provisioner) loadDatabaseServiceTarget(ctx context.Context, job store.ProvisioningJob, payload EnsureDatabaseServicePayload) (store.Service, string, string, error) {
	var (
		svc               store.Service
		parentDokployID   string
		existingDokployID string
	)
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		svc, getErr = p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.Kind != store.ServiceKindDatabase {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "service.kind",
				Reason: "must be database for ensure_database_service",
			}))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}
		envRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindEnvironment, svc.EnvironmentID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range envRefs {
			if ref.DokployResource == store.DokployResourceEnvironment {
				parentDokployID = ref.DokployID
				break
			}
		}
		if parentDokployID == "" {
			return Terminal(apierr.Conflict("parent Dokploy environment mapping is required before ensuring a database service"))
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == store.DokployResourceDatabase {
				existingDokployID = ref.DokployID
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return store.Service{}, "", "", err
	}
	return svc, parentDokployID, existingDokployID, nil
}

func (p *Provisioner) loadRestartServiceTarget(ctx context.Context, job store.ProvisioningJob, payload RestartServicePayload) (string, error) {
	var dokployServiceID string
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		svc, getErr := p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.DeletionScheduledAt != nil {
			return Terminal(apierr.Conflict("service is scheduled for deletion and cannot be restarted"))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}

		wantResource, resourceErr := dokployResourceForServiceKind(svc.Kind, "restart_service")
		if resourceErr != nil {
			return resourceErr
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == wantResource {
				dokployServiceID = ref.DokployID
				break
			}
		}
		if dokployServiceID == "" {
			return Terminal(apierr.Conflict("service Dokploy mapping is required before restarting a service"))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return dokployServiceID, nil
}

func (p *Provisioner) loadRollbackServiceTarget(ctx context.Context, job store.ProvisioningJob, payload RollbackServicePayload) (string, error) {
	var dokployServiceID string
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		svc, getErr := p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.DeletionScheduledAt != nil {
			return Terminal(apierr.Conflict("service is scheduled for deletion and cannot be rolled back"))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}

		wantResource, resourceErr := dokployResourceForServiceKind(svc.Kind, "rollback_service")
		if resourceErr != nil {
			return resourceErr
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == wantResource {
				dokployServiceID = ref.DokployID
				break
			}
		}
		if dokployServiceID == "" {
			return Terminal(apierr.Conflict("service Dokploy mapping is required before rolling back a service"))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return dokployServiceID, nil
}

func (p *Provisioner) loadStopServiceTarget(ctx context.Context, job store.ProvisioningJob, payload StopServicePayload) (string, error) {
	var dokployServiceID string
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		svc, getErr := p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.DeletionScheduledAt != nil {
			return Terminal(apierr.Conflict("service is scheduled for deletion and cannot be stopped"))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}

		wantResource, resourceErr := dokployResourceForServiceKind(svc.Kind, "stop_service")
		if resourceErr != nil {
			return resourceErr
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == wantResource {
				dokployServiceID = ref.DokployID
				break
			}
		}
		if dokployServiceID == "" {
			return Terminal(apierr.Conflict("service Dokploy mapping is required before stopping a service"))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return dokployServiceID, nil
}

func (p *Provisioner) loadStartServiceTarget(ctx context.Context, job store.ProvisioningJob, payload StartServicePayload) (string, error) {
	var dokployServiceID string
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		svc, getErr := p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.DeletionScheduledAt != nil {
			return Terminal(apierr.Conflict("service is scheduled for deletion and cannot be started"))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}

		wantResource, resourceErr := dokployResourceForServiceKind(svc.Kind, "start_service")
		if resourceErr != nil {
			return resourceErr
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == wantResource {
				dokployServiceID = ref.DokployID
				break
			}
		}
		if dokployServiceID == "" {
			return Terminal(apierr.Conflict("service Dokploy mapping is required before starting a service"))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return dokployServiceID, nil
}

func (p *Provisioner) loadDeleteServiceTarget(ctx context.Context, job store.ProvisioningJob, payload DeleteServicePayload) (string, error) {
	var dokployServiceID string
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		svc, getErr := p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}

		wantResource, resourceErr := dokployResourceForServiceKind(svc.Kind, "delete_service")
		if resourceErr != nil {
			return resourceErr
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == wantResource {
				dokployServiceID = ref.DokployID
				break
			}
		}
		if dokployServiceID == "" {
			return Terminal(apierr.Conflict("service Dokploy mapping is required before deleting a service"))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return dokployServiceID, nil
}

func (p *Provisioner) loadDeleteEnvironmentTarget(ctx context.Context, job store.ProvisioningJob, payload DeleteEnvironmentPayload) (string, error) {
	var dokployEnvironmentID string
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		env, getErr := p.environments.GetByID(ctx, q, payload.OrganizationID, payload.EnvironmentID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if env.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the environment organization_id",
			}))
		}
		if env.ProjectID != payload.ProjectID || env.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the environment project_id",
			}))
		}
		if job.DesiredVersion > 0 && env.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(env.Version))
		}

		envRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindEnvironment, env.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range envRefs {
			if ref.DokployResource == store.DokployResourceEnvironment {
				dokployEnvironmentID = ref.DokployID
				break
			}
		}
		if dokployEnvironmentID == "" {
			return Terminal(apierr.Conflict("environment Dokploy mapping is required before deleting an environment"))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return dokployEnvironmentID, nil
}

func (p *Provisioner) loadDeleteProjectTarget(ctx context.Context, job store.ProvisioningJob, payload DeleteProjectPayload) (string, error) {
	var dokployProjectID string
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		project, getErr := p.projects.Get(ctx, q, payload.OrganizationID, payload.ProjectID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if project.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the project organization_id",
			}))
		}
		if job.DesiredVersion > 0 && project.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(project.Version))
		}

		projectRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindProject, project.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range projectRefs {
			if ref.DokployResource == store.DokployResourceProject {
				dokployProjectID = ref.DokployID
				break
			}
		}
		if dokployProjectID == "" {
			return Terminal(apierr.Conflict("project Dokploy mapping is required before deleting a project"))
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return dokployProjectID, nil
}

func (p *Provisioner) loadSyncDomainsTarget(ctx context.Context, job store.ProvisioningJob, payload SyncDomainsPayload) ([]syncDomainTarget, error) {
	var targets []syncDomainTarget
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		svc, getErr := p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.DeletionScheduledAt != nil {
			return Terminal(apierr.Conflict("service is scheduled for deletion and cannot sync domains"))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}

		wantResource, resourceErr := dokployResourceForServiceKind(svc.Kind, "sync_domains")
		if resourceErr != nil {
			return resourceErr
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		var dokployServiceID string
		for _, ref := range serviceRefs {
			if ref.DokployResource == wantResource {
				dokployServiceID = ref.DokployID
				break
			}
		}
		if dokployServiceID == "" {
			return Terminal(apierr.Conflict("service Dokploy mapping is required before syncing domains"))
		}

		domains, listErr := p.domains.ListByService(ctx, q, job.OrganizationID, svc.ID)
		if listErr != nil {
			return listErr
		}
		targets = make([]syncDomainTarget, 0, len(domains))
		for _, domainRow := range domains {
			domainRefs, refsErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindServiceDomain, domainRow.ID)
			if refsErr != nil {
				return refsErr
			}
			var existingDokployID string
			for _, ref := range domainRefs {
				if ref.DokployResource == store.DokployResourceDomain {
					existingDokployID = ref.DokployID
					break
				}
			}
			targets = append(targets, syncDomainTarget{
				Domain:            domainRow,
				DokployServiceID:  dokployServiceID,
				ExistingDokployID: existingDokployID,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return targets, nil
}

func (p *Provisioner) loadSyncVariablesTarget(ctx context.Context, job store.ProvisioningJob, payload SyncVariablesPayload) (syncVariablesTarget, error) {
	var target syncVariablesTarget
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		svc, getErr := p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.DeletionScheduledAt != nil {
			return Terminal(apierr.Conflict("service is scheduled for deletion and cannot sync variables"))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}

		wantResource, resourceErr := dokployResourceForServiceKind(svc.Kind, "sync_variables")
		if resourceErr != nil {
			return resourceErr
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == wantResource {
				target.DokployServiceID = ref.DokployID
				break
			}
		}
		if target.DokployServiceID == "" {
			return Terminal(apierr.Conflict("service Dokploy mapping is required before syncing variables"))
		}

		orgVars, err := p.orgVariables.ListByOrganization(ctx, q, payload.OrganizationID)
		if err != nil {
			return err
		}
		projectVars, err := p.projVariables.ListByProject(ctx, q, payload.OrganizationID, payload.ProjectID)
		if err != nil {
			return err
		}
		envVars, err := p.envVariables.ListByEnvironment(ctx, q, payload.OrganizationID, payload.EnvironmentID)
		if err != nil {
			return err
		}
		serviceVars, err := p.svcVariables.ListByService(ctx, q, payload.OrganizationID, payload.ServiceID)
		if err != nil {
			return err
		}
		resolved, err := p.resolver.Resolve(variables.ResolveInput{
			OrganizationVariables: scopedOrganizationVariables(orgVars),
			ProjectVariables:      scopedProjectVariables(projectVars),
			EnvironmentVariables:  scopedEnvironmentVariables(envVars),
			ServiceVariables:      scopedServiceVariables(serviceVars),
		}, variables.Options{})
		if err != nil {
			return Terminal(err)
		}

		serviceType, engine, kindErr := dokploySyncKindForService(svc, payload.Engine)
		if kindErr != nil {
			return kindErr
		}
		target.ServiceType = serviceType
		target.Engine = engine
		target.Env = renderDotenv(resolved.Variables)
		return nil
	})
	if err != nil {
		return syncVariablesTarget{}, err
	}
	return target, nil
}

func (p *Provisioner) loadRunBackupTarget(ctx context.Context, job store.ProvisioningJob, payload RunBackupPayload) (runBackupTarget, error) {
	var target runBackupTarget
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		svc, getErr := p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.DeletionScheduledAt != nil {
			return Terminal(apierr.Conflict("service is scheduled for deletion and cannot run backups"))
		}

		backup, backupErr := p.backups.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID, payload.BackupID)
		if backupErr != nil {
			return Terminal(backupErr)
		}
		if backup.ServiceID != svc.ID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.backup_id",
				Reason: "must match the service backup parent",
			}))
		}
		if !backup.Enabled {
			return Terminal(apierr.Conflict("backup is disabled and cannot be run"))
		}
		if backup.Status == store.ServiceBackupStatusRunning {
			return Terminal(apierr.Conflict("backup is already running"))
		}
		if job.DesiredVersion > 0 && backup.Status != store.ServiceBackupStatusSucceeded && backup.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(backup.Version))
		}
		target.Backup = backup
		if backup.Status == store.ServiceBackupStatusSucceeded {
			return nil
		}

		wantResource, resourceErr := dokployResourceForServiceKind(svc.Kind, "run_backup")
		if resourceErr != nil {
			return resourceErr
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == wantResource {
				target.DokployServiceID = ref.DokployID
				break
			}
		}
		if target.DokployServiceID == "" {
			return Terminal(apierr.Conflict("service Dokploy mapping is required before running a backup"))
		}
		return nil
	})
	if err != nil {
		return runBackupTarget{}, err
	}
	return target, nil
}

func (p *Provisioner) loadRestoreBackupTarget(ctx context.Context, job store.ProvisioningJob, payload RestoreBackupPayload) (restoreBackupTarget, error) {
	var target restoreBackupTarget
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		svc, getErr := p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.DeletionScheduledAt != nil {
			return Terminal(apierr.Conflict("service is scheduled for deletion and cannot restore backups"))
		}

		backup, backupErr := p.backups.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID, payload.BackupID)
		if backupErr != nil {
			return Terminal(backupErr)
		}
		if backup.ServiceID != svc.ID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.backup_id",
				Reason: "must match the service backup parent",
			}))
		}
		if !backup.Enabled {
			return Terminal(apierr.Conflict("backup is disabled and cannot be restored"))
		}
		if backup.Status != store.ServiceBackupStatusSucceeded {
			return Terminal(apierr.Conflict("backup must have a successful run before it can be restored"))
		}
		if job.DesiredVersion > 0 && backup.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(backup.Version))
		}
		target.Backup = backup

		wantResource, resourceErr := dokployResourceForServiceKind(svc.Kind, "restore_backup")
		if resourceErr != nil {
			return resourceErr
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == wantResource {
				target.DokployServiceID = ref.DokployID
				break
			}
		}
		if target.DokployServiceID == "" {
			return Terminal(apierr.Conflict("service Dokploy mapping is required before restoring a backup"))
		}
		return nil
	})
	if err != nil {
		return restoreBackupTarget{}, err
	}
	return target, nil
}

func (p *Provisioner) loadDeploymentTarget(ctx context.Context, job store.ProvisioningJob, payload DeployServicePayload) (store.Deployment, string, error) {
	var (
		deployment       store.Deployment
		dokployServiceID string
	)
	err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		deployment, getErr = p.deployments.GetByID(ctx, q, payload.OrganizationID, payload.DeploymentID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if deployment.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the deployment organization_id",
			}))
		}
		if deployment.ProjectID != payload.ProjectID || deployment.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the deployment project_id",
			}))
		}
		if deployment.EnvironmentID != payload.EnvironmentID || deployment.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the deployment environment_id",
			}))
		}
		if deployment.ServiceID != payload.ServiceID || deployment.ServiceID != job.ServiceID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.service_id",
				Reason: "must match the deployment service_id",
			}))
		}
		if deployment.Status == store.DeploymentStatusSucceeded {
			return nil
		}
		if deployment.Status != store.DeploymentStatusQueued && deployment.Status != store.DeploymentStatusRunning {
			return Terminal(apierr.Conflict("deployment is in a terminal state and cannot be deployed"))
		}
		if job.DesiredVersion > 0 && deployment.Status == store.DeploymentStatusQueued && deployment.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(deployment.Version))
		}

		svc, getErr := p.services.GetByID(ctx, q, payload.OrganizationID, payload.ServiceID)
		if getErr != nil {
			return Terminal(getErr)
		}
		if svc.ProjectID != deployment.ProjectID || svc.EnvironmentID != deployment.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.service_id",
				Reason: "must match the deployment parent service",
			}))
		}

		wantResource, resourceErr := dokployResourceForServiceKind(svc.Kind, "deploy_service")
		if resourceErr != nil {
			return resourceErr
		}
		serviceRefs, listErr := p.refs.ListByYallaResource(ctx, q, job.OrganizationID, store.YallaKindService, svc.ID)
		if listErr != nil {
			return listErr
		}
		for _, ref := range serviceRefs {
			if ref.DokployResource == wantResource {
				dokployServiceID = ref.DokployID
				break
			}
		}
		if dokployServiceID == "" {
			return Terminal(apierr.Conflict("service Dokploy mapping is required before deploying a service"))
		}
		return nil
	})
	if err != nil {
		return store.Deployment{}, "", err
	}
	return deployment, dokployServiceID, nil
}

func dokployResourceForServiceKind(kind, jobName string) (store.DokployResource, error) {
	switch kind {
	case store.ServiceKindApplication:
		return store.DokployResourceApplication, nil
	case store.ServiceKindCompose:
		return store.DokployResourceCompose, nil
	case store.ServiceKindDatabase:
		return store.DokployResourceDatabase, nil
	default:
		return "", Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service.kind",
			Reason: "must be application, compose, or database for " + jobName,
		}))
	}
}

func dokploySyncKindForService(svc store.Service, engine string) (dokploy.ServiceType, string, error) {
	switch svc.Kind {
	case store.ServiceKindApplication:
		return dokploy.ServiceApplication, "", nil
	case store.ServiceKindCompose:
		return dokploy.ServiceCompose, "", nil
	case store.ServiceKindDatabase:
		engine = strings.TrimSpace(engine)
		switch engine {
		case dokploy.EnginePostgres, dokploy.EngineMysql, dokploy.EngineMariadb, dokploy.EngineMongo, dokploy.EngineRedis:
			return dokploy.ServiceDatabase, engine, nil
		default:
			return "", "", Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.engine",
				Reason: "must be postgres, mysql, mariadb, mongo, or redis for database sync_variables",
			}))
		}
	default:
		return "", "", Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "service.kind",
			Reason: "must be application, compose, or database for sync_variables",
		}))
	}
}

func renderDotenv(vars []variables.Rendered) string {
	if len(vars) == 0 {
		return ""
	}
	copied := append([]variables.Rendered(nil), vars...)
	sort.SliceStable(copied, func(i, j int) bool {
		return copied[i].Key < copied[j].Key
	})
	var b strings.Builder
	for i, v := range copied {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(v.Key)
		b.WriteByte('=')
		b.WriteString(dotenvValue(v.Value))
	}
	return b.String()
}

func dotenvValue(value string) string {
	if value == "" {
		return ""
	}
	if strings.ContainsAny(value, "\n\r\"'\\# ") {
		return strconv.Quote(value)
	}
	return value
}

func scopedOrganizationVariables(rows []store.OrganizationVariable) []variables.ScopedVariable {
	out := make([]variables.ScopedVariable, 0, len(rows))
	for _, row := range rows {
		out = append(out, variables.ScopedVariable{
			ResourceID:       row.ID,
			Key:              row.Key,
			Value:            row.Value,
			IsSecret:         row.IsSecret,
			SecretProvider:   row.SecretProvider,
			SecretKeyID:      row.SecretKeyID,
			SecretCiphertext: append([]byte(nil), row.SecretCiphertext...),
		})
	}
	return out
}

func scopedProjectVariables(rows []store.ProjectVariable) []variables.ScopedVariable {
	out := make([]variables.ScopedVariable, 0, len(rows))
	for _, row := range rows {
		out = append(out, variables.ScopedVariable{
			ResourceID:       row.ID,
			Key:              row.Key,
			Value:            row.Value,
			IsSecret:         row.IsSecret,
			SecretProvider:   row.SecretProvider,
			SecretKeyID:      row.SecretKeyID,
			SecretCiphertext: append([]byte(nil), row.SecretCiphertext...),
		})
	}
	return out
}

func scopedEnvironmentVariables(rows []store.EnvironmentVariable) []variables.ScopedVariable {
	out := make([]variables.ScopedVariable, 0, len(rows))
	for _, row := range rows {
		out = append(out, variables.ScopedVariable{
			ResourceID:       row.ID,
			Key:              row.Key,
			Value:            row.Value,
			IsSecret:         row.IsSecret,
			SecretProvider:   row.SecretProvider,
			SecretKeyID:      row.SecretKeyID,
			SecretCiphertext: append([]byte(nil), row.SecretCiphertext...),
		})
	}
	return out
}

func scopedServiceVariables(rows []store.ServiceVariable) []variables.ScopedVariable {
	out := make([]variables.ScopedVariable, 0, len(rows))
	for _, row := range rows {
		out = append(out, variables.ScopedVariable{
			ResourceID:       row.ID,
			Key:              row.Key,
			Value:            row.Value,
			IsSecret:         row.IsSecret,
			SecretProvider:   row.SecretProvider,
			SecretKeyID:      row.SecretKeyID,
			SecretCiphertext: append([]byte(nil), row.SecretCiphertext...),
		})
	}
	return out
}

func (p *Provisioner) persistOrganizationRef(ctx context.Context, job store.ProvisioningJob, payload EnsureDokployOrganizationPayload, dokployID string) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		org, err := p.organizations.Get(ctx, tx, payload.OrganizationID)
		if err != nil {
			return Terminal(err)
		}
		if job.DesiredVersion > 0 && org.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(org.Version))
		}
		refs, err := p.refs.ListByYallaResource(ctx, tx, job.OrganizationID, store.YallaKindOrganization, payload.OrganizationID)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if ref.DokployResource == store.DokployResourceOrganization {
				return nil
			}
		}
		_, err = p.refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  job.OrganizationID,
			YallaKind:       store.YallaKindOrganization,
			YallaID:         payload.OrganizationID,
			DokployResource: store.DokployResourceOrganization,
			DokployID:       dokployID,
		})
		if err != nil {
			return err
		}
		return nil
	})
}

func (p *Provisioner) persistEnvironmentRef(ctx context.Context, job store.ProvisioningJob, payload EnsureEnvironmentPayload, dokployID string) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		env, err := p.environments.GetByID(ctx, tx, payload.OrganizationID, payload.EnvironmentID)
		if err != nil {
			return Terminal(err)
		}
		if env.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the environment organization_id",
			}))
		}
		if env.ProjectID != payload.ProjectID || env.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the environment project_id",
			}))
		}
		if job.DesiredVersion > 0 && env.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(env.Version))
		}
		refs, err := p.refs.ListByYallaResource(ctx, tx, job.OrganizationID, store.YallaKindEnvironment, payload.EnvironmentID)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if ref.DokployResource == store.DokployResourceEnvironment {
				return nil
			}
		}
		_, err = p.refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  job.OrganizationID,
			YallaKind:       store.YallaKindEnvironment,
			YallaID:         payload.EnvironmentID,
			DokployResource: store.DokployResourceEnvironment,
			DokployID:       dokployID,
		})
		if err != nil {
			return err
		}
		return nil
	})
}

func (p *Provisioner) persistApplicationServiceRef(ctx context.Context, job store.ProvisioningJob, payload EnsureApplicationServicePayload, dokployID string) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		svc, err := p.services.GetByID(ctx, tx, payload.OrganizationID, payload.ServiceID)
		if err != nil {
			return Terminal(err)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.Kind != store.ServiceKindApplication {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "service.kind",
				Reason: "must be application for ensure_application_service",
			}))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}
		refs, err := p.refs.ListByYallaResource(ctx, tx, job.OrganizationID, store.YallaKindService, payload.ServiceID)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if ref.DokployResource == store.DokployResourceApplication {
				return nil
			}
		}
		_, err = p.refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  job.OrganizationID,
			YallaKind:       store.YallaKindService,
			YallaID:         payload.ServiceID,
			DokployResource: store.DokployResourceApplication,
			DokployID:       dokployID,
		})
		if err != nil {
			return err
		}
		return nil
	})
}

func (p *Provisioner) persistComposeServiceRef(ctx context.Context, job store.ProvisioningJob, payload EnsureComposeServicePayload, dokployID string) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		svc, err := p.services.GetByID(ctx, tx, payload.OrganizationID, payload.ServiceID)
		if err != nil {
			return Terminal(err)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.Kind != store.ServiceKindCompose {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "service.kind",
				Reason: "must be compose for ensure_compose_service",
			}))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}
		refs, err := p.refs.ListByYallaResource(ctx, tx, job.OrganizationID, store.YallaKindService, payload.ServiceID)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if ref.DokployResource == store.DokployResourceCompose {
				return nil
			}
		}
		_, err = p.refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  job.OrganizationID,
			YallaKind:       store.YallaKindService,
			YallaID:         payload.ServiceID,
			DokployResource: store.DokployResourceCompose,
			DokployID:       dokployID,
		})
		if err != nil {
			return err
		}
		return nil
	})
}

func (p *Provisioner) persistDatabaseServiceRef(ctx context.Context, job store.ProvisioningJob, payload EnsureDatabaseServicePayload, dokployID string) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		svc, err := p.services.GetByID(ctx, tx, payload.OrganizationID, payload.ServiceID)
		if err != nil {
			return Terminal(err)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.Kind != store.ServiceKindDatabase {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "service.kind",
				Reason: "must be database for ensure_database_service",
			}))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}
		refs, err := p.refs.ListByYallaResource(ctx, tx, job.OrganizationID, store.YallaKindService, payload.ServiceID)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if ref.DokployResource == store.DokployResourceDatabase {
				return nil
			}
		}
		_, err = p.refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  job.OrganizationID,
			YallaKind:       store.YallaKindService,
			YallaID:         payload.ServiceID,
			DokployResource: store.DokployResourceDatabase,
			DokployID:       dokployID,
		})
		if err != nil {
			return err
		}
		return nil
	})
}

func (p *Provisioner) persistProjectRef(ctx context.Context, job store.ProvisioningJob, payload EnsureProjectPayload, dokployID string) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		project, err := p.projects.Get(ctx, tx, payload.OrganizationID, payload.ProjectID)
		if err != nil {
			return Terminal(err)
		}
		if project.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the project organization_id",
			}))
		}
		if job.DesiredVersion > 0 && project.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(project.Version))
		}
		refs, err := p.refs.ListByYallaResource(ctx, tx, job.OrganizationID, store.YallaKindProject, payload.ProjectID)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if ref.DokployResource == store.DokployResourceProject {
				return nil
			}
		}
		_, err = p.refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  job.OrganizationID,
			YallaKind:       store.YallaKindProject,
			YallaID:         payload.ProjectID,
			DokployResource: store.DokployResourceProject,
			DokployID:       dokployID,
		})
		if err != nil {
			return err
		}
		return nil
	})
}

func (p *Provisioner) persistServiceDomainRef(ctx context.Context, job store.ProvisioningJob, payload SyncDomainsPayload, domainID, dokployID string) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		svc, err := p.services.GetByID(ctx, tx, payload.OrganizationID, payload.ServiceID)
		if err != nil {
			return Terminal(err)
		}
		if svc.OrganizationID != job.OrganizationID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.organization_id",
				Reason: "must match the service organization_id",
			}))
		}
		if svc.ProjectID != payload.ProjectID || svc.ProjectID != job.ProjectID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.project_id",
				Reason: "must match the service project_id",
			}))
		}
		if svc.EnvironmentID != payload.EnvironmentID || svc.EnvironmentID != job.EnvironmentID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.environment_id",
				Reason: "must match the service environment_id",
			}))
		}
		if svc.DeletionScheduledAt != nil {
			return Terminal(apierr.Conflict("service is scheduled for deletion and cannot sync domains"))
		}
		if job.DesiredVersion > 0 && svc.Version != job.DesiredVersion {
			return Terminal(apierr.ConflictStale(svc.Version))
		}
		domainRow, err := p.domains.GetByID(ctx, tx, payload.OrganizationID, payload.ServiceID, domainID)
		if err != nil {
			return Terminal(err)
		}
		if domainRow.OrganizationID != job.OrganizationID || domainRow.ServiceID != payload.ServiceID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.service_id",
				Reason: "must match the service domain parent",
			}))
		}

		refs, err := p.refs.ListByYallaResource(ctx, tx, job.OrganizationID, store.YallaKindServiceDomain, domainID)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if ref.DokployResource == store.DokployResourceDomain {
				return nil
			}
		}
		_, err = p.refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  job.OrganizationID,
			YallaKind:       store.YallaKindServiceDomain,
			YallaID:         domainID,
			DokployResource: store.DokployResourceDomain,
			DokployID:       dokployID,
		})
		if err != nil {
			return err
		}
		return nil
	})
}

func (p *Provisioner) markDeploymentRunning(ctx context.Context, job store.ProvisioningJob, payload DeployServicePayload) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		current, err := p.deployments.GetByID(ctx, tx, job.OrganizationID, payload.DeploymentID)
		if err != nil {
			return Terminal(err)
		}
		if current.Status == store.DeploymentStatusSucceeded {
			return nil
		}
		if current.ProjectID != payload.ProjectID || current.EnvironmentID != payload.EnvironmentID || current.ServiceID != payload.ServiceID {
			return Terminal(apierr.InvalidInput(apierr.FieldViolation{
				Field:  "payload.deployment_id",
				Reason: "must match the job resource scope",
			}))
		}
		_, err = p.deployments.MarkRunning(ctx, tx, job.OrganizationID, payload.DeploymentID, job.DesiredVersion)
		if err != nil {
			if apierr.Retryable(err) {
				return err
			}
			return Terminal(err)
		}
		return nil
	})
}

func (p *Provisioner) markDeploymentSucceeded(ctx context.Context, job store.ProvisioningJob, payload DeployServicePayload) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := p.deployments.MarkSucceeded(ctx, tx, job.OrganizationID, payload.DeploymentID)
		if err != nil {
			if apierr.Retryable(err) {
				return err
			}
			return Terminal(err)
		}
		return nil
	})
}

func (p *Provisioner) markDeploymentFailed(ctx context.Context, job store.ProvisioningJob, payload DeployServicePayload, code, message string) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := p.deployments.MarkFailed(ctx, tx, job.OrganizationID, payload.DeploymentID, code, message)
		if err != nil {
			if apierr.Retryable(err) {
				return err
			}
			return Terminal(err)
		}
		return nil
	})
}

func (p *Provisioner) markBackupRunning(ctx context.Context, payload RunBackupPayload) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := p.backups.MarkRunning(ctx, tx, payload.OrganizationID, payload.ServiceID, payload.BackupID)
		if err != nil {
			if apierr.Retryable(err) {
				return err
			}
			return Terminal(err)
		}
		return nil
	})
}

func (p *Provisioner) markBackupSucceeded(ctx context.Context, payload RunBackupPayload) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := p.backups.MarkSucceeded(ctx, tx, payload.OrganizationID, payload.ServiceID, payload.BackupID)
		if err != nil {
			if apierr.Retryable(err) {
				return err
			}
			return Terminal(err)
		}
		return nil
	})
}

func (p *Provisioner) markBackupFailed(ctx context.Context, payload RunBackupPayload) error {
	return p.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		_, err := p.backups.MarkFailed(ctx, tx, payload.OrganizationID, payload.ServiceID, payload.BackupID)
		if err != nil {
			if apierr.Retryable(err) {
				return err
			}
			return Terminal(err)
		}
		return nil
	})
}
