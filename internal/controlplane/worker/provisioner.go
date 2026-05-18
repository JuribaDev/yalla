package worker

import (
	"context"
	"errors"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
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

// DokployClient is the narrow typed-client surface these worker jobs
// needs. *dokploy.Client satisfies it in production; tests can supply fakes.
type DokployClient interface {
	EnsureOrganization(context.Context, dokploy.EnsureOrganizationInput) (dokploy.Organization, error)
	EnsureProject(context.Context, dokploy.EnsureProjectInput) (dokploy.Project, error)
	EnsureEnvironment(context.Context, dokploy.EnsureEnvironmentInput) (dokploy.Environment, error)
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

// ProvisionerConfig configures a Provisioner.
type ProvisionerConfig struct {
	Store         *store.Store
	Organizations *store.OrganizationRepository
	Projects      *store.ProjectRepository
	Environments  *store.EnvironmentRepository
	Refs          *store.DokployRefRepository
	Mapper        *dokploy.Mapper
	Client        DokployClient
}

// Provisioner executes typed durable provisioning jobs.
type Provisioner struct {
	store         *store.Store
	organizations *store.OrganizationRepository
	projects      *store.ProjectRepository
	environments  *store.EnvironmentRepository
	refs          *store.DokployRefRepository
	mapper        *dokploy.Mapper
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
	refs := cfg.Refs
	if refs == nil {
		refs = store.NewDokployRefRepository()
	}
	mapper := cfg.Mapper
	if mapper == nil {
		mapper = dokploy.NewMapper()
	}
	return &Provisioner{
		store:         cfg.Store,
		organizations: orgs,
		projects:      projects,
		environments:  environments,
		refs:          refs,
		mapper:        mapper,
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
