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

// DokployOrganizationClient is the narrow typed-client surface this worker job
// needs. *dokploy.Client satisfies it in production; tests can supply fakes.
type DokployOrganizationClient interface {
	EnsureOrganization(context.Context, dokploy.EnsureOrganizationInput) (dokploy.Organization, error)
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

// ProvisionerConfig configures a Provisioner.
type ProvisionerConfig struct {
	Store         *store.Store
	Organizations *store.OrganizationRepository
	Refs          *store.DokployRefRepository
	Mapper        *dokploy.Mapper
	Client        DokployOrganizationClient
}

// Provisioner executes typed durable provisioning jobs.
type Provisioner struct {
	store         *store.Store
	organizations *store.OrganizationRepository
	refs          *store.DokployRefRepository
	mapper        *dokploy.Mapper
	client        DokployOrganizationClient
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
