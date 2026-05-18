package worker

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/dokploy"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/migrateimport"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
)

func (p *Provisioner) runImportDokployResource(ctx context.Context, job store.ProvisioningJob) error {
	if job.Status == store.JobStatusSucceeded {
		return nil
	}
	payload, err := ParseImportDokployResourcePayload(job)
	if err != nil {
		return err
	}
	if p.importScanner == nil {
		return Terminal(apierr.Internal(errors.New("worker: import_dokploy_resource requires an import scanner")))
	}
	org, err := p.loadImportOrganizationTarget(ctx, job, payload)
	if err != nil {
		return err
	}
	orgID, parseErr := domain.ParseID(org.ID)
	if parseErr != nil || orgID.Kind() != domain.KindOrganization {
		return Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "organization_id",
			Reason: "must be a valid organization id",
		}))
	}

	repo := &importRepository{
		store:          p.store,
		organizations:  p.organizations,
		projects:       p.projects,
		environments:   p.environments,
		services:       p.services,
		refs:           p.refs,
		organizationID: org.ID,
	}
	importer, err := migrateimport.New(migrateimport.Config{
		Scanner:    p.importScanner,
		Repository: repo,
	})
	if err != nil {
		return Terminal(err)
	}
	plan, err := importer.Plan(ctx, migrateimport.PlanInput{
		DokployOrganizationID: payload.DokployOrganizationID,
		Assignment: migrateimport.OwnerAssignment{
			DokployOrganizationID: payload.AssignmentDokployOrgID,
			YallaOrganizationID:   orgID,
		},
	})
	if err != nil {
		if interrupted(ctx, err) {
			return err
		}
		if apierr.Retryable(err) {
			return err
		}
		return Terminal(err)
	}
	result, err := importer.Apply(ctx, plan)
	if err != nil {
		if interrupted(ctx, err) {
			return err
		}
		if apierr.Retryable(err) {
			return err
		}
		return Terminal(err)
	}
	if len(result.Failures) > 0 {
		err := result.Failures[0].Err
		if apierr.Retryable(err) {
			return err
		}
		return Terminal(err)
	}
	return nil
}

func (p *Provisioner) loadImportOrganizationTarget(ctx context.Context, job store.ProvisioningJob, payload ImportDokployResourcePayload) (store.Organization, error) {
	var org store.Organization
	if err := p.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		org, getErr = p.organizations.Get(ctx, q, payload.OrganizationID)
		return getErr
	}); err != nil {
		if interrupted(ctx, err) {
			return store.Organization{}, err
		}
		if isNotFound(err) {
			return store.Organization{}, Terminal(err)
		}
		return store.Organization{}, err
	}
	if org.ID != job.OrganizationID {
		return store.Organization{}, Terminal(apierr.InvalidInput(apierr.FieldViolation{
			Field:  "payload.organization_id",
			Reason: "must match persisted organization",
		}))
	}
	if job.DesiredVersion != 0 && org.Version != job.DesiredVersion {
		return store.Organization{}, Terminal(apierr.Conflict("desired state is stale"))
	}
	return org, nil
}

type importRepository struct {
	store          *store.Store
	organizations  *store.OrganizationRepository
	projects       *store.ProjectRepository
	environments   *store.EnvironmentRepository
	services       *store.ServiceRepository
	refs           *store.DokployRefRepository
	organizationID string
}

func (r *importRepository) FindOrganization(ctx context.Context, id domain.ID) (migrateimport.ExistingOrganization, error) {
	if string(id) != r.organizationID {
		return migrateimport.ExistingOrganization{}, apierr.NotFound("organization", string(id))
	}
	var org store.Organization
	err := r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var getErr error
		org, getErr = r.organizations.Get(ctx, q, string(id))
		return getErr
	})
	if err != nil {
		return migrateimport.ExistingOrganization{}, err
	}
	return migrateimport.ExistingOrganization{ID: domain.ID(org.ID)}, nil
}

func (r *importRepository) FindProjectByDokployID(ctx context.Context, organizationID domain.ID, dokployID string) (migrateimport.ExistingProject, error) {
	if string(organizationID) != r.organizationID {
		return migrateimport.ExistingProject{}, apierr.NotFound("project", dokployID)
	}
	var ref store.DokployRef
	var project store.Project
	err := r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		ref, err = r.refs.GetByDokployTarget(ctx, q, r.organizationID, store.DokployResourceProject, dokployID)
		if err != nil {
			return err
		}
		project, err = r.projects.Get(ctx, q, r.organizationID, ref.YallaID)
		return err
	})
	if err != nil {
		return migrateimport.ExistingProject{}, err
	}
	return migrateimport.ExistingProject{ID: domain.ID(project.ID), DokployID: ref.DokployID}, nil
}

func (r *importRepository) FindProjectBySlug(ctx context.Context, organizationID domain.ID, slug string) (migrateimport.ExistingProject, error) {
	if string(organizationID) != r.organizationID {
		return migrateimport.ExistingProject{}, apierr.NotFound("project", slug)
	}
	var projects []store.Project
	err := r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		projects, err = r.projects.ListByOrganization(ctx, q, r.organizationID)
		return err
	})
	if err != nil {
		return migrateimport.ExistingProject{}, err
	}
	for _, project := range projects {
		if project.Slug == slug {
			return migrateimport.ExistingProject{
				ID:        domain.ID(project.ID),
				DokployID: r.firstDokployID(ctx, store.YallaKindProject, project.ID, store.DokployResourceProject),
			}, nil
		}
	}
	return migrateimport.ExistingProject{}, apierr.NotFound("project", slug)
}

func (r *importRepository) CreateProject(ctx context.Context, in migrateimport.CreateProjectInput) (domain.ID, error) {
	if string(in.OrganizationID) != r.organizationID {
		return "", apierr.NotFound("organization", string(in.OrganizationID))
	}
	id, err := domain.NewID(domain.KindProject)
	if err != nil {
		return "", apierr.Internal(err)
	}
	err = r.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		created, err := r.projects.Insert(ctx, tx, store.Project{
			ID:             id.String(),
			OrganizationID: r.organizationID,
			Slug:           in.Slug,
			DisplayName:    in.DisplayName,
		})
		if err != nil {
			return err
		}
		_, err = r.refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  r.organizationID,
			YallaKind:       store.YallaKindProject,
			YallaID:         created.ID,
			DokployResource: store.DokployResourceProject,
			DokployID:       in.DokployID,
		})
		return err
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func (r *importRepository) FindEnvironmentByDokployID(ctx context.Context, projectID domain.ID, dokployID string) (migrateimport.ExistingEnvironment, error) {
	var ref store.DokployRef
	var env store.Environment
	err := r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		ref, err = r.refs.GetByDokployTarget(ctx, q, r.organizationID, store.DokployResourceEnvironment, dokployID)
		if err != nil {
			return err
		}
		env, err = r.environments.GetByID(ctx, q, r.organizationID, ref.YallaID)
		if err != nil {
			return err
		}
		if env.ProjectID != string(projectID) {
			return apierr.NotFound("environment", dokployID)
		}
		return nil
	})
	if err != nil {
		return migrateimport.ExistingEnvironment{}, err
	}
	return migrateimport.ExistingEnvironment{ID: domain.ID(env.ID), ProjectID: domain.ID(env.ProjectID), DokployID: ref.DokployID}, nil
}

func (r *importRepository) FindEnvironmentBySlug(ctx context.Context, projectID domain.ID, slug string) (migrateimport.ExistingEnvironment, error) {
	var envs []store.Environment
	err := r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		envs, err = r.environments.ListByProject(ctx, q, r.organizationID, string(projectID))
		return err
	})
	if err != nil {
		return migrateimport.ExistingEnvironment{}, err
	}
	for _, env := range envs {
		if env.Slug == slug {
			return migrateimport.ExistingEnvironment{
				ID:        domain.ID(env.ID),
				ProjectID: domain.ID(env.ProjectID),
				DokployID: r.firstDokployID(ctx, store.YallaKindEnvironment, env.ID, store.DokployResourceEnvironment),
			}, nil
		}
	}
	return migrateimport.ExistingEnvironment{}, apierr.NotFound("environment", slug)
}

func (r *importRepository) CreateEnvironment(ctx context.Context, in migrateimport.CreateEnvironmentInput) (domain.ID, error) {
	var project store.Project
	id, err := domain.NewID(domain.KindEnvironment)
	if err != nil {
		return "", apierr.Internal(err)
	}
	err = r.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		project, err = r.projects.Get(ctx, tx, r.organizationID, string(in.ProjectID))
		if err != nil {
			return err
		}
		created, err := r.environments.Insert(ctx, tx, store.Environment{
			ID:             id.String(),
			OrganizationID: r.organizationID,
			ProjectID:      project.ID,
			Slug:           in.Slug,
			DisplayName:    in.DisplayName,
			Kind:           store.EnvironmentKindStandard,
		})
		if err != nil {
			return err
		}
		_, err = r.refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  r.organizationID,
			YallaKind:       store.YallaKindEnvironment,
			YallaID:         created.ID,
			DokployResource: store.DokployResourceEnvironment,
			DokployID:       in.DokployID,
		})
		return err
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func (r *importRepository) FindServiceByDokployID(ctx context.Context, environmentID domain.ID, dokployID string) (migrateimport.ExistingService, error) {
	var lastErr error
	for _, resource := range []store.DokployResource{store.DokployResourceApplication, store.DokployResourceCompose, store.DokployResourceDatabase} {
		var ref store.DokployRef
		var svc store.Service
		err := r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
			var err error
			ref, err = r.refs.GetByDokployTarget(ctx, q, r.organizationID, resource, dokployID)
			if err != nil {
				return err
			}
			svc, err = r.services.GetByID(ctx, q, r.organizationID, ref.YallaID)
			if err != nil {
				return err
			}
			if svc.EnvironmentID != string(environmentID) {
				return apierr.NotFound("service", dokployID)
			}
			return nil
		})
		if err == nil {
			return migrateimport.ExistingService{ID: domain.ID(svc.ID), EnvironmentID: domain.ID(svc.EnvironmentID), DokployID: ref.DokployID}, nil
		}
		lastErr = err
		if !isNotFound(err) {
			return migrateimport.ExistingService{}, err
		}
	}
	if lastErr != nil {
		return migrateimport.ExistingService{}, lastErr
	}
	return migrateimport.ExistingService{}, apierr.NotFound("service", dokployID)
}

func (r *importRepository) FindServiceBySlug(ctx context.Context, environmentID domain.ID, slug string) (migrateimport.ExistingService, error) {
	var services []store.Service
	err := r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		services, err = r.services.ListByEnvironment(ctx, q, r.organizationID, string(environmentID))
		return err
	})
	if err != nil {
		return migrateimport.ExistingService{}, err
	}
	for _, svc := range services {
		if svc.Slug == slug {
			return migrateimport.ExistingService{
				ID:            domain.ID(svc.ID),
				EnvironmentID: domain.ID(svc.EnvironmentID),
				DokployID:     r.firstDokployID(ctx, store.YallaKindService, svc.ID, importDokployResourceForServiceKind(svc.Kind)),
			}, nil
		}
	}
	return migrateimport.ExistingService{}, apierr.NotFound("service", slug)
}

func (r *importRepository) CreateService(ctx context.Context, in migrateimport.CreateServiceInput) (domain.ID, error) {
	kind, resource, err := serviceImportKind(in.Type)
	if err != nil {
		return "", err
	}
	id, err := domain.NewID(domain.KindService)
	if err != nil {
		return "", apierr.Internal(err)
	}
	err = r.store.Write(ctx, func(ctx context.Context, tx *store.Tx) error {
		env, err := r.environments.GetByID(ctx, tx, r.organizationID, string(in.EnvironmentID))
		if err != nil {
			return err
		}
		created, err := r.services.Insert(ctx, tx, store.Service{
			ID:             id.String(),
			OrganizationID: r.organizationID,
			ProjectID:      env.ProjectID,
			EnvironmentID:  env.ID,
			Slug:           in.Slug,
			DisplayName:    in.DisplayName,
			Kind:           kind,
		})
		if err != nil {
			return err
		}
		_, err = r.refs.Insert(ctx, tx, store.DokployRef{
			OrganizationID:  r.organizationID,
			YallaKind:       store.YallaKindService,
			YallaID:         created.ID,
			DokployResource: resource,
			DokployID:       in.DokployID,
		})
		return err
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func (r *importRepository) firstDokployID(ctx context.Context, kind store.YallaKind, yallaID string, resource store.DokployResource) string {
	var refs []store.DokployRef
	_ = r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		var err error
		refs, err = r.refs.ListByYallaResource(ctx, q, r.organizationID, kind, yallaID)
		return err
	})
	for _, ref := range refs {
		if ref.DokployResource == resource {
			return ref.DokployID
		}
	}
	return ""
}

func serviceImportKind(raw string) (string, store.DokployResource, error) {
	switch strings.TrimSpace(raw) {
	case string(dokploy.ServiceApplication):
		return store.ServiceKindApplication, store.DokployResourceApplication, nil
	case string(dokploy.ServiceCompose):
		return store.ServiceKindCompose, store.DokployResourceCompose, nil
	case string(dokploy.ServiceDatabase):
		return store.ServiceKindDatabase, store.DokployResourceDatabase, nil
	default:
		return "", "", apierr.InvalidInput(apierr.FieldViolation{Field: "service_type", Reason: "must be application, compose, or database"})
	}
}

func importDokployResourceForServiceKind(kind string) store.DokployResource {
	switch kind {
	case store.ServiceKindCompose:
		return store.DokployResourceCompose
	case store.ServiceKindDatabase:
		return store.DokployResourceDatabase
	default:
		return store.DokployResourceApplication
	}
}
