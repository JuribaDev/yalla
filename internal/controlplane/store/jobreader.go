package store

import (
	"context"
	"errors"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// JobReader is the store-backed read adapter for the customer-facing
// provisioning-jobs list surface. It verifies any supplied parent filter inside
// the caller's tenant before listing jobs, so an unknown or cross-tenant
// project/environment/service id is a deterministic NotFound instead of an
// ambiguous empty list.
type JobReader struct {
	store        *Store
	jobs         *JobRepository
	projects     *ProjectRepository
	environments *EnvironmentRepository
	services     *ServiceRepository
}

// NewJobReader builds a JobReader over store.
func NewJobReader(s *Store) (*JobReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &JobReader{
		store:        s,
		jobs:         NewJobRepository(),
		projects:     NewProjectRepository(),
		environments: NewEnvironmentRepository(),
		services:     NewServiceRepository(),
	}, nil
}

// ListJobs returns the provisioning jobs visible under the supplied tenant and
// optional resource filters.
func (r *JobReader) ListJobs(ctx context.Context, in ListProvisioningJobsInput) ([]ProvisioningJob, error) {
	var out []ProvisioningJob
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if in.ProjectID != "" {
			if _, err := r.projects.Get(ctx, q, in.OrganizationID, in.ProjectID); err != nil {
				return err
			}
		}
		if in.EnvironmentID != "" {
			env, err := r.environments.GetByID(ctx, q, in.OrganizationID, in.EnvironmentID)
			if err != nil {
				return err
			}
			if in.ProjectID != "" && env.ProjectID != in.ProjectID {
				return apierr.NotFound("environment", in.EnvironmentID)
			}
		}
		if in.ServiceID != "" {
			svc, err := r.services.GetByID(ctx, q, in.OrganizationID, in.ServiceID)
			if err != nil {
				return err
			}
			if in.ProjectID != "" && svc.ProjectID != in.ProjectID {
				return apierr.NotFound("service", in.ServiceID)
			}
			if in.EnvironmentID != "" && svc.EnvironmentID != in.EnvironmentID {
				return apierr.NotFound("service", in.ServiceID)
			}
		}
		list, err := r.jobs.List(ctx, q, in)
		if err != nil {
			return err
		}
		out = list
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
