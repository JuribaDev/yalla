package store

import (
	"context"
	"errors"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// DriftFindingReader is the store-backed adapter for the admin drift listing
// endpoint. It verifies the target organization and any supplied descendant
// filters inside the same read transaction before listing findings, so an
// unknown or cross-tenant resource id collapses to a deterministic NotFound
// instead of an ambiguous empty page.
type DriftFindingReader struct {
	store        *Store
	findings     *DriftFindingRepository
	orgs         *OrganizationRepository
	projects     *ProjectRepository
	environments *EnvironmentRepository
	services     *ServiceRepository
}

// NewDriftFindingReader builds a DriftFindingReader over store.
func NewDriftFindingReader(s *Store) (*DriftFindingReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &DriftFindingReader{
		store:        s,
		findings:     NewDriftFindingRepository(),
		orgs:         NewOrganizationRepository(),
		projects:     NewProjectRepository(),
		environments: NewEnvironmentRepository(),
		services:     NewServiceRepository(),
	}, nil
}

// ListDriftFindings returns drift findings visible within organizationID and
// matching query. Parent filters are checked before the list so a typo in a
// scoped request is visible as NotFound, not a misleading empty list.
func (r *DriftFindingReader) ListDriftFindings(ctx context.Context, organizationID string, query DriftFindingListQuery) ([]DriftFinding, error) {
	var out []DriftFinding
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, err := r.orgs.Get(ctx, q, organizationID); err != nil {
			return err
		}
		if query.ProjectID != "" {
			if _, err := r.projects.Get(ctx, q, organizationID, query.ProjectID); err != nil {
				return err
			}
		}
		if query.EnvironmentID != "" {
			env, err := r.environments.GetByID(ctx, q, organizationID, query.EnvironmentID)
			if err != nil {
				return err
			}
			if query.ProjectID != "" && env.ProjectID != query.ProjectID {
				return apierr.NotFound("environment", query.EnvironmentID)
			}
		}
		if query.ServiceID != "" {
			svc, err := r.services.GetByID(ctx, q, organizationID, query.ServiceID)
			if err != nil {
				return err
			}
			if query.ProjectID != "" && svc.ProjectID != query.ProjectID {
				return apierr.NotFound("service", query.ServiceID)
			}
			if query.EnvironmentID != "" && svc.EnvironmentID != query.EnvironmentID {
				return apierr.NotFound("service", query.ServiceID)
			}
		}
		list, err := r.findings.List(ctx, q, organizationID, query)
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
