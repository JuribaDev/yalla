package metering

import (
	"context"
	"errors"
	"strings"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/store"
	"github.com/jackc/pgx/v5"
)

// StoreTraefikResolver resolves Traefik samples against Yalla's source of
// truth. A service must both exist in services and have a service-level
// dokploy_refs mapping before it is considered attributable.
type StoreTraefikResolver struct {
	store *store.Store
}

// NewStoreTraefikResolver builds the Postgres-backed Traefik resolver.
func NewStoreTraefikResolver(s *store.Store) (*StoreTraefikResolver, error) {
	if s == nil {
		return nil, errors.New("metering: nil store")
	}
	return &StoreTraefikResolver{store: s}, nil
}

// ResolveTraefikService resolves one extracted service id to tenant scope.
func (r *StoreTraefikResolver) ResolveTraefikService(ctx context.Context, in TraefikResolveInput) (TraefikResourceAttribution, error) {
	if r == nil || r.store == nil {
		return TraefikResourceAttribution{}, errors.New("metering: nil StoreTraefikResolver")
	}
	serviceID := strings.TrimSpace(in.ServiceID)
	if serviceID == "" {
		return TraefikResourceAttribution{}, ErrTraefikUnmanagedResource
	}

	var attr TraefikResourceAttribution
	err := r.store.Read(ctx, func(ctx context.Context, q store.Querier) error {
		row := q.QueryRow(ctx,
			`SELECT s.organization_id, s.project_id, s.environment_id, s.id, s.status
			   FROM services s
			   JOIN dokploy_refs dr
			     ON dr.organization_id = s.organization_id
			    AND dr.yalla_kind = 'service'
			    AND dr.yalla_id = s.id
			    AND dr.dokploy_resource IN ('application', 'compose', 'database')
			  WHERE s.id = $1
			  ORDER BY dr.id ASC
			  LIMIT 1`,
			serviceID)
		var status string
		if err := row.Scan(&attr.OrganizationID, &attr.ProjectID, &attr.EnvironmentID, &attr.ServiceID, &status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrTraefikAttributionNotFound
			}
			return apierr.StoreUnavailable(err)
		}
		attr.Deleted = store.ServiceStatus(status) == store.ServiceStatusDeleted
		attr.Source, attr.Confidence = resolveStoreAttributionSource(in)
		return nil
	})
	if err != nil {
		return TraefikResourceAttribution{}, err
	}
	return attr, nil
}

func resolveStoreAttributionSource(in TraefikResolveInput) (TraefikAttributionSource, TraefikAttributionConfidence) {
	serviceID := strings.TrimSpace(in.ServiceID)
	for _, key := range []string{"yalla_service_id", "yalla.service.id", "service_id", "com.yalla.service_id"} {
		if normalizeServiceID(in.Labels[key]) == serviceID {
			return TraefikAttributionSourceLabel, TraefikAttributionConfidenceHigh
		}
	}
	return TraefikAttributionSourceName, TraefikAttributionConfidenceMedium
}
