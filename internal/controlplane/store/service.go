package store

import (
	"context"
	"errors"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// Service is the source-of-truth representation of a row in the
// services table. A service belongs to exactly one environment and
// inherits the environment's project and organization through the
// composite (organization_id, project_id, environment_id) foreign key
// declared in migration 0002 — a child can never cross the tenant
// boundary at the database, regardless of application bugs.
//
// Kind mirrors Dokploy's service taxonomy ("application", "database",
// "compose"). The CHECK constraint in 0002 keeps the value in that
// closed set so the application layer can rely on it without a runtime
// validation pass.
//
// Version is the database-owned optimistic-concurrency token: it
// starts at 1 on INSERT and is bumped by the services_bump_version
// trigger from migration 0011 on every UPDATE. Callers must not mutate
// it; the trigger is the only writer.
//
// The struct carries no credential material — the services table
// stores only structural identifiers, the kind taxonomy, and lifecycle
// timestamps. Service-scoped variables, deployments, and other secret-
// bearing resources live in their own dedicated migrations and are
// redacted wherever they are handled.
type Service struct {
	ID             string
	OrganizationID string
	ProjectID      string
	EnvironmentID  string
	Slug           string
	DisplayName    string
	Kind           string
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// serviceColumns is the SELECT projection used by every read in this
// repository. Keeping it as a single string keeps the column list in
// lockstep with scanService.
const serviceColumns = `id, organization_id, project_id, environment_id, slug, display_name, kind, version, created_at, updated_at`

// serviceListMaxRows caps how many rows a single ListByEnvironment
// call returns. An unbounded query can never be issued by accident; an
// HTTP layer that wants pagination later will add an explicit offset
// or cursor parameter rather than relax this ceiling.
const serviceListMaxRows = 500

// ServiceRepository is the persistence half of the services surface.
// Every read is tenant-scoped: the organization_id and environment_id
// legs of the predicate are non-optional, so a missing or cross-tenant
// id simply matches no rows and yields an empty list — never another
// tenant's services. The repository is stateless; the constructor
// exists so call sites depend on a value rather than a bare struct
// literal.
type ServiceRepository struct{}

// NewServiceRepository builds a stateless ServiceRepository.
func NewServiceRepository() *ServiceRepository { return &ServiceRepository{} }

// ListByEnvironment returns every service owned by (organizationID,
// environmentID), in deterministic (slug ASC, id ASC) order so an
// agent observing the response sees a stable ordering across calls.
// The read is tenant-scoped at the SQL predicate, so a cross-tenant
// (organization, environment) tuple matches no rows. A raw driver
// error surfaces as the typed apierr.StoreUnavailable — the cause is
// wrapped for logging only, never leaked into the customer-facing
// message.
//
// This method does NOT verify the environment exists; callers that
// need to distinguish "environment missing" from "environment has no
// services" must Get the environment first (the ServiceReader adapter
// does so in the same short-lived transaction).
func (r *ServiceRepository) ListByEnvironment(ctx context.Context, q Querier, organizationID, environmentID string) ([]Service, error) {
	rows, err := q.Query(ctx,
		`SELECT `+serviceColumns+`
		   FROM services
		  WHERE organization_id = $1 AND environment_id = $2
		  ORDER BY slug ASC, id ASC
		  LIMIT $3`,
		organizationID, environmentID, serviceListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]Service, 0)
	for rows.Next() {
		s, scanErr := scanService(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// Insert writes a new services row inside the supplied transaction
// and returns the persisted row, in serviceColumns order, so the
// caller sees the database-assigned timestamps and the initial
// version (1) without re-reading. Calling Insert with a nil
// transaction is a wiring error and is reported as a typed
// apierr.Internal so the bug can never silently degrade into a
// "succeeded with no audit trail" failure mode.
//
// The schema enforces the tenant invariant — the composite foreign
// key (organization_id, project_id, environment_id) references
// environments (organization_id, project_id, id) — so a service whose
// organization_id, project_id, or environment_id does not match its
// parent environment's row is rejected at the database before it can
// be persisted, regardless of application bugs. The kind CHECK in
// migration 0002 confines kind to the closed Dokploy taxonomy
// ("application", "database", "compose"), and a slug already taken by
// another service in the same environment violates UNIQUE
// (environment_id, slug) and surfaces through mapWriteError as a
// deterministic apierr.Conflict — never a 500 leaking the constraint
// name.
func (r *ServiceRepository) Insert(ctx context.Context, tx *Tx, s Service) (Service, error) {
	if tx == nil {
		return Service{}, apierr.Internal(errors.New("store: ServiceRepository.Insert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO services (id, organization_id, project_id, environment_id, slug, display_name, kind)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING `+serviceColumns,
		s.ID, s.OrganizationID, s.ProjectID, s.EnvironmentID, s.Slug, s.DisplayName, s.Kind)
	created, err := scanService(row)
	if err != nil {
		return Service{}, mapWriteError(err, "a service with this slug already exists in the environment")
	}
	return created, nil
}

// scanService scans one services row in serviceColumns order.
func scanService(row scanRow) (Service, error) {
	var s Service
	if err := row.Scan(
		&s.ID,
		&s.OrganizationID,
		&s.ProjectID,
		&s.EnvironmentID,
		&s.Slug,
		&s.DisplayName,
		&s.Kind,
		&s.Version,
		&s.CreatedAt,
		&s.UpdatedAt,
	); err != nil {
		return Service{}, err
	}
	return s, nil
}

// ServiceReader is the store-backed read adapter for the services
// surface: the persistence surface the httpapi layer needs to render
// GET /v1/environments/{environment_id}/services. It mirrors
// EnvironmentReader — it composes EnvironmentRepository and
// ServiceRepository through a short-lived read-only transaction
// (Store.Read), so the tenant-scoping guarantees the repositories
// prove in their integration tests are inherited for free, and every
// cross-tenant or unknown environment_id is rejected as a typed
// apierr.NotFound at the parent existence check before any service
// row is scanned.
type ServiceReader struct {
	store        *Store
	environments *EnvironmentRepository
	services     *ServiceRepository
}

// NewServiceReader builds a ServiceReader over store. It returns an
// error rather than panicking on a nil store so the caller (the API
// boot path) can surface the wiring mistake as a typed startup failure.
func NewServiceReader(s *Store) (*ServiceReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &ServiceReader{
		store:        s,
		environments: NewEnvironmentRepository(),
		services:     NewServiceRepository(),
	}, nil
}

// ListEnvironmentServices returns every service owned by
// (organizationID, environmentID), in deterministic (slug ASC, id
// ASC) order. The adapter performs the parent environment existence
// check inside the same short-lived read-only transaction as the
// service list query so a cross-tenant or unknown environment_id is
// reported as a typed apierr.NotFound at the environment boundary —
// never as an empty list, which would invite an agent to believe the
// environment exists with no services. An environment that exists but
// has no services yields an empty slice and a nil error.
func (r *ServiceReader) ListEnvironmentServices(ctx context.Context, organizationID, environmentID string) ([]Service, error) {
	var services []Service
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, getErr := r.environments.GetByID(ctx, q, organizationID, environmentID); getErr != nil {
			return getErr
		}
		list, listErr := r.services.ListByEnvironment(ctx, q, organizationID, environmentID)
		if listErr != nil {
			return listErr
		}
		services = list
		return nil
	})
	if err != nil {
		return nil, err
	}
	return services, nil
}
