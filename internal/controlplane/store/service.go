package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
)

// ServiceStatus is the closed-set lifecycle the services table permits.
// The service state machine records customer/worker intent for the service row
// itself; Dokploy runtime state remains a separate upstream concern.
type ServiceStatus string

const (
	// ServiceStatusPending records a service created before provisioning has converged.
	ServiceStatusPending ServiceStatus = "pending"
	// ServiceStatusActive records the normal live mutable service lifecycle state.
	ServiceStatusActive ServiceStatus = "active"
	// ServiceStatusSuspended records a reversible hold on a service.
	ServiceStatusSuspended ServiceStatus = "suspended"
	// ServiceStatusDeleting records accepted teardown intent.
	ServiceStatusDeleting ServiceStatus = "deleting"
	// ServiceStatusDeleted records the terminal service lifecycle state.
	ServiceStatusDeleted ServiceStatus = "deleted"
)

func (s ServiceStatus) String() string { return string(s) }

// serviceTransitions is the documented service lifecycle table. Existing rows
// default to active. Pending is reserved for services created before their
// first successful provisioning pass, active is the normal mutable state,
// suspended is a reversible operator/customer hold, deleting is teardown
// intent, and deleted is terminal.
var serviceTransitions = map[ServiceStatus]map[ServiceStatus]struct{}{
	ServiceStatusPending: {
		ServiceStatusActive:   {},
		ServiceStatusDeleting: {},
	},
	ServiceStatusActive: {
		ServiceStatusSuspended: {},
		ServiceStatusDeleting:  {},
	},
	ServiceStatusSuspended: {
		ServiceStatusActive:   {},
		ServiceStatusDeleting: {},
	},
	ServiceStatusDeleting: {
		ServiceStatusActive:  {},
		ServiceStatusDeleted: {},
	},
	ServiceStatusDeleted: {},
}

// CanTransitionTo reports whether the service state machine permits a status
// change from s to next. Repository mutations call this before touching the
// services row.
func (s ServiceStatus) CanTransitionTo(next ServiceStatus) bool {
	allowed, ok := serviceTransitions[s]
	if !ok {
		return false
	}
	_, ok = allowed[next]
	return ok
}

func (s ServiceStatus) serviceEventType() ServiceEventType {
	switch s {
	case ServiceStatusPending:
		return ServiceEventTypePending
	case ServiceStatusActive:
		return ServiceEventTypeActive
	case ServiceStatusSuspended:
		return ServiceEventTypeSuspended
	case ServiceStatusDeleting:
		return ServiceEventTypeDeleting
	case ServiceStatusDeleted:
		return ServiceEventTypeDeleted
	default:
		return ""
	}
}

// ServiceTransition is the audited state-machine mutation input for a services
// row. Actor and request fields are persisted into the service event emitted
// atomically with the status update.
type ServiceTransition struct {
	OrganizationID  string
	ServiceID       string
	NextStatus      ServiceStatus
	ExpectedVersion *int64
	ActorID         string
	ActorKind       string
	RequestID       string
	CorrelationID   string
	Reason          string
}

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
// DeletionScheduledAt is the soft-delete marker added by migration
// 0020 (mirroring environments.deletion_scheduled_at from 0016): NULL
// means the service is live, a non-NULL value means it is scheduled
// for teardown by a later worker job. The store-layer service refuses
// a second scheduling request as a typed apierr.Conflict rather than
// moving the timestamp.
//
// The struct carries no credential material — the services table
// stores only structural identifiers, the kind taxonomy, and lifecycle
// timestamps. Service-scoped variables, deployments, and other secret-
// bearing resources live in their own dedicated migrations and are
// redacted wherever they are handled.
type Service struct {
	ID                  string
	OrganizationID      string
	ProjectID           string
	EnvironmentID       string
	Slug                string
	DisplayName         string
	Kind                string
	Status              ServiceStatus
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DeletionScheduledAt *time.Time
}

// serviceColumns is the SELECT projection used by every read in this
// repository. Keeping it as a single string keeps the column list in
// lockstep with scanService.
const serviceColumns = `id, organization_id, project_id, environment_id, slug, display_name, kind, status, version, created_at, updated_at, deletion_scheduled_at`

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

// GetByID returns the single services row identified by
// (organizationID, serviceID), tenant-scoped at the SQL predicate. The
// composite predicate is non-optional: a missing or cross-tenant
// organizationID matches no row even when a service with the same id
// exists in another tenant, so the response is never an oracle that
// reveals another organization's service ids. A row that does not
// exist — whether because it was never created, was destructively torn
// down, or simply belongs to another tenant — surfaces as the same
// typed apierr.NotFound, never as a 500 leaking the cause; the
// not-found payload names only the service_id the caller already
// supplied. A raw driver error surfaces as the typed
// apierr.StoreUnavailable — the cause is wrapped for logging only,
// never leaked into the customer-facing message.
//
// GetByID is the persistence half of GET /v1/services/{service_id};
// the ServiceReader adapter composes it inside a short-lived read-only
// transaction so the tenant boundary the predicate proves at the
// database is inherited by the HTTP boundary for free.
func (r *ServiceRepository) GetByID(ctx context.Context, q Querier, organizationID, serviceID string) (Service, error) {
	row := q.QueryRow(ctx,
		`SELECT `+serviceColumns+`
		   FROM services
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, serviceID)
	s, err := scanService(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Service{}, apierr.NotFound("service", serviceID)
	}
	if err != nil {
		return Service{}, apierr.StoreUnavailable(err)
	}
	return s, nil
}

// Update rewrites a services row in place — slug and display_name are
// the only updatable columns; kind is taxonomy and cannot be changed
// once Dokploy has been told what to provision, and the parent
// (organization_id, project_id, environment_id) tuple is structural
// identity and cannot be reparented through this endpoint. The row's
// version column is owned by the services_bump_version trigger from
// migration 0011 — Update never writes it itself, the trigger bumps
// it on every successful UPDATE.
//
// When ifMatchVersion is nil the predicate matches on (organization,
// id) alone — next-write-wins. When ifMatchVersion is non-nil the
// predicate also requires version = *ifMatchVersion, so a concurrent
// writer landing between the caller's read and this write is rejected
// as a typed apierr.ConflictStale carrying the row's authoritative
// version. The disambiguation between "row missing" and "version
// stale" runs through classifyServiceConcurrencyMiss so the caller
// learns which precondition actually failed.
//
// A slug already taken by another service in the same environment
// violates UNIQUE (environment_id, slug) and surfaces through
// mapWriteError as a deterministic apierr.Conflict — never a 500
// leaking the constraint name. The repository is tenant-scoped at the
// SQL predicate: a cross-tenant (organization_id, service_id) tuple
// matches no row even when a service with the same id exists in
// another tenant, so the response is never an oracle that reveals
// another organization's service ids.
func (r *ServiceRepository) Update(ctx context.Context, tx *Tx, s Service, ifMatchVersion *int64) (Service, error) {
	if tx == nil {
		return Service{}, apierr.Internal(errors.New("store: ServiceRepository.Update called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`UPDATE services
			    SET slug = $3, display_name = $4
			  WHERE organization_id = $1 AND id = $2
			 RETURNING `+serviceColumns,
			s.OrganizationID, s.ID, s.Slug, s.DisplayName)
	} else {
		row = tx.QueryRow(ctx,
			`UPDATE services
			    SET slug = $3, display_name = $4
			  WHERE organization_id = $1 AND id = $2 AND version = $5
			 RETURNING `+serviceColumns,
			s.OrganizationID, s.ID, s.Slug, s.DisplayName, *ifMatchVersion)
	}
	updated, err := scanService(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return Service{}, apierr.NotFound("service", s.ID)
		}
		return Service{}, classifyServiceConcurrencyMiss(ctx, tx, s.OrganizationID, s.ID, *ifMatchVersion)
	}
	if err != nil {
		return Service{}, mapWriteError(err, "a service with this slug already exists in the environment")
	}
	return updated, nil
}

// Transition moves a service through the documented service state machine and
// appends the matching service_events row in the same transaction. Invalid
// edges return E_INVALID_STATE_TRANSITION before any update, so the service row
// and timeline remain unchanged.
func (r *ServiceRepository) Transition(ctx context.Context, tx *Tx, in ServiceTransition) (Service, ServiceEvent, error) {
	if tx == nil {
		return Service{}, ServiceEvent{}, apierr.Internal(errors.New("store: ServiceRepository.Transition called with a nil transaction"))
	}
	orgID := strings.TrimSpace(in.OrganizationID)
	serviceID := strings.TrimSpace(in.ServiceID)
	next := in.NextStatus
	if next.serviceEventType() == "" {
		return Service{}, ServiceEvent{}, apierr.InvalidStateTransition("service", "", next.String())
	}

	current, err := scanService(tx.QueryRow(ctx,
		`SELECT `+serviceColumns+`
		   FROM services
		  WHERE organization_id = $1 AND id = $2
		  FOR UPDATE`,
		orgID, serviceID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Service{}, ServiceEvent{}, apierr.NotFound("service", serviceID)
	}
	if err != nil {
		return Service{}, ServiceEvent{}, apierr.StoreUnavailable(err)
	}
	if in.ExpectedVersion != nil && current.Version != *in.ExpectedVersion {
		return Service{}, ServiceEvent{}, apierr.ConflictStale(current.Version)
	}
	if !current.Status.CanTransitionTo(next) {
		return Service{}, ServiceEvent{}, apierr.InvalidStateTransition("service", current.Status.String(), next.String())
	}

	updated, err := scanService(tx.QueryRow(ctx,
		`UPDATE services
		    SET status = $3
		  WHERE organization_id = $1 AND id = $2
		  RETURNING `+serviceColumns,
		orgID, serviceID, next.String()))
	if err != nil {
		return Service{}, ServiceEvent{}, apierr.StoreUnavailable(err)
	}

	reason := output.NewRedactor().Redact(strings.TrimSpace(in.Reason))
	event, err := NewServiceEventRepository().Append(ctx, tx, ServiceEvent{
		OrganizationID: orgID,
		ServiceID:      serviceID,
		EventType:      next.serviceEventType(),
		Message:        reason,
		Metadata: map[string]string{
			"actor_id":       strings.TrimSpace(in.ActorID),
			"actor_kind":     strings.TrimSpace(in.ActorKind),
			"previous_state": current.Status.String(),
			"next_state":     next.String(),
			"reason":         reason,
		},
		RequestID:     strings.TrimSpace(in.RequestID),
		CorrelationID: strings.TrimSpace(in.CorrelationID),
	})
	if err != nil {
		return Service{}, ServiceEvent{}, err
	}
	return updated, event, nil
}

// classifyServiceConcurrencyMiss disambiguates the two reasons a
// version-checked UPDATE matched no rows: the service was deleted
// (rare, and reported as NotFound for parity with the unchecked path)
// or the caller's view of the version is stale (reported as
// apierr.ConflictStale carrying the row's authoritative version). The
// read runs on the same *Tx as the failed write so the version it
// reports is consistent with the predicate that just rejected.
func classifyServiceConcurrencyMiss(ctx context.Context, tx *Tx, organizationID, serviceID string, ifMatchVersion int64) error {
	r := NewServiceRepository()
	current, err := r.GetByID(ctx, tx, organizationID, serviceID)
	if err != nil {
		return err
	}
	if current.Version == ifMatchVersion {
		// The row was found AND its version matches the precondition,
		// yet the version-checked UPDATE returned no rows — that is a
		// driver-level anomaly the caller cannot recover from, so it
		// is reported as Internal to surface as a 500 rather than
		// silently disguising itself as a 404 or a stale-version 409.
		return apierr.Internal(errors.New("store: ServiceRepository.Update saw the same version after a no-row UPDATE"))
	}
	return apierr.ConflictStale(current.Version)
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
		&s.Status,
		&s.Version,
		&s.CreatedAt,
		&s.UpdatedAt,
		&s.DeletionScheduledAt,
	); err != nil {
		return Service{}, err
	}
	return s, nil
}

// ScheduleDeletion stamps deletion_scheduled_at = now() on the service
// identified by (organizationID, serviceID) inside tx and returns the
// persisted row, including the trigger-refreshed updated_at timestamp
// and bumped version. It requires a *Tx — not a bare Querier — so a
// service can never be marked for teardown outside the transaction
// that also carries its audit record. The query is tenant scoped by
// organization_id first, so a serviceID that belongs to another
// organization simply does not match and is reported as NotFound — a
// cross-tenant id can never schedule another organization's service
// for teardown. The parent (project, environment) relationship is
// preserved by construction: the UPDATE touches only
// deletion_scheduled_at and never the composite (organization_id,
// project_id, environment_id) tenant key.
//
// The UPDATE is unconditional in its predicate apart from the optional
// version check: re-scheduling a service already scheduled for
// deletion is a conflict the ServiceService detects with a prior read
// inside the same transaction, not a not-found this repository can
// distinguish (the repository must remain SQL-idempotent for
// non-customer callers — workers, admin jobs — that need a stable
// retry surface).
//
// ifMatchVersion enforces optimistic concurrency identically to
// Update — a nil pointer disables the check, a non-nil pointer adds a
// WHERE clause on the current version, and a stale view is reported
// as a typed apierr.ConflictStale carrying the row's authoritative
// version through classifyServiceConcurrencyMiss.
func (r *ServiceRepository) ScheduleDeletion(ctx context.Context, tx *Tx, organizationID, serviceID string, ifMatchVersion *int64) (Service, error) {
	if tx == nil {
		return Service{}, apierr.Internal(errors.New("store: ServiceRepository.ScheduleDeletion called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`UPDATE services
			    SET deletion_scheduled_at = now()
			  WHERE organization_id = $1 AND id = $2
			 RETURNING `+serviceColumns,
			organizationID, serviceID)
	} else {
		row = tx.QueryRow(ctx,
			`UPDATE services
			    SET deletion_scheduled_at = now()
			  WHERE organization_id = $1 AND id = $2 AND version = $3
			 RETURNING `+serviceColumns,
			organizationID, serviceID, *ifMatchVersion)
	}
	updated, err := scanService(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return Service{}, apierr.NotFound("service", serviceID)
		}
		return Service{}, classifyServiceConcurrencyMiss(ctx, tx, organizationID, serviceID, *ifMatchVersion)
	}
	if err != nil {
		return Service{}, apierr.StoreUnavailable(err)
	}
	return updated, nil
}

// Restore clears deletion_scheduled_at on the service identified by
// (organizationID, serviceID) inside tx and returns the persisted row,
// including the trigger-refreshed updated_at timestamp and bumped
// version. It requires a *Tx — not a bare Querier — so a service can
// never be restored outside the transaction that also carries its
// audit record. The query is tenant scoped by organization_id first,
// so a serviceID that belongs to another organization simply does not
// match and is reported as NotFound — a cross-tenant id can never
// restore another organization's service. The parent (project,
// environment) relationship is preserved by construction: the UPDATE
// touches only deletion_scheduled_at and never the composite
// (organization_id, project_id, environment_id) tenant key.
//
// The UPDATE is unconditional in its predicate apart from the optional
// version check: restoring a service that was never scheduled for
// deletion is a conflict the ServiceService detects with a prior read
// inside the same transaction, not a not-found this repository can
// distinguish (the repository must remain SQL-idempotent for
// non-customer callers — workers, admin jobs — that need a stable
// retry surface).
//
// ifMatchVersion enforces optimistic concurrency identically to
// Update — a nil pointer disables the check, a non-nil pointer adds a
// WHERE clause on the current version, and a stale view is reported
// as a typed apierr.ConflictStale carrying the row's authoritative
// version through classifyServiceConcurrencyMiss.
func (r *ServiceRepository) Restore(ctx context.Context, tx *Tx, organizationID, serviceID string, ifMatchVersion *int64) (Service, error) {
	if tx == nil {
		return Service{}, apierr.Internal(errors.New("store: ServiceRepository.Restore called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`UPDATE services
			    SET deletion_scheduled_at = NULL
			  WHERE organization_id = $1 AND id = $2
			 RETURNING `+serviceColumns,
			organizationID, serviceID)
	} else {
		row = tx.QueryRow(ctx,
			`UPDATE services
			    SET deletion_scheduled_at = NULL
			  WHERE organization_id = $1 AND id = $2 AND version = $3
			 RETURNING `+serviceColumns,
			organizationID, serviceID, *ifMatchVersion)
	}
	updated, err := scanService(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return Service{}, apierr.NotFound("service", serviceID)
		}
		return Service{}, classifyServiceConcurrencyMiss(ctx, tx, organizationID, serviceID, *ifMatchVersion)
	}
	if err != nil {
		return Service{}, apierr.StoreUnavailable(err)
	}
	return updated, nil
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

// GetService returns the single service identified by
// (organizationID, serviceID), reading it inside a short-lived
// read-only transaction. The read is tenant-scoped at the SQL leg, so
// a cross-tenant or unknown service_id surfaces as a deterministic
// apierr.NotFound — never as another tenant's row, and never as a 500
// leaking the cause. A live service in the principal's own tenant
// returns the persisted row verbatim. A datastore failure is
// propagated as its own typed error.
//
// GetService is the persistence half of GET /v1/services/{service_id}
// (BE-0184): the bare top-level lookup-by-id endpoint that does not
// carry the parent project_id or environment_id in its path. The
// handler authorizes on action service.read against the (principal
// home organization, service_id) resource the resolver builds, and
// trusts this method to keep the tenant boundary at the persistence
// layer even when the policy resource scope cannot pin the parent
// project_id or environment_id.
func (r *ServiceReader) GetService(ctx context.Context, organizationID, serviceID string) (Service, error) {
	var svc Service
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		got, getErr := r.services.GetByID(ctx, q, organizationID, serviceID)
		if getErr != nil {
			return getErr
		}
		svc = got
		return nil
	})
	if err != nil {
		return Service{}, err
	}
	return svc, nil
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
