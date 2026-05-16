package store

import (
	"context"
	"errors"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// ServiceBackup is a single service-scoped backup policy: a schedule
// + retention + on/off flag bound to a service, plus the most recent
// worker-driven run state (status, last_run_at, last_succeeded_at)
// the worker projects onto the row as it drives Dokploy backups. A
// service may hold many backup policies (e.g. nightly + weekly +
// pre-deploy); a backup row never sits under a foreign tenant's
// service (the table's composite FK (organization_id, service_id) ->
// services refuses the insert structurally).
//
// The struct shape is the stable structural row the httpapi
// service-backups payload projects onto the wire as-is (modulo JSON
// tag naming) — no pointer-typed fields except the
// last_run_at / last_succeeded_at timestamps that are genuinely
// optional (nil until the worker records the first run /
// success), no embedded interfaces, no Dokploy- or worker-specific
// identifiers. Adding a new field is a strictly forward-compatible
// operation; renaming or removing one is a wire break.
//
// The backup artefact bytes themselves are NEVER held in this table
// — they live in the worker / Dokploy / object-storage layer and
// never round-trip through the control-plane database. This row is
// desired-state policy + run-state metadata only.
type ServiceBackup struct {
	ID              string
	OrganizationID  string
	ServiceID       string
	DisplayName     string
	Schedule        string
	RetentionCount  int
	Enabled         bool
	Status          string
	LastRunAt       *time.Time
	LastSucceededAt *time.Time
	Version         int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// serviceBackupColumns is the SELECT projection used by every read in
// this repository. Keeping it as a single string keeps the column list
// in lockstep with scanServiceBackup.
const serviceBackupColumns = `id, organization_id, service_id, display_name, schedule, retention_count, enabled, status, last_run_at, last_succeeded_at, version, created_at, updated_at`

// serviceBackupListMaxRows caps how many rows a single ListByService
// call returns. An unbounded query can never be issued by accident; an
// HTTP layer that wants pagination later will add an explicit offset
// or cursor parameter rather than relax this ceiling.
const serviceBackupListMaxRows = 500

// ServiceBackup* status constants enumerate the closed taxonomy the
// service_backups.status column's CHECK confines. The worker is the
// authority for transitions between StatusRunning and {StatusSucceeded,
// StatusFailed}; the customer-facing PATCH is restricted to
// {StatusDisabled, StatusPending} so a customer cannot forge a
// successful run through the public API surface.
const (
	ServiceBackupStatusDisabled  = "disabled"
	ServiceBackupStatusPending   = "pending"
	ServiceBackupStatusRunning   = "running"
	ServiceBackupStatusSucceeded = "succeeded"
	ServiceBackupStatusFailed    = "failed"
)

// ServiceBackupRepository is the persistence half of the
// service-backups surface. Every read is tenant-scoped: the
// organization_id and service_id legs of the predicate are
// non-optional, so a missing or cross-tenant id simply matches no
// rows and yields an empty list — never another tenant's backups. The
// repository is stateless; the constructor exists so call sites
// depend on a value rather than a bare struct literal.
type ServiceBackupRepository struct{}

// NewServiceBackupRepository builds a stateless ServiceBackupRepository.
func NewServiceBackupRepository() *ServiceBackupRepository {
	return &ServiceBackupRepository{}
}

// ListByService returns every service-scoped backup policy owned by
// (organizationID, serviceID), in deterministic (created_at ASC, id
// ASC) order so an agent observing the response sees a stable
// ordering across calls. The read is tenant-scoped at the SQL
// predicate, so a cross-tenant (organization, service) tuple matches
// no rows. A raw driver error surfaces as the typed
// apierr.StoreUnavailable — the cause is wrapped for logging only,
// never leaked into the customer-facing message.
//
// This method does NOT verify the service exists; callers that need
// to distinguish "service missing" from "service has no backups"
// must Get the service first (the ServiceBackupReader adapter does
// so in the same short-lived transaction).
func (r *ServiceBackupRepository) ListByService(ctx context.Context, q Querier, organizationID, serviceID string) ([]ServiceBackup, error) {
	rows, err := q.Query(ctx,
		`SELECT `+serviceBackupColumns+`
		   FROM service_backups
		  WHERE organization_id = $1 AND service_id = $2
		  ORDER BY created_at ASC, id ASC
		  LIMIT $3`,
		organizationID, serviceID, serviceBackupListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]ServiceBackup, 0)
	for rows.Next() {
		b, scanErr := scanServiceBackup(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// scanServiceBackup scans one service_backups row in
// serviceBackupColumns order.
func scanServiceBackup(row scanRow) (ServiceBackup, error) {
	var b ServiceBackup
	if err := row.Scan(
		&b.ID,
		&b.OrganizationID,
		&b.ServiceID,
		&b.DisplayName,
		&b.Schedule,
		&b.RetentionCount,
		&b.Enabled,
		&b.Status,
		&b.LastRunAt,
		&b.LastSucceededAt,
		&b.Version,
		&b.CreatedAt,
		&b.UpdatedAt,
	); err != nil {
		return ServiceBackup{}, err
	}
	return b, nil
}

// ServiceBackupReader is the store-backed read adapter for the
// service-backups surface: the persistence surface the httpapi layer
// needs to render GET /v1/services/{service_id}/backups. It mirrors
// ServiceDomainReader — it composes ServiceRepository and
// ServiceBackupRepository through a short-lived read-only transaction
// (Store.Read), so the tenant-scoping guarantees the repositories
// prove in their integration tests are inherited for free, and every
// cross-tenant or unknown service_id surfaces as a deterministic
// apierr.NotFound rather than an empty list.
type ServiceBackupReader struct {
	store    *Store
	services *ServiceRepository
	backups  *ServiceBackupRepository
}

// NewServiceBackupReader builds a ServiceBackupReader over store. It
// returns an error for a nil store so a misconfigured adapter fails
// at construction rather than on its first request.
func NewServiceBackupReader(s *Store) (*ServiceBackupReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &ServiceBackupReader{
		store:    s,
		services: NewServiceRepository(),
		backups:  NewServiceBackupRepository(),
	}, nil
}

// ListServiceBackupsInput is the typed input shape
// ServiceBackupReader.ListBackups accepts. OrganizationID is always
// taken from the authenticated principal's home org at the httpapi
// layer (never from caller-controlled request input), and ServiceID
// is always taken from the path parameter; both surface here as
// plain strings so the tenant-scoped existence check that defends
// the boundary cannot be bypassed by a zero value.
type ListServiceBackupsInput struct {
	OrganizationID string
	ServiceID      string
}

// ServiceBackups is the typed response of
// ServiceBackupReader.ListBackups: the service id the backup
// policies belong to (echoed back so a caller can distinguish a
// multi-resource batch in a future backups-stream endpoint even
// though today's GET addresses exactly one service) and the backup
// policies themselves in deterministic order. An empty Backups slice
// with a populated ServiceID means the service exists, is owned by
// the tenant, and has no backup policies — never disguised as a
// NotFound.
type ServiceBackups struct {
	ServiceID string
	Backups   []ServiceBackup
}

// ListBackups returns the backup-policy rows for the service
// identified by (organizationID, serviceID), reading them inside a
// short-lived read-only transaction. The read is tenant scoped at
// both legs: it Gets the service first so a cross-tenant or unknown
// service_id surfaces as a deterministic apierr.NotFound — never as
// an empty list, which would invite an agent to believe the service
// exists with no backups. A live service with no backups is then a
// deterministic empty slice. A datastore failure is propagated as
// its own typed error.
func (r *ServiceBackupReader) ListBackups(ctx context.Context, in ListServiceBackupsInput) (ServiceBackups, error) {
	var svcID string
	var backups []ServiceBackup
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		svc, getErr := r.services.GetByID(ctx, q, in.OrganizationID, in.ServiceID)
		if getErr != nil {
			return getErr
		}
		svcID = svc.ID
		list, listErr := r.backups.ListByService(ctx, q, in.OrganizationID, in.ServiceID)
		if listErr != nil {
			return listErr
		}
		backups = list
		return nil
	})
	if err != nil {
		return ServiceBackups{}, err
	}
	return ServiceBackups{ServiceID: svcID, Backups: backups}, nil
}
