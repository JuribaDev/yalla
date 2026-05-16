package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/controlplane/domain"
	"github.com/JuribaDev/yalla/internal/controlplane/validate"
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

// Insert writes a new service-scoped backup-policy row inside tx. The
// caller must already have confirmed the parent service exists under
// (organizationID, serviceID) — Insert relies on the table's composite
// FK (organization_id, service_id) -> services (organization_id, id)
// as the database-side belt-and-braces, so a foreign-tenant or unknown
// service id would surface here as a typed mapWriteError rather than a
// raw constraint name. A duplicate backup id (the table's PRIMARY KEY)
// is rejected by the database and mapped to a typed apierr.Conflict
// with a stable, value-free message — the customer-facing reason never
// echoes the submitted id.
//
// retention_count, enabled, status, last_run_at, last_succeeded_at,
// version, created_at, and updated_at are owned by the database
// (defaults + triggers from migration 0024) when not supplied — the
// caller passes the desired values (or zero values to take the
// schema-side defaults) and Insert returns the persisted row with
// those fields populated so the audit record and the wire response
// can name the row's authoritative state.
func (r *ServiceBackupRepository) Insert(ctx context.Context, tx *Tx, b ServiceBackup) (ServiceBackup, error) {
	if tx == nil {
		return ServiceBackup{}, apierr.Internal(errors.New("store: ServiceBackupRepository.Insert called with a nil transaction"))
	}
	status := b.Status
	if status == "" {
		status = ServiceBackupStatusPending
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO service_backups
		    (id, organization_id, service_id, display_name, schedule, retention_count, enabled, status)
		  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		  RETURNING `+serviceBackupColumns,
		b.ID, b.OrganizationID, b.ServiceID, b.DisplayName, b.Schedule, b.RetentionCount, b.Enabled, status)
	created, err := scanServiceBackup(row)
	if err != nil {
		return ServiceBackup{}, mapWriteError(err, "a service backup with this id already exists")
	}
	return created, nil
}

// serviceBackupCreateAction is the immutable audit-event Action string
// emitted when a service backup policy is created. The constant lives
// in the store layer because the audit event is written from the same
// *Tx as the desired-state row.
const serviceBackupCreateAction = "backup.create"

// serviceBackupRunAction is the immutable audit-event Action string
// emitted when a service backup policy is manually triggered through
// POST /v1/services/{service_id}/backups/{backup_id}/run. The
// constant lives in the store layer because the audit event is
// written from the same *Tx as the status flip the worker observes.
const serviceBackupRunAction = "backup.run"

// serviceBackupDefaultRetentionCount is the retention applied when the
// caller does not supply one; the table's default is the same, so a
// caller that omits retention takes the same value the schema would.
const serviceBackupDefaultRetentionCount = 7

// serviceBackupRetentionMin / serviceBackupRetentionMax bound the
// retention_count column. The values mirror the CHECK in migration
// 0024 so the validate layer rejects out-of-range values before any
// database work; the schema CHECK is the database-side belt-and-braces
// that rejects an out-of-range value even if the application layer
// ever forgets.
const (
	serviceBackupRetentionMin = 1
	serviceBackupRetentionMax = 365
)

// serviceBackupDisplayNameMaxLen bounds the display_name column. The
// validate layer enforces it before any database work; the schema
// CHECK enforces only non-emptiness, so the upper bound lives here as
// the application-layer guarantee.
const serviceBackupDisplayNameMaxLen = 200

// serviceBackupScheduleMaxLen bounds the schedule column. A cron-style
// expression is at most a handful of tokens; a generous cap prevents
// pathological inputs from reaching the row without echoing the
// submitted value in any error message.
const serviceBackupScheduleMaxLen = 200

// CreateServiceBackupInput is the unvalidated input to
// ServiceBackupService.Create. OrganizationID, ServiceID, BackupID,
// DisplayName, Schedule, RetentionCount, and Enabled are the caller-
// supplied resource fields; the Actor* and correlation fields describe
// the authenticated principal performing the create and are recorded
// verbatim on the audit event. They are plain strings so the store
// layer takes no build dependency on the policy or telemetry packages
// — the httpapi handler, which already holds the resolved principal
// and the request correlation, fills them in.
//
// OrganizationID is sourced from the principal's home organization at
// the HTTP boundary (never from the request body or path), so a
// cross-tenant id cannot point the write at another tenant by
// construction. ServiceID is sourced from the {service_id} PATH
// parameter, and the create unit of work re-reads the parent service
// under (OrganizationID, ServiceID) before any write — a cross-tenant
// or unknown service_id surfaces as a deterministic apierr.NotFound
// rather than a 500 or a silent success.
//
// RetentionCount defaults to the schema-side default
// (serviceBackupDefaultRetentionCount) when zero. Enabled is a bool so
// it carries no absent-vs-default distinction — callers that want the
// row created in the disabled state must explicitly set
// Enabled=false; the HTTP layer normalises a missing wire field to
// true (the most common case) before calling. The customer-facing
// create never sets Status — the row lands in
// ServiceBackupStatusPending so the worker takes the first transition
// — and never sets last_run_at / last_succeeded_at because those are
// worker-projected fields, not customer desired state.
type CreateServiceBackupInput struct {
	OrganizationID string
	ServiceID      string
	BackupID       string
	DisplayName    string
	Schedule       string
	RetentionCount int
	Enabled        bool
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// ServiceBackupService is the reference unit-of-work orchestrator for
// the create-service-backup transaction pattern. Create composes — in
// this fixed order, inside one transaction — a parent-service existence
// check, an in-transaction authorization check, the desired-state
// write, and the immutable audit record. Because every step shares the
// *Tx opened by Store.Write, a failure in any step rolls back every
// other step: the authorization and audit checks are impossible to
// bypass, and a backup row is never persisted without its audit trail.
//
// The httpapi RequireAuth middleware is the authoritative authorization
// gate for action backup.create (service-scoped via serviceIDResolver).
// The store-layer Authorize call is defense-in-depth against a grant
// change that landed between the HTTP authorize and the desired-state
// write — it runs on the same *Tx as the write so the in-transaction
// policy view sees exactly the state the row commits against.
//
// Service backups do not yet have a quota (the per-organization
// backup-policy quota lands in a later worker story) and do not yet
// enqueue a provisioning job — the backup row is the source of truth,
// and the Dokploy reconciler will project it as part of the broader
// service-reconcile loop. When the dedicated worker story lands, the
// orchestrator will gain JobEnqueuer and QuotaReserver dependencies
// the same way ServiceService did, alongside the worker's contract
// tests.
type ServiceBackupService struct {
	store    *Store
	services *ServiceRepository
	backups  *ServiceBackupRepository
	authz    Authorizer
	audit    AuditAppender
}

// NewServiceBackupService wires a ServiceBackupService from its
// dependencies. It returns a typed error if any dependency is nil, so
// a misconfigured service fails at construction rather than on its
// first request.
func NewServiceBackupService(s *Store, services *ServiceRepository, backups *ServiceBackupRepository, authz Authorizer, audit AuditAppender) (*ServiceBackupService, error) {
	switch {
	case s == nil:
		return nil, errors.New("store: nil store")
	case services == nil:
		return nil, errors.New("store: nil service repository")
	case backups == nil:
		return nil, errors.New("store: nil service backup repository")
	case authz == nil:
		return nil, errors.New("store: nil authorizer")
	case audit == nil:
		return nil, errors.New("store: nil audit appender")
	}
	return &ServiceBackupService{
		store:    s,
		services: services,
		backups:  backups,
		authz:    authz,
		audit:    audit,
	}, nil
}

// Create validates in, then runs the create-backup unit of work inside
// one transaction: confirm the parent service exists under
// (OrganizationID, ServiceID), authorize, write the backup row, append
// the immutable audit record. Validation runs before the transaction
// is opened, so an invalid request never touches the database. Every
// failure after that point — a missing parent service, a denied
// authorization decision, a duplicate id conflict, or a failed audit
// append — rolls the whole transaction back, so the backup row is
// never persisted without its audit trail and the checks can never be
// skipped.
//
// The parent-service Get is tenant-scoped — it filters by
// organization_id first — so a cross-tenant or unknown service_id
// surfaces as a deterministic apierr.NotFound. This is the same
// boundary GET /v1/services/{service_id}/backups inherits, so a
// foreign service_id reaches the persistence layer with the
// principal's home organization id and is reported as 404 here just
// as it is on the read side, never disguised as a 403 that would
// confirm the foreign service's existence.
func (svc *ServiceBackupService) Create(ctx context.Context, in CreateServiceBackupInput) (ServiceBackup, error) {
	row, err := validateCreateServiceBackupInput(in)
	if err != nil {
		return ServiceBackup{}, err
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its resource
	// id names the backup that was created. A missing actor
	// organization is a wiring error (an authenticated request always
	// carries one), not client input, so it is reported as Internal
	// rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return ServiceBackup{}, apierr.Internal(errors.New("store: ServiceBackupService.Create requires an actor organization for the audit record"))
	}

	var created ServiceBackup
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Parent service existence is tenant-scoped: a cross-tenant or
		// unknown service_id surfaces as a deterministic
		// apierr.NotFound, never a 500 or a silent success. The check
		// runs first so the in-tx authorize and the Insert do not have
		// to guess whether the parent exists.
		if _, getErr := svc.services.GetByID(ctx, tx, row.OrganizationID, row.ServiceID); getErr != nil {
			return getErr
		}
		// Defense-in-depth: the HTTP RequireAuth middleware already
		// authorized action backup.create against the (home org,
		// service_id) resource the path names. The in-transaction
		// Authorize is a redundant check whose real adapter reads
		// grant rows from the same *Tx as the desired-state write —
		// so a grant change that landed between the HTTP authorize
		// and this point still cannot let the write through.
		if err := svc.authz.Authorize(ctx, tx, serviceBackupCreateAction, row.OrganizationID); err != nil {
			return err
		}
		inserted, err := svc.backups.Insert(ctx, tx, row)
		if err != nil {
			return err
		}
		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         serviceBackupCreateAction,
			ResourceKind:   string(domain.KindServiceBackup),
			ResourceID:     inserted.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for backup.create",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			// The service_id is recorded verbatim because it is a
			// structural identifier, never secret material. The
			// display_name and schedule are caller-supplied strings;
			// the schedule is a cron-style expression (no credential
			// material round-trips through this table — the backup
			// artefact bytes live in the worker / Dokploy /
			// object-storage layer) but it is still caller-controlled
			// free text, so it is NOT recorded as audit metadata, to
			// keep the audit row free of any value the application
			// layer cannot prove redaction-safe by construction. The
			// retention_count and enabled flag carry no caller-secret
			// material — they are bounded integers and a boolean.
			Metadata: map[string]string{
				"service_id":      inserted.ServiceID,
				"retention_count": strconvI(inserted.RetentionCount),
				"enabled":         boolStr(inserted.Enabled),
			},
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		created = inserted
		return nil
	})
	if txErr != nil {
		return ServiceBackup{}, txErr
	}
	return created, nil
}

// strconvI renders a non-negative int as a string for audit metadata.
// The bound is bounded by the validate layer (1..365) so a plain
// base-10 render is safe; using strconv.Itoa would force an extra
// import on a hot path that has no other strconv calls.
func strconvI(n int) string {
	// Manual base-10 conversion keeps the import surface narrow.
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// boolStr renders a bool as the literal "true" / "false" string for
// audit metadata.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// validateCreateServiceBackupInput checks in and returns the
// ServiceBackup row it would map to. Field-level validation uses the
// shared validate.Collector so a single request rejecting on more
// than one field surfaces every violation in one typed
// apierr.InvalidInput. A submitted value never appears in a violation
// reason — a schedule or display name that ended up in the wrong
// field cannot leak through the validation error.
func validateCreateServiceBackupInput(in CreateServiceBackupInput) (ServiceBackup, error) {
	c := validate.New()

	orgID := strings.TrimSpace(in.OrganizationID)
	validate.ID(c, "organization_id", orgID, domain.KindOrganization)

	serviceID := strings.TrimSpace(in.ServiceID)
	validate.ID(c, "service_id", serviceID, domain.KindService)

	backupID := strings.TrimSpace(in.BackupID)
	validate.ID(c, "id", backupID, domain.KindServiceBackup)

	displayName := strings.TrimSpace(in.DisplayName)
	validateServiceBackupDisplayName(c, "display_name", displayName)

	schedule := strings.TrimSpace(in.Schedule)
	validateServiceBackupSchedule(c, "schedule", schedule)

	retention := in.RetentionCount
	if retention == 0 {
		retention = serviceBackupDefaultRetentionCount
	}
	if retention < serviceBackupRetentionMin || retention > serviceBackupRetentionMax {
		c.Addf("retention_count", "must be between %d and %d", serviceBackupRetentionMin, serviceBackupRetentionMax)
	}

	if err := c.Err(); err != nil {
		return ServiceBackup{}, err
	}

	return ServiceBackup{
		ID:             backupID,
		OrganizationID: orgID,
		ServiceID:      serviceID,
		DisplayName:    displayName,
		Schedule:       schedule,
		RetentionCount: retention,
		Enabled:        in.Enabled,
		Status:         ServiceBackupStatusPending,
	}, nil
}

// validateServiceBackupDisplayName validates the human-authored
// display_name for a backup policy. The submitted value is never
// echoed in the violation reason — a typo or accidental secret
// pasted into the field cannot leak through the validation error.
func validateServiceBackupDisplayName(c *validate.Collector, field, value string) {
	if value == "" {
		c.Add(field, "must not be blank")
		return
	}
	if len(value) > serviceBackupDisplayNameMaxLen {
		c.Addf(field, "must be at most %d characters", serviceBackupDisplayNameMaxLen)
		return
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			c.Add(field, "must not contain control characters")
			return
		}
	}
}

// validateServiceBackupSchedule validates the cron-style schedule
// for a backup policy. The validation is intentionally permissive at
// this layer — the worker is the authority for cron parsing and will
// reject a malformed expression when it next plans a run — so the
// store layer enforces only the structural guarantees: non-empty,
// bounded length, no control bytes, no caller-supplied newline. The
// submitted value is never echoed in the violation reason.
func validateServiceBackupSchedule(c *validate.Collector, field, value string) {
	if value == "" {
		c.Add(field, "must not be blank")
		return
	}
	if len(value) > serviceBackupScheduleMaxLen {
		c.Addf(field, "must be at most %d characters", serviceBackupScheduleMaxLen)
		return
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			c.Add(field, "must not contain control characters")
			return
		}
	}
}

// GetByID returns the single service_backups row identified by
// (organizationID, serviceID, backupID). The read is tenant scoped at
// the SQL predicate: a cross-tenant (organization_id, service_id, id)
// tuple matches no row even when a backup with the same id exists in
// another tenant, so the response is never an oracle that confirms
// another organization's backup ids. A missing row surfaces as the
// typed apierr.NotFound the customer-facing endpoints render as 404;
// the customer-facing message names the resource kind and the
// requested id only — never the parent service or organization, both
// of which are derived from the principal at the HTTP boundary and
// would only confirm the caller's own identity.
func (r *ServiceBackupRepository) GetByID(ctx context.Context, q Querier, organizationID, serviceID, backupID string) (ServiceBackup, error) {
	row := q.QueryRow(ctx,
		`SELECT `+serviceBackupColumns+`
		   FROM service_backups
		  WHERE organization_id = $1 AND service_id = $2 AND id = $3`,
		organizationID, serviceID, backupID)
	b, err := scanServiceBackup(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceBackup{}, apierr.NotFound("service backup", backupID)
	}
	if err != nil {
		return ServiceBackup{}, apierr.StoreUnavailable(err)
	}
	return b, nil
}

// MarkPending flips the service_backups row identified by
// (organizationID, serviceID, backupID) into the pending state so the
// worker takes the next transition on its next scheduling pass. The
// row's version column is owned by the service_backups_bump_version
// trigger from migration 0024 — MarkPending never writes it itself,
// the trigger bumps it on every successful UPDATE — and updated_at is
// refreshed by service_backups_set_updated_at, so the returned row
// names the row's authoritative state after the write. A no-row
// UPDATE (tenant tuple does not match an existing row) surfaces as
// the typed apierr.NotFound — never a 500 leaking the cause —
// because the customer-facing handler will already have proved the
// row exists in the same *Tx through GetByID, so a no-row outcome
// here is the deletion-race path. The repository is tenant-scoped at
// the SQL predicate.
func (r *ServiceBackupRepository) MarkPending(ctx context.Context, tx *Tx, organizationID, serviceID, backupID string) (ServiceBackup, error) {
	if tx == nil {
		return ServiceBackup{}, apierr.Internal(errors.New("store: ServiceBackupRepository.MarkPending called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`UPDATE service_backups
		    SET status = $4
		  WHERE organization_id = $1 AND service_id = $2 AND id = $3
		 RETURNING `+serviceBackupColumns,
		organizationID, serviceID, backupID, ServiceBackupStatusPending)
	updated, err := scanServiceBackup(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceBackup{}, apierr.NotFound("service backup", backupID)
	}
	if err != nil {
		return ServiceBackup{}, apierr.StoreUnavailable(err)
	}
	return updated, nil
}

// RunServiceBackupInput is the unvalidated input to
// ServiceBackupService.Run. OrganizationID, ServiceID, and BackupID
// name the backup-policy row whose manual run was requested; the
// Actor* and correlation fields describe the authenticated principal
// performing the request and are recorded verbatim on the audit
// event. They are plain strings so the store layer takes no build
// dependency on the policy or telemetry packages — the httpapi
// handler, which already holds the resolved principal and the
// request correlation, fills them in.
//
// OrganizationID is sourced from the principal's home organization
// at the HTTP boundary (never from the request body or path), and
// ServiceID and BackupID are sourced from the {service_id} and
// {backup_id} PATH parameters; the run unit of work re-reads the
// parent service and the backup row under
// (OrganizationID, ServiceID[, BackupID]) before any mutation, so a
// cross-tenant or unknown id surfaces as a deterministic
// apierr.NotFound rather than a 500 or a silent success.
//
// The run request carries no caller-supplied body fields beyond the
// path parameters: backup.run is a fire-and-forget signal that
// targets a single backup-policy row and carries no caller-supplied
// schedule, retention, or override. The worker is the authority for
// the actual run — Run flips the row's status to pending so the
// worker picks it up on its next scheduling pass and appends the
// immutable audit record naming the actor; the worker subsequently
// transitions the row to running, succeeded, or failed.
type RunServiceBackupInput struct {
	OrganizationID string
	ServiceID      string
	BackupID       string
	ActorID        string
	ActorKind      string
	ActorOrgID     string
	RequestID      string
	CorrelationID  string
}

// Run records customer intent to trigger a manual run of the backup
// policy named by (in.OrganizationID, in.ServiceID, in.BackupID) and
// flips the row into the pending state so the worker takes the next
// transition on its next scheduling pass. The unit of work runs
// inside one transaction: confirm the parent service exists under
// (OrganizationID, ServiceID), confirm the backup row exists under
// (OrganizationID, ServiceID, BackupID), reject a disabled or
// already-running policy with a deterministic 409, re-authorize
// action backup.run against the parent service's organization on the
// same *Tx (defense-in-depth against a grant change that landed
// between the HTTP authorize and the desired-state write), flip the
// row's status to pending, and append the immutable audit record.
// Because every step shares the *Tx, a failure in any of them rolls
// the others back: a partial run and an orphaned audit row are both
// impossible, and a backup.run audit record can never exist without
// the desired-state flip.
//
// The parent-service Get is tenant-scoped — it filters by
// organization_id first — so a cross-tenant or unknown service_id
// surfaces as a deterministic apierr.NotFound. The backup Get is
// likewise tenant-scoped on the composite (organization_id,
// service_id, id) tuple, so a backup id from another tenant or under
// another service cannot be addressed. A backup whose enabled flag
// is false cannot be manually run — the customer must first PATCH
// the row to enabled=true; the rejection is a deterministic 409
// rather than a silent flip that would later surprise the customer
// when the worker refused the disabled policy. A backup whose
// status is already 'running' cannot be re-triggered: the
// concurrent-run rejection is a deterministic 409 too, never a 500
// or a silent success that would double-enqueue work.
//
// The HTTP RequireAuth middleware is the authoritative authorization
// gate for action backup.run (service-scoped via
// serviceIDResolver). The store-layer Authorize call is
// defense-in-depth against a grant change that landed between the
// HTTP authorize and the desired-state write — it runs on the same
// *Tx as the write so the in-transaction policy view sees exactly
// the state the row commits against.
func (svc *ServiceBackupService) Run(ctx context.Context, in RunServiceBackupInput) (ServiceBackup, error) {
	c := validate.New()
	organizationID := strings.TrimSpace(in.OrganizationID)
	validate.ID(c, "organization_id", organizationID, domain.KindOrganization)
	serviceID := strings.TrimSpace(in.ServiceID)
	validate.ID(c, "service_id", serviceID, domain.KindService)
	backupID := strings.TrimSpace(in.BackupID)
	validate.ID(c, "backup_id", backupID, domain.KindServiceBackup)
	if err := c.Err(); err != nil {
		return ServiceBackup{}, err
	}

	// The audit record is filed under the actor's home organization —
	// the tenant the principal authenticated into — while its
	// resource id names the backup that was triggered. A missing
	// actor organization is a wiring error (an authenticated request
	// always carries one), not client input, so it is reported as
	// Internal rather than a validation failure.
	actorOrgID := strings.TrimSpace(in.ActorOrgID)
	if actorOrgID == "" {
		return ServiceBackup{}, apierr.Internal(errors.New("store: ServiceBackupService.Run requires an actor organization for the audit record"))
	}

	var triggered ServiceBackup
	txErr := svc.store.Write(ctx, func(ctx context.Context, tx *Tx) error {
		// Parent-service existence is tenant-scoped: a cross-tenant
		// or unknown service_id surfaces as the typed apierr.NotFound
		// the repository produces, never a 500 or a silent success.
		if _, err := svc.services.GetByID(ctx, tx, organizationID, serviceID); err != nil {
			return err
		}
		// Backup existence is also tenant-scoped: the composite
		// (organization_id, service_id, id) predicate matches no row
		// even when a backup with the same id exists in another
		// tenant or under another service.
		current, err := svc.backups.GetByID(ctx, tx, organizationID, serviceID, backupID)
		if err != nil {
			return err
		}
		// A disabled policy cannot be manually run: the worker would
		// refuse the row, so refuse here with a deterministic 409
		// rather than emit a no-op run whose outcome would later
		// surprise the customer.
		if !current.Enabled {
			return apierr.Conflict("backup is disabled")
		}
		// A backup whose status is already 'running' cannot be
		// re-triggered: a concurrent run would double-enqueue work
		// the worker has already accepted.
		if current.Status == ServiceBackupStatusRunning {
			return apierr.Conflict("backup is already running")
		}
		// Defense-in-depth: the HTTP RequireAuth middleware already
		// authorized action backup.run against the (home org,
		// service_id) resource the path names. The in-transaction
		// Authorize is a redundant check whose real adapter reads
		// grant rows from the same *Tx as the desired-state write —
		// so a grant change that landed between the HTTP authorize
		// and this point still cannot let the write through.
		if err := svc.authz.Authorize(ctx, tx, serviceBackupRunAction, organizationID); err != nil {
			return err
		}
		updated, err := svc.backups.MarkPending(ctx, tx, organizationID, serviceID, backupID)
		if err != nil {
			return err
		}
		event := AuditEvent{
			OrganizationID: actorOrgID,
			ActorID:        strings.TrimSpace(in.ActorID),
			ActorKind:      strings.TrimSpace(in.ActorKind),
			Action:         serviceBackupRunAction,
			ResourceKind:   string(domain.KindServiceBackup),
			ResourceID:     updated.ID,
			Decision:       AuditDecisionAllowed,
			Reason:         "authorization granted for backup.run",
			RequestID:      strings.TrimSpace(in.RequestID),
			CorrelationID:  strings.TrimSpace(in.CorrelationID),
			// The service_id is recorded verbatim because it is a
			// structural identifier, never secret material. The
			// status_before and status_after fields are closed-
			// taxonomy enums (one of disabled/pending/running/
			// succeeded/failed), so they are safe to record by
			// construction. The display_name and schedule are
			// caller-controlled free text and are NOT recorded as
			// audit metadata for this action — Run does not edit
			// either field, so neither needs to appear on the audit
			// row to make the run reconstructable, and keeping them
			// off the row keeps the audit trail free of any value
			// the application layer cannot prove redaction-safe by
			// construction.
			Metadata: map[string]string{
				"service_id":    updated.ServiceID,
				"status_before": current.Status,
				"status_after":  updated.Status,
			},
		}
		if _, err := svc.audit.Append(ctx, tx, event); err != nil {
			return err
		}
		triggered = updated
		return nil
	})
	if txErr != nil {
		return ServiceBackup{}, txErr
	}
	return triggered, nil
}
