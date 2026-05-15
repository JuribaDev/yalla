package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// QuotaResource is one countable quota dimension. It mirrors the quota_resource
// Postgres DOMAIN exactly: the set is closed, so a value outside it is rejected
// both by this type's Valid check and by the database.
type QuotaResource string

// The closed set of quota dimensions. Adding a dimension is a new migration
// that runs ALTER DOMAIN plus a new constant here.
const (
	QuotaResourceProjects              QuotaResource = "projects"
	QuotaResourceEnvironments          QuotaResource = "environments"
	QuotaResourceServices              QuotaResource = "services"
	QuotaResourceApplications          QuotaResource = "applications"
	QuotaResourceComposeStacks         QuotaResource = "compose_stacks"
	QuotaResourceDatabases             QuotaResource = "databases"
	QuotaResourceDomains               QuotaResource = "domains"
	QuotaResourcePreviewEnvironments   QuotaResource = "preview_environments"
	QuotaResourceCPUMillicores         QuotaResource = "cpu_millicores"
	QuotaResourceMemoryMB              QuotaResource = "memory_mb"
	QuotaResourceStorageGB             QuotaResource = "storage_gb"
	QuotaResourceBackups               QuotaResource = "backups"
	QuotaResourceConcurrentDeployments QuotaResource = "concurrent_deployments"
	QuotaResourceMonthlyDeployments    QuotaResource = "monthly_deployments"
)

// quotaResources is the membership set behind QuotaResource.Valid.
var quotaResources = map[QuotaResource]struct{}{
	QuotaResourceProjects:              {},
	QuotaResourceEnvironments:          {},
	QuotaResourceServices:              {},
	QuotaResourceApplications:          {},
	QuotaResourceComposeStacks:         {},
	QuotaResourceDatabases:             {},
	QuotaResourceDomains:               {},
	QuotaResourcePreviewEnvironments:   {},
	QuotaResourceCPUMillicores:         {},
	QuotaResourceMemoryMB:              {},
	QuotaResourceStorageGB:             {},
	QuotaResourceBackups:               {},
	QuotaResourceConcurrentDeployments: {},
	QuotaResourceMonthlyDeployments:    {},
}

// Valid reports whether r is one of the closed set of quota dimensions.
func (r QuotaResource) Valid() bool {
	_, ok := quotaResources[r]
	return ok
}

// String returns the resource's stable string value.
func (r QuotaResource) String() string { return string(r) }

// EnforcementMode is how a quota limit is enforced. It mirrors the
// quota_enforcement_mode Postgres DOMAIN.
type EnforcementMode string

const (
	// EnforcementModeHard rejects any allocation that would exceed the limit.
	EnforcementModeHard EnforcementMode = "hard"
	// EnforcementModeSoft records the allocation but never rejects it.
	EnforcementModeSoft EnforcementMode = "soft"
	// EnforcementModeMetered tracks usage for billing without a ceiling.
	EnforcementModeMetered EnforcementMode = "metered"
	// EnforcementModeDisabled is not enforced at all.
	EnforcementModeDisabled EnforcementMode = "disabled"
)

// Reservation status values, mirroring the quota_reservations status CHECK.
const (
	ReservationStatusActive    = "active"
	ReservationStatusCommitted = "committed"
	ReservationStatusReleased  = "released"
	ReservationStatusExpired   = "expired"
)

// QuotaLimit is the effective limit for one resource within an organization:
// the numeric ceiling plus how it is enforced. It is resolved from
// quota_policies as the organization override if present, else the plan
// default.
type QuotaLimit struct {
	Resource        QuotaResource
	LimitValue      int64
	EnforcementMode EnforcementMode
}

// QuotaScope is which scope produced an effective quota policy: a plan default
// or an organization-level override. The string values match the
// quota_policies.scope_kind column verbatim, so the wire shape of the limits
// API can be projected from this type without a separate translation table.
type QuotaScope string

const (
	// QuotaScopePlanDefault marks an effective limit inherited from the
	// tenant's plan default.
	QuotaScopePlanDefault QuotaScope = "plan_default"
	// QuotaScopeOrganization marks an effective limit set as an organization
	// override; it takes precedence over the plan default for the same
	// resource.
	QuotaScopeOrganization QuotaScope = "organization"
)

// EffectiveQuotaLimit is one resource's resolved limit, along with the scope
// that produced it. It is what the customer-facing GET
// /v1/organizations/{org_id}/limits endpoint projects onto the wire: the
// resolution rule (organization override beats plan default) is applied in
// SQL so the wire shape always matches what the quota checker would see.
type EffectiveQuotaLimit struct {
	Resource        QuotaResource
	LimitValue      int64
	EnforcementMode EnforcementMode
	Scope           QuotaScope
}

// QuotaReservation is a short-lived claim on a resource dimension. An active
// reservation counts against the tenant's limit until it is committed (the
// resource was created) or released/expired (it was not). JobID is the
// provisioning job that owns the reservation; it is empty until the durable
// job table lands.
type QuotaReservation struct {
	ID             string
	OrganizationID string
	Resource       QuotaResource
	Amount         int64
	Status         string
	JobID          string
	ExpiresAt      time.Time
	SettledAt      time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// QuotaRepository is the persistence layer for Yalla's quota system. It follows
// the same transaction pattern as ProjectRepository:
//
//   - Reads accept a Querier, so they run against a read-only transaction or an
//     open write transaction.
//   - Mutations require a *Tx, so they can only run inside the Store.Write
//     transaction that also carries the authorization decision and the
//     desired-state write they guard.
//   - Every query is tenant scoped by organization_id.
//
// The quota checker service in internal/controlplane/quota composes these
// methods into the QuotaReserver unit of work.
type QuotaRepository struct{}

// NewQuotaRepository constructs a QuotaRepository. It is stateless; the
// constructor exists for symmetry with the other repositories and so callers
// depend on the type, not a bare struct literal.
func NewQuotaRepository() *QuotaRepository { return &QuotaRepository{} }

// quotaReservationColumns is the column list returned by every reservation
// query, in the order scanQuotaReservation expects.
const quotaReservationColumns = `id, organization_id, resource, amount, status, job_id, expires_at, settled_at, created_at, updated_at`

// EffectiveLimit resolves the limit that applies to resource for organizationID
// on the given plan. An organization override takes precedence over the plan
// default; a single ordered query resolves both. The boolean is false when no
// policy is configured for the dimension at either scope, in which case the
// resource is unconstrained.
func (r *QuotaRepository) EffectiveLimit(ctx context.Context, q Querier, organizationID, plan string, resource QuotaResource) (QuotaLimit, bool, error) {
	row := q.QueryRow(ctx,
		`SELECT limit_value, enforcement_mode
		   FROM quota_policies
		  WHERE resource = $3
		    AND (
		          (scope_kind = 'organization' AND organization_id = $1)
		       OR (scope_kind = 'plan_default'  AND plan = $2)
		    )
		  ORDER BY (scope_kind = 'organization') DESC
		  LIMIT 1`,
		organizationID, plan, string(resource))
	var (
		limit int64
		mode  string
	)
	if err := row.Scan(&limit, &mode); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return QuotaLimit{}, false, nil
		}
		return QuotaLimit{}, false, apierr.StoreUnavailable(err)
	}
	return QuotaLimit{Resource: resource, LimitValue: limit, EnforcementMode: EnforcementMode(mode)}, true, nil
}

// ListEffectiveLimits resolves the effective limit for every resource that has
// a policy configured for organizationID or its plan, in deterministic
// resource order. Organization overrides win over plan defaults for the same
// resource; resources with no policy at either scope are unconstrained and
// omitted from the result.
//
// The resolution is done in a single SQL statement (a DISTINCT ON over the two
// candidate rows per resource) so the wire shape can never disagree with the
// per-resource EffectiveLimit lookup the quota checker uses, and a single
// round trip is enough regardless of how many dimensions the plan covers.
//
// The query is tenant scoped: only plan defaults for the named plan and
// organization overrides for organizationID are considered, so the result
// never reveals another tenant's policies.
func (r *QuotaRepository) ListEffectiveLimits(ctx context.Context, q Querier, organizationID, plan string) ([]EffectiveQuotaLimit, error) {
	rows, err := q.Query(ctx,
		`SELECT DISTINCT ON (resource) resource, limit_value, enforcement_mode, scope_kind
		   FROM quota_policies
		  WHERE (scope_kind = 'organization' AND organization_id = $1)
		     OR (scope_kind = 'plan_default'  AND plan = $2)
		  ORDER BY resource, (scope_kind = 'organization') DESC`,
		organizationID, plan)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	out := make([]EffectiveQuotaLimit, 0)
	for rows.Next() {
		var (
			resource  string
			limit     int64
			mode      string
			scopeKind string
		)
		if scanErr := rows.Scan(&resource, &limit, &mode, &scopeKind); scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, EffectiveQuotaLimit{
			Resource:        QuotaResource(resource),
			LimitValue:      limit,
			EnforcementMode: EnforcementMode(mode),
			Scope:           QuotaScope(scopeKind),
		})
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, apierr.StoreUnavailable(rowsErr)
	}
	return out, nil
}

// LockUsage ensures the (organization, resource) counter row exists and locks
// it FOR UPDATE for the remainder of tx, returning the current used_value. A
// concurrent unit of work that calls LockUsage for the same tenant and
// resource blocks here until this transaction commits or rolls back — that is
// the primitive that makes it impossible for two units of work to both decide
// they have headroom and over-allocate. It requires a *Tx so the lock can
// never be taken outside the transaction whose write it guards.
func (r *QuotaRepository) LockUsage(ctx context.Context, tx *Tx, organizationID string, resource QuotaResource) (int64, error) {
	if tx == nil {
		return 0, apierr.Internal(errors.New("store: QuotaRepository.LockUsage called with a nil transaction"))
	}
	id, err := newQuotaID("qusg")
	if err != nil {
		return 0, apierr.Internal(err)
	}
	// Ensure a counter row exists. A concurrent reserver that created it first
	// simply wins the ON CONFLICT; either way there is a row to lock next.
	if _, err := tx.Exec(ctx,
		`INSERT INTO quota_usage (id, organization_id, resource)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (organization_id, resource) DO NOTHING`,
		id, organizationID, string(resource)); err != nil {
		return 0, mapWriteError(err, "a quota usage counter for this resource already exists")
	}
	var used int64
	if err := tx.QueryRow(ctx,
		`SELECT used_value FROM quota_usage
		  WHERE organization_id = $1 AND resource = $2
		  FOR UPDATE`,
		organizationID, string(resource)).Scan(&used); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, apierr.Internal(fmt.Errorf("store: quota usage row vanished after upsert for resource %s", resource))
		}
		return 0, apierr.StoreUnavailable(err)
	}
	return used, nil
}

// SumActiveReservations returns the total amount of live reservations for
// organizationID and resource: rows that are still active and have not yet
// passed their expiry as of now. It is the in-flight half of the headroom
// check. The query is tenant scoped by organization_id.
func (r *QuotaRepository) SumActiveReservations(ctx context.Context, q Querier, organizationID string, resource QuotaResource, now time.Time) (int64, error) {
	var sum int64
	if err := q.QueryRow(ctx,
		`SELECT COALESCE(SUM(amount), 0)
		   FROM quota_reservations
		  WHERE organization_id = $1
		    AND resource = $2
		    AND status = 'active'
		    AND expires_at > $3`,
		organizationID, string(resource), now).Scan(&sum); err != nil {
		return 0, apierr.StoreUnavailable(err)
	}
	return sum, nil
}

// InsertReservation writes a new reservation row inside tx and returns the
// persisted row, including the database-assigned timestamps. A blank ID is
// minted here, and a blank Status defaults to active. It requires a *Tx so a
// reservation can never be recorded outside the transaction that also carries
// the headroom check and the desired-state write it guards.
func (r *QuotaRepository) InsertReservation(ctx context.Context, tx *Tx, res QuotaReservation) (QuotaReservation, error) {
	if tx == nil {
		return QuotaReservation{}, apierr.Internal(errors.New("store: QuotaRepository.InsertReservation called with a nil transaction"))
	}
	if res.ID == "" {
		id, err := newQuotaID("qres")
		if err != nil {
			return QuotaReservation{}, apierr.Internal(err)
		}
		res.ID = id
	}
	if res.Status == "" {
		res.Status = ReservationStatusActive
	}
	var jobID *string
	if res.JobID != "" {
		jobID = &res.JobID
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO quota_reservations (id, organization_id, resource, amount, status, job_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING `+quotaReservationColumns,
		res.ID, res.OrganizationID, string(res.Resource), res.Amount, res.Status, jobID, res.ExpiresAt)
	created, err := scanQuotaReservation(row)
	if err != nil {
		return QuotaReservation{}, mapWriteError(err, "a quota reservation with this id already exists")
	}
	return created, nil
}

// scanQuotaReservation scans one reservation row in quotaReservationColumns
// order, mapping the nullable job_id and settled_at columns to their zero
// values when absent.
func scanQuotaReservation(row pgx.Row) (QuotaReservation, error) {
	var (
		res       QuotaReservation
		resource  string
		jobID     *string
		settledAt *time.Time
	)
	if err := row.Scan(
		&res.ID, &res.OrganizationID, &resource, &res.Amount, &res.Status,
		&jobID, &res.ExpiresAt, &settledAt, &res.CreatedAt, &res.UpdatedAt,
	); err != nil {
		return QuotaReservation{}, err
	}
	res.Resource = QuotaResource(resource)
	if jobID != nil {
		res.JobID = *jobID
	}
	if settledAt != nil {
		res.SettledAt = *settledAt
	}
	return res, nil
}

// newQuotaID mints an opaque, non-guessable id for an internal quota accounting
// row — a quota_usage counter or a quota_reservations claim. These rows are not
// customer-facing domain resources, so they carry their own prefixed id rather
// than a domain.Kind id.
func newQuotaID(prefix string) (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("store: generating quota id entropy: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(buf[:]), nil
}
