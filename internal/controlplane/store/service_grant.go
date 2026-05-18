package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// ServiceGrant is the source-of-truth representation of a row in the
// service_grants table — a scoped grant that confers a built-in role on a
// principal at a specific service. The policy engine consumes the same shape
// through policy.Grant on the resolved Principal; this struct is the
// persistence-layer mirror and carries no HTTP concerns of its own.
//
// PrincipalKind is closed to "usr" or "sa" — the two principal kinds the
// policy engine resolves. Role is closed to one of the six built-in role
// names ('owner','admin','developer','viewer','ci','support'); a future
// custom-role migration is the only path that widens the column.
//
// Unlike ProjectGrant and EnvironmentGrant, a service-scoped grant has no
// further nested scope pointers: the service is already the leaf of the
// Organization -> Project -> Environment -> Service hierarchy, so a grant
// cannot be narrowed below the service.
//
// Version is the database-owned optimistic-concurrency token: it starts at 1
// on INSERT and is bumped by the service_grants_bump_version trigger on every
// UPDATE. Callers must not mutate it; the trigger is the only writer.
type ServiceGrant struct {
	ID             string
	OrganizationID string
	ServiceID      string
	PrincipalID    string
	PrincipalKind  string
	Role           string
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ServiceGrantRepository is the persistence half of the service-grants
// surface. It follows the same conventions as EnvironmentGrantRepository —
// mutations require a *Tx so they cannot be separated from the authorization
// checks that share the transaction, reads accept a Querier so they work
// against a read-only or open write transaction, and every query is tenant
// scoped by organization_id first so a resource id from another organization
// can never match. The repository is stateless; the constructor exists so
// call sites depend on a value rather than a bare struct literal.
type ServiceGrantRepository struct{}

// NewServiceGrantRepository returns a stateless ServiceGrantRepository.
func NewServiceGrantRepository() *ServiceGrantRepository {
	return &ServiceGrantRepository{}
}

// serviceGrantColumns is the column list returned by every service_grants
// query, in the order scanServiceGrant expects.
const serviceGrantColumns = `id, organization_id, service_id, principal_id, principal_kind, role, version, created_at, updated_at`

// serviceGrantListMaxRows caps how many rows a single ListByService call
// returns. An unbounded query can never be issued by accident; an HTTP layer
// that wants pagination later will add an explicit offset or cursor
// parameter rather than relax this ceiling.
const serviceGrantListMaxRows = 500

// ListByService returns every grant attached to the service identified by
// (organizationID, serviceID), ordered deterministically by
// (principal_id, id) so a given set of rows always renders the same
// response. The query is tenant scoped at the persistence layer: it filters
// by organization_id and service_id, so a cross-tenant id simply matches no
// rows and yields an empty slice — a cross-tenant id can never reveal
// another organization's grants. The result is always a non-nil slice
// (possibly empty) so callers can iterate it without a nil check.
//
// This method does NOT verify the service exists; callers that need to
// distinguish "service missing" from "service has no grants" must Get the
// service first (a future ServiceGrantReader adapter will compose that
// check in the same short-lived transaction).
func (r *ServiceGrantRepository) ListByService(ctx context.Context, q Querier, organizationID, serviceID string) ([]ServiceGrant, error) {
	rows, err := q.Query(ctx,
		`SELECT `+serviceGrantColumns+`
		   FROM service_grants
		  WHERE organization_id = $1 AND service_id = $2
		  ORDER BY principal_id ASC,
		           id ASC
		  LIMIT $3`,
		organizationID, serviceID, serviceGrantListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	grants := make([]ServiceGrant, 0)
	for rows.Next() {
		g, scanErr := scanServiceGrant(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return grants, nil
}

// Upsert installs the grant identified by the scope-tuple
// (organization_id, service_id, principal_id) — the same composite key the
// service_grants_organization_id_service_id_principal_id_key unique
// constraint enforces — and returns the persisted row. If a row at that
// scope tuple already exists, only the role (the only customer-mutable
// field) is updated; the immutable identifiers (id, organization_id,
// service_id, principal_id, principal_kind) and the lifecycle stamps are
// preserved. The service_grants_bump_version trigger refreshes version +
// updated_at on the UPDATE branch.
//
// The caller-supplied id is used only on the INSERT branch — it is ignored
// when a row already exists at the scope tuple, so a re-upsert is
// idempotent at the customer's view of the resource (same scope tuple =
// same logical grant). principal_kind is not part of the scope tuple, so
// an existing row stays at its current principal_kind even if the caller
// supplied a different one for the same principal_id; promoting or
// demoting a principal's grant is therefore a role change, not a
// principal_kind change — a guarantee a future Replace orchestrator relies
// on so cross-kind smuggling is impossible.
//
// The mutation requires a *Tx so it cannot be separated from the
// authorization check or the audit append that share the transaction; a
// nil transaction is a programming error and is reported as Internal.
func (r *ServiceGrantRepository) Upsert(ctx context.Context, tx *Tx, id, organizationID, serviceID, principalID, principalKind, role string) (ServiceGrant, error) {
	if tx == nil {
		return ServiceGrant{}, apierr.Internal(errors.New("store: ServiceGrantRepository.Upsert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO service_grants
		   (id, organization_id, service_id, principal_id, principal_kind, role)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (organization_id, service_id, principal_id)
		 DO UPDATE SET role = EXCLUDED.role
		 RETURNING `+serviceGrantColumns,
		id, organizationID, serviceID, principalID, principalKind, role)
	g, err := scanServiceGrant(row)
	if err != nil {
		return ServiceGrant{}, mapWriteError(err, "a service grant with this id already exists")
	}
	return g, nil
}

// DeleteByServiceExceptIDs removes every service_grants row owned by
// (organizationID, serviceID) whose id is NOT in keepIDs. It is the bulk
// delete-by-exclusion half of the PUT replace contract: callers Upsert the
// replacement rows first, then call this method with the persisted ids of
// the rows to retain, and any row whose id is absent is dropped. The query
// is tenant scoped (filters by organization_id AND service_id) so a
// cross-tenant id can never reach into another organization's grants.
//
// keepIDs may be empty — that means "drop every grant of this service",
// which is the deliberate semantic of a PUT with grants:[]: a customer
// explicitly asking to clear every grant of a service is meaningful
// (extreme), not a silent no-op. nil and an empty slice are treated
// identically: every row at (organizationID, serviceID) is removed. The
// mutation requires a *Tx so it cannot be separated from the audit append;
// a nil transaction is a programming error.
func (r *ServiceGrantRepository) DeleteByServiceExceptIDs(ctx context.Context, tx *Tx, organizationID, serviceID string, keepIDs []string) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: ServiceGrantRepository.DeleteByServiceExceptIDs called with a nil transaction"))
	}
	if len(keepIDs) == 0 {
		_, err := tx.Exec(ctx,
			`DELETE FROM service_grants
			  WHERE organization_id = $1 AND service_id = $2`,
			organizationID, serviceID)
		if err != nil {
			return apierr.StoreUnavailable(err)
		}
		return nil
	}
	_, err := tx.Exec(ctx,
		`DELETE FROM service_grants
		  WHERE organization_id = $1 AND service_id = $2
		    AND NOT (id = ANY($3::text[]))`,
		organizationID, serviceID, keepIDs)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	return nil
}

// scanServiceGrant scans one service_grants row in serviceGrantColumns order.
func scanServiceGrant(row pgx.Row) (ServiceGrant, error) {
	var g ServiceGrant
	err := row.Scan(
		&g.ID,
		&g.OrganizationID,
		&g.ServiceID,
		&g.PrincipalID,
		&g.PrincipalKind,
		&g.Role,
		&g.Version,
		&g.CreatedAt,
		&g.UpdatedAt,
	)
	return g, err
}
