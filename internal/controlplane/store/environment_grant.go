package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// EnvironmentGrant is the source-of-truth representation of a row in the
// environment_grants table — a scoped grant that confers a built-in role on a
// principal at a specific (environment, optional service) target. The policy
// engine consumes the same shape through policy.Grant on the resolved
// Principal; this struct is the persistence-layer mirror and carries no HTTP
// concerns of its own.
//
// PrincipalKind is closed to domain.KindUser ("usr") or
// domain.KindServiceAccount ("sa") — the two principal kinds the policy
// engine resolves. Role is closed to one of the six built-in role names
// ('owner','admin','developer','viewer','ci','support'); a future custom-role
// migration is the only path that widens the column.
//
// ServiceID is a pointer so the wire and audit layers can distinguish
// "environment-scoped grant" (nil) from "service-scoped grant" (set). The
// persistence layer treats it as a plain text identifier without an FK — a
// grant must outlive a recreated service of the same id, and a grant whose
// nested id no longer resolves is simply unreachable through the policy
// engine (a defensive ignore, not a hard error).
//
// Version is the database-owned optimistic-concurrency token: it starts at 1
// on INSERT and is bumped by the environment_grants_bump_version trigger on
// every UPDATE. Callers must not mutate it; the trigger is the only writer.
type EnvironmentGrant struct {
	ID             string
	OrganizationID string
	EnvironmentID  string
	PrincipalID    string
	PrincipalKind  string
	Role           string
	ServiceID      *string
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// EnvironmentGrantRepository is the persistence half of the
// environment-grants surface. It follows the same conventions as
// ProjectGrantRepository — mutations require a *Tx so they cannot be
// separated from the authorization checks that share the transaction, reads
// accept a Querier so they work against a read-only or open write
// transaction, and every query is tenant scoped by organization_id first so
// a resource id from another organization can never match. The repository is
// stateless; the constructor exists so call sites depend on a value rather
// than a bare struct literal.
type EnvironmentGrantRepository struct{}

// NewEnvironmentGrantRepository returns a stateless EnvironmentGrantRepository.
func NewEnvironmentGrantRepository() *EnvironmentGrantRepository {
	return &EnvironmentGrantRepository{}
}

// environmentGrantColumns is the column list returned by every
// environment_grants query, in the order scanEnvironmentGrant expects.
const environmentGrantColumns = `id, organization_id, environment_id, principal_id, principal_kind, role, service_id, version, created_at, updated_at`

// environmentGrantListMaxRows caps how many rows a single ListByEnvironment
// call returns. An unbounded query can never be issued by accident; an HTTP
// layer that wants pagination later will add an explicit offset or cursor
// parameter rather than relax this ceiling.
const environmentGrantListMaxRows = 500

// ListByEnvironment returns every grant attached to the environment
// identified by (organizationID, environmentID), ordered deterministically by
// (principal_id, service_id NULLS FIRST, id) so a given set of rows always
// renders the same response. The query is tenant scoped at the persistence
// layer: it filters by organization_id and environment_id, so a cross-tenant
// id simply matches no rows and yields an empty slice — a cross-tenant id
// can never reveal another organization's grants. The result is always a
// non-nil slice (possibly empty) so callers can iterate it without a nil
// check.
//
// This method does NOT verify the environment exists; callers that need to
// distinguish "environment missing" from "environment has no grants" must
// GetByID the environment first (the EnvironmentGrantReader adapter does so
// in the same short-lived transaction).
func (r *EnvironmentGrantRepository) ListByEnvironment(ctx context.Context, q Querier, organizationID, environmentID string) ([]EnvironmentGrant, error) {
	rows, err := q.Query(ctx,
		`SELECT `+environmentGrantColumns+`
		   FROM environment_grants
		  WHERE organization_id = $1 AND environment_id = $2
		  ORDER BY principal_id ASC,
		           service_id ASC NULLS FIRST,
		           id ASC
		  LIMIT $3`,
		organizationID, environmentID, environmentGrantListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	grants := make([]EnvironmentGrant, 0)
	for rows.Next() {
		g, scanErr := scanEnvironmentGrant(rows)
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

// scanEnvironmentGrant scans one environment_grants row in
// environmentGrantColumns order.
func scanEnvironmentGrant(row pgx.Row) (EnvironmentGrant, error) {
	var g EnvironmentGrant
	err := row.Scan(
		&g.ID,
		&g.OrganizationID,
		&g.EnvironmentID,
		&g.PrincipalID,
		&g.PrincipalKind,
		&g.Role,
		&g.ServiceID,
		&g.Version,
		&g.CreatedAt,
		&g.UpdatedAt,
	)
	return g, err
}

// EnvironmentGrantReader is the store-backed read adapter for
// environment_grants. It mirrors ProjectGrantReader — it composes
// EnvironmentGrantRepository (and EnvironmentRepository, for the
// tenant-scoped environment existence check) through a short-lived
// Store.Read transaction, so the repository's tenant-scoping guarantees are
// inherited for free and the adapter cannot smuggle a mutation past
// Store.Write.
type EnvironmentGrantReader struct {
	store        *Store
	environments *EnvironmentRepository
	grants       *EnvironmentGrantRepository
}

// NewEnvironmentGrantReader builds an EnvironmentGrantReader over store. It
// returns an error for a nil store so a misconfigured adapter fails at
// construction rather than on its first request.
func NewEnvironmentGrantReader(s *Store) (*EnvironmentGrantReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &EnvironmentGrantReader{
		store:        s,
		environments: NewEnvironmentRepository(),
		grants:       NewEnvironmentGrantRepository(),
	}, nil
}

// ListEnvironmentGrants returns every grant of the environment identified by
// (organizationID, environmentID), reading them inside a short-lived
// read-only transaction. The read is tenant scoped at both legs: it
// GetByID's the environment first so a cross-tenant or unknown
// environment_id surfaces as a deterministic apierr.NotFound — never as an
// empty list, which would invite an agent to believe the environment exists
// with no grants. A live environment with no grants is then a deterministic
// empty slice. A datastore failure is propagated as its own typed error.
func (r *EnvironmentGrantReader) ListEnvironmentGrants(ctx context.Context, organizationID, environmentID string) ([]EnvironmentGrant, error) {
	var grants []EnvironmentGrant
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, getErr := r.environments.GetByID(ctx, q, organizationID, environmentID); getErr != nil {
			return getErr
		}
		list, listErr := r.grants.ListByEnvironment(ctx, q, organizationID, environmentID)
		if listErr != nil {
			return listErr
		}
		grants = list
		return nil
	})
	if err != nil {
		return nil, err
	}
	return grants, nil
}
