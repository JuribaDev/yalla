package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// ProjectGrant is the source-of-truth representation of a row in the
// project_grants table — a scoped grant that confers a built-in role on a
// principal at a specific (project, optional environment, optional service)
// target. The policy engine consumes the same shape through policy.Grant on
// the resolved Principal; this struct is the persistence-layer mirror and
// carries no HTTP concerns of its own.
//
// PrincipalKind is closed to domain.KindUser ("usr") or
// domain.KindServiceAccount ("sa") — the two principal kinds the policy
// engine resolves. Role is closed to one of the six built-in role names
// ('owner','admin','developer','viewer','ci','support'); a future custom-role
// migration is the only path that widens the column.
//
// EnvironmentID and ServiceID are pointers so the wire and audit layers can
// distinguish "project-scoped grant" (both nil) from "environment-scoped
// grant" (only EnvironmentID set) from "service-scoped grant" (both set).
// The persistence layer treats them as plain text identifiers without an FK
// — a grant must outlive a recreated environment or service of the same id,
// and a grant whose nested id no longer resolves is simply unreachable
// through the policy engine (a defensive ignore, not a hard error).
//
// Version is the database-owned optimistic-concurrency token: it starts at 1
// on INSERT and is bumped by the project_grants_bump_version trigger on every
// UPDATE. Callers must not mutate it; the trigger is the only writer.
type ProjectGrant struct {
	ID             string
	OrganizationID string
	ProjectID      string
	PrincipalID    string
	PrincipalKind  string
	Role           string
	EnvironmentID  *string
	ServiceID      *string
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ProjectGrantRepository is the persistence half of the project-grants
// surface. It follows the same conventions as ProjectRepository — mutations
// require a *Tx so they cannot be separated from the authorization checks
// that share the transaction, reads accept a Querier so they work against a
// read-only or open write transaction, and every query is tenant scoped by
// organization_id first so a resource id from another organization can never
// match. The repository is stateless; the constructor exists so call sites
// depend on a value rather than a bare struct literal.
type ProjectGrantRepository struct{}

// NewProjectGrantRepository returns a stateless ProjectGrantRepository.
func NewProjectGrantRepository() *ProjectGrantRepository { return &ProjectGrantRepository{} }

// projectGrantColumns is the column list returned by every project_grants
// query, in the order scanProjectGrant expects.
const projectGrantColumns = `id, organization_id, project_id, principal_id, principal_kind, role, environment_id, service_id, version, created_at, updated_at`

// projectGrantListMaxRows caps how many rows a single ListByProject call
// returns. An unbounded query can never be issued by accident; an HTTP layer
// that wants pagination later will add an explicit offset or cursor
// parameter rather than relax this ceiling.
const projectGrantListMaxRows = 500

// ListByProject returns every grant attached to the project identified by
// (organizationID, projectID), ordered deterministically by
// (principal_id, environment_id NULLS FIRST, service_id NULLS FIRST, id) so
// a given set of rows always renders the same response. The query is tenant
// scoped at the persistence layer: it filters by organization_id and
// project_id, so a cross-tenant id simply matches no rows and yields an
// empty slice — a cross-tenant id can never reveal another organization's
// grants. The result is always a non-nil slice (possibly empty) so callers
// can iterate it without a nil check.
//
// This method does NOT verify the project exists; callers that need to
// distinguish "project missing" from "project has no grants" must Get the
// project first (the ProjectGrantReader adapter does so in the same
// short-lived transaction).
func (r *ProjectGrantRepository) ListByProject(ctx context.Context, q Querier, organizationID, projectID string) ([]ProjectGrant, error) {
	rows, err := q.Query(ctx,
		`SELECT `+projectGrantColumns+`
		   FROM project_grants
		  WHERE organization_id = $1 AND project_id = $2
		  ORDER BY principal_id ASC,
		           environment_id ASC NULLS FIRST,
		           service_id ASC NULLS FIRST,
		           id ASC
		  LIMIT $3`,
		organizationID, projectID, projectGrantListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	grants := make([]ProjectGrant, 0)
	for rows.Next() {
		g, scanErr := scanProjectGrant(rows)
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

// scanProjectGrant scans one project_grants row in projectGrantColumns order.
func scanProjectGrant(row pgx.Row) (ProjectGrant, error) {
	var g ProjectGrant
	err := row.Scan(
		&g.ID,
		&g.OrganizationID,
		&g.ProjectID,
		&g.PrincipalID,
		&g.PrincipalKind,
		&g.Role,
		&g.EnvironmentID,
		&g.ServiceID,
		&g.Version,
		&g.CreatedAt,
		&g.UpdatedAt,
	)
	return g, err
}

// ProjectGrantReader is the store-backed read adapter for project_grants. It
// mirrors ProjectReader / OrganizationVariableReader — it composes
// ProjectGrantRepository (and ProjectRepository, for the tenant-scoped
// project existence check) through a short-lived Store.Read transaction, so
// the repository's tenant-scoping guarantees are inherited for free and the
// adapter cannot smuggle a mutation past Store.Write.
type ProjectGrantReader struct {
	store    *Store
	projects *ProjectRepository
	grants   *ProjectGrantRepository
}

// NewProjectGrantReader builds a ProjectGrantReader over store. It returns
// an error for a nil store so a misconfigured adapter fails at construction
// rather than on its first request.
func NewProjectGrantReader(s *Store) (*ProjectGrantReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &ProjectGrantReader{
		store:    s,
		projects: NewProjectRepository(),
		grants:   NewProjectGrantRepository(),
	}, nil
}

// ListProjectGrants returns every grant of the project identified by
// (organizationID, projectID), reading them inside a short-lived read-only
// transaction. The read is tenant scoped at both legs: it Gets the project
// first so a cross-tenant or unknown project_id surfaces as a deterministic
// apierr.NotFound — never as an empty list, which would invite an agent to
// believe the project exists with no grants. A live project with no grants
// is then a deterministic empty slice. A datastore failure is propagated as
// its own typed error.
func (r *ProjectGrantReader) ListProjectGrants(ctx context.Context, organizationID, projectID string) ([]ProjectGrant, error) {
	var grants []ProjectGrant
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, getErr := r.projects.Get(ctx, q, organizationID, projectID); getErr != nil {
			return getErr
		}
		list, listErr := r.grants.ListByProject(ctx, q, organizationID, projectID)
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
