package store

import (
	"context"
	"errors"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// Project is the source-of-truth representation of a row in the projects
// table. It is the persistence-layer shape; HTTP request and response shapes
// are the job of the httpapi layer.
type Project struct {
	ID             string
	OrganizationID string
	Slug           string
	DisplayName    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ProjectRepository is the reference repository for the transaction pattern
// every customer-data table follows:
//
//   - Mutations require a *Tx, so they can only run inside Store.Write and can
//     never be separated from the authorization and quota checks that share
//     that transaction.
//   - Reads accept a Querier, so they run against either a read-only
//     transaction or an open write transaction.
//   - Every query is tenant scoped by organization_id before resource id, so a
//     resource id from another organization can never match.
//   - Every statement is fully parameterized; no SQL is built by concatenating
//     caller input.
//   - Missing rows are reported as a typed apierr.NotFound, never a bare
//     pgx.ErrNoRows.
//
// The repository is stateless; the constructor exists so call sites depend on
// a value rather than a bare struct literal.
type ProjectRepository struct{}

// NewProjectRepository returns a ProjectRepository.
func NewProjectRepository() *ProjectRepository { return &ProjectRepository{} }

// projectColumns is the column list returned by every project query, in the
// order scanProject expects.
const projectColumns = `id, organization_id, slug, display_name, created_at, updated_at`

// Insert writes a new project row inside tx and returns the persisted row,
// including the database-assigned timestamps. It requires a *Tx — not a bare
// Querier — so a project can never be created outside the transaction that
// also carries its authorization and quota checks. A slug that collides with
// an existing project in the same organization is reported as a Conflict.
func (r *ProjectRepository) Insert(ctx context.Context, tx *Tx, p Project) (Project, error) {
	if tx == nil {
		return Project{}, apierr.Internal(errors.New("store: ProjectRepository.Insert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO projects (id, organization_id, slug, display_name)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+projectColumns,
		p.ID, p.OrganizationID, p.Slug, p.DisplayName)
	created, err := scanProject(row)
	if err != nil {
		return Project{}, mapWriteError(err, "a project with this slug already exists in the organization")
	}
	return created, nil
}

// Get returns the project identified by projectID within organizationID. The
// query is tenant scoped: it filters by organization_id first, so a project id
// that belongs to another organization simply does not match and is reported
// as NotFound — a cross-tenant id can never reveal another organization's
// data. It accepts a Querier so it works against a read-only transaction or an
// open write transaction.
func (r *ProjectRepository) Get(ctx context.Context, q Querier, organizationID, projectID string) (Project, error) {
	row := q.QueryRow(ctx,
		`SELECT `+projectColumns+`
		 FROM projects
		 WHERE organization_id = $1 AND id = $2`,
		organizationID, projectID)
	p, err := scanProject(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, apierr.NotFound("project", projectID)
	}
	if err != nil {
		return Project{}, apierr.StoreUnavailable(err)
	}
	return p, nil
}

// CountByOrganization returns the number of projects owned by organizationID.
// It is the read the quota layer uses to enforce a per-organization project
// limit; running it through the same *Tx as the insert keeps the check
// race-free.
func (r *ProjectRepository) CountByOrganization(ctx context.Context, q Querier, organizationID string) (int, error) {
	var n int
	if err := q.QueryRow(ctx,
		`SELECT count(*) FROM projects WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		return 0, apierr.StoreUnavailable(err)
	}
	return n, nil
}

// scanProject scans one project row in projectColumns order.
func scanProject(row pgx.Row) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.OrganizationID, &p.Slug, &p.DisplayName, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}
