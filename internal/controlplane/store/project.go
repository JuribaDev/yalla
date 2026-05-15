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
//
// Version is the database-owned optimistic-concurrency token: it starts at 1
// on INSERT and is bumped by the projects_bump_version trigger on every
// UPDATE. Callers must not mutate it; the trigger is the only writer.
type Project struct {
	ID             string
	OrganizationID string
	Slug           string
	DisplayName    string
	Version        int64
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
const projectColumns = `id, organization_id, slug, display_name, version, created_at, updated_at`

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

// ListByOrganization returns every project owned by organizationID, ordered
// deterministically by (slug, id) so a given set of rows always renders the
// same response. The query is tenant scoped at the persistence layer: it
// filters by organization_id, so a cross-tenant id simply matches no rows
// and yields an empty slice — a cross-tenant id can never reveal another
// organization's projects. It accepts a Querier so it works against a
// read-only transaction or an open write transaction. The result is always
// a non-nil slice (possibly empty) so callers can iterate it without a nil
// check.
func (r *ProjectRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string) ([]Project, error) {
	rows, err := q.Query(ctx,
		`SELECT `+projectColumns+`
		 FROM projects
		 WHERE organization_id = $1
		 ORDER BY slug ASC, id ASC`,
		organizationID)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	projects := make([]Project, 0)
	for rows.Next() {
		p, scanErr := scanProject(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		projects = append(projects, p)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return projects, nil
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
	err := row.Scan(&p.ID, &p.OrganizationID, &p.Slug, &p.DisplayName, &p.Version, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// ProjectReader is the store-backed read adapter for project resources: the
// persistence surface the httpapi layer needs to render GET /v1/projects.
// It mirrors OrganizationReader / MembershipReader — it composes the
// ProjectRepository rather than issuing its own SQL, so the tenant-scoping
// guarantees the repository proves in its integration tests are inherited
// for free, and every method opens its own short-lived read transaction
// through Store.Read.
type ProjectReader struct {
	store    *Store
	projects *ProjectRepository
}

// NewProjectReader builds a ProjectReader over store. It returns an error
// for a nil store so a misconfigured adapter fails at construction rather
// than on its first request.
func NewProjectReader(s *Store) (*ProjectReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &ProjectReader{store: s, projects: NewProjectRepository()}, nil
}

// ListProjects returns every project of organizationID, reading them inside
// a short-lived read-only transaction. The read is tenant scoped: a
// cross-tenant id simply matches no rows and yields an empty slice, never
// another organization's projects. A datastore failure is propagated as
// its own typed error.
func (r *ProjectReader) ListProjects(ctx context.Context, organizationID string) ([]Project, error) {
	var projects []Project
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var listErr error
		projects, listErr = r.projects.ListByOrganization(ctx, q, organizationID)
		return listErr
	})
	if err != nil {
		return nil, err
	}
	return projects, nil
}

// GetProject returns the project identified by (organizationID, projectID),
// reading it inside a short-lived read-only transaction. The read is tenant
// scoped at the persistence layer: the repository filters by
// organization_id first, so a projectID that belongs to another organization
// simply does not match and is reported as a typed apierr.NotFound — a
// cross-tenant id can never reveal another organization's data. A datastore
// failure is propagated as its own typed error and never disguised as a
// not-found.
func (r *ProjectReader) GetProject(ctx context.Context, organizationID, projectID string) (Project, error) {
	var project Project
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var getErr error
		project, getErr = r.projects.Get(ctx, q, organizationID, projectID)
		return getErr
	})
	if err != nil {
		return Project{}, err
	}
	return project, nil
}

// UpdateDisplayName writes a new display_name for the project identified by
// (organizationID, projectID) inside tx and returns the persisted row,
// including the trigger-refreshed updated_at timestamp and bumped version.
// It requires a *Tx — not a bare Querier — so a project can never be
// mutated outside the transaction that also carries its authorization,
// quota, audit, and provisioning checks. The query is tenant scoped: a
// projectID that belongs to another organization simply does not match and
// is reported as NotFound, so a cross-tenant id can never reveal another
// organization's data.
//
// ifMatchVersion enforces optimistic concurrency identically to the
// organization repository: a nil pointer disables the check (next-write-wins
// behaviour), a non-nil pointer adds a WHERE clause on the row's current
// version, and a stale view is reported as a typed apierr.ConflictStale
// carrying the row's authoritative version. The HTTP layer that exposes
// PATCH /v1/projects/{project_id} fills it from the request's If-Match
// header; this method exists so the optimistic-concurrency contract can be
// exercised against the projects table at the persistence layer in
// isolation from the full Update path.
func (r *ProjectRepository) UpdateDisplayName(ctx context.Context, tx *Tx, organizationID, projectID, displayName string, ifMatchVersion *int64) (Project, error) {
	if tx == nil {
		return Project{}, apierr.Internal(errors.New("store: ProjectRepository.UpdateDisplayName called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`UPDATE projects
			    SET display_name = $3
			  WHERE organization_id = $1 AND id = $2
			 RETURNING `+projectColumns,
			organizationID, projectID, displayName)
	} else {
		row = tx.QueryRow(ctx,
			`UPDATE projects
			    SET display_name = $3
			  WHERE organization_id = $1 AND id = $2 AND version = $4
			 RETURNING `+projectColumns,
			organizationID, projectID, displayName, *ifMatchVersion)
	}
	updated, err := scanProject(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return Project{}, apierr.NotFound("project", projectID)
		}
		return Project{}, classifyProjectConcurrencyMiss(ctx, r, tx, organizationID, projectID)
	}
	if err != nil {
		return Project{}, mapWriteError(err, "a project with this slug already exists in the organization")
	}
	return updated, nil
}

// Update writes new slug and display_name values for the project identified
// by (p.OrganizationID, p.ID) inside tx and returns the persisted row,
// including the trigger-refreshed updated_at timestamp and bumped version.
// It requires a *Tx — not a bare Querier — so a project can never be
// mutated outside the transaction that also carries its authorization,
// quota, audit, and provisioning checks. The query is tenant scoped by
// organization_id first, so a projectID that belongs to another organization
// simply does not match and is reported as NotFound — a cross-tenant id can
// never reveal another organization's data.
//
// ifMatchVersion enforces optimistic concurrency identically to the
// organization repository: a nil pointer disables the check (next-write-wins
// behaviour), a non-nil pointer adds a WHERE clause on the row's current
// version, and a stale view is reported as a typed apierr.ConflictStale
// carrying the row's authoritative version. A slug that collides with
// another project in the same organization is reported as a typed Conflict.
func (r *ProjectRepository) Update(ctx context.Context, tx *Tx, p Project, ifMatchVersion *int64) (Project, error) {
	if tx == nil {
		return Project{}, apierr.Internal(errors.New("store: ProjectRepository.Update called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`UPDATE projects
			    SET slug = $3, display_name = $4
			  WHERE organization_id = $1 AND id = $2
			 RETURNING `+projectColumns,
			p.OrganizationID, p.ID, p.Slug, p.DisplayName)
	} else {
		row = tx.QueryRow(ctx,
			`UPDATE projects
			    SET slug = $3, display_name = $4
			  WHERE organization_id = $1 AND id = $2 AND version = $5
			 RETURNING `+projectColumns,
			p.OrganizationID, p.ID, p.Slug, p.DisplayName, *ifMatchVersion)
	}
	updated, err := scanProject(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return Project{}, apierr.NotFound("project", p.ID)
		}
		return Project{}, classifyProjectConcurrencyMiss(ctx, r, tx, p.OrganizationID, p.ID)
	}
	if err != nil {
		return Project{}, mapWriteError(err, "a project with this slug already exists in the organization")
	}
	return updated, nil
}

// classifyProjectConcurrencyMiss disambiguates the two reasons a
// version-checked UPDATE matched no rows: the project was deleted (rare,
// and reported as NotFound for parity with the unchecked path) or the
// caller's view of the version is stale (reported as ConflictStale with the
// row's current version). It runs inside the same transaction so the
// disambiguation is consistent with the failed UPDATE. The query is tenant
// scoped, so a cross-tenant id is still reported as NotFound.
func classifyProjectConcurrencyMiss(ctx context.Context, r *ProjectRepository, tx *Tx, organizationID, projectID string) error {
	current, getErr := r.Get(ctx, tx, organizationID, projectID)
	if getErr != nil {
		return getErr
	}
	return apierr.ConflictStale(current.Version)
}
