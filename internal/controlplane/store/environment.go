package store

import (
	"context"
	"errors"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// Environment is the source-of-truth representation of a row in the
// environments table. An environment belongs to exactly one project and
// inherits the project's organization through the composite (organization_id,
// project_id) foreign key declared in migration 0002 — a child can never
// cross the tenant boundary at the database, regardless of application bugs.
//
// Version is the database-owned optimistic-concurrency token: it starts at 1
// on INSERT and is bumped by the environments_bump_version trigger from
// migration 0011 on every UPDATE. Callers must not mutate it; the trigger is
// the only writer. The HTTP layer surfaces it as the optimistic-concurrency
// counter callers use as an If-Match precondition on PATCH / DELETE in
// later stories.
//
// The struct carries no credential material — the environments table stores
// only structural identifiers and lifecycle timestamps. Environment-scoped
// secrets live in a later environment_variables migration and are redacted
// wherever they are handled.
type Environment struct {
	ID             string
	OrganizationID string
	ProjectID      string
	Slug           string
	DisplayName    string
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// environmentColumns is the SELECT projection used by every read in this
// repository. Keeping it as a single string keeps the column list in
// lockstep with scanEnvironment.
const environmentColumns = `id, organization_id, project_id, slug, display_name, version, created_at, updated_at`

// environmentListMaxRows caps how many rows a single ListByProject call
// returns. An unbounded query can never be issued by accident; an HTTP
// layer that wants pagination later will add an explicit offset or cursor
// parameter rather than relax this ceiling.
const environmentListMaxRows = 500

// EnvironmentRepository is the persistence half of the environments
// surface. Every read is tenant-scoped: the organization_id and project_id
// legs of the predicate are non-optional, so a missing or cross-tenant id
// simply matches no rows and yields an empty list — never another tenant's
// environments. The repository is stateless; the constructor exists so
// call sites depend on a value rather than a bare struct literal.
type EnvironmentRepository struct{}

// NewEnvironmentRepository builds a stateless EnvironmentRepository.
func NewEnvironmentRepository() *EnvironmentRepository { return &EnvironmentRepository{} }

// Insert writes a new environments row inside the supplied transaction
// and returns the persisted row, in environmentColumns order, so the
// caller sees the database-assigned timestamps and the initial version
// (1) without re-reading. Calling Insert with a nil transaction is a
// wiring error and is reported as a typed apierr.Internal so the bug
// can never silently degrade into a "succeeded with no audit trail"
// failure mode.
//
// The schema enforces the tenant invariant — the composite foreign key
// (organization_id, project_id) references projects (organization_id, id)
// — so an environment whose organization_id does not match its parent
// project's row is rejected at the database before it can be persisted,
// regardless of application bugs. A slug already taken by another
// environment in the same project violates UNIQUE (project_id, slug)
// and surfaces through mapWriteError as a deterministic
// apierr.Conflict, never as a 500 leaking the constraint name.
func (r *EnvironmentRepository) Insert(ctx context.Context, tx *Tx, e Environment) (Environment, error) {
	if tx == nil {
		return Environment{}, apierr.Internal(errors.New("store: EnvironmentRepository.Insert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO environments (id, organization_id, project_id, slug, display_name)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING `+environmentColumns,
		e.ID, e.OrganizationID, e.ProjectID, e.Slug, e.DisplayName)
	created, err := scanEnvironment(row)
	if err != nil {
		return Environment{}, mapWriteError(err, "an environment with this slug already exists in the project")
	}
	return created, nil
}

// ListByProject returns every environment owned by (organizationID,
// projectID), in deterministic (slug ASC, id ASC) order so an agent
// observing the response sees a stable ordering across calls. The read
// is tenant-scoped at the SQL predicate, so a cross-tenant (organization,
// project) tuple matches no rows. A raw driver error surfaces as the
// typed apierr.StoreUnavailable — the cause is wrapped for logging only,
// never leaked into the customer-facing message.
//
// This method does NOT verify the project exists; callers that need to
// distinguish "project missing" from "project has no environments" must
// Get the project first (the EnvironmentReader adapter does so in the
// same short-lived transaction).
func (r *EnvironmentRepository) ListByProject(ctx context.Context, q Querier, organizationID, projectID string) ([]Environment, error) {
	rows, err := q.Query(ctx,
		`SELECT `+environmentColumns+`
		   FROM environments
		  WHERE organization_id = $1 AND project_id = $2
		  ORDER BY slug ASC, id ASC
		  LIMIT $3`,
		organizationID, projectID, environmentListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]Environment, 0)
	for rows.Next() {
		e, scanErr := scanEnvironment(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// scanEnvironment scans one environments row in environmentColumns order.
func scanEnvironment(row scanRow) (Environment, error) {
	var e Environment
	if err := row.Scan(
		&e.ID,
		&e.OrganizationID,
		&e.ProjectID,
		&e.Slug,
		&e.DisplayName,
		&e.Version,
		&e.CreatedAt,
		&e.UpdatedAt,
	); err != nil {
		return Environment{}, err
	}
	return e, nil
}

// EnvironmentReader is the store-backed read adapter for the environments
// surface: the persistence surface the httpapi layer needs to render GET
// /v1/projects/{project_id}/environments. It mirrors ProjectVariableReader —
// it composes ProjectRepository and EnvironmentRepository through a
// short-lived read-only transaction (Store.Read), so the tenant-scoping
// guarantees the repositories prove in their integration tests are
// inherited for free, and every cross-tenant or unknown project_id
// surfaces as a deterministic apierr.NotFound rather than an empty list.
type EnvironmentReader struct {
	store        *Store
	projects     *ProjectRepository
	environments *EnvironmentRepository
}

// NewEnvironmentReader builds an EnvironmentReader over store. It returns
// an error for a nil store so a misconfigured adapter fails at
// construction rather than on its first request.
func NewEnvironmentReader(s *Store) (*EnvironmentReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &EnvironmentReader{
		store:        s,
		projects:     NewProjectRepository(),
		environments: NewEnvironmentRepository(),
	}, nil
}

// ListProjectEnvironments returns every environment owned by
// (organizationID, projectID), reading them inside a short-lived
// read-only transaction. The read is tenant scoped at both legs: it Gets
// the project first so a cross-tenant or unknown project_id surfaces as a
// deterministic apierr.NotFound — never as an empty list, which would
// invite an agent to believe the project exists with no environments. A
// live project with no environments is then a deterministic empty slice.
// A datastore failure is propagated as its own typed error.
func (r *EnvironmentReader) ListProjectEnvironments(ctx context.Context, organizationID, projectID string) ([]Environment, error) {
	var envs []Environment
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, getErr := r.projects.Get(ctx, q, organizationID, projectID); getErr != nil {
			return getErr
		}
		list, listErr := r.environments.ListByProject(ctx, q, organizationID, projectID)
		if listErr != nil {
			return listErr
		}
		envs = list
		return nil
	})
	if err != nil {
		return nil, err
	}
	return envs, nil
}
