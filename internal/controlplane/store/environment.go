package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

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
// DeletionScheduledAt is the soft-delete marker added by migration 0016
// (mirroring projects.deletion_scheduled_at from 0013): NULL means the
// environment is live; a non-NULL value means it has been scheduled for
// teardown. The destructive teardown — the cascade that removes the
// environment's services and audit trail — is carried out by a later
// worker story, so the row and its audit trail still exist after a
// scheduled deletion returns.
//
// The struct carries no credential material — the environments table stores
// only structural identifiers and lifecycle timestamps. Environment-scoped
// secrets live in a later environment_variables migration and are redacted
// wherever they are handled.
type Environment struct {
	ID                  string
	OrganizationID      string
	ProjectID           string
	Slug                string
	DisplayName         string
	Kind                string
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DeletionScheduledAt *time.Time
}

// environmentColumns is the SELECT projection used by every read in this
// repository. Keeping it as a single string keeps the column list in
// lockstep with scanEnvironment.
const environmentColumns = `id, organization_id, project_id, slug, display_name, kind, version, created_at, updated_at, deletion_scheduled_at`

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
		`INSERT INTO environments (id, organization_id, project_id, slug, display_name, kind)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING `+environmentColumns,
		e.ID, e.OrganizationID, e.ProjectID, e.Slug, e.DisplayName, e.Kind)
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

// Update writes new slug and display_name values for the environment
// identified by (e.OrganizationID, e.ID) inside tx and returns the
// persisted row, including the trigger-refreshed updated_at timestamp
// and bumped version. It requires a *Tx — not a bare Querier — so an
// environment can never be mutated outside the transaction that also
// carries its audit record. The query is tenant scoped by
// organization_id first, so an environment id that belongs to another
// organization simply does not match and is reported as NotFound — a
// cross-tenant id can never reveal another organization's data. The
// parent project relationship is preserved by construction: the UPDATE
// touches only the mutable columns (slug, display_name) and never the
// composite (organization_id, project_id) tenant key.
//
// ifMatchVersion enforces optimistic concurrency identically to the
// projects repository: a nil pointer disables the check
// (next-write-wins behaviour), a non-nil pointer adds a WHERE clause
// on the row's current version, and a stale view is reported as a
// typed apierr.ConflictStale carrying the row's authoritative version.
// A slug that collides with another environment in the same project
// violates UNIQUE (project_id, slug) and surfaces through
// mapWriteError as a deterministic apierr.Conflict, never as a 500
// leaking the constraint name.
func (r *EnvironmentRepository) Update(ctx context.Context, tx *Tx, e Environment, ifMatchVersion *int64) (Environment, error) {
	if tx == nil {
		return Environment{}, apierr.Internal(errors.New("store: EnvironmentRepository.Update called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`UPDATE environments
			    SET slug = $3, display_name = $4
			  WHERE organization_id = $1 AND id = $2
			 RETURNING `+environmentColumns,
			e.OrganizationID, e.ID, e.Slug, e.DisplayName)
	} else {
		row = tx.QueryRow(ctx,
			`UPDATE environments
			    SET slug = $3, display_name = $4
			  WHERE organization_id = $1 AND id = $2 AND version = $5
			 RETURNING `+environmentColumns,
			e.OrganizationID, e.ID, e.Slug, e.DisplayName, *ifMatchVersion)
	}
	updated, err := scanEnvironment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return Environment{}, apierr.NotFound("environment", e.ID)
		}
		return Environment{}, classifyEnvironmentConcurrencyMiss(ctx, r, tx, e.OrganizationID, e.ID)
	}
	if err != nil {
		return Environment{}, mapWriteError(err, "an environment with this slug already exists in the project")
	}
	return updated, nil
}

// classifyEnvironmentConcurrencyMiss disambiguates the two reasons a
// version-checked UPDATE matched no rows: the environment was deleted
// (rare, and reported as NotFound for parity with the unchecked path)
// or the caller's view of the version is stale (reported as
// ConflictStale with the row's current version). It runs inside the
// same transaction so the disambiguation is consistent with the failed
// UPDATE. The query is tenant scoped, so a cross-tenant id is still
// reported as NotFound.
func classifyEnvironmentConcurrencyMiss(ctx context.Context, r *EnvironmentRepository, tx *Tx, organizationID, environmentID string) error {
	current, getErr := r.GetByID(ctx, tx, organizationID, environmentID)
	if getErr != nil {
		return getErr
	}
	return apierr.ConflictStale(current.Version)
}

// GetByID returns the single environments row identified by
// (organizationID, environmentID), tenant-scoped at the SQL predicate. The
// composite predicate is non-optional: a missing or cross-tenant
// organizationID matches no row even when an environment with the same id
// exists in another tenant, so the response is never an oracle that
// reveals another organization's environment ids. A row that does not
// exist — whether because it was never created, was destructively torn
// down, or simply belongs to another tenant — surfaces as the same typed
// apierr.NotFound, never as a 500 leaking the cause; the not-found
// payload names only the env_id the caller already supplied. A raw
// driver error surfaces as the typed apierr.StoreUnavailable — the
// cause is wrapped for logging only, never leaked into the
// customer-facing message.
//
// GetByID is the persistence half of GET /v1/environments/{environment_id};
// the EnvironmentReader adapter composes it inside a short-lived
// read-only transaction so the tenant boundary the predicate proves at
// the database is inherited by the HTTP boundary for free.
func (r *EnvironmentRepository) GetByID(ctx context.Context, q Querier, organizationID, environmentID string) (Environment, error) {
	row := q.QueryRow(ctx,
		`SELECT `+environmentColumns+`
		   FROM environments
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, environmentID)
	e, err := scanEnvironment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Environment{}, apierr.NotFound("environment", environmentID)
	}
	if err != nil {
		return Environment{}, apierr.StoreUnavailable(err)
	}
	return e, nil
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
		&e.Kind,
		&e.Version,
		&e.CreatedAt,
		&e.UpdatedAt,
		&e.DeletionScheduledAt,
	); err != nil {
		return Environment{}, err
	}
	return e, nil
}

// ScheduleDeletion stamps deletion_scheduled_at = now() on the environment
// identified by (organizationID, environmentID) inside tx and returns the
// persisted row, including the trigger-refreshed updated_at timestamp and
// bumped version. It requires a *Tx — not a bare Querier — so an
// environment can never be marked for teardown outside the transaction
// that also carries its audit record. The query is tenant scoped by
// organization_id first, so an environmentID that belongs to another
// organization simply does not match and is reported as NotFound — a
// cross-tenant id can never schedule another organization's environment
// for teardown. The parent project relationship is preserved by
// construction: the UPDATE touches only deletion_scheduled_at and never
// the composite (organization_id, project_id) tenant key.
//
// The UPDATE is unconditional in its predicate apart from the optional
// version check: re-scheduling an environment already scheduled for
// deletion is a conflict the EnvironmentService detects with a prior read
// inside the same transaction, not a not-found this repository can
// distinguish (the repository must remain SQL-idempotent for non-customer
// callers — workers, admin jobs — that need a stable retry surface).
//
// ifMatchVersion enforces optimistic concurrency identically to Update — a
// nil pointer disables the check, a non-nil pointer adds a WHERE clause on
// the current version, and a stale view is reported as a typed
// apierr.ConflictStale carrying the row's authoritative version through
// classifyEnvironmentConcurrencyMiss.
func (r *EnvironmentRepository) ScheduleDeletion(ctx context.Context, tx *Tx, organizationID, environmentID string, ifMatchVersion *int64) (Environment, error) {
	if tx == nil {
		return Environment{}, apierr.Internal(errors.New("store: EnvironmentRepository.ScheduleDeletion called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`UPDATE environments
			    SET deletion_scheduled_at = now()
			  WHERE organization_id = $1 AND id = $2
			 RETURNING `+environmentColumns,
			organizationID, environmentID)
	} else {
		row = tx.QueryRow(ctx,
			`UPDATE environments
			    SET deletion_scheduled_at = now()
			  WHERE organization_id = $1 AND id = $2 AND version = $3
			 RETURNING `+environmentColumns,
			organizationID, environmentID, *ifMatchVersion)
	}
	updated, err := scanEnvironment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return Environment{}, apierr.NotFound("environment", environmentID)
		}
		return Environment{}, classifyEnvironmentConcurrencyMiss(ctx, r, tx, organizationID, environmentID)
	}
	if err != nil {
		return Environment{}, apierr.StoreUnavailable(err)
	}
	return updated, nil
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

// GetEnvironment returns the single environment identified by
// (organizationID, environmentID), reading it inside a short-lived
// read-only transaction. The read is tenant-scoped at the SQL leg, so a
// cross-tenant or unknown environment_id surfaces as a deterministic
// apierr.NotFound — never as another tenant's row, and never as a 500
// leaking the cause. A live environment in the principal's own tenant
// returns the persisted row verbatim. A datastore failure is propagated
// as its own typed error.
//
// GetEnvironment is the persistence half of GET
// /v1/environments/{environment_id} (BE-0154): the bare top-level
// lookup-by-id endpoint that does not carry the parent project_id in
// its path. The handler authorizes on action environment.read against
// the (principal home organization, environment_id) resource the
// resolver builds, and trusts this method to keep the tenant boundary
// at the persistence layer even when the policy resource scope cannot
// pin the parent project_id.
func (r *EnvironmentReader) GetEnvironment(ctx context.Context, organizationID, environmentID string) (Environment, error) {
	var env Environment
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		got, getErr := r.environments.GetByID(ctx, q, organizationID, environmentID)
		if getErr != nil {
			return getErr
		}
		env = got
		return nil
	})
	if err != nil {
		return Environment{}, err
	}
	return env, nil
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
