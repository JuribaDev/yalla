package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// PreviewEnvironment is the project-scoped lifecycle record for an
// ephemeral preview environment. The actual deployable clone is an
// environments row with kind='preview'; this row carries the source
// environment, change reference, status, expiry, and teardown marker
// the preview API and worker need without exposing raw Dokploy state.
type PreviewEnvironment struct {
	ID                  string
	OrganizationID      string
	ProjectID           string
	EnvironmentID       string
	SourceEnvironmentID string
	DisplayName         string
	ChangeRef           string
	Status              string
	ExpiresAt           *time.Time
	DeletionScheduledAt *time.Time
	Version             int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

const previewEnvironmentColumns = `id, organization_id, project_id, environment_id, source_environment_id, display_name, change_ref, status, expires_at, deletion_scheduled_at, version, created_at, updated_at`

const previewEnvironmentListMaxRows = 500

// PreviewEnvironment* status constants enumerate the closed taxonomy
// enforced by the preview_environments.status CHECK constraint.
const (
	PreviewEnvironmentStatusPending      = "pending"
	PreviewEnvironmentStatusProvisioning = "provisioning"
	PreviewEnvironmentStatusReady        = "ready"
	PreviewEnvironmentStatusDeleting     = "deleting"
	PreviewEnvironmentStatusDeleted      = "deleted"
	PreviewEnvironmentStatusFailed       = "failed"
)

// PreviewEnvironmentRepository is the persistence half of the preview
// environment surface. Every read and write predicates on
// organization_id and project_id, so a foreign project or preview id
// matches no rows and never confirms another tenant's state.
type PreviewEnvironmentRepository struct{}

// NewPreviewEnvironmentRepository builds a stateless
// PreviewEnvironmentRepository.
func NewPreviewEnvironmentRepository() *PreviewEnvironmentRepository {
	return &PreviewEnvironmentRepository{}
}

// Insert writes a new preview_environments row inside tx and returns
// the database-owned timestamps, initial version, and default status.
func (r *PreviewEnvironmentRepository) Insert(ctx context.Context, tx *Tx, p PreviewEnvironment) (PreviewEnvironment, error) {
	if tx == nil {
		return PreviewEnvironment{}, apierr.Internal(errors.New("store: PreviewEnvironmentRepository.Insert called with a nil transaction"))
	}
	status := p.Status
	if status == "" {
		status = PreviewEnvironmentStatusPending
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO preview_environments
		    (id, organization_id, project_id, environment_id, source_environment_id, display_name, change_ref, status, expires_at)
		  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		  RETURNING `+previewEnvironmentColumns,
		p.ID, p.OrganizationID, p.ProjectID, p.EnvironmentID, p.SourceEnvironmentID, p.DisplayName, p.ChangeRef, status, p.ExpiresAt)
	created, err := scanPreviewEnvironment(row)
	if err != nil {
		return PreviewEnvironment{}, mapWriteError(err, "a preview environment with this id or environment already exists")
	}
	return created, nil
}

// GetByID returns the preview row identified by
// (organizationID, projectID, previewID), or apierr.NotFound when no
// tenant-scoped row matches.
func (r *PreviewEnvironmentRepository) GetByID(ctx context.Context, q Querier, organizationID, projectID, previewID string) (PreviewEnvironment, error) {
	row := q.QueryRow(ctx,
		`SELECT `+previewEnvironmentColumns+`
		   FROM preview_environments
		  WHERE organization_id = $1 AND project_id = $2 AND id = $3`,
		organizationID, projectID, previewID)
	p, err := scanPreviewEnvironment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return PreviewEnvironment{}, apierr.NotFound("preview environment", previewID)
	}
	if err != nil {
		return PreviewEnvironment{}, apierr.StoreUnavailable(err)
	}
	return p, nil
}

// ListByProject returns preview rows for a project in deterministic
// creation order. A cross-tenant or unknown project tuple returns an
// empty non-nil slice.
func (r *PreviewEnvironmentRepository) ListByProject(ctx context.Context, q Querier, organizationID, projectID string) ([]PreviewEnvironment, error) {
	rows, err := q.Query(ctx,
		`SELECT `+previewEnvironmentColumns+`
		   FROM preview_environments
		  WHERE organization_id = $1 AND project_id = $2
		  ORDER BY created_at ASC, id ASC
		  LIMIT $3`,
		organizationID, projectID, previewEnvironmentListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]PreviewEnvironment, 0)
	for rows.Next() {
		p, scanErr := scanPreviewEnvironment(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// Update rewrites preview metadata that customers may edit while
// preserving structural identity, status, deletion_scheduled_at,
// version, and timestamps as database-owned or worker-owned fields.
func (r *PreviewEnvironmentRepository) Update(ctx context.Context, tx *Tx, p PreviewEnvironment, ifMatchVersion *int64) (PreviewEnvironment, error) {
	if tx == nil {
		return PreviewEnvironment{}, apierr.Internal(errors.New("store: PreviewEnvironmentRepository.Update called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`UPDATE preview_environments
			    SET display_name = $4,
			        change_ref   = $5,
			        expires_at   = $6
			  WHERE organization_id = $1 AND project_id = $2 AND id = $3
			 RETURNING `+previewEnvironmentColumns,
			p.OrganizationID, p.ProjectID, p.ID, p.DisplayName, p.ChangeRef, p.ExpiresAt)
	} else {
		row = tx.QueryRow(ctx,
			`UPDATE preview_environments
			    SET display_name = $4,
			        change_ref   = $5,
			        expires_at   = $6
			  WHERE organization_id = $1 AND project_id = $2 AND id = $3 AND version = $7
			 RETURNING `+previewEnvironmentColumns,
			p.OrganizationID, p.ProjectID, p.ID, p.DisplayName, p.ChangeRef, p.ExpiresAt, *ifMatchVersion)
	}
	updated, err := scanPreviewEnvironment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return PreviewEnvironment{}, apierr.NotFound("preview environment", p.ID)
		}
		return PreviewEnvironment{}, classifyPreviewEnvironmentConcurrencyMiss(ctx, tx, p.OrganizationID, p.ProjectID, p.ID, *ifMatchVersion)
	}
	if err != nil {
		return PreviewEnvironment{}, mapWriteError(err, "a preview environment update conflicts with existing state")
	}
	return updated, nil
}

// ScheduleDeletion marks a preview for worker-driven teardown. It is
// intentionally soft: the preview row remains visible with status
// deleting until the delete-preview worker has torn down Dokploy and
// hard-deleted the source-of-truth row.
func (r *PreviewEnvironmentRepository) ScheduleDeletion(ctx context.Context, tx *Tx, organizationID, projectID, previewID string, ifMatchVersion *int64) (PreviewEnvironment, error) {
	if tx == nil {
		return PreviewEnvironment{}, apierr.Internal(errors.New("store: PreviewEnvironmentRepository.ScheduleDeletion called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`UPDATE preview_environments
			    SET status = $4,
			        deletion_scheduled_at = COALESCE(deletion_scheduled_at, now())
			  WHERE organization_id = $1 AND project_id = $2 AND id = $3
			 RETURNING `+previewEnvironmentColumns,
			organizationID, projectID, previewID, PreviewEnvironmentStatusDeleting)
	} else {
		row = tx.QueryRow(ctx,
			`UPDATE preview_environments
			    SET status = $4,
			        deletion_scheduled_at = COALESCE(deletion_scheduled_at, now())
			  WHERE organization_id = $1 AND project_id = $2 AND id = $3 AND version = $5
			 RETURNING `+previewEnvironmentColumns,
			organizationID, projectID, previewID, PreviewEnvironmentStatusDeleting, *ifMatchVersion)
	}
	scheduled, err := scanPreviewEnvironment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return PreviewEnvironment{}, apierr.NotFound("preview environment", previewID)
		}
		return PreviewEnvironment{}, classifyPreviewEnvironmentConcurrencyMiss(ctx, tx, organizationID, projectID, previewID, *ifMatchVersion)
	}
	if err != nil {
		return PreviewEnvironment{}, apierr.StoreUnavailable(err)
	}
	return scheduled, nil
}

// DeleteByID hard-deletes a preview row. The customer-facing delete
// path should call ScheduleDeletion first; hard delete is for worker
// cleanup after external teardown or parent cascade tests.
func (r *PreviewEnvironmentRepository) DeleteByID(ctx context.Context, tx *Tx, organizationID, projectID, previewID string, ifMatchVersion *int64) (PreviewEnvironment, error) {
	if tx == nil {
		return PreviewEnvironment{}, apierr.Internal(errors.New("store: PreviewEnvironmentRepository.DeleteByID called with a nil transaction"))
	}
	var row pgx.Row
	if ifMatchVersion == nil {
		row = tx.QueryRow(ctx,
			`DELETE FROM preview_environments
			  WHERE organization_id = $1 AND project_id = $2 AND id = $3
			 RETURNING `+previewEnvironmentColumns,
			organizationID, projectID, previewID)
	} else {
		row = tx.QueryRow(ctx,
			`DELETE FROM preview_environments
			  WHERE organization_id = $1 AND project_id = $2 AND id = $3 AND version = $4
			 RETURNING `+previewEnvironmentColumns,
			organizationID, projectID, previewID, *ifMatchVersion)
	}
	deleted, err := scanPreviewEnvironment(row)
	if errors.Is(err, pgx.ErrNoRows) {
		if ifMatchVersion == nil {
			return PreviewEnvironment{}, apierr.NotFound("preview environment", previewID)
		}
		return PreviewEnvironment{}, classifyPreviewEnvironmentConcurrencyMiss(ctx, tx, organizationID, projectID, previewID, *ifMatchVersion)
	}
	if err != nil {
		return PreviewEnvironment{}, apierr.StoreUnavailable(err)
	}
	return deleted, nil
}

func classifyPreviewEnvironmentConcurrencyMiss(ctx context.Context, tx *Tx, organizationID, projectID, previewID string, ifMatchVersion int64) error {
	row := tx.QueryRow(ctx,
		`SELECT version
		   FROM preview_environments
		  WHERE organization_id = $1 AND project_id = $2 AND id = $3`,
		organizationID, projectID, previewID)
	var current int64
	if err := row.Scan(&current); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("preview environment", previewID)
		}
		return apierr.StoreUnavailable(err)
	}
	if current == ifMatchVersion {
		return apierr.Internal(errors.New("store: PreviewEnvironmentRepository saw the same version after a no-row write"))
	}
	return apierr.ConflictStale(current)
}

func scanPreviewEnvironment(row scanRow) (PreviewEnvironment, error) {
	var p PreviewEnvironment
	if err := row.Scan(
		&p.ID,
		&p.OrganizationID,
		&p.ProjectID,
		&p.EnvironmentID,
		&p.SourceEnvironmentID,
		&p.DisplayName,
		&p.ChangeRef,
		&p.Status,
		&p.ExpiresAt,
		&p.DeletionScheduledAt,
		&p.Version,
		&p.CreatedAt,
		&p.UpdatedAt,
	); err != nil {
		return PreviewEnvironment{}, err
	}
	return p, nil
}
