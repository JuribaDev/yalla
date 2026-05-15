package store

import (
	"context"
	"errors"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// Organization is the source-of-truth representation of a row in the
// organizations table — the tenant root of Yalla's
// Organization -> Project -> Environment -> Service hierarchy. It is the
// persistence-layer shape; HTTP request and response shapes are the job of the
// httpapi layer.
//
// DeletionScheduledAt is nil for a live organization and carries the stamp time
// once a deletion has been scheduled through DELETE /v1/organizations/{org_id}.
// The destructive teardown itself (the ON DELETE CASCADE) is a later worker
// story, so a scheduled organization — and its audit trail — still exists.
type Organization struct {
	ID                  string
	Slug                string
	DisplayName         string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DeletionScheduledAt *time.Time
}

// OrganizationRepository is the persistence layer for the organizations table.
// It follows the repository pattern used across the store package: reads accept
// a Querier so they run against a read-only transaction or an open write
// transaction, every statement is fully parameterized, and a missing row is
// reported as a typed apierr.NotFound rather than a bare pgx.ErrNoRows.
//
// organizations is the tenant root, so a read is scoped by the row's own id —
// there is no parent organization_id to filter by first. The caller is
// responsible for only ever passing an organization id the authenticated
// principal is authorized to see; that authorization decision is the policy
// engine's job and is made before this repository is reached.
//
// The repository is stateless; the constructor exists so call sites depend on
// a value rather than a bare struct literal.
type OrganizationRepository struct{}

// NewOrganizationRepository returns an OrganizationRepository.
func NewOrganizationRepository() *OrganizationRepository { return &OrganizationRepository{} }

// organizationColumns is the column list returned by every organization query,
// in the order scanOrganization expects.
const organizationColumns = `id, slug, display_name, created_at, updated_at, deletion_scheduled_at`

// Get returns the organization identified by organizationID. A missing id is
// reported as a typed NotFound — the same shape any other unknown id produces,
// so a caller can never tell "no such organization" apart from "an organization
// you cannot see". It accepts a Querier so it works against a read-only
// transaction or an open write transaction.
func (r *OrganizationRepository) Get(ctx context.Context, q Querier, organizationID string) (Organization, error) {
	row := q.QueryRow(ctx,
		`SELECT `+organizationColumns+`
		 FROM organizations
		 WHERE id = $1`,
		organizationID)
	o, err := scanOrganization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, apierr.NotFound("organization", organizationID)
	}
	if err != nil {
		return Organization{}, apierr.StoreUnavailable(err)
	}
	return o, nil
}

// Insert writes a new organization row inside tx and returns the persisted
// row, including the database-assigned timestamps. It requires a *Tx — not a
// bare Querier — so an organization can never be created outside the
// transaction that also carries its audit record. A slug that collides with an
// existing organization is reported as a typed Conflict; the raw driver error,
// which may name the constraint, is preserved only as the wrapped cause for
// server-side logging and never reaches the user-facing message.
func (r *OrganizationRepository) Insert(ctx context.Context, tx *Tx, o Organization) (Organization, error) {
	if tx == nil {
		return Organization{}, apierr.Internal(errors.New("store: OrganizationRepository.Insert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO organizations (id, slug, display_name)
		 VALUES ($1, $2, $3)
		 RETURNING `+organizationColumns,
		o.ID, o.Slug, o.DisplayName)
	created, err := scanOrganization(row)
	if err != nil {
		return Organization{}, mapWriteError(err, "an organization with this slug already exists")
	}
	return created, nil
}

// Update writes new slug and display_name values for the organization
// identified by o.ID inside tx and returns the persisted row, including the
// trigger-refreshed updated_at timestamp. It requires a *Tx — not a bare
// Querier — so an organization can never be updated outside the transaction
// that also carries its audit record. A missing id is reported as a typed
// NotFound — the same shape any other unknown id produces, so a caller can
// never tell "no such organization" apart from "an organization you cannot
// see". A slug that collides with an existing organization is reported as a
// typed Conflict; the raw driver error, which may name the constraint, is
// preserved only as the wrapped cause for server-side logging and never
// reaches the user-facing message.
func (r *OrganizationRepository) Update(ctx context.Context, tx *Tx, o Organization) (Organization, error) {
	if tx == nil {
		return Organization{}, apierr.Internal(errors.New("store: OrganizationRepository.Update called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`UPDATE organizations
		    SET slug = $2, display_name = $3
		  WHERE id = $1
		 RETURNING `+organizationColumns,
		o.ID, o.Slug, o.DisplayName)
	updated, err := scanOrganization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, apierr.NotFound("organization", o.ID)
	}
	if err != nil {
		return Organization{}, mapWriteError(err, "an organization with this slug already exists")
	}
	return updated, nil
}

// ScheduleDeletion stamps deletion_scheduled_at on the organization identified
// by organizationID inside tx and returns the persisted row, including the
// trigger-refreshed updated_at timestamp. It requires a *Tx — not a bare
// Querier — so an organization can never be marked for teardown outside the
// transaction that also carries its audit record. A missing id is reported as a
// typed NotFound — the same shape any other unknown id produces, so a caller
// can never tell "no such organization" apart from "an organization you cannot
// see". The UPDATE is unconditional: re-scheduling an organization already
// scheduled for deletion is a conflict the OrganizationService detects with a
// prior read, not a not-found this repository can distinguish.
func (r *OrganizationRepository) ScheduleDeletion(ctx context.Context, tx *Tx, organizationID string) (Organization, error) {
	if tx == nil {
		return Organization{}, apierr.Internal(errors.New("store: OrganizationRepository.ScheduleDeletion called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`UPDATE organizations
		    SET deletion_scheduled_at = now()
		  WHERE id = $1
		 RETURNING `+organizationColumns,
		organizationID)
	updated, err := scanOrganization(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, apierr.NotFound("organization", organizationID)
	}
	if err != nil {
		return Organization{}, apierr.StoreUnavailable(err)
	}
	return updated, nil
}

// scanOrganization scans one organizations row in organizationColumns order.
func scanOrganization(row pgx.Row) (Organization, error) {
	var o Organization
	err := row.Scan(&o.ID, &o.Slug, &o.DisplayName, &o.CreatedAt, &o.UpdatedAt, &o.DeletionScheduledAt)
	return o, err
}

// OrganizationReader is the store-backed read adapter for organization
// resources: the persistence surface the httpapi layer needs to render
// GET /v1/organizations. It mirrors CredentialReader — it composes the
// OrganizationRepository rather than issuing its own SQL, so the tenant-scoping
// guarantees the repository proves in its integration tests are inherited for
// free, and every method opens its own short-lived read transaction through
// Store.Read.
type OrganizationReader struct {
	store *Store
	orgs  *OrganizationRepository
}

// NewOrganizationReader builds an OrganizationReader over store. It returns an
// error for a nil store so a misconfigured adapter fails at construction rather
// than on its first request.
func NewOrganizationReader(s *Store) (*OrganizationReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &OrganizationReader{store: s, orgs: NewOrganizationRepository()}, nil
}

// GetOrganization returns the organization identified by organizationID,
// reading it inside a short-lived read-only transaction. A missing id is the
// typed NotFound the repository produces; a datastore failure is propagated as
// its own typed error and never disguised as a not-found.
func (r *OrganizationReader) GetOrganization(ctx context.Context, organizationID string) (Organization, error) {
	var org Organization
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		var getErr error
		org, getErr = r.orgs.Get(ctx, q, organizationID)
		return getErr
	})
	if err != nil {
		return Organization{}, err
	}
	return org, nil
}
