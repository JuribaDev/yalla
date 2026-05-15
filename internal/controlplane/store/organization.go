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
type Organization struct {
	ID          string
	Slug        string
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
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
const organizationColumns = `id, slug, display_name, created_at, updated_at`

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

// scanOrganization scans one organizations row in organizationColumns order.
func scanOrganization(row pgx.Row) (Organization, error) {
	var o Organization
	err := row.Scan(&o.ID, &o.Slug, &o.DisplayName, &o.CreatedAt, &o.UpdatedAt)
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
