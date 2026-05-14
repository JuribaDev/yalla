package store

import (
	"context"
	"errors"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/jackc/pgx/v5"
)

// ServiceAccount is the source-of-truth representation of a row in the
// service_accounts table. A service account is a non-human principal — it lets
// CI and automation authenticate without a human user and without ever holding
// a Dokploy token. It belongs to exactly one organization and owns API keys;
// what it is permitted to do (and the rule that it cannot manage billing,
// owners, or break-glass access unless a policy grant allows it) is the policy
// engine's concern, not this struct's. It is the persistence-layer shape; HTTP
// request and response shapes are the job of the httpapi layer.
type ServiceAccount struct {
	ID             string
	OrganizationID string
	Slug           string
	DisplayName    string
	// DisabledAt is set when the service account has been parked. A disabled
	// service account keeps its rows and its keys, but the auth layer must
	// refuse to authenticate as it.
	DisabledAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// IsDisabled reports whether the service account has been disabled.
func (s ServiceAccount) IsDisabled() bool { return s.DisabledAt != nil }

// ServiceAccountRepository is the persistence layer for service accounts. It
// follows the repository transaction pattern: mutations require a *Tx (so they
// can only run inside Store.Write, never separated from the authorization and
// quota checks that share that transaction), reads accept a Querier, and every
// query is tenant scoped by organization_id before resource id — so a service
// account id from another organization can never match.
type ServiceAccountRepository struct{}

// NewServiceAccountRepository returns a ServiceAccountRepository.
func NewServiceAccountRepository() *ServiceAccountRepository { return &ServiceAccountRepository{} }

// serviceAccountColumns is the column list returned by every service_accounts
// query, in the order scanServiceAccount expects.
const serviceAccountColumns = `id, organization_id, slug, display_name, disabled_at, created_at, updated_at`

// scanServiceAccount scans one service_accounts row in serviceAccountColumns
// order.
func scanServiceAccount(row pgx.Row) (ServiceAccount, error) {
	var s ServiceAccount
	err := row.Scan(
		&s.ID, &s.OrganizationID, &s.Slug, &s.DisplayName,
		&s.DisabledAt, &s.CreatedAt, &s.UpdatedAt,
	)
	return s, err
}

// Insert writes a new service account row inside tx and returns the persisted
// row, including the database-assigned timestamps. It requires a *Tx — not a
// bare Querier — so a service account can never be created outside the
// transaction that also carries its authorization and quota checks. A slug
// that collides with an existing service account in the same organization is
// reported as a Conflict.
func (r *ServiceAccountRepository) Insert(ctx context.Context, tx *Tx, sa ServiceAccount) (ServiceAccount, error) {
	if tx == nil {
		return ServiceAccount{}, apierr.Internal(errors.New("store: ServiceAccountRepository.Insert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO service_accounts (id, organization_id, slug, display_name, disabled_at)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING `+serviceAccountColumns,
		sa.ID, sa.OrganizationID, sa.Slug, sa.DisplayName, sa.DisabledAt)
	created, err := scanServiceAccount(row)
	if err != nil {
		return ServiceAccount{}, mapWriteError(err, "a service account with this slug already exists in the organization")
	}
	return created, nil
}

// Get returns the service account identified by serviceAccountID within
// organizationID. The query is tenant scoped: it filters by organization_id
// first, so a service account id that belongs to another organization simply
// does not match and is reported as NotFound — a cross-tenant id can never
// reveal another organization's data.
func (r *ServiceAccountRepository) Get(ctx context.Context, q Querier, organizationID, serviceAccountID string) (ServiceAccount, error) {
	row := q.QueryRow(ctx,
		`SELECT `+serviceAccountColumns+`
		 FROM service_accounts
		 WHERE organization_id = $1 AND id = $2`,
		organizationID, serviceAccountID)
	sa, err := scanServiceAccount(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServiceAccount{}, apierr.NotFound("service_account", serviceAccountID)
	}
	if err != nil {
		return ServiceAccount{}, apierr.StoreUnavailable(err)
	}
	return sa, nil
}

// ListByOrganization returns every service account owned by organizationID,
// oldest first. The query is tenant scoped, so it can never return another
// organization's service accounts.
func (r *ServiceAccountRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string) ([]ServiceAccount, error) {
	rows, err := q.Query(ctx,
		`SELECT `+serviceAccountColumns+`
		 FROM service_accounts
		 WHERE organization_id = $1
		 ORDER BY created_at, id`,
		organizationID)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()

	var accounts []ServiceAccount
	for rows.Next() {
		sa, err := scanServiceAccount(rows)
		if err != nil {
			return nil, apierr.StoreUnavailable(err)
		}
		accounts = append(accounts, sa)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return accounts, nil
}

// CountByOrganization returns the number of service accounts owned by
// organizationID. It is the read the quota layer uses to enforce a
// per-organization service-account limit; running it through the same *Tx as
// the insert keeps the check race-free.
func (r *ServiceAccountRepository) CountByOrganization(ctx context.Context, q Querier, organizationID string) (int, error) {
	var n int
	if err := q.QueryRow(ctx,
		`SELECT count(*) FROM service_accounts WHERE organization_id = $1`,
		organizationID).Scan(&n); err != nil {
		return 0, apierr.StoreUnavailable(err)
	}
	return n, nil
}

// Disable marks the service account identified by (organizationID,
// serviceAccountID) as disabled at disabledAt. It requires a *Tx and is tenant
// scoped. Disabling is idempotent: COALESCE keeps the first disable timestamp,
// so disabling an already-disabled service account is a no-op success rather
// than an error. A service account id that belongs to another organization
// does not match and is reported as NotFound.
func (r *ServiceAccountRepository) Disable(ctx context.Context, tx *Tx, organizationID, serviceAccountID string, disabledAt time.Time) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: ServiceAccountRepository.Disable called with a nil transaction"))
	}
	tag, err := tx.Exec(ctx,
		`UPDATE service_accounts
		 SET disabled_at = COALESCE(disabled_at, $3)
		 WHERE organization_id = $1 AND id = $2`,
		organizationID, serviceAccountID, disabledAt)
	if err != nil {
		return mapWriteError(err, "the service account could not be disabled")
	}
	if tag.RowsAffected() == 0 {
		return apierr.NotFound("service_account", serviceAccountID)
	}
	return nil
}
