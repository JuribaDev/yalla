package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
)

// APIKeyScope is the source-of-truth representation of a row in the
// api_key_scopes table — one capability string assigned to an api_keys row.
// The embedded api_keys.scopes text[] is the legacy authentication-path read
// surface; this struct mirrors a normalised row a future per-scope endpoint
// will mutate without rewriting the whole array, and lets the audit trail
// record per-scope created_at / updated_at / version stamps.
//
// OrganizationID, APIKeyID, and the composite FK to api_keys
// (organization_id, id) pin the row to a single tenant; a row whose
// api-key belongs to one tenant is structurally unrepresentable as another
// tenant's scope. Scope is the capability string the wire layer surfaces
// in clear text and is bounded by the table's CHECK (1..64 bytes).
//
// Version is the database-owned optimistic-concurrency token: it starts at
// 1 on INSERT and is bumped by the api_key_scopes_bump_version trigger on
// every UPDATE. Callers must not mutate it; the trigger is the only writer.
type APIKeyScope struct {
	ID             string
	OrganizationID string
	APIKeyID       string
	Scope          string
	Version        int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// APIKeyScopeRepository is the persistence half of the api_key_scopes
// surface. It follows the same conventions as ProjectGrantRepository —
// mutations require a *Tx so they cannot be separated from the
// authorization and audit steps that share the transaction, reads accept a
// Querier so they work against either a read-only or open write
// transaction, and every query is tenant scoped by organization_id before
// any other identifier so a cross-tenant id can never match. The repository
// is stateless; the constructor exists so call sites depend on a value
// rather than a bare struct literal.
type APIKeyScopeRepository struct{}

// NewAPIKeyScopeRepository returns a stateless APIKeyScopeRepository.
func NewAPIKeyScopeRepository() *APIKeyScopeRepository { return &APIKeyScopeRepository{} }

// apiKeyScopeColumns is the column list returned by every api_key_scopes
// query, in the order scanAPIKeyScope expects.
const apiKeyScopeColumns = `id, organization_id, api_key_id, scope, version, created_at, updated_at`

// apiKeyScopeListMaxRows caps how many rows a single list call returns. An
// unbounded query can never be issued by accident; an HTTP layer that wants
// pagination later will add an explicit offset or cursor parameter rather
// than relax this ceiling.
const apiKeyScopeListMaxRows = 500

// scanAPIKeyScope scans one api_key_scopes row in apiKeyScopeColumns order.
func scanAPIKeyScope(row pgx.Row) (APIKeyScope, error) {
	var s APIKeyScope
	err := row.Scan(
		&s.ID,
		&s.OrganizationID,
		&s.APIKeyID,
		&s.Scope,
		&s.Version,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	return s, err
}

// Insert writes a new api_key_scopes row inside tx and returns the persisted
// row. The composite FK (organization_id, api_key_id) to api_keys means a
// cross-tenant api_key_id (or one that does not exist at all) is rejected by
// the database with a foreign-key violation, which mapWriteError surfaces as
// a typed apierr.Conflict carrying a non-sensitive message — the duplicate
// (organization_id, api_key_id, scope) tuple lands on the same conflict code
// for the same reason. nil tx is a programming error and is reported as
// Internal so a caller cannot accidentally insert outside a transaction.
func (r *APIKeyScopeRepository) Insert(ctx context.Context, tx *Tx, s APIKeyScope) (APIKeyScope, error) {
	if tx == nil {
		return APIKeyScope{}, apierr.Internal(errors.New("store: APIKeyScopeRepository.Insert called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`INSERT INTO api_key_scopes
		   (id, organization_id, api_key_id, scope)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+apiKeyScopeColumns,
		s.ID, s.OrganizationID, s.APIKeyID, s.Scope)
	inserted, err := scanAPIKeyScope(row)
	if err != nil {
		return APIKeyScope{}, mapWriteError(err, "an api key scope with this id, api key, or scope already exists")
	}
	return inserted, nil
}

// Get returns the api_key_scopes row identified by scopeID within
// organizationID. The query is tenant scoped at the SQL predicate: a scope
// id that belongs to another organization simply does not match and is
// reported as NotFound — a cross-tenant id can never reveal another
// organization's data.
func (r *APIKeyScopeRepository) Get(ctx context.Context, q Querier, organizationID, scopeID string) (APIKeyScope, error) {
	row := q.QueryRow(ctx,
		`SELECT `+apiKeyScopeColumns+`
		   FROM api_key_scopes
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, scopeID)
	s, err := scanAPIKeyScope(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKeyScope{}, apierr.NotFound("api_key_scope", scopeID)
	}
	if err != nil {
		return APIKeyScope{}, apierr.StoreUnavailable(err)
	}
	return s, nil
}

// ListByAPIKey returns every scope row attached to the api key identified by
// (organizationID, apiKeyID), ordered deterministically by (scope ASC, id
// ASC) so a given set of rows always renders the same response. The query
// is tenant scoped at the SQL predicate: a cross-tenant api_key_id matches
// no rows and yields an empty slice — a cross-tenant id can never reveal
// another organization's scopes. The result is always a non-nil slice
// (possibly empty) so callers can iterate it without a nil check.
//
// This method does NOT verify the parent api_keys row exists; callers that
// need to distinguish "api key missing" from "api key has no scopes" must
// Get the api key first.
func (r *APIKeyScopeRepository) ListByAPIKey(ctx context.Context, q Querier, organizationID, apiKeyID string) ([]APIKeyScope, error) {
	rows, err := q.Query(ctx,
		`SELECT `+apiKeyScopeColumns+`
		   FROM api_key_scopes
		  WHERE organization_id = $1 AND api_key_id = $2
		  ORDER BY scope ASC, id ASC
		  LIMIT $3`,
		organizationID, apiKeyID, apiKeyScopeListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	scopes := make([]APIKeyScope, 0)
	for rows.Next() {
		s, scanErr := scanAPIKeyScope(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		scopes = append(scopes, s)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return scopes, nil
}

// ListByOrganization returns every api_key_scopes row owned by
// organizationID, ordered deterministically by (api_key_id ASC, scope ASC,
// id ASC). The query is tenant scoped at the SQL predicate so a cross-tenant
// id can never reveal another organization's scopes. The result is always a
// non-nil slice (possibly empty).
func (r *APIKeyScopeRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string) ([]APIKeyScope, error) {
	rows, err := q.Query(ctx,
		`SELECT `+apiKeyScopeColumns+`
		   FROM api_key_scopes
		  WHERE organization_id = $1
		  ORDER BY api_key_id ASC, scope ASC, id ASC
		  LIMIT $2`,
		organizationID, apiKeyScopeListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	scopes := make([]APIKeyScope, 0)
	for rows.Next() {
		s, scanErr := scanAPIKeyScope(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		scopes = append(scopes, s)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return scopes, nil
}

// UpdateScope rewrites the scope text of the row identified by
// (organizationID, scopeID) and returns the persisted row, including the
// trigger-refreshed updated_at and the trigger-bumped version. The mutation
// is the only customer-mutable field on an api_key_scopes row — id,
// organization_id, api_key_id, and the lifecycle stamps are immutable. The
// query is tenant scoped: a scope id from another organization does not
// match and is reported as the typed apierr.NotFound so a cross-tenant id
// can never mutate another tenant's scope. A duplicate (organization_id,
// api_key_id, scope) tuple — for example renaming a scope to one that
// already exists on the same key — surfaces as the typed apierr.Conflict
// mapWriteError produces.
func (r *APIKeyScopeRepository) UpdateScope(ctx context.Context, tx *Tx, organizationID, scopeID, scope string) (APIKeyScope, error) {
	if tx == nil {
		return APIKeyScope{}, apierr.Internal(errors.New("store: APIKeyScopeRepository.UpdateScope called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`UPDATE api_key_scopes
		    SET scope = $3
		  WHERE organization_id = $1 AND id = $2
		 RETURNING `+apiKeyScopeColumns,
		organizationID, scopeID, scope)
	updated, err := scanAPIKeyScope(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKeyScope{}, apierr.NotFound("api_key_scope", scopeID)
	}
	if err != nil {
		return APIKeyScope{}, mapWriteError(err, "an api key scope with this scope already exists for this api key")
	}
	return updated, nil
}

// Delete removes the row identified by (organizationID, scopeID). The query
// is tenant scoped at the SQL predicate: a cross-tenant id matches no rows
// and the method reports apierr.NotFound via the RowsAffected() == 0 path —
// the same idempotent-tag pattern api_keys.Revoke uses. A successful delete
// returns nil; the caller does not need the prior row body because every
// mutation has already audited the identity it removed.
func (r *APIKeyScopeRepository) Delete(ctx context.Context, tx *Tx, organizationID, scopeID string) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: APIKeyScopeRepository.Delete called with a nil transaction"))
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM api_key_scopes
		  WHERE organization_id = $1 AND id = $2`,
		organizationID, scopeID)
	if err != nil {
		return apierr.StoreUnavailable(err)
	}
	if tag.RowsAffected() == 0 {
		return apierr.NotFound("api_key_scope", scopeID)
	}
	return nil
}
