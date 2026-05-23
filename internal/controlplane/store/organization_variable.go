package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
)

// OrganizationVariable is a single organization-scoped environment variable
// — the lowest-precedence layer of the Organization -> Project ->
// Environment -> Service variable hierarchy the Dokploy renderer composes.
//
// Value is the literal value of NON-SECRET variables; for IsSecret = true
// the column is forced to "" by the schema CHECK and the actual secret
// bytes live behind (SecretProvider, SecretKeyID, SecretCiphertext),
// sealed by an internal/controlplane/secrets.Provider. An internal-only
// caller that legitimately needs the plaintext (today, the future Dokploy
// provisioning renderer) calls Provider.Open against the sealed tuple.
// The wire layer NEVER projects the sealed bytes — secret values appear
// as output.Sentinel on every public response.
//
// SecretProvider / SecretKeyID / SecretCiphertext are populated when
// IsSecret = true and empty/nil when IsSecret = false. The store layer
// upholds that invariant in the same transaction as the write; the
// database CHECK constraint
// organization_variables_secret_columns_consistent is the defence-in-
// depth guarantee that no row can ever drift from it.
//
// The LogValue method below makes log records that accidentally carry an
// OrganizationVariable safe by structurally hiding both the plain value
// AND the ciphertext at the slog boundary as a second line of defence —
// a panic stack trace or a debug log that captures the struct cannot
// leak the literal or the sealed bytes.
type OrganizationVariable struct {
	ID               string
	OrganizationID   string
	Key              string
	Value            string
	IsSecret         bool
	SecretProvider   string
	SecretKeyID      string
	SecretCiphertext []byte
	Version          int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// LogValue redacts every variable value at the slog boundary so a stray
// log record that captures an OrganizationVariable cannot leak the literal
// plaintext OR the sealed ciphertext. Non-secret values reach the wire
// through the HTTP projection (which has its own explicit redaction
// policy); logs always see the sentinel. The slog record exposes the
// provider id and key id (already non-secret) so an operator can debug
// the encryption seam without exfiltrating the bytes themselves.
func (v OrganizationVariable) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", v.ID),
		slog.String("organization_id", v.OrganizationID),
		slog.String("key", v.Key),
		slog.String("value", output.Sentinel),
		slog.Bool("is_secret", v.IsSecret),
		slog.String("secret_provider", v.SecretProvider),
		slog.String("secret_key_id", v.SecretKeyID),
		slog.String("secret_ciphertext", output.Sentinel),
		slog.Int64("version", v.Version),
	)
}

// organizationVariableColumns is the SELECT projection used by every read
// in this repository. Keeping it as a single string keeps the column list
// in lockstep with scanOrganizationVariable. The encryption-at-rest
// columns (secret_provider, secret_key_id, secret_ciphertext) live next
// to value so a single Scan returns the whole row in one round trip; the
// store-layer service decides whether and when to call Provider.Open
// against the sealed tuple.
const organizationVariableColumns = `id, organization_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext, version, created_at, updated_at`

// organizationVariableListMaxRows caps how many rows a single
// ListByOrganization call returns. An unbounded query can never be issued
// by accident; an HTTP layer that wants pagination later will add an
// explicit offset or cursor parameter rather than relax this ceiling.
const organizationVariableListMaxRows = 500

// OrganizationVariableRepository is the persistence half of the
// organization-variables surface. Every read is tenant-scoped: the
// organization_id leg of the predicate is non-optional, so a missing or
// cross-tenant id simply matches no rows and yields an empty list — never
// another tenant's variables.
type OrganizationVariableRepository struct{}

// NewOrganizationVariableRepository builds a stateless
// OrganizationVariableRepository.
func NewOrganizationVariableRepository() *OrganizationVariableRepository {
	return &OrganizationVariableRepository{}
}

// ListByOrganization returns every organization-scoped variable owned by
// organizationID, in deterministic (key ASC, id ASC) order so an agent
// observing the response sees a stable ordering across calls. The read is
// tenant-scoped at the SQL predicate, so a cross-tenant id matches no
// rows. A raw driver error surfaces as the typed apierr.StoreUnavailable
// — the cause is wrapped for logging only, never leaked into the
// customer-facing message.
func (r *OrganizationVariableRepository) ListByOrganization(ctx context.Context, q Querier, organizationID string) ([]OrganizationVariable, error) {
	rows, err := q.Query(ctx,
		`SELECT `+organizationVariableColumns+`
		   FROM organization_variables
		  WHERE organization_id = $1
		  ORDER BY key ASC, id ASC
		  LIMIT $2`,
		organizationID, organizationVariableListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	var out []OrganizationVariable
	for rows.Next() {
		v, scanErr := scanOrganizationVariable(rows)
		if scanErr != nil {
			return nil, apierr.StoreUnavailable(scanErr)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	return out, nil
}

// OrganizationVariableUpsert is the closed-set tuple Upsert and
// UpdateMutable accept. It binds the plain `value` column with the
// (secret_provider, secret_key_id, secret_ciphertext) encryption-at-rest
// tuple in one struct so the repository signature stays narrow as new
// secret fields land. The store-layer service builds this struct by
// calling secrets.Provider.Seal once per item; an IsSecret = true item
// MUST carry a non-empty ciphertext and Value MUST be "", and an
// IsSecret = false item MUST carry only Value with the ciphertext fields
// zeroed. The database CHECK constraint
// organization_variables_secret_columns_consistent rejects any drift as
// a deterministic apierr.Conflict.
type OrganizationVariableUpsert struct {
	Value            string
	IsSecret         bool
	SecretProvider   string
	SecretKeyID      string
	SecretCiphertext []byte
}

// Upsert inserts or updates the (organization_id, key) row carrying value /
// is_secret. The (organization_id, key) UNIQUE constraint from migration
// 0012 is the conflict target, so an existing row keeps its id and bumps
// version through the bump_version trigger; a new row uses the caller-
// supplied id (already minted by the service layer through
// domain.NewID(KindOrganizationVariable) so the id is non-guessable and
// tenant-anonymous). The returned OrganizationVariable reflects the
// committed state — its id is the row's stable id (the existing id for an
// update, the freshly minted one for an insert), its version is the
// post-trigger version, and its updated_at is the moment the row
// persisted.
//
// The tenant predicate is non-optional: organization_id is part of the
// upsert key, so a cross-tenant smuggling attempt at this seam either
// matches an existing (organization_id, key) pair owned by the supplied
// organization (the intended idempotent overwrite) or inserts a fresh row
// scoped to that organization — never another tenant's data. Validation
// of organizationID, key, and value happens in the service layer before a
// transaction is opened; this method assumes its inputs already cleared
// validate.EnvVars.
//
// A foreign-key violation (organizationID does not exist) and the table's
// CHECK constraints both surface as apierr.Conflict through mapWriteError;
// any other driver error surfaces as apierr.StoreUnavailable. The raw
// driver error is wrapped as the cause for server-side logging only and
// never reaches the user-facing message — so a customer-facing 409 here
// never echoes value content.
func (r *OrganizationVariableRepository) Upsert(ctx context.Context, tx *Tx, id, organizationID, key string, in OrganizationVariableUpsert) (OrganizationVariable, error) {
	if tx == nil {
		return OrganizationVariable{}, apierr.Internal(errors.New("store: OrganizationVariableRepository.Upsert called with a nil transaction"))
	}
	provider, keyID, ciphertext := nullableSecretColumns(in)
	row := tx.QueryRow(ctx,
		`INSERT INTO organization_variables (id, organization_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext)
		     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (organization_id, key) DO UPDATE
		    SET value             = EXCLUDED.value,
		        is_secret         = EXCLUDED.is_secret,
		        secret_provider   = EXCLUDED.secret_provider,
		        secret_key_id     = EXCLUDED.secret_key_id,
		        secret_ciphertext = EXCLUDED.secret_ciphertext
		RETURNING `+organizationVariableColumns,
		id, organizationID, key, in.Value, in.IsSecret, provider, keyID, ciphertext)
	v, err := scanOrganizationVariable(row)
	if err != nil {
		return OrganizationVariable{}, mapWriteError(err, "the organization variable could not be saved")
	}
	return v, nil
}

// nullableSecretColumns projects an OrganizationVariableUpsert onto the
// (provider, keyID, ciphertext) tuple the SQL bind parameters expect.
// For IsSecret = false the tuple is (nil, nil, nil) so the columns are
// NULL — the CHECK constraint requires NULL in the non-secret state.
// For IsSecret = true the tuple is (provider, keyID, ciphertext) values
// the service just sealed.
func nullableSecretColumns(in OrganizationVariableUpsert) (provider, keyID any, ciphertext any) {
	if !in.IsSecret {
		return nil, nil, nil
	}
	return in.SecretProvider, in.SecretKeyID, in.SecretCiphertext
}

// DeleteByOrganizationExceptKeys removes every organization_variables row
// owned by organizationID whose key is not in keepKeys. It is the
// counterpart of Upsert in the bulk-replace unit of work: Upsert applies
// every variable the caller wants to keep, and this method drops the rest
// — so the post-condition is "the tenant's variables == exactly the
// caller-supplied set". keepKeys MAY be empty (the caller asked to clear
// every organization-scoped variable); the SQL predicate is written so
// `key <> ALL($2)` is true for every row when the array is empty,
// producing a deterministic full clear.
//
// The tenant predicate is non-optional: organization_id is part of the
// WHERE clause, so a cross-tenant id matches no rows and deletes nothing —
// never another tenant's data. Validation of organizationID and the keep
// list happens in the service layer; this method assumes the caller
// already produced a deduplicated, validated list of POSIX env-var names.
func (r *OrganizationVariableRepository) DeleteByOrganizationExceptKeys(ctx context.Context, tx *Tx, organizationID string, keepKeys []string) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: OrganizationVariableRepository.DeleteByOrganizationExceptKeys called with a nil transaction"))
	}
	if keepKeys == nil {
		keepKeys = []string{}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM organization_variables
		  WHERE organization_id = $1
		    AND key <> ALL($2)`,
		organizationID, keepKeys); err != nil {
		return mapWriteError(err, "the organization variables could not be reconciled")
	}
	return nil
}

// GetByKey returns the organization-scoped variable with key inside
// organizationID. The query is tenant scoped — organization_id is the
// first predicate — so a key that exists in another tenant simply does
// not match and is reported as the typed apierr.NotFound the PATCH /
// DELETE endpoints surface; a cross-tenant id can never reveal another
// tenant's variable. A raw driver error surfaces as
// apierr.StoreUnavailable with the cause wrapped for server-side
// logging only — never leaked into the customer-facing message.
//
// q is a Querier so the method can run either against a pooled
// connection (a stand-alone read) or inside a transaction (a read-then-
// write unit of work like PATCH /v1/organizations/{org_id}/variables/{key},
// where the row must be observed in the same transaction that updates
// it so a row that vanishes mid-flight is impossible).
func (r *OrganizationVariableRepository) GetByKey(ctx context.Context, q Querier, organizationID, key string) (OrganizationVariable, error) {
	row := q.QueryRow(ctx,
		`SELECT `+organizationVariableColumns+`
		   FROM organization_variables
		  WHERE organization_id = $1 AND key = $2`,
		organizationID, key)
	v, err := scanOrganizationVariable(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationVariable{}, apierr.NotFound("organization_variable", key)
	}
	if err != nil {
		return OrganizationVariable{}, apierr.StoreUnavailable(err)
	}
	return v, nil
}

// DeleteByKey removes the organization-scoped variable identified by
// (organizationID, key) inside tx and returns the deleted row exactly as
// it stood at the moment of removal — including value and is_secret —
// so the unit-of-work orchestrator can project the snapshot onto the
// HTTP response and the audit metadata without a separate read-then-
// delete race. It requires a *Tx — not a bare Querier — so a delete can
// never be persisted outside the transaction that also carries its
// audit record. The query is tenant scoped: a key that belongs to
// another organization simply does not match and is reported as the
// typed apierr.NotFound the GET endpoint uses, never disguised as a
// 5xx and never revealing whether another tenant owns that key.
//
// organization_variables has no soft-delete column (unlike organizations
// or api_keys) — a customer's organization-scoped variable carries no
// continuing audit-trail tie that must outlive the resource, so the
// row is removed outright. The audit log already records the deletion
// independently of the row's lifetime, so removing the row does not
// erase the operator-facing history of the change.
//
// Returns apierr.NotFound when no row matches and apierr.StoreUnavailable
// for any other driver error. The raw driver error is wrapped as the
// cause for server-side logging only and never reaches the user-facing
// message.
func (r *OrganizationVariableRepository) DeleteByKey(ctx context.Context, tx *Tx, organizationID, key string) (OrganizationVariable, error) {
	if tx == nil {
		return OrganizationVariable{}, apierr.Internal(errors.New("store: OrganizationVariableRepository.DeleteByKey called with a nil transaction"))
	}
	row := tx.QueryRow(ctx,
		`DELETE FROM organization_variables
		  WHERE organization_id = $1 AND key = $2
		 RETURNING `+organizationVariableColumns,
		organizationID, key)
	deleted, err := scanOrganizationVariable(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationVariable{}, apierr.NotFound("organization_variable", key)
	}
	if err != nil {
		return OrganizationVariable{}, apierr.StoreUnavailable(err)
	}
	return deleted, nil
}

// UpdateMutable writes the caller-supplied value and is_secret onto the
// organization_variables row identified by (organizationID, key) inside
// tx and returns the persisted row, including the trigger-refreshed
// version and updated_at timestamp. It requires a *Tx — not a bare
// Querier — so a mutation can never be persisted outside the transaction
// that also carries its audit record. The query is tenant scoped: a key
// that belongs to another organization simply does not match and is
// reported as the typed apierr.NotFound the GET endpoint uses, never
// disguised as a 5xx and never revealing whether another tenant owns
// that key.
//
// The immutable identity fields (id, organization_id, key) and the
// lifecycle stamps (created_at) are deliberately not part of this
// method's surface — they are minted once at upsert time. The
// bump_version trigger refreshes version and updated_at as part of the
// row update, so the returned OrganizationVariable always reflects the
// post-commit state. Validation of organizationID, key, and value
// happens in the service layer before a transaction is opened; this
// method assumes its inputs already cleared the same shape checks
// PUT /v1/organizations/{org_id}/variables enforces.
//
// Returns apierr.NotFound when no row matches, apierr.Conflict for a
// CHECK or constraint violation, and apierr.StoreUnavailable for any
// other driver error. The raw driver error is wrapped as the cause for
// server-side logging only and never reaches the user-facing message —
// so a customer-facing 409 here never echoes value content.
func (r *OrganizationVariableRepository) UpdateMutable(ctx context.Context, tx *Tx, organizationID, key string, in OrganizationVariableUpsert) (OrganizationVariable, error) {
	if tx == nil {
		return OrganizationVariable{}, apierr.Internal(errors.New("store: OrganizationVariableRepository.UpdateMutable called with a nil transaction"))
	}
	provider, keyID, ciphertext := nullableSecretColumns(in)
	row := tx.QueryRow(ctx,
		`UPDATE organization_variables
		    SET value             = $3,
		        is_secret         = $4,
		        secret_provider   = $5,
		        secret_key_id     = $6,
		        secret_ciphertext = $7
		  WHERE organization_id = $1 AND key = $2
		 RETURNING `+organizationVariableColumns,
		organizationID, key, in.Value, in.IsSecret, provider, keyID, ciphertext)
	updated, err := scanOrganizationVariable(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationVariable{}, apierr.NotFound("organization_variable", key)
	}
	if err != nil {
		return OrganizationVariable{}, mapWriteError(err, "the organization variable could not be updated")
	}
	return updated, nil
}

// scanRow is the minimal Scan interface pgx.Row and pgx.Rows both satisfy.
// Keeping the scanner generic over both lets ListByOrganization and a
// future Get share the projection.
type scanRow interface {
	Scan(dest ...any) error
}

// scanOrganizationVariable scans one row into an OrganizationVariable. The
// column order must match organizationVariableColumns above. The three
// encryption-at-rest columns are nullable in the schema (NULL for
// non-secret rows); pgtype-aware scans into *string would reject NULL,
// so we route through sql.NullString and sql.NullBytes here.
func scanOrganizationVariable(row scanRow) (OrganizationVariable, error) {
	var (
		v          OrganizationVariable
		provider   sql.NullString
		keyID      sql.NullString
		ciphertext []byte
	)
	if err := row.Scan(
		&v.ID,
		&v.OrganizationID,
		&v.Key,
		&v.Value,
		&v.IsSecret,
		&provider,
		&keyID,
		&ciphertext,
		&v.Version,
		&v.CreatedAt,
		&v.UpdatedAt,
	); err != nil {
		return OrganizationVariable{}, err
	}
	if provider.Valid {
		v.SecretProvider = provider.String
	}
	if keyID.Valid {
		v.SecretKeyID = keyID.String
	}
	if len(ciphertext) > 0 {
		v.SecretCiphertext = ciphertext
	}
	return v, nil
}
