package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/JuribaDev/yalla/internal/controlplane/apierr"
	"github.com/JuribaDev/yalla/internal/output"
)

// environmentVariablesWriteAction is the action recorded on the audit event
// for PUT /v1/environments/{environment_id}/variables. It is kept as a plain
// string so the store layer takes no build dependency on
// internal/controlplane/policy; the HTTP authorization middleware authorizes
// the same action before the handler is reached, and the policy matrix tests
// keep the two values in sync.
const environmentVariablesWriteAction = "env.write"

// EnvironmentVariable is a single environment-scoped environment variable —
// the third-from-lowest precedence layer of the
// Organization -> Project -> Environment -> Service variable hierarchy the
// Dokploy renderer composes. An environment-scoped variable shadows any
// project-scoped variable of the same key for services inside the
// environment, which in turn shadows the organization-scoped variable of
// the same key.
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
// environment_variables_secret_columns_consistent is the defence-in-
// depth guarantee that no row can ever drift from it.
//
// The LogValue method below makes log records that accidentally carry an
// EnvironmentVariable safe by structurally hiding both the plain value AND
// the ciphertext at the slog boundary as a second line of defence —
// a panic stack trace or a debug log that captures the struct cannot
// leak the literal or the sealed bytes.
type EnvironmentVariable struct {
	ID               string
	OrganizationID   string
	EnvironmentID    string
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
// log record that captures an EnvironmentVariable cannot leak the literal
// plaintext OR the sealed ciphertext. Non-secret values reach the wire
// through the HTTP projection (which has its own explicit redaction
// policy); logs always see the sentinel. The slog record exposes the
// provider id and key id (already non-secret) so an operator can debug
// the encryption seam without exfiltrating the bytes themselves.
func (v EnvironmentVariable) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", v.ID),
		slog.String("organization_id", v.OrganizationID),
		slog.String("environment_id", v.EnvironmentID),
		slog.String("key", v.Key),
		slog.String("value", output.Sentinel),
		slog.Bool("is_secret", v.IsSecret),
		slog.String("secret_provider", v.SecretProvider),
		slog.String("secret_key_id", v.SecretKeyID),
		slog.String("secret_ciphertext", output.Sentinel),
		slog.Int64("version", v.Version),
	)
}

// environmentVariableColumns is the SELECT projection used by every read in
// this repository. Keeping it as a single string keeps the column list in
// lockstep with scanEnvironmentVariable. The encryption-at-rest columns
// (secret_provider, secret_key_id, secret_ciphertext) live next to value
// so a single Scan returns the whole row in one round trip; the store-
// layer service decides whether and when to call Provider.Open against
// the sealed tuple.
const environmentVariableColumns = `id, organization_id, environment_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext, version, created_at, updated_at`

// environmentVariableListMaxRows caps how many rows a single
// ListByEnvironment call returns. An unbounded query can never be issued
// by accident; an HTTP layer that wants pagination later will add an
// explicit offset or cursor parameter rather than relax this ceiling.
const environmentVariableListMaxRows = 500

// EnvironmentVariableRepository is the persistence half of the
// environment-variables surface. Every read is tenant-scoped: the
// organization_id and environment_id legs of the predicate are
// non-optional, so a missing or cross-tenant id simply matches no rows
// and yields an empty list — never another tenant's variables. The
// repository is stateless; the constructor exists so call sites depend
// on a value rather than a bare struct literal.
type EnvironmentVariableRepository struct{}

// NewEnvironmentVariableRepository builds a stateless
// EnvironmentVariableRepository.
func NewEnvironmentVariableRepository() *EnvironmentVariableRepository {
	return &EnvironmentVariableRepository{}
}

// ListByEnvironment returns every environment-scoped variable owned by
// (organizationID, environmentID), in deterministic (key ASC, id ASC)
// order so an agent observing the response sees a stable ordering across
// calls. The read is tenant-scoped at the SQL predicate, so a
// cross-tenant (organization, environment) tuple matches no rows. A raw
// driver error surfaces as the typed apierr.StoreUnavailable — the cause
// is wrapped for logging only, never leaked into the customer-facing
// message.
//
// This method does NOT verify the environment exists; callers that need
// to distinguish "environment missing" from "environment has no
// variables" must Get the environment first (the
// EnvironmentVariableReader adapter does so in the same short-lived
// transaction).
func (r *EnvironmentVariableRepository) ListByEnvironment(ctx context.Context, q Querier, organizationID, environmentID string) ([]EnvironmentVariable, error) {
	rows, err := q.Query(ctx,
		`SELECT `+environmentVariableColumns+`
		   FROM environment_variables
		  WHERE organization_id = $1 AND environment_id = $2
		  ORDER BY key ASC, id ASC
		  LIMIT $3`,
		organizationID, environmentID, environmentVariableListMaxRows)
	if err != nil {
		return nil, apierr.StoreUnavailable(err)
	}
	defer rows.Close()
	out := make([]EnvironmentVariable, 0)
	for rows.Next() {
		v, scanErr := scanEnvironmentVariable(rows)
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

// EnvironmentVariableUpsert is the closed-set tuple Upsert accepts. It
// binds the plain `value` column with the (secret_provider, secret_key_id,
// secret_ciphertext) encryption-at-rest tuple in one struct so the
// repository signature stays narrow as new secret fields land. The
// store-layer service builds this struct by calling
// secrets.Provider.Seal once per item; an IsSecret = true item MUST
// carry a non-empty ciphertext and Value MUST be "", and an
// IsSecret = false item MUST carry only Value with the ciphertext fields
// zeroed. The database CHECK constraint
// environment_variables_secret_columns_consistent rejects any drift as a
// deterministic apierr.Conflict.
type EnvironmentVariableUpsert struct {
	Value            string
	IsSecret         bool
	SecretProvider   string
	SecretKeyID      string
	SecretCiphertext []byte
}

// Upsert inserts or updates the (organization_id, environment_id, key) row
// carrying value / is_secret and (for secret rows) the encryption-at-rest
// tuple. The (organization_id, environment_id, key) UNIQUE constraint from
// migration 0018 is the conflict target, so an existing row keeps its id
// and bumps version through the bump_version trigger; a new row uses the
// caller-supplied id (already minted by the service layer through
// domain.NewID(KindEnvironmentVariable) so the id is non-guessable and
// tenant-anonymous). The returned EnvironmentVariable reflects the
// committed state — its id is the row's stable id (the existing id for an
// update, the freshly minted one for an insert), its version is the
// post-trigger version, and its updated_at is the moment the row
// persisted.
//
// The tenant predicate is non-optional: organization_id AND environment_id
// are part of the upsert key, so a cross-tenant smuggling attempt at this
// seam either matches an existing (organization_id, environment_id, key)
// tuple owned by the supplied tenant (the intended idempotent overwrite)
// or inserts a fresh row scoped to that tenant — never another tenant's
// data. Validation of organizationID, environmentID, key, and value
// happens in the service layer before a transaction is opened; this
// method assumes its inputs already cleared the same shape checks the PUT
// endpoint enforces.
//
// A foreign-key violation (organizationID/environmentID does not exist),
// the table's CHECK constraints (including the encryption-at-rest
// consistency invariant), and any other 23xxx integrity violation surface
// as apierr.Conflict through mapWriteError; any other driver error
// surfaces as apierr.StoreUnavailable. The raw driver error is wrapped as
// the cause for server-side logging only and never reaches the
// user-facing message — so a customer-facing 409 here never echoes value
// content.
func (r *EnvironmentVariableRepository) Upsert(ctx context.Context, tx *Tx, id, organizationID, environmentID, key string, in EnvironmentVariableUpsert) (EnvironmentVariable, error) {
	if tx == nil {
		return EnvironmentVariable{}, apierr.Internal(errors.New("store: EnvironmentVariableRepository.Upsert called with a nil transaction"))
	}
	provider, keyID, ciphertext := nullableEnvironmentSecretColumns(in)
	row := tx.QueryRow(ctx,
		`INSERT INTO environment_variables (id, organization_id, environment_id, key, value, is_secret, secret_provider, secret_key_id, secret_ciphertext)
		     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (organization_id, environment_id, key) DO UPDATE
		    SET value             = EXCLUDED.value,
		        is_secret         = EXCLUDED.is_secret,
		        secret_provider   = EXCLUDED.secret_provider,
		        secret_key_id     = EXCLUDED.secret_key_id,
		        secret_ciphertext = EXCLUDED.secret_ciphertext
		RETURNING `+environmentVariableColumns,
		id, organizationID, environmentID, key, in.Value, in.IsSecret, provider, keyID, ciphertext)
	v, err := scanEnvironmentVariable(row)
	if err != nil {
		return EnvironmentVariable{}, mapWriteError(err, "the environment variable could not be saved")
	}
	return v, nil
}

// nullableEnvironmentSecretColumns projects an EnvironmentVariableUpsert
// onto the (provider, keyID, ciphertext) tuple the SQL bind parameters
// expect. For IsSecret = false the tuple is (nil, nil, nil) so the
// columns are NULL — the CHECK constraint requires NULL in the non-secret
// state. For IsSecret = true the tuple is (provider, keyID, ciphertext)
// values the service just sealed.
func nullableEnvironmentSecretColumns(in EnvironmentVariableUpsert) (provider, keyID any, ciphertext any) {
	if !in.IsSecret {
		return nil, nil, nil
	}
	return in.SecretProvider, in.SecretKeyID, in.SecretCiphertext
}

// DeleteByEnvironmentExceptKeys removes every environment_variables row
// owned by (organizationID, environmentID) whose key is not in keepKeys.
// It is the counterpart of Upsert in the bulk-replace unit of work:
// Upsert applies every variable the caller wants to keep, and this method
// drops the rest — so the post-condition is "the environment's variables
// == exactly the caller-supplied set". keepKeys MAY be empty (the caller
// asked to clear every environment-scoped variable); the SQL predicate is
// written so `key <> ALL($3)` is true for every row when the array is
// empty, producing a deterministic full clear.
//
// The tenant predicate is non-optional: organization_id AND
// environment_id are part of the WHERE clause, so a cross-tenant tuple
// matches no rows and deletes nothing — never another tenant's data.
// Validation of organizationID, environmentID, and the keep list happens
// in the service layer; this method assumes the caller already produced a
// deduplicated, validated list of POSIX env-var names.
func (r *EnvironmentVariableRepository) DeleteByEnvironmentExceptKeys(ctx context.Context, tx *Tx, organizationID, environmentID string, keepKeys []string) error {
	if tx == nil {
		return apierr.Internal(errors.New("store: EnvironmentVariableRepository.DeleteByEnvironmentExceptKeys called with a nil transaction"))
	}
	if keepKeys == nil {
		keepKeys = []string{}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM environment_variables
		  WHERE organization_id = $1
		    AND environment_id  = $2
		    AND key <> ALL($3)`,
		organizationID, environmentID, keepKeys); err != nil {
		return mapWriteError(err, "the environment variables could not be reconciled")
	}
	return nil
}

// scanEnvironmentVariable scans one environment_variables row in
// environmentVariableColumns order. The three encryption-at-rest columns
// are nullable in the schema (NULL for non-secret rows); pgtype-aware
// scans into *string would reject NULL, so we route through
// sql.NullString and a plain []byte slice here.
func scanEnvironmentVariable(row scanRow) (EnvironmentVariable, error) {
	var (
		v          EnvironmentVariable
		provider   sql.NullString
		keyID      sql.NullString
		ciphertext []byte
	)
	if err := row.Scan(
		&v.ID,
		&v.OrganizationID,
		&v.EnvironmentID,
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
		return EnvironmentVariable{}, err
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

// EnvironmentVariableReader is the store-backed read adapter for the
// environment-variables surface: the persistence surface the httpapi
// layer needs to render GET /v1/environments/{environment_id}/variables.
// It mirrors ProjectVariableReader — it composes EnvironmentRepository
// and EnvironmentVariableRepository through a short-lived read-only
// transaction (Store.Read), so the tenant-scoping guarantees the
// repositories prove in their integration tests are inherited for free,
// and every cross-tenant or unknown environment_id surfaces as a
// deterministic apierr.NotFound rather than an empty list.
type EnvironmentVariableReader struct {
	store        *Store
	environments *EnvironmentRepository
	variables    *EnvironmentVariableRepository
}

// NewEnvironmentVariableReader builds an EnvironmentVariableReader over
// store. It returns an error for a nil store so a misconfigured adapter
// fails at construction rather than on its first request.
func NewEnvironmentVariableReader(s *Store) (*EnvironmentVariableReader, error) {
	if s == nil {
		return nil, errors.New("store: nil store")
	}
	return &EnvironmentVariableReader{
		store:        s,
		environments: NewEnvironmentRepository(),
		variables:    NewEnvironmentVariableRepository(),
	}, nil
}

// ListEnvironmentVariables returns every environment-scoped variable
// owned by (organizationID, environmentID), reading them inside a
// short-lived read-only transaction. The read is tenant scoped at both
// legs: it Gets the environment first so a cross-tenant or unknown
// environment_id surfaces as a deterministic apierr.NotFound — never as
// an empty list, which would invite an agent to believe the environment
// exists with no variables. A live environment with no variables is
// then a deterministic empty slice. A datastore failure is propagated
// as its own typed error.
//
// Variable values reach this layer verbatim from the database. The HTTP
// layer is the wire redaction chokepoint (secret values become the
// redaction sentinel; non-secret values project verbatim). A future
// audit layer will be the audit-metadata redaction chokepoint (every
// value redacted regardless of is_secret). The store does not redact at
// persistence — a future write path needs to round-trip values losslessly
// — but every consumer that surfaces values is required to redact, and
// EnvironmentVariable.LogValue redacts at the slog boundary as a second
// line of defence.
func (r *EnvironmentVariableReader) ListEnvironmentVariables(ctx context.Context, organizationID, environmentID string) ([]EnvironmentVariable, error) {
	var vars []EnvironmentVariable
	err := r.store.Read(ctx, func(ctx context.Context, q Querier) error {
		if _, getErr := r.environments.GetByID(ctx, q, organizationID, environmentID); getErr != nil {
			return getErr
		}
		list, listErr := r.variables.ListByEnvironment(ctx, q, organizationID, environmentID)
		if listErr != nil {
			return listErr
		}
		vars = list
		return nil
	})
	if err != nil {
		return nil, err
	}
	return vars, nil
}
